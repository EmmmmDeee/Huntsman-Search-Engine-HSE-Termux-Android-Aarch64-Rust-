//! Embedded append-only graph store with a dedicated batched background writer.

use std::path::Path;
use std::sync::Arc;
use std::thread::JoinHandle;

use huntsman_core::{Entity, EntityId};
use redb::{Database, TableDefinition};
use tokio::sync::{mpsc, oneshot};
use tracing::error;

use crate::error::StorageError;

/// Entities keyed by their deterministic 32-byte id, valued by canonical JSON.
const ENTITIES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("entities");

/// Bounded write queue depth: backpressure pauses producers once this many writes are in flight.
const WRITE_QUEUE_CAPACITY: usize = 512;

/// Maximum operations folded into a single commit, bounding transaction size and flash churn.
const BATCH_MAX: usize = 256;

/// A unit of work for the background writer.
enum WriteOp {
    /// Persist one serialized entity.
    Put { key: [u8; 32], value: Vec<u8> },
    /// Flush the current batch and acknowledge durability (or report the commit error).
    Sync(oneshot::Sender<Result<(), String>>),
}

/// An embedded graph store backed by a pure-Rust [`redb`] database.
///
/// All writes funnel through one background thread that batches them into append-only commits,
/// so concurrent producers never contend on the database write lock and flash writes stay
/// coalesced. Reads run on independent MVCC transactions and never block the writer.
pub struct GraphStore {
    db: Arc<Database>,
    writer_tx: Option<mpsc::Sender<WriteOp>>,
    writer: Option<JoinHandle<()>>,
}

impl GraphStore {
    /// Open (or create) the store at `path` and start its background writer.
    ///
    /// # Errors
    /// Returns [`StorageError::Backend`] if the database cannot be created, the entity table
    /// cannot be initialized, or the writer thread cannot be spawned.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let db = Database::create(path).map_err(|e| StorageError::Backend(e.to_string()))?;

        // Create the table eagerly so the first read never fails on a missing table.
        {
            let txn = db
                .begin_write()
                .map_err(|e| StorageError::Backend(e.to_string()))?;
            {
                let _table = txn
                    .open_table(ENTITIES)
                    .map_err(|e| StorageError::Backend(e.to_string()))?;
            }
            txn.commit()
                .map_err(|e| StorageError::Backend(e.to_string()))?;
        }

        let db = Arc::new(db);
        let (writer_tx, writer_rx) = mpsc::channel(WRITE_QUEUE_CAPACITY);
        let writer_db = Arc::clone(&db);
        let writer = std::thread::Builder::new()
            .name("huntsman-storage-writer".to_owned())
            .spawn(move || writer_loop(&writer_db, writer_rx))
            .map_err(|e| StorageError::Backend(format!("failed to spawn writer thread: {e}")))?;

        Ok(Self {
            db,
            writer_tx: Some(writer_tx),
            writer: Some(writer),
        })
    }

    /// Enqueue an entity for durable storage.
    ///
    /// Returns once the write is queued, applying bounded backpressure when the queue is full.
    /// Durability is confirmed separately by [`GraphStore::sync`]; a commit failure for an
    /// un-synced write is logged by the background writer.
    ///
    /// # Errors
    /// Returns [`StorageError::Serialization`] if the entity cannot be encoded, or
    /// [`StorageError::WriterUnavailable`] if the background writer has stopped.
    pub async fn put(&self, entity: &Entity) -> Result<(), StorageError> {
        let key = entity.provenance.entity_id;
        let value = serde_json::to_vec(entity)?;
        self.sender()?
            .send(WriteOp::Put { key, value })
            .await
            .map_err(|_| StorageError::WriterUnavailable("write queue closed".to_owned()))
    }

    /// Flush every write enqueued before this call and await its durable commit.
    ///
    /// # Errors
    /// Returns [`StorageError::Backend`] if the flushing commit failed, or
    /// [`StorageError::WriterUnavailable`] if the writer stopped before acknowledging.
    pub async fn sync(&self) -> Result<(), StorageError> {
        let (ack_tx, ack_rx) = oneshot::channel();
        self.sender()?
            .send(WriteOp::Sync(ack_tx))
            .await
            .map_err(|_| StorageError::WriterUnavailable("write queue closed".to_owned()))?;
        match ack_rx.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(msg)) => Err(StorageError::Backend(msg)),
            Err(_) => Err(StorageError::WriterUnavailable(
                "writer dropped before acknowledging sync".to_owned(),
            )),
        }
    }

    /// Load the entity stored under `id`, if present.
    ///
    /// # Errors
    /// Returns [`StorageError::Backend`] on a read-transaction failure or
    /// [`StorageError::Serialization`] if the stored bytes cannot be decoded.
    pub fn get(&self, id: &EntityId) -> Result<Option<Entity>, StorageError> {
        let txn = self
            .db
            .begin_read()
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        let table = txn
            .open_table(ENTITIES)
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        let guard = table
            .get(id.as_slice())
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        match guard {
            Some(bytes) => Ok(Some(serde_json::from_slice(bytes.value())?)),
            None => Ok(None),
        }
    }

    /// Stop the background writer and join its thread, ensuring all queued writes are flushed.
    ///
    /// # Errors
    /// Returns [`StorageError::Backend`] if the writer thread panicked while draining.
    pub fn shutdown(mut self) -> Result<(), StorageError> {
        // Dropping the only remaining sender closes the queue, so the writer drains and exits.
        drop(self.writer_tx.take());
        if let Some(handle) = self.writer.take() {
            handle
                .join()
                .map_err(|_| StorageError::Backend("writer thread panicked".to_owned()))?;
        }
        Ok(())
    }

    fn sender(&self) -> Result<&mpsc::Sender<WriteOp>, StorageError> {
        self.writer_tx
            .as_ref()
            .ok_or_else(|| StorageError::WriterUnavailable("store already shut down".to_owned()))
    }
}

fn writer_loop(db: &Database, mut rx: mpsc::Receiver<WriteOp>) {
    while let Some(first) = rx.blocking_recv() {
        let mut puts: Vec<([u8; 32], Vec<u8>)> = Vec::new();
        let mut acks: Vec<oneshot::Sender<Result<(), String>>> = Vec::new();
        collect(first, &mut puts, &mut acks);
        while puts.len() + acks.len() < BATCH_MAX {
            match rx.try_recv() {
                Ok(op) => collect(op, &mut puts, &mut acks),
                Err(_) => break,
            }
        }

        let result = commit_batch(db, &puts);
        if let Err(ref msg) = result {
            error!("storage commit failed for {} entries: {msg}", puts.len());
        }
        for ack in acks {
            let _ = ack.send(result.clone());
        }
    }
}

fn collect(
    op: WriteOp,
    puts: &mut Vec<([u8; 32], Vec<u8>)>,
    acks: &mut Vec<oneshot::Sender<Result<(), String>>>,
) {
    match op {
        WriteOp::Put { key, value } => puts.push((key, value)),
        WriteOp::Sync(ack) => acks.push(ack),
    }
}

fn commit_batch(db: &Database, puts: &[([u8; 32], Vec<u8>)]) -> Result<(), String> {
    if puts.is_empty() {
        return Ok(());
    }
    let txn = db.begin_write().map_err(|e| e.to_string())?;
    {
        let mut table = txn.open_table(ENTITIES).map_err(|e| e.to_string())?;
        for (key, value) in puts {
            table
                .insert(key.as_slice(), value.as_slice())
                .map_err(|e| e.to_string())?;
        }
    }
    txn.commit().map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use huntsman_core::{EntityKind, EpistemicLevel, ProvenanceEnvelope};

    fn scratch_path(tag: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "huntsman-storage-{tag}-{}-{nanos}.redb",
            std::process::id()
        ))
    }

    fn entity(domain: &str) -> Entity {
        let kind = match EntityKind::new_domain(domain) {
            Ok(kind) => kind,
            Err(err) => panic!("domain must canonicalize: {err}"),
        };
        let provenance = ProvenanceEnvelope::new(
            "test",
            1_710_000_000,
            domain.as_bytes(),
            &kind,
            EpistemicLevel::DirectObservation,
        );
        Entity {
            provenance,
            kind,
            hop_depth: 0,
        }
    }

    #[tokio::test]
    async fn put_sync_then_get_round_trips_through_the_background_writer() {
        let path = scratch_path("roundtrip");
        let store = match GraphStore::open(&path) {
            Ok(store) => store,
            Err(err) => panic!("open failed: {err}"),
        };

        let alpha = entity("alpha.example");
        let beta = entity("beta.example");
        let alpha_id = alpha.provenance.entity_id;
        let beta_id = beta.provenance.entity_id;

        if let Err(err) = store.put(&alpha).await {
            panic!("put alpha: {err}");
        }
        if let Err(err) = store.put(&beta).await {
            panic!("put beta: {err}");
        }
        if let Err(err) = store.sync().await {
            panic!("sync: {err}");
        }

        let loaded = match store.get(&alpha_id) {
            Ok(value) => value,
            Err(err) => panic!("get alpha: {err}"),
        };
        assert_eq!(loaded.as_ref(), Some(&alpha));
        match store.get(&beta_id) {
            Ok(Some(found)) => assert_eq!(found, beta),
            other => panic!("expected beta, got {other:?}"),
        }

        let missing = entity("absent.example").provenance.entity_id;
        match store.get(&missing) {
            Ok(None) => {}
            other => panic!("expected absence, got {other:?}"),
        }

        if let Err(err) = store.shutdown() {
            panic!("shutdown: {err}");
        }
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn committed_entities_survive_a_reopen() {
        let path = scratch_path("reopen");
        let seed = entity("persist.example");
        let seed_id = seed.provenance.entity_id;

        {
            let store = match GraphStore::open(&path) {
                Ok(store) => store,
                Err(err) => panic!("open: {err}"),
            };
            if let Err(err) = store.put(&seed).await {
                panic!("put: {err}");
            }
            if let Err(err) = store.sync().await {
                panic!("sync: {err}");
            }
            if let Err(err) = store.shutdown() {
                panic!("shutdown: {err}");
            }
        }

        let reopened = match GraphStore::open(&path) {
            Ok(store) => store,
            Err(err) => panic!("reopen: {err}"),
        };
        match reopened.get(&seed_id) {
            Ok(Some(found)) => assert_eq!(found, seed),
            other => panic!("entity did not survive reopen: {other:?}"),
        }
        let _ = reopened.shutdown();
        let _ = std::fs::remove_file(&path);
    }
}
