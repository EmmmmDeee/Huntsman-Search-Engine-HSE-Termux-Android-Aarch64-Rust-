//! Embedded append-only graph store with a dedicated batched background writer.
//!
//! # Tables
//!
//! * `entities` — one row per [`EntityId`], holding the canonical JSON of the **first** [`Entity`]
//!   observed under that id. A row is inserted only when absent and is never rewritten, so the
//!   provenance under which a node first entered the graph survives every later re-scan.
//! * `observations` — one row per distinct [`ProvenanceEnvelope`] recorded for an id, keyed by
//!   `entity_id ‖ observed_at_utc (u64 BE) ‖ epistemic tag ‖ raw_evidence_hash ‖ source_module`.
//!   The key is an injective encoding of the envelope, so re-putting the identical observation is
//!   idempotent while any differing observation appends a new row. Rows are never updated or
//!   deleted; [`GraphStore::observations`] returns them oldest first.
//!
//! # Durability truth
//!
//! Operations enter one FIFO queue and the writer commits them in order. The first failed commit
//! is latched for the lifetime of the handle: from then on every [`GraphStore::sync`] returns it
//! (even when nothing new was queued), [`GraphStore::put`] refuses new writes, and
//! [`GraphStore::shutdown`] reports it. A `sync` that returns `Ok` therefore guarantees that every
//! operation enqueued before it was committed. `redb` itself refuses every write after an I/O
//! error until the file is reopened, so the only recovery is to drop the store and open it again.

use std::path::Path;
use std::sync::{Arc, OnceLock};
use std::thread::{JoinHandle, Thread};
use std::time::{Duration, Instant};

use huntsman_core::{Entity, EntityId, EpistemicLevel, ProvenanceEnvelope};
use redb::{Database, ReadableTable, TableDefinition};
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::{mpsc, oneshot};
use tracing::error;

use crate::error::StorageError;

/// First observation of each entity, keyed by its deterministic 32-byte id, valued by JSON.
const ENTITIES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("entities");

/// Every distinct provenance envelope ever recorded, keyed by [`observation_key`], valued by JSON.
const OBSERVATIONS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("observations");

/// Bounded write queue depth: backpressure pauses producers once this many writes are in flight.
const WRITE_QUEUE_CAPACITY: usize = 512;

/// Maximum operations folded into a single commit, bounding transaction size and flash churn.
const BATCH_MAX: usize = 256;

/// Tuning knobs for [`GraphStore::open_with`], bounded to the 128 MiB device ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreConfig {
    cache_bytes: usize,
    linger: Duration,
}

impl StoreConfig {
    /// Heap `redb` may spend on its page cache unless overridden: a quarter of the process ceiling.
    pub const DEFAULT_CACHE_BYTES: usize = 32 * 1024 * 1024;

    /// Largest page cache [`GraphStore::open_with`] accepts: half of the 128 MiB process ceiling.
    pub const MAX_CACHE_BYTES: usize = 64 * 1024 * 1024;

    /// How long the writer waits for more puts before committing a batch that holds no sync.
    pub const DEFAULT_LINGER: Duration = Duration::from_millis(10);

    /// Longest linger [`GraphStore::open_with`] accepts.
    pub const MAX_LINGER: Duration = Duration::from_secs(1);

    /// Set the page-cache budget in bytes (at most [`StoreConfig::MAX_CACHE_BYTES`]).
    #[must_use]
    pub fn with_cache_bytes(mut self, cache_bytes: usize) -> Self {
        self.cache_bytes = cache_bytes;
        self
    }

    /// Set the commit linger for put-only batches (at most [`StoreConfig::MAX_LINGER`]).
    ///
    /// `Duration::ZERO` commits every batch as soon as the queue runs dry. A sync always commits
    /// its batch immediately, whatever the linger.
    #[must_use]
    pub fn with_linger(mut self, linger: Duration) -> Self {
        self.linger = linger;
        self
    }

    /// The page-cache budget in bytes.
    #[must_use]
    pub fn cache_bytes(&self) -> usize {
        self.cache_bytes
    }

    /// The commit linger for put-only batches.
    #[must_use]
    pub fn linger(&self) -> Duration {
        self.linger
    }

    fn validate(&self) -> Result<(), StorageError> {
        if self.cache_bytes > Self::MAX_CACHE_BYTES {
            return Err(StorageError::ConfigOutOfRange {
                setting: "cache_bytes",
                requested: self.cache_bytes as u64,
                max: Self::MAX_CACHE_BYTES as u64,
            });
        }
        if self.linger > Self::MAX_LINGER {
            return Err(StorageError::ConfigOutOfRange {
                setting: "linger_millis",
                requested: u64::try_from(self.linger.as_millis()).unwrap_or(u64::MAX),
                max: u64::try_from(Self::MAX_LINGER.as_millis()).unwrap_or(u64::MAX),
            });
        }
        Ok(())
    }
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            cache_bytes: Self::DEFAULT_CACHE_BYTES,
            linger: Self::DEFAULT_LINGER,
        }
    }
}

/// One entity encoded for the writer: the writer never serializes, it only stores bytes.
struct PendingWrite {
    id: EntityId,
    observation_key: Vec<u8>,
    entity: Vec<u8>,
    envelope: Vec<u8>,
}

impl PendingWrite {
    fn encode(entity: &Entity) -> Result<Self, StorageError> {
        Ok(Self {
            id: entity.provenance.entity_id,
            observation_key: observation_key(&entity.provenance),
            entity: serde_json::to_vec(entity)?,
            envelope: serde_json::to_vec(&entity.provenance)?,
        })
    }
}

/// A unit of work for the background writer.
enum WriteOp {
    /// Persist one encoded entity and its observation.
    Put(PendingWrite),
    /// Commit the current batch now and acknowledge durability (or report the latched failure).
    Sync(oneshot::Sender<Result<(), String>>),
}

/// State shared between the handle and its writer thread.
#[derive(Debug, Default)]
struct WriterShared {
    /// The first commit failure, latched for the lifetime of the store.
    first_error: OnceLock<String>,
}

/// An embedded graph store backed by a pure-Rust [`redb`] database.
///
/// All writes funnel through one background thread that batches them into append-only commits,
/// so concurrent producers never contend on the database write lock and flash writes stay
/// coalesced. Reads run on independent MVCC transactions and never block the writer.
///
/// Dropping the store closes the queue, drains it and joins the writer before the database file
/// is released, so an immediate reopen succeeds and no queued write is abandoned. Dropping inside
/// an async task blocks that worker for the length of the drain; call [`GraphStore::shutdown`]
/// instead when the drain result matters.
pub struct GraphStore {
    db: Arc<Database>,
    config: StoreConfig,
    shared: Arc<WriterShared>,
    writer_tx: Option<mpsc::Sender<WriteOp>>,
    writer_thread: Thread,
    writer: Option<JoinHandle<Result<(), String>>>,
}

impl GraphStore {
    /// Open (or create) the store at `path` with [`StoreConfig::default`].
    ///
    /// # Errors
    /// See [`GraphStore::open_with`].
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        Self::open_with(path, StoreConfig::default())
    }

    /// Open (or create) the store at `path` with an explicit `config` and start its writer.
    ///
    /// The database is always opened through [`redb::Builder`] with `config`'s cache budget;
    /// `redb`'s own default of 1 GiB is never used.
    ///
    /// # Errors
    /// Returns [`StorageError::ConfigOutOfRange`] if `config` exceeds a platform ceiling, or
    /// [`StorageError::Backend`] if the database cannot be created, a table cannot be initialized,
    /// or the writer thread cannot be spawned.
    pub fn open_with(path: impl AsRef<Path>, config: StoreConfig) -> Result<Self, StorageError> {
        config.validate()?;
        let db = Database::builder()
            .set_cache_size(config.cache_bytes)
            .create(path)
            .map_err(backend)?;
        Self::from_database(db, config)
    }

    /// Wrap an already-open database: the seam `open_with` and the fault-injection tests share.
    fn from_database(db: Database, config: StoreConfig) -> Result<Self, StorageError> {
        config.validate()?;

        // Create both tables eagerly so the first read never fails on a missing table.
        {
            let txn = db.begin_write().map_err(backend)?;
            {
                let _entities = txn.open_table(ENTITIES).map_err(backend)?;
                let _observations = txn.open_table(OBSERVATIONS).map_err(backend)?;
            }
            txn.commit().map_err(backend)?;
        }

        let db = Arc::new(db);
        let shared = Arc::new(WriterShared::default());
        let (writer_tx, writer_rx) = mpsc::channel(WRITE_QUEUE_CAPACITY);
        let writer_db = Arc::clone(&db);
        let writer_shared = Arc::clone(&shared);
        let linger = config.linger;
        let writer = std::thread::Builder::new()
            .name("huntsman-storage-writer".to_owned())
            .spawn(move || writer_loop(&writer_db, &writer_shared, linger, writer_rx))
            .map_err(|e| StorageError::Backend(format!("failed to spawn writer thread: {e}")))?;
        let writer_thread = writer.thread().clone();

        Ok(Self {
            db,
            config,
            shared,
            writer_tx: Some(writer_tx),
            writer_thread,
            writer: Some(writer),
        })
    }

    /// The configuration this store was opened with.
    #[must_use]
    pub fn config(&self) -> StoreConfig {
        self.config
    }

    /// Enqueue an entity for durable storage.
    ///
    /// Returns once the write is queued, applying bounded backpressure when the queue is full.
    /// The entity row is written only if its id is new; its provenance envelope is appended to
    /// the observation ledger unless that exact observation is already recorded. Durability is
    /// confirmed separately by [`GraphStore::sync`].
    ///
    /// # Errors
    /// Returns [`StorageError::Serialization`] if the entity cannot be encoded,
    /// [`StorageError::Backend`] if an earlier commit has already failed (the store is poisoned
    /// and accepts nothing further), or [`StorageError::WriterUnavailable`] if the writer has
    /// stopped.
    pub async fn put(&self, entity: &Entity) -> Result<(), StorageError> {
        self.check_poisoned()?;
        let write = PendingWrite::encode(entity)?;
        self.enqueue(WriteOp::Put(write)).await
    }

    /// Commit every write enqueued before this call and await its durability.
    ///
    /// `Ok` means every operation enqueued before this call, by any producer, is committed.
    ///
    /// # Errors
    /// Returns [`StorageError::Backend`] if any commit has failed since the store was opened,
    /// including commits of batches that held no sync, or [`StorageError::WriterUnavailable`]
    /// if the writer stopped before acknowledging.
    pub async fn sync(&self) -> Result<(), StorageError> {
        self.check_poisoned()?;
        let (ack_tx, ack_rx) = oneshot::channel();
        self.enqueue(WriteOp::Sync(ack_tx)).await?;
        match ack_rx.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(msg)) => Err(StorageError::Backend(msg)),
            Err(_) => Err(self.unavailable("writer stopped before acknowledging the sync")),
        }
    }

    /// Load the first entity observed under `id`, if any.
    ///
    /// # Errors
    /// Returns [`StorageError::Backend`] on a read-transaction failure or
    /// [`StorageError::Serialization`] if the stored bytes cannot be decoded.
    pub fn get(&self, id: &EntityId) -> Result<Option<Entity>, StorageError> {
        let txn = self.db.begin_read().map_err(backend)?;
        let table = txn.open_table(ENTITIES).map_err(backend)?;
        let guard = table.get(id.as_slice()).map_err(backend)?;
        match guard {
            Some(bytes) => Ok(Some(serde_json::from_slice(bytes.value())?)),
            None => Ok(None),
        }
    }

    /// Load up to `limit` provenance observations recorded for `id`, oldest first.
    ///
    /// Every distinct envelope ever put for `id` is returned, including the one carried by the
    /// entity row; identical re-observations appear once. `limit` bounds the memory of one read.
    ///
    /// # Errors
    /// Returns [`StorageError::Backend`] on a read-transaction failure or
    /// [`StorageError::Serialization`] if a stored envelope cannot be decoded.
    pub fn observations(
        &self,
        id: &EntityId,
        limit: usize,
    ) -> Result<Vec<ProvenanceEnvelope>, StorageError> {
        let txn = self.db.begin_read().map_err(backend)?;
        let table = txn.open_table(OBSERVATIONS).map_err(backend)?;
        let rows = table.range::<&[u8]>(id.as_slice()..).map_err(backend)?;
        let mut found = Vec::new();
        for row in rows {
            if found.len() >= limit {
                break;
            }
            let (key, value) = row.map_err(backend)?;
            if !key.value().starts_with(id) {
                break;
            }
            found.push(serde_json::from_slice(value.value())?);
        }
        Ok(found)
    }

    /// Stop the background writer and join its thread, ensuring all queued writes are flushed.
    ///
    /// Dropping the store performs the same drain; `shutdown` is the path that reports its result.
    ///
    /// # Errors
    /// Returns [`StorageError::Backend`] if any commit failed since the store was opened,
    /// including one made while draining the queue, or if the writer thread panicked.
    pub fn shutdown(mut self) -> Result<(), StorageError> {
        self.close_writer()
    }

    /// Close the queue, wake a lingering writer, drain and join it. Idempotent: the second call
    /// (from `Drop` after `shutdown`) finds nothing to do.
    fn close_writer(&mut self) -> Result<(), StorageError> {
        // Dropping the only sender closes the queue, so the writer drains and exits.
        drop(self.writer_tx.take());
        self.writer_thread.unpark();
        let Some(handle) = self.writer.take() else {
            return Ok(());
        };
        match handle.join() {
            Ok(Ok(())) => Ok(()),
            Ok(Err(msg)) => Err(StorageError::Backend(msg)),
            Err(_) => Err(StorageError::Backend(
                "writer thread panicked; queued writes were lost".to_owned(),
            )),
        }
    }

    async fn enqueue(&self, op: WriteOp) -> Result<(), StorageError> {
        let sender = self
            .writer_tx
            .as_ref()
            .ok_or_else(|| self.unavailable("store already shut down"))?;
        sender
            .send(op)
            .await
            .map_err(|_| self.unavailable("write queue closed"))?;
        // A lingering writer is parked; wake it so a sync never waits out the linger.
        self.writer_thread.unpark();
        Ok(())
    }

    fn check_poisoned(&self) -> Result<(), StorageError> {
        match self.shared.first_error.get() {
            Some(msg) => Err(StorageError::Backend(msg.clone())),
            None => Ok(()),
        }
    }

    /// The latched commit failure when there is one (it explains why the writer is gone),
    /// otherwise a [`StorageError::WriterUnavailable`] carrying `reason`.
    fn unavailable(&self, reason: &str) -> StorageError {
        self.shared.first_error.get().map_or_else(
            || StorageError::WriterUnavailable(reason.to_owned()),
            |msg| StorageError::Backend(msg.clone()),
        )
    }
}

impl Drop for GraphStore {
    fn drop(&mut self) {
        if let Err(err) = self.close_writer() {
            error!("storage writer reported a failure while closing: {err}");
        }
    }
}

fn backend(err: impl std::fmt::Display) -> StorageError {
    StorageError::Backend(err.to_string())
}

/// The injective ledger key of an observation: fixed-width fields first, the variable-length
/// module name last, so two envelopes share a key only when every field is equal. Keys of one
/// entity are contiguous and sort by observation time.
fn observation_key(envelope: &ProvenanceEnvelope) -> Vec<u8> {
    let module = envelope.source_module.as_bytes();
    let mut key = Vec::with_capacity(32 + 8 + 1 + 32 + module.len());
    key.extend_from_slice(&envelope.entity_id);
    key.extend_from_slice(&envelope.observed_at_utc.to_be_bytes());
    key.push(epistemic_tag(envelope.epistemic_level));
    key.extend_from_slice(&envelope.raw_evidence_hash);
    key.extend_from_slice(module);
    key
}

/// Stable one-byte encoding of the epistemic tier inside observation keys. Never renumber.
fn epistemic_tag(level: EpistemicLevel) -> u8 {
    match level {
        EpistemicLevel::DirectObservation => 0,
        EpistemicLevel::ProtocolLog => 1,
        EpistemicLevel::ThirdPartyIndex => 2,
    }
}

/// Operations gathered for one commit.
#[derive(Default)]
struct Batch {
    puts: Vec<PendingWrite>,
    acks: Vec<oneshot::Sender<Result<(), String>>>,
}

impl Batch {
    fn push(&mut self, op: WriteOp) {
        match op {
            WriteOp::Put(write) => self.puts.push(write),
            WriteOp::Sync(ack) => self.acks.push(ack),
        }
    }

    fn is_full(&self) -> bool {
        self.puts.len() + self.acks.len() >= BATCH_MAX
    }

    fn wants_immediate_commit(&self) -> bool {
        !self.acks.is_empty()
    }
}

/// The writer thread: gathers a batch, lingers for more puts unless a sync is waiting, commits,
/// then acknowledges. Returns the latched commit failure, if any, through the join handle.
fn writer_loop(
    db: &Database,
    shared: &WriterShared,
    linger: Duration,
    mut rx: mpsc::Receiver<WriteOp>,
) -> Result<(), String> {
    let mut discarded = 0usize;
    while let Some(first) = rx.blocking_recv() {
        let mut batch = Batch::default();
        batch.push(first);
        let deadline = Instant::now()
            .checked_add(linger)
            .unwrap_or_else(Instant::now);
        loop {
            match rx.try_recv() {
                Ok(op) => {
                    batch.push(op);
                    if batch.is_full() {
                        break;
                    }
                }
                Err(TryRecvError::Empty) => {
                    if batch.wants_immediate_commit() {
                        break;
                    }
                    let now = Instant::now();
                    if now >= deadline {
                        break;
                    }
                    // Producers and `close_writer` unpark this thread; spurious wakes just loop.
                    std::thread::park_timeout(deadline - now);
                }
                Err(TryRecvError::Disconnected) => break,
            }
        }

        let result = match shared.first_error.get() {
            Some(msg) => {
                discarded += batch.puts.len();
                Err(msg.clone())
            }
            None => commit_batch(db, &batch.puts).map_err(|msg| {
                error!(
                    "storage commit failed for {} entries; the store is now poisoned: {msg}",
                    batch.puts.len()
                );
                // First failure wins; a second `set` can only happen if a race set it already.
                let _ = shared.first_error.set(msg.clone());
                msg
            }),
        };
        for ack in batch.acks {
            let _ = ack.send(result.clone());
        }
    }
    if discarded > 0 {
        error!("discarded {discarded} queued writes after the first commit failure");
    }
    shared.first_error.get().cloned().map_or(Ok(()), Err)
}

/// Commit one batch: entity rows insert-if-absent, observation rows append-if-absent.
fn commit_batch(db: &Database, puts: &[PendingWrite]) -> Result<(), String> {
    if puts.is_empty() {
        return Ok(());
    }
    let txn = db.begin_write().map_err(|e| e.to_string())?;
    {
        let mut entities = txn.open_table(ENTITIES).map_err(|e| e.to_string())?;
        let mut observations = txn.open_table(OBSERVATIONS).map_err(|e| e.to_string())?;
        for put in puts {
            let id = put.id.as_slice();
            let first_observation = entities.get(id).map_err(|e| e.to_string())?.is_none();
            if first_observation {
                entities
                    .insert(id, put.entity.as_slice())
                    .map_err(|e| e.to_string())?;
            }
            let key = put.observation_key.as_slice();
            let unseen = observations.get(key).map_err(|e| e.to_string())?.is_none();
            if unseen {
                observations
                    .insert(key, put.envelope.as_slice())
                    .map_err(|e| e.to_string())?;
            }
        }
    }
    txn.commit().map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use huntsman_core::{EntityKind, EpistemicLevel, ProvenanceEnvelope};
    use redb::backends::InMemoryBackend;
    use redb::StorageBackend;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    /// A scratch database path that is removed when the test ends, pass or fail.
    struct ScratchFile(std::path::PathBuf);

    impl ScratchFile {
        fn new(tag: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            Self(std::env::temp_dir().join(format!(
                "huntsman-storage-{tag}-{}-{nanos}.redb",
                std::process::id()
            )))
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for ScratchFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn open(path: &Path) -> GraphStore {
        match GraphStore::open(path) {
            Ok(store) => store,
            Err(err) => panic!("open {}: {err}", path.display()),
        }
    }

    fn observed(
        domain: &str,
        module: &'static str,
        observed_at_utc: u64,
        payload: &[u8],
        level: EpistemicLevel,
    ) -> Entity {
        let kind = match EntityKind::new_domain(domain) {
            Ok(kind) => kind,
            Err(err) => panic!("domain must canonicalize: {err}"),
        };
        let provenance = ProvenanceEnvelope::new(module, observed_at_utc, payload, &kind, level);
        Entity {
            provenance,
            kind,
            hop_depth: 0,
        }
    }

    fn entity(domain: &str) -> Entity {
        observed(
            domain,
            "test",
            1_710_000_000,
            domain.as_bytes(),
            EpistemicLevel::DirectObservation,
        )
    }

    /// Fault-injection switches shared between a test and its [`FaultBackend`].
    #[derive(Debug, Default)]
    struct Faults {
        /// When set, every mutating backend call fails with `StorageFull` (ENOSPC).
        storage_full: AtomicBool,
        /// Mutating calls that were refused while `storage_full` was set.
        refused: AtomicUsize,
        /// `sync_data` calls that reached the backend: one commit costs a fixed number of them.
        syncs: AtomicUsize,
    }

    /// An in-memory redb backend whose writes can be made to fail like a full flash partition.
    #[derive(Debug)]
    struct FaultBackend {
        inner: InMemoryBackend,
        faults: Arc<Faults>,
    }

    impl FaultBackend {
        fn mutate<T>(&self, op: impl FnOnce() -> std::io::Result<T>) -> std::io::Result<T> {
            if self.faults.storage_full.load(Ordering::SeqCst) {
                self.faults.refused.fetch_add(1, Ordering::SeqCst);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::StorageFull,
                    "injected: no space left on device",
                ));
            }
            op()
        }
    }

    impl StorageBackend for FaultBackend {
        fn len(&self) -> std::io::Result<u64> {
            self.inner.len()
        }

        fn read(&self, offset: u64, len: usize) -> std::io::Result<Vec<u8>> {
            self.inner.read(offset, len)
        }

        fn set_len(&self, len: u64) -> std::io::Result<()> {
            self.mutate(|| self.inner.set_len(len))
        }

        fn sync_data(&self, eventual: bool) -> std::io::Result<()> {
            self.faults.syncs.fetch_add(1, Ordering::SeqCst);
            self.mutate(|| self.inner.sync_data(eventual))
        }

        fn write(&self, offset: u64, data: &[u8]) -> std::io::Result<()> {
            self.mutate(|| self.inner.write(offset, data))
        }
    }

    fn open_faulty_with(config: StoreConfig) -> (GraphStore, Arc<Faults>) {
        let faults = Arc::new(Faults::default());
        let backend = FaultBackend {
            inner: InMemoryBackend::new(),
            faults: Arc::clone(&faults),
        };
        let db = match Database::builder()
            .set_cache_size(1 << 20)
            .create_with_backend(backend)
        {
            Ok(db) => db,
            Err(err) => panic!("create in-memory database: {err}"),
        };
        let store = match GraphStore::from_database(db, config) {
            Ok(store) => store,
            Err(err) => panic!("open store on in-memory database: {err}"),
        };
        (store, faults)
    }

    fn open_faulty() -> (GraphStore, Arc<Faults>) {
        open_faulty_with(StoreConfig::default())
    }

    /// Wait until the backend has refused at least one mutating call, proving the writer has
    /// attempted (and failed) a commit, without going through `sync()`.
    async fn wait_for_refusal(faults: &Faults) {
        for _ in 0..5_000 {
            if faults.refused.load(Ordering::SeqCst) > 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        panic!("the writer never attempted a commit against the failing backend");
    }

    #[tokio::test]
    async fn sync_reports_an_earlier_commit_failure_even_when_its_own_batch_is_empty() {
        let (store, faults) = open_faulty();
        if let Err(err) = store.put(&entity("before.example")).await {
            panic!("put before fault: {err}");
        }
        if let Err(err) = store.sync().await {
            panic!("sync before fault: {err}");
        }

        faults.storage_full.store(true, Ordering::SeqCst);
        if let Err(err) = store.put(&entity("lost.example")).await {
            panic!("put must still enqueue (durability is confirmed by sync): {err}");
        }
        // The writer commits the put in its own batch and that commit fails. A later sync whose
        // batch holds no puts must still surface that failure instead of claiming durability.
        wait_for_refusal(&faults).await;

        match store.sync().await {
            Err(StorageError::Backend(_)) => {}
            other => panic!("sync after a failed commit must report it, got {other:?}"),
        }
        match store.sync().await {
            Err(StorageError::Backend(_)) => {}
            other => panic!("the commit failure must stay sticky, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn put_fails_fast_once_a_commit_has_failed() {
        let (store, faults) = open_faulty();
        faults.storage_full.store(true, Ordering::SeqCst);
        if let Err(err) = store.put(&entity("first.example")).await {
            panic!("the first put enqueues normally: {err}");
        }
        wait_for_refusal(&faults).await;

        match store.put(&entity("second.example")).await {
            Err(StorageError::Backend(_)) => {}
            other => panic!("put into a poisoned store must fail fast, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn shutdown_reports_a_commit_that_failed_during_the_drain() {
        let (store, faults) = open_faulty();
        faults.storage_full.store(true, Ordering::SeqCst);
        if let Err(err) = store.put(&entity("drained.example")).await {
            panic!("put: {err}");
        }
        match store.shutdown() {
            Err(StorageError::Backend(_)) => {}
            other => panic!("shutdown must report the failed drain commit, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_healthy_store_shuts_down_cleanly_after_a_drain() {
        let (store, faults) = open_faulty();
        for i in 0..300 {
            if let Err(err) = store.put(&entity(&format!("d{i}.example"))).await {
                panic!("put: {err}");
            }
        }
        if let Err(err) = store.shutdown() {
            panic!("shutdown of a healthy store: {err}");
        }
        assert_eq!(faults.refused.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn the_first_observation_of_an_entity_is_never_overwritten() {
        let scratch = ScratchFile::new("first-wins");
        let store = open(scratch.path());
        let direct = observed(
            "shared.example",
            "dns_resolve",
            1_710_000_000,
            b"wire response",
            EpistemicLevel::DirectObservation,
        );
        let indexed = observed(
            "shared.example",
            "third-party-index",
            1_720_000_000,
            b"index row",
            EpistemicLevel::ThirdPartyIndex,
        );
        assert_eq!(direct.provenance.entity_id, indexed.provenance.entity_id);
        assert_ne!(direct.provenance, indexed.provenance);
        let id = direct.provenance.entity_id;

        for entity in [&direct, &indexed] {
            if let Err(err) = store.put(entity).await {
                panic!("put: {err}");
            }
        }
        if let Err(err) = store.sync().await {
            panic!("sync: {err}");
        }

        match store.get(&id) {
            Ok(Some(found)) => assert_eq!(
                found, direct,
                "a later observation replaced the first one's provenance"
            ),
            other => panic!("expected the first observation, got {other:?}"),
        }
        if let Err(err) = store.shutdown() {
            panic!("shutdown: {err}");
        }
    }

    #[tokio::test]
    async fn every_distinct_observation_is_appended_once_and_read_back_oldest_first() {
        let scratch = ScratchFile::new("ledger");
        let store = open(scratch.path());
        let direct = observed(
            "ledger.example",
            "dns_resolve",
            1_710_000_000,
            b"wire response",
            EpistemicLevel::DirectObservation,
        );
        let indexed = observed(
            "ledger.example",
            "third-party-index",
            1_720_000_000,
            b"index row",
            EpistemicLevel::ThirdPartyIndex,
        );
        let id = direct.provenance.entity_id;

        // The identical observation twice (in separate commits) must land exactly once.
        for entity in [&indexed, &direct, &direct] {
            if let Err(err) = store.put(entity).await {
                panic!("put: {err}");
            }
            if let Err(err) = store.sync().await {
                panic!("sync: {err}");
            }
        }

        match store.observations(&id, 16) {
            Ok(found) => assert_eq!(
                found,
                vec![direct.provenance.clone(), indexed.provenance.clone()],
                "the ledger must hold each distinct envelope once, oldest first"
            ),
            Err(err) => panic!("observations: {err}"),
        }
        match store.observations(&id, 1) {
            Ok(found) => assert_eq!(found, vec![direct.provenance.clone()]),
            Err(err) => panic!("bounded observations: {err}"),
        }
        match store.observations(&entity("absent.example").provenance.entity_id, 16) {
            Ok(found) => assert!(found.is_empty()),
            Err(err) => panic!("observations of an unknown id: {err}"),
        }
        match store.get(&id) {
            Ok(Some(found)) => assert_eq!(found, indexed, "the first put owns the entity row"),
            other => panic!("expected the entity row, got {other:?}"),
        }
        if let Err(err) = store.shutdown() {
            panic!("shutdown: {err}");
        }
    }

    #[test]
    fn observation_keys_are_injective_over_every_envelope_field() {
        let base = observed(
            "key.example",
            "mod",
            7,
            b"payload",
            EpistemicLevel::DirectObservation,
        )
        .provenance;
        let variants = [
            observed(
                "key.example",
                "mod",
                8,
                b"payload",
                EpistemicLevel::DirectObservation,
            )
            .provenance,
            observed(
                "key.example",
                "mod",
                7,
                b"payload",
                EpistemicLevel::ProtocolLog,
            )
            .provenance,
            observed(
                "key.example",
                "mod",
                7,
                b"other",
                EpistemicLevel::DirectObservation,
            )
            .provenance,
            observed(
                "key.example",
                "module",
                7,
                b"payload",
                EpistemicLevel::DirectObservation,
            )
            .provenance,
        ];
        let base_key = observation_key(&base);
        assert_eq!(base_key, observation_key(&base.clone()));
        assert!(base_key.starts_with(&base.entity_id));
        for variant in &variants {
            assert_ne!(observation_key(variant), base_key, "{variant:?}");
        }
    }

    #[tokio::test]
    async fn dropping_the_store_drains_the_queue_and_releases_the_database() {
        let scratch = ScratchFile::new("drop-reopen");
        let entities: Vec<Entity> = (0..600).map(|i| entity(&format!("e{i}.example"))).collect();
        {
            let store = open(scratch.path());
            for entity in &entities {
                if let Err(err) = store.put(entity).await {
                    panic!("put: {err}");
                }
            }
            drop(store);
        }

        let reopened = match GraphStore::open(scratch.path()) {
            Ok(store) => store,
            Err(err) => panic!("reopen right after drop failed: {err}"),
        };
        let persisted = entities
            .iter()
            .filter(|entity| {
                matches!(reopened.get(&entity.provenance.entity_id), Ok(Some(found)) if &found == *entity)
            })
            .count();
        assert_eq!(
            persisted,
            entities.len(),
            "writes queued before the drop were not all flushed"
        );
        if let Err(err) = reopened.shutdown() {
            panic!("shutdown: {err}");
        }
    }

    #[tokio::test]
    async fn the_default_cache_budget_is_small_enough_to_evict_under_a_large_graph() {
        let scratch = ScratchFile::new("default-cache");
        let store = open(scratch.path());
        assert_eq!(store.config(), StoreConfig::default());
        assert_eq!(StoreConfig::default().cache_bytes(), 32 * 1024 * 1024);
        // 48 MiB of banner payload, well past a 32 MiB budget and nowhere near redb's 1 GiB default.
        let banner = "x".repeat(96 * 1024);
        for i in 0..512u16 {
            let kind = EntityKind::ServiceBanner {
                port: i,
                banner: banner.clone(),
            };
            let provenance = ProvenanceEnvelope::new(
                "banner",
                1_710_000_000,
                &i.to_be_bytes(),
                &kind,
                EpistemicLevel::DirectObservation,
            );
            let entity = Entity {
                provenance,
                kind,
                hop_depth: 0,
            };
            if let Err(err) = store.put(&entity).await {
                panic!("put: {err}");
            }
        }
        if let Err(err) = store.sync().await {
            panic!("sync: {err}");
        }
        assert!(
            store.db.cache_stats().evictions() > 0,
            "no page was ever evicted: the store is running on redb's unbounded default cache"
        );
        if let Err(err) = store.shutdown() {
            panic!("shutdown: {err}");
        }
    }

    #[test]
    fn open_with_rejects_a_config_beyond_the_platform_ceilings() {
        let scratch = ScratchFile::new("config-ceiling");
        let too_much_cache =
            StoreConfig::default().with_cache_bytes(StoreConfig::MAX_CACHE_BYTES + 1);
        match GraphStore::open_with(scratch.path(), too_much_cache) {
            Err(StorageError::ConfigOutOfRange {
                setting: "cache_bytes",
                requested,
                max,
            }) => {
                assert_eq!(requested, StoreConfig::MAX_CACHE_BYTES as u64 + 1);
                assert_eq!(max, StoreConfig::MAX_CACHE_BYTES as u64);
            }
            Ok(_) => panic!("a cache above the ceiling was accepted"),
            Err(other) => panic!("wrong error for an oversized cache: {other}"),
        }

        let too_long =
            StoreConfig::default().with_linger(StoreConfig::MAX_LINGER + Duration::from_millis(1));
        match GraphStore::open_with(scratch.path(), too_long) {
            Err(StorageError::ConfigOutOfRange {
                setting: "linger_millis",
                requested: 1_001,
                max: 1_000,
            }) => {}
            Ok(_) => panic!("a linger above the ceiling was accepted"),
            Err(other) => panic!("wrong error for an oversized linger: {other}"),
        }

        let at_the_ceiling = StoreConfig::default()
            .with_cache_bytes(StoreConfig::MAX_CACHE_BYTES)
            .with_linger(StoreConfig::MAX_LINGER);
        match GraphStore::open_with(scratch.path(), at_the_ceiling) {
            Ok(store) => {
                assert_eq!(store.config(), at_the_ceiling);
                if let Err(err) = store.shutdown() {
                    panic!("shutdown: {err}");
                }
            }
            Err(err) => panic!("a config at the ceiling must open: {err}"),
        }
    }

    #[tokio::test]
    async fn puts_coalesce_into_one_commit_while_lingering_and_a_sync_commits_at_once() {
        let linger = StoreConfig::MAX_LINGER;
        let (store, faults) = open_faulty_with(StoreConfig::default().with_linger(linger));
        let started = Instant::now();

        let before = faults.syncs.load(Ordering::SeqCst);
        if let Err(err) = store.put(&entity("one.example")).await {
            panic!("put: {err}");
        }
        if let Err(err) = store.sync().await {
            panic!("sync: {err}");
        }
        let one_commit = faults.syncs.load(Ordering::SeqCst) - before;
        assert!(one_commit > 0, "a commit must reach the backend");

        let before = faults.syncs.load(Ordering::SeqCst);
        for domain in ["two.example", "three.example", "four.example"] {
            if let Err(err) = store.put(&entity(domain)).await {
                panic!("put: {err}");
            }
        }
        if let Err(err) = store.sync().await {
            panic!("sync: {err}");
        }
        assert_eq!(
            faults.syncs.load(Ordering::SeqCst) - before,
            one_commit,
            "three puts followed by a sync must fold into a single commit"
        );
        assert!(
            started.elapsed() < linger,
            "a sync must bypass the linger rather than wait it out"
        );
        if let Err(err) = store.shutdown() {
            panic!("shutdown: {err}");
        }
    }

    #[tokio::test]
    async fn put_sync_then_get_round_trips_through_the_background_writer() {
        let scratch = ScratchFile::new("roundtrip");
        let store = open(scratch.path());

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
    }

    #[tokio::test]
    async fn committed_entities_survive_a_reopen() {
        let scratch = ScratchFile::new("reopen");
        let seed = entity("persist.example");
        let seed_id = seed.provenance.entity_id;

        {
            let store = open(scratch.path());
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

        let reopened = open(scratch.path());
        match reopened.get(&seed_id) {
            Ok(Some(found)) => assert_eq!(found, seed),
            other => panic!("entity did not survive reopen: {other:?}"),
        }
        match reopened.observations(&seed_id, 8) {
            Ok(found) => assert_eq!(found, vec![seed.provenance.clone()]),
            Err(err) => panic!("observations after reopen: {err}"),
        }
        if let Err(err) = reopened.shutdown() {
            panic!("shutdown: {err}");
        }
    }
}
