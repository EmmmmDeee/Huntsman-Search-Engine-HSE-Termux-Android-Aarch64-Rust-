//! Async DB-writer actor — batches event writes off the main async reactor.
//!
//! [`DbWriter`] is a cheaply-cloneable handle to a background task that owns
//! the `store.insert_events_batch` call path.  Callers submit events
//! synchronously (non-blocking enqueue) and the actor drains the queue into
//! `spawn_blocking` batches of up to [`WRITER_BATCH_MAX`], each persisted under
//! a single transaction (one WAL commit per batch), so no reactor thread ever
//! blocks on a rusqlite write and a burst of events costs one fsync, not N.
//!
//! The `flush().await` barrier guarantees that all events submitted before the
//! call are persisted before the future resolves — called at scan-completion so
//! the caller sees a complete event log before the scan is returned.

use std::sync::Arc;

use tokio::sync::{mpsc, oneshot};
use tracing::warn;

use crate::core::{event::Event, port::StoragePort};

/// Maximum number of events drained into a single `spawn_blocking`
/// transaction.
///
/// Each batch becomes exactly one
/// [`insert_events_batch`](crate::core::port::StoragePort::insert_events_batch)
/// call —
/// one `spawn_blocking` hop and one WAL commit (one fsync at
/// `synchronous=NORMAL`). On breach-heavy scans that emit thousands of
/// `EntityFound`/`EvidenceFound` events in a burst, a small cap forces many
/// more `spawn_blocking` round-trips and WAL commits than necessary. 512 is
/// sized to amortise the `spawn_blocking` + transaction cost on low-power
/// aarch64 while bounding the worst-case transaction size (and the events held
/// in memory) so a single commit can never grow unbounded.
const WRITER_BATCH_MAX: usize = 512;

enum WriteCmd {
    Event(Box<Event>),
    Flush(oneshot::Sender<()>),
}

/// Cheaply-cloneable handle to the background DB-writer actor.
///
/// All clones share the same actor task (same unbounded-channel sender).
/// Dropped when all `ScanEngine` clones are dropped; the actor task exits
/// cleanly when the last sender is released.
#[derive(Clone)]
pub(super) struct DbWriter {
    tx: mpsc::UnboundedSender<WriteCmd>,
}

impl DbWriter {
    /// Spawn the background actor.  Requires a running tokio runtime
    /// (production `new_multi_thread`, or `#[tokio::test]` with
    /// `flavor = "multi_thread"`).
    pub(super) fn spawn(store: Arc<dyn StoragePort>) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(writer_loop(rx, store));
        Self { tx }
    }

    /// Enqueue an event for persistence.  Returns immediately; the event will
    /// be written to the store by the background task.  Only fails silently if
    /// the actor has already exited (not expected during an active scan).
    pub(super) fn submit(&self, event: Event) {
        let _ = self.tx.send(WriteCmd::Event(Box::new(event)));
    }

    /// Barrier: wait until all events submitted before this call are persisted.
    pub(super) async fn flush(&self) {
        let (tx, rx) = oneshot::channel();
        if self.tx.send(WriteCmd::Flush(tx)).is_ok() {
            let _ = rx.await;
        }
    }
}

async fn writer_loop(mut rx: mpsc::UnboundedReceiver<WriteCmd>, store: Arc<dyn StoragePort>) {
    let mut batch: Vec<Event> = Vec::with_capacity(WRITER_BATCH_MAX);

    loop {
        batch.clear();
        let mut pending_flush: Option<oneshot::Sender<()>> = None;

        // Block until at least one command is ready.
        match rx.recv().await {
            None => break,
            Some(WriteCmd::Flush(reply)) => {
                // No pending events; acknowledge immediately.
                let _ = reply.send(());
                continue;
            }
            Some(WriteCmd::Event(e)) => batch.push(*e),
        }

        // Greedily drain immediately-available commands until the queue is
        // empty or the batch hits WRITER_BATCH_MAX, so a burst of entity events
        // collapses into a single spawn_blocking + transaction (≪ N context
        // switches and ≪ N WAL fsyncs instead of N). A Flush seen mid-drain is
        // coalesced with the still-draining queue: events already in `batch`
        // were submitted before that flush, so persisting them and then acking
        // the flush in the same iteration honours the barrier without forcing
        // an extra empty round-trip.
        while batch.len() < WRITER_BATCH_MAX {
            match rx.try_recv() {
                Ok(WriteCmd::Event(e)) => batch.push(*e),
                Ok(WriteCmd::Flush(reply)) => {
                    pending_flush = Some(reply);
                    break;
                }
                Err(_) => break,
            }
        }

        if !batch.is_empty() {
            let evts = std::mem::take(&mut batch);
            let s = Arc::clone(&store);
            if let Err(e) = tokio::task::spawn_blocking(move || {
                // One transaction for the whole batch — a single WAL commit
                // (one fsync at synchronous=NORMAL) rather than one per event.
                // The batch is all-or-nothing; on failure fall back to
                // per-event inserts so a single poison event can't drop the
                // rest of the burst from the log.
                if let Err(err) = s.insert_events_batch(&evts) {
                    warn!(error = %err, "db-writer: batch persist failed; retrying per-event");
                    for ev in &evts {
                        if let Err(e2) = s.insert_event(ev) {
                            warn!(error = %e2, "db-writer: event persist failed");
                        }
                    }
                }
            })
            .await
            {
                warn!(error = %e, "db-writer: spawn_blocking panicked");
            }
        }

        if let Some(reply) = pending_flush {
            let _ = reply.send(());
        }
    }
}
