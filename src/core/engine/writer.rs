//! Async DB-writer actor — batches event writes off the main async reactor.
//!
//! [`DbWriter`] is a cheaply-cloneable handle to a background task that owns
//! the `store.insert_event` call path.  Callers submit events synchronously
//! (non-blocking enqueue) and the actor drains the queue in `spawn_blocking`
//! chunks, so no reactor thread ever blocks on a rusqlite write.
//!
//! The `flush().await` barrier guarantees that all events submitted before the
//! call are persisted before the future resolves — called at scan-completion so
//! the caller sees a complete event log before the scan is returned.

use std::sync::Arc;

use tokio::sync::{mpsc, oneshot};
use tracing::warn;

use crate::core::{event::Event, port::StoragePort};

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
    let mut batch: Vec<Event> = Vec::with_capacity(64);

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

        // Greedily drain up to 63 more immediately-available commands so that
        // a burst of entity events becomes a single spawn_blocking call
        // (≪ N context switches instead of N).
        let mut drained = 0usize;
        while drained < 63 {
            match rx.try_recv() {
                Ok(WriteCmd::Event(e)) => {
                    batch.push(*e);
                    drained += 1;
                }
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
                for ev in &evts {
                    if let Err(err) = s.insert_event(ev) {
                        warn!(error = %err, "db-writer: event persist failed");
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
