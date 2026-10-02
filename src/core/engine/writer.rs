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
//!
//! ## Why the queue is unbounded, and what actually bounds it
//!
//! An unbounded channel on a no-root Android target reads like a memory bug, so
//! the reasoning is recorded here rather than left to be rediscovered and
//! "fixed" into a regression.
//!
//! It is deliberate, because the two ways to bound it both cost more than they
//! buy. [`DbWriter::submit`] is synchronous and infallible, called from the
//! engine's dispatch path; a bounded channel forces either `try_send` — which
//! DROPS events on a full queue, silently breaking the one guarantee
//! [`DbWriter::flush`] exists to make — or an async send, which pushes an
//! `.await` into a sync call site for backpressure the producer cannot act on
//! anyway.
//!
//! And the queue is not unbounded in the sense that matters. A scan's event
//! count is already capped upstream by
//! [`DEFAULT_MAX_ENTITIES`](crate::core::scan::DEFAULT_MAX_ENTITIES) (2500) and
//! the wall-time watchdog, so the worst-case backlog is one scan's events, not
//! an open-ended stream. The queue absorbs a burst; it does not accumulate
//! forever.
//!
//! What WAS wrong is that a pathological backlog was invisible. If storage
//! stalls — a phone's flash under load, a filesystem near full — the difference
//! between what the scan produced and what sqlite has written sits in memory
//! with nothing saying so. That is the same silent-degradation class this
//! codebase rejects everywhere else, so the depth is now disclosed once it
//! crosses [`BACKLOG_WARN_EVENTS`], with hysteresis so a queue hovering at the
//! threshold cannot spam the log.

use std::sync::Arc;

use tokio::sync::{mpsc, oneshot};
use tracing::warn;

use crate::core::{event::Event, port::StoragePort};

enum WriteCmd {
    Event(Box<Event>),
    Flush(oneshot::Sender<()>),
}

/// Queue depth at which a backlog stops being a burst and starts being a
/// symptom worth telling the operator about.
///
/// Sized against the scan's own ceiling rather than picked round: a scan is
/// capped at [`DEFAULT_MAX_ENTITIES`](crate::core::scan::DEFAULT_MAX_ENTITIES)
/// = 2500 entities, so 1024 queued events means storage is far enough behind
/// that a large fraction of the whole scan is sitting in memory unwritten. The
/// drain takes 64 per cycle, so a healthy writer never approaches this — it is
/// a stall signal, not a busy signal.
const BACKLOG_WARN_EVENTS: usize = 1024;

/// Whether a backlog of `depth` should be disclosed now.
///
/// Pure, and separated from the loop for the same reason `util::circuit_breaker`
/// takes `now` explicitly: the hysteresis is the part that can be wrong, and it
/// is worth testing by passing values rather than by stalling a real database.
fn should_disclose_backlog(depth: usize, already_warned: bool) -> bool {
    depth >= BACKLOG_WARN_EVENTS && !already_warned
}

/// Whether the latch re-arms, so a later stall is disclosed again.
///
/// Deliberately NOT the inverse of [`should_disclose_backlog`]. Re-arming at
/// the same threshold would make a queue oscillating around it log on every
/// cycle — the spam that stops anyone reading the warning at all. Recovery has
/// to be genuine (half the threshold) before the next stall is announced.
fn backlog_latch_rearms(depth: usize) -> bool {
    depth < BACKLOG_WARN_EVENTS / 2
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
    let mut backlog_warned = false;

    loop {
        batch.clear();
        let mut pending_flush: Option<oneshot::Sender<()>> = None;

        // Measured before the drain, when the queue is at its peak for this
        // cycle: everything the scan submitted while the previous batch was in
        // `spawn_blocking` is still waiting. Measuring after the drain would
        // always read 64 lower and understate a stall.
        let depth = rx.len();
        if should_disclose_backlog(depth, backlog_warned) {
            warn!(
                queued_events = depth,
                threshold = BACKLOG_WARN_EVENTS,
                "db-writer: storage is not keeping up with the scan — queued events are \
                 held in memory until they are written"
            );
            backlog_warned = true;
        } else if backlog_latch_rearms(depth) {
            backlog_warned = false;
        }

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
            // Swap in a fresh pre-sized buffer rather than `mem::take` (which
            // leaves `batch` at capacity 0, forcing it to re-grow from scratch —
            // ~log2(64) reallocations — on every drain cycle). The drain is capped
            // at 64 events, so 64 is the steady-state capacity; the drained Vec is
            // moved into the blocking task and dropped there.
            let evts = std::mem::replace(&mut batch, Vec::with_capacity(64));
            let s = Arc::clone(&store);
            if let Err(e) = tokio::task::spawn_blocking(move || {
                // One transaction for the whole coalesced drain (≤64 events) —
                // one commit/fsync on the phone's flash filesystem instead of one
                // per event. On a batch rollback, salvage what we can per-event
                // (the same fallback contract as the entity batch path).
                if let Err(batch_err) = s.insert_events_batch(&evts) {
                    warn!(error = %batch_err, "db-writer: batch event persist failed — falling back to per-event");
                    for ev in &evts {
                        if let Err(err) = s.insert_event(ev) {
                            warn!(error = %err, "db-writer: event persist failed");
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::event::EventKind;
    use crate::core::test_support::InMemoryStore;

    fn ev(scan_id: &str, module: &str) -> Event {
        Event::new(
            scan_id,
            EventKind::ModuleStart {
                module: module.to_string(),
            },
        )
    }

    /// The disclosure fires once on the way up, and not again until the queue
    /// has genuinely recovered.
    ///
    /// The hysteresis is the whole point. Re-arming at the same threshold would
    /// make a queue oscillating around it warn on every drain cycle, and a
    /// warning that appears thousands of times is one nobody reads — which
    /// leaves the stall just as invisible as having no warning at all.
    #[test]
    fn backlog_is_disclosed_once_per_stall_not_once_per_cycle() {
        let mut warned = false;

        // Healthy: nothing to say, and the latch stays armed.
        assert!(!should_disclose_backlog(0, warned));
        assert!(!should_disclose_backlog(BACKLOG_WARN_EVENTS - 1, warned));
        assert!(backlog_latch_rearms(0));

        // Crossing the threshold discloses exactly once.
        assert!(should_disclose_backlog(BACKLOG_WARN_EVENTS, warned));
        warned = true;
        assert!(
            !should_disclose_backlog(BACKLOG_WARN_EVENTS, warned),
            "a still-stalled queue must not re-log every cycle"
        );
        assert!(!should_disclose_backlog(BACKLOG_WARN_EVENTS * 10, warned));

        // Draining to just under the threshold is NOT recovery: the latch must
        // stay held, or an oscillating queue logs on every cycle.
        assert!(
            !backlog_latch_rearms(BACKLOG_WARN_EVENTS - 1),
            "hovering just below the threshold is not recovery"
        );
        assert!(!backlog_latch_rearms(BACKLOG_WARN_EVENTS / 2));

        // Genuine recovery re-arms, so the NEXT stall is disclosed too.
        assert!(backlog_latch_rearms(BACKLOG_WARN_EVENTS / 2 - 1));
        warned = false;
        assert!(should_disclose_backlog(BACKLOG_WARN_EVENTS, warned));
    }

    /// `flush()` must mean what its doc says: every event submitted before the
    /// call is durable when the future resolves.
    ///
    /// This is the contract that rules out bounding the queue with `try_send` —
    /// a drop on a full queue would satisfy the type signature and quietly
    /// violate this. Submits more than one drain cycle's worth (64) so the
    /// batching path, the greedy drain and the flush barrier are all crossed.
    #[tokio::test(flavor = "multi_thread")]
    async fn flush_persists_every_event_submitted_before_it() {
        let store = Arc::new(InMemoryStore::default());
        let writer = DbWriter::spawn(store.clone());

        const N: usize = 200;
        for i in 0..N {
            writer.submit(ev("scan-flush", &format!("m{i}")));
        }
        writer.flush().await;

        let persisted = store
            .events_for_scan("scan-flush")
            .expect("in-memory store must read back");
        assert_eq!(
            persisted.len(),
            N,
            "flush() resolved with {} of {N} events written — the barrier does not \
             hold, and any bounded-queue rewrite that drops on full would look like this",
            persisted.len()
        );
    }

    /// A flush with nothing queued resolves rather than hanging — the
    /// `rx.recv()` arm that acknowledges immediately.
    #[tokio::test(flavor = "multi_thread")]
    async fn flush_on_an_idle_writer_resolves() {
        let store = Arc::new(InMemoryStore::default());
        let writer = DbWriter::spawn(store.clone());
        writer.flush().await;
        assert!(
            store
                .events_for_scan("nothing")
                .expect("store readable")
                .is_empty()
        );
    }
}
