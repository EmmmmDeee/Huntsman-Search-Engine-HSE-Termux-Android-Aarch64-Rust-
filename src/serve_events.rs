//! A bounded in-process broadcast hub, so `serve` can push what happens to it — a scan changing
//! state, a continuous alert — to connected Web UI clients over Server-Sent Events, instead of the
//! page polling on a timer.
//!
//! One hub is shared by the scan service (the producer) and every live `/api/events` connection
//! (a consumer). A producer [`publish`](EventHub::publish)es without blocking; a consumer holds a
//! [`Subscription`] and [`recv`](Subscription::recv)s events after its cursor, waiting up to a
//! deadline. The hub keeps only the newest [`CAPACITY`] events: a consumer that falls behind that
//! far is told it `lagged` so the page can resync from `/api/scans` rather than miss state
//! silently. Nothing here touches the network; the SSE framing and the connection live in the
//! server. Events carry only non-sensitive fields (a scan id, a status, an alert's risk and rule),
//! never a target or a finding's text, because they are pushed to whatever holds the page open.

use std::collections::VecDeque;
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;

/// The most events the hub remembers for consumers that have not yet caught up. A Web UI client
/// reads continuously, so it only falls this far behind if it stalls; then it resyncs.
pub const CAPACITY: usize = 1024;

/// Something worth telling the page about, as a client receives it. Serialized as the SSE data,
/// tagged by `kind`, with only fields that are safe on a shared screen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Event {
    /// A saved scan changed state (created, running, finished, failed, …).
    Scan {
        id: String,
        status: String,
        /// Server time of the change, Unix milliseconds.
        at: u64,
    },
    /// A continuous-collection decision raised an alert. Only the newest scan's id and the reasons'
    /// risks and rules, as the notification text carries them — never the target.
    Alert {
        /// The id of the later scan the alert was decided on.
        scan: String,
        at: u64,
        /// Each reason as "RISK rule", or "N new values".
        reasons: Vec<String>,
    },
}

/// One event with the sequence number the hub assigned it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Seqd {
    seq: u64,
    event: Event,
}

#[derive(Default)]
struct Ring {
    /// The newest [`CAPACITY`] events, oldest first.
    events: VecDeque<Seqd>,
    /// The sequence number the next published event will get; also the count ever published.
    next: u64,
}

/// A shared broadcast buffer. Cheap to clone the `Arc` the server and scan service hold.
#[derive(Default)]
pub struct EventHub {
    ring: Mutex<Ring>,
    woken: Condvar,
}

impl EventHub {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append `event` for every subscriber and wake those waiting. Never blocks; the oldest event
    /// is dropped when the buffer is full. A poisoned lock is recovered, since one panicking
    /// consumer must not stop the server telling the others what happened.
    pub fn publish(&self, event: Event) {
        let mut ring = self
            .ring
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let seq = ring.next;
        ring.next += 1;
        ring.events.push_back(Seqd { seq, event });
        while ring.events.len() > CAPACITY {
            ring.events.pop_front();
        }
        drop(ring);
        self.woken.notify_all();
    }

    /// A consumer reading from now on: it receives only events published after this call.
    #[must_use]
    pub fn subscribe(&self) -> Subscription<'_> {
        let next = self
            .ring
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .next;
        Subscription {
            hub: self,
            cursor: next,
        }
    }

    /// For tests and metrics: how many events have ever been published.
    #[must_use]
    pub fn published(&self) -> u64 {
        self.ring
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .next
    }
}

/// What a [`Subscription::recv`] returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Batch {
    /// The events after the subscription's previous cursor, oldest first. Empty on a timeout.
    pub events: Vec<Event>,
    /// Whether the buffer advanced past the cursor before these were read, so earlier events were
    /// missed. The consumer should resync its whole view, not trust that `events` is every change.
    pub lagged: bool,
}

/// One consumer's place in the hub. Not `Clone`: each live connection holds its own.
pub struct Subscription<'a> {
    hub: &'a EventHub,
    cursor: u64,
}

impl Subscription<'_> {
    /// Waits up to `timeout` for events after the cursor, then returns them and advances the
    /// cursor past them. Returns at once if some are already waiting. An empty, not-lagged batch
    /// means the timeout elapsed with nothing new — the caller sends an SSE keepalive and calls
    /// again. The wait is bounded, so a connection with a write deadline is never stuck here.
    pub fn recv(&mut self, timeout: Duration) -> Batch {
        let deadline = Instant::now() + timeout;
        let mut ring = self
            .hub
            .ring
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            if ring.next > self.cursor {
                let oldest = ring.events.front().map_or(ring.next, |front| front.seq);
                let lagged = oldest > self.cursor;
                let events: Vec<Event> = ring
                    .events
                    .iter()
                    .filter(|seqd| seqd.seq >= self.cursor)
                    .map(|seqd| seqd.event.clone())
                    .collect();
                self.cursor = ring.next;
                return Batch { events, lagged };
            }
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return Batch {
                    events: Vec::new(),
                    lagged: false,
                };
            };
            let (guard, _) = self
                .hub
                .woken
                .wait_timeout(ring, remaining)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            ring = guard;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    fn scan(id: &str, status: &str) -> Event {
        Event::Scan {
            id: id.to_owned(),
            status: status.to_owned(),
            at: 1,
        }
    }

    #[test]
    fn a_subscriber_receives_only_events_published_after_it_subscribed() {
        let hub = EventHub::new();
        hub.publish(scan("a", "created")); // before: not seen
        let mut sub = hub.subscribe();
        hub.publish(scan("a", "running"));
        hub.publish(scan("a", "finished"));
        let batch = sub.recv(Duration::from_millis(10));
        assert_eq!(
            batch.events,
            vec![scan("a", "running"), scan("a", "finished")]
        );
        assert!(!batch.lagged);
        // Cursor advanced: nothing new now, so a short wait times out empty.
        assert_eq!(
            sub.recv(Duration::from_millis(5)),
            Batch {
                events: Vec::new(),
                lagged: false
            }
        );
    }

    #[test]
    fn a_subscriber_that_falls_a_whole_buffer_behind_is_told_it_lagged() {
        let hub = EventHub::new();
        let mut sub = hub.subscribe();
        for i in 0..CAPACITY + 50 {
            hub.publish(scan("a", &format!("s{i}")));
        }
        let batch = sub.recv(Duration::from_millis(10));
        assert!(
            batch.lagged,
            "overflowed the buffer, so earlier events were dropped"
        );
        assert_eq!(
            batch.events.len(),
            CAPACITY,
            "only the newest CAPACITY are kept"
        );
        // After catching up, a fresh event is delivered without a lag flag.
        hub.publish(scan("b", "created"));
        let batch = sub.recv(Duration::from_millis(10));
        assert_eq!(batch.events, vec![scan("b", "created")]);
        assert!(!batch.lagged);
    }

    #[test]
    fn recv_blocks_until_an_event_arrives_then_returns_it() {
        let hub = Arc::new(EventHub::new());
        let consumer = Arc::clone(&hub);
        let handle = thread::spawn(move || {
            let mut sub = consumer.subscribe();
            sub.recv(Duration::from_secs(5))
        });
        // Give the consumer time to block, then publish.
        thread::sleep(Duration::from_millis(50));
        hub.publish(scan("a", "running"));
        let batch = handle.join().unwrap();
        assert_eq!(batch.events, vec![scan("a", "running")]);
    }

    #[test]
    fn an_empty_timeout_is_distinct_from_a_dropped_event_and_serialises_by_kind() {
        let hub = EventHub::new();
        let mut sub = hub.subscribe();
        let empty = sub.recv(Duration::from_millis(5));
        assert!(empty.events.is_empty() && !empty.lagged);
        assert_eq!(hub.published(), 0);

        let alert = Event::Alert {
            scan: "deadbeef".to_owned(),
            at: 2,
            reasons: vec!["HIGH new_exposure".to_owned()],
        };
        let json = serde_json::to_string(&alert).unwrap();
        assert!(json.contains("\"kind\":\"alert\""), "{json}");
        assert!(!json.contains("target"));
    }
}
