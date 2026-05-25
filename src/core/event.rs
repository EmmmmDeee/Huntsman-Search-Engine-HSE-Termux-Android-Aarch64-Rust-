//! Event bus + event types. Modules and the engine emit events; consumers
//! (CLI verbose mode, future SSE endpoint, future live UI) subscribe via
//! `EventBus::subscribe()`.

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use crate::core::entity::{Entity, unix_now};

/// Cloneable sender shared across the engine, modules, and consumers.
pub type EventBus = broadcast::Sender<Event>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub scan_id: String,
    pub ts: u64,
    pub kind: EventKind,
}

impl Event {
    pub fn new(scan_id: impl Into<String>, kind: EventKind) -> Self {
        Self {
            scan_id: scan_id.into(),
            ts: unix_now(),
            kind,
        }
    }
}

/// Event variants. JSON tag = `type`, snake_case — matches the future SPA's
/// `evt.type === 'module_start'` checks.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EventKind {
    ScanStart {
        target_kind: String,
        target_value: String,
    },
    ModuleStart {
        module: String,
    },
    ModuleDone {
        module: String,
        found: usize,
    },
    ModuleError {
        module: String,
        error: String,
    },
    ModuleSkipped {
        module: String,
        reason: String,
    },
    EntityFound {
        entity: Entity,
    },
    /// Autonomous expansion round about to start.
    ExpansionTick {
        depth: u32,
        queued: usize,
        visited: usize,
    },
    /// Autonomous expansion stopped early (budget, no candidates, etc.).
    ExpansionStop {
        reason: String,
    },
    /// Correlator rule fired post-scan (v0.4+).
    CorrelationFound {
        correlation: crate::core::correlator::Correlation,
    },
    /// Correlator finished evaluating all rules (v0.4+).
    CorrelationsDone {
        count: usize,
    },
    /// Live session started (v0.5+). `scan_id` field on the wrapping
    /// `Event` carries the live_id, not a scan_id.
    LiveStart {
        live_id: String,
        target_kind: String,
        target_value: String,
        interval_secs: u64,
    },
    /// A live iteration is about to begin (v0.5+). `scan_id` field on the
    /// wrapping `Event` carries the live_id; the iteration's own scan_id
    /// is in this variant's `scan_id` field.
    LiveTick {
        live_id: String,
        iteration: u32,
        scan_id: String,
    },
    /// Live session ended (v0.5+).
    LiveStop {
        live_id: String,
        reason: String,
    },
    ScanComplete {
        scan_id: String,
        entity_count: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Event::new ──────────────────────────────────────────────────────

    #[test]
    fn event_new_sets_scan_id_and_ts() {
        let before = unix_now();
        let evt = Event::new("scan-42", EventKind::ScanComplete {
            scan_id: "scan-42".into(),
            entity_count: 0,
        });
        let after = unix_now();

        assert_eq!(evt.scan_id, "scan-42");
        assert!(evt.ts >= before && evt.ts <= after);
    }

    // ── EventKind round-trips ───────────────────────────────────────────

    #[test]
    fn scan_start_json_round_trip() {
        let kind = EventKind::ScanStart {
            target_kind: "email".into(),
            target_value: "a@b.com".into(),
        };
        let json = serde_json::to_string(&kind).unwrap();
        assert!(json.contains("\"type\":\"scan_start\""));

        let back: EventKind = serde_json::from_str(&json).unwrap();
        match back {
            EventKind::ScanStart { target_kind, target_value } => {
                assert_eq!(target_kind, "email");
                assert_eq!(target_value, "a@b.com");
            }
            other => panic!("expected ScanStart, got: {other:?}"),
        }
    }

    #[test]
    fn module_done_json_round_trip() {
        let kind = EventKind::ModuleDone {
            module: "whois".into(),
            found: 7,
        };
        let json = serde_json::to_string(&kind).unwrap();
        let back: EventKind = serde_json::from_str(&json).unwrap();
        match back {
            EventKind::ModuleDone { module, found } => {
                assert_eq!(module, "whois");
                assert_eq!(found, 7);
            }
            other => panic!("expected ModuleDone, got: {other:?}"),
        }
    }

    #[test]
    fn module_error_json_round_trip() {
        let kind = EventKind::ModuleError {
            module: "dns_resolve".into(),
            error: "timeout".into(),
        };
        let json = serde_json::to_string(&kind).unwrap();
        let back: EventKind = serde_json::from_str(&json).unwrap();
        match back {
            EventKind::ModuleError { module, error } => {
                assert_eq!(module, "dns_resolve");
                assert_eq!(error, "timeout");
            }
            other => panic!("expected ModuleError, got: {other:?}"),
        }
    }

    #[test]
    fn scan_complete_json_round_trip() {
        let kind = EventKind::ScanComplete {
            scan_id: "scan-99".into(),
            entity_count: 42,
        };
        let json = serde_json::to_string(&kind).unwrap();
        let back: EventKind = serde_json::from_str(&json).unwrap();
        match back {
            EventKind::ScanComplete { scan_id, entity_count } => {
                assert_eq!(scan_id, "scan-99");
                assert_eq!(entity_count, 42);
            }
            other => panic!("expected ScanComplete, got: {other:?}"),
        }
    }

    // ── Full Event round-trip ───────────────────────────────────────────

    #[test]
    fn full_event_json_round_trip() {
        let evt = Event::new("scan-7", EventKind::ModuleDone {
            module: "shodan".into(),
            found: 3,
        });
        let json = serde_json::to_string(&evt).unwrap();
        let back: Event = serde_json::from_str(&json).unwrap();

        assert_eq!(back.scan_id, evt.scan_id);
        assert_eq!(back.ts, evt.ts);
        match back.kind {
            EventKind::ModuleDone { module, found } => {
                assert_eq!(module, "shodan");
                assert_eq!(found, 3);
            }
            other => panic!("expected ModuleDone, got: {other:?}"),
        }
    }
}
