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
