//! Event bus + event types. Modules and the engine emit events; consumers
//! (CLI verbose mode, the SSE endpoint, the live UI) subscribe via
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
    /// A scan event of `kind`, timestamped now ([`unix_now`]) — the form the
    /// engine publishes on the [`EventBus`] and persists to the event log.
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
    /// An entity was deliberately NOT expanded this round, with the reason
    /// (low confidence, ROI-saturated, non-routable IP, incidental infra).
    /// Surfaces every pruning decision so expansion is never a black box.
    EntityExcluded {
        kind: String,
        value: String,
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

/// Distinct dispatched module names from this scan's own `ModuleDone` events,
/// each judged on whether it EVER yielded ≥1 entity — a module re-dispatched
/// across expansion rounds (e.g. an empty first round, a productive second)
/// is judged on its best outcome, not per-dispatch. `true` = yielded
/// something at least once this scan, `false` = zero yield throughout.
/// Sorted by name (a `BTreeMap`), so downstream consumers get deterministic
/// order for free. The single canonical source for this computation — both
/// the dossier's bounded per-module optimization hint (`PROBLEM_TREE` T2.14)
/// and the cross-scan module-stats ledger's zero-yield tracking build on it,
/// rather than each re-deriving the same dedup-by-best-outcome logic.
#[must_use]
pub fn module_yield_outcomes(events: &[Event]) -> std::collections::BTreeMap<String, bool> {
    let mut outcomes: std::collections::BTreeMap<String, bool> = std::collections::BTreeMap::new();
    for ev in events {
        if let EventKind::ModuleDone { module, found } = &ev.kind {
            let yielded_this_dispatch = *found > 0;
            outcomes
                .entry(module.clone())
                .and_modify(|ever| *ever = *ever || yielded_this_dispatch)
                .or_insert(yielded_this_dispatch);
        }
    }
    outcomes
}

/// Names of modules dispatched this scan that never yielded anything —
/// see [`module_yield_outcomes`] for the dedup-by-best-outcome semantics.
/// Sorted, deduped (a `BTreeMap` key set).
#[must_use]
pub fn zero_yield_module_names(events: &[Event]) -> Vec<String> {
    module_yield_outcomes(events)
        .into_iter()
        .filter_map(|(name, yielded)| (!yielded).then_some(name))
        .collect()
}

impl EventKind {
    /// The variant's stable snake_case tag — identical to the serde `type` field,
    /// so a consumer can switch on the event type without deserialising. One source
    /// for both the wire form and in-process matching.
    #[must_use]
    pub fn event_type_str(&self) -> &'static str {
        match self {
            Self::ScanStart { .. } => "scan_start",
            Self::ModuleStart { .. } => "module_start",
            Self::ModuleDone { .. } => "module_done",
            Self::ModuleError { .. } => "module_error",
            Self::ModuleSkipped { .. } => "module_skipped",
            Self::EntityFound { .. } => "entity_found",
            Self::ExpansionTick { .. } => "expansion_tick",
            Self::ExpansionStop { .. } => "expansion_stop",
            Self::EntityExcluded { .. } => "entity_excluded",
            Self::CorrelationFound { .. } => "correlation_found",
            Self::CorrelationsDone { .. } => "correlations_done",
            Self::LiveStart { .. } => "live_start",
            Self::LiveTick { .. } => "live_tick",
            Self::LiveStop { .. } => "live_stop",
            Self::ScanComplete { .. } => "scan_complete",
        }
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
