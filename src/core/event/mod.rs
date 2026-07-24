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

    /// A compact, human-readable one-line summary for the scan event log:
    /// `(category, body)`, where `category` is the short fixed column
    /// (`scan` / `module` / `entity` / `expand` / `corr` / `live`) and `body`
    /// leads with a status glyph. This is the single Rust-side definition of how
    /// an event reads to a human — the downloaded `events.log`, `hse export
    /// --format events`, and the debug bundle's sequence section all render
    /// through it — deliberately mirroring the browser Scan-Log view
    /// (`web/js/scan_info/log.js` `mapEvent`) so on-screen and on-disk agree.
    /// Pure.
    #[must_use]
    pub fn log_summary(&self) -> (&'static str, String) {
        match self {
            Self::ScanStart {
                target_kind,
                target_value,
            } => (
                "scan",
                format!("● scan started · {target_kind}={target_value}"),
            ),
            Self::ModuleStart { module } => ("module", format!("▶ {module}")),
            Self::ModuleDone { module, found } => {
                ("module", format!("✓ {module}  ({found} found)"))
            }
            Self::ModuleError { module, error } => ("module", format!("✗ {module}  {error}")),
            Self::ModuleSkipped { module, reason } => ("module", format!("◌ {module}  {reason}")),
            Self::EntityFound { entity } => {
                let cand = if entity.has_tag(crate::core::tags::CANDIDATE) {
                    "  (candidate)"
                } else {
                    ""
                };
                (
                    "entity",
                    format!(
                        "+ {}  {}  ·{:.2}{cand}",
                        entity.kind, entity.value, entity.confidence
                    ),
                )
            }
            Self::ExpansionTick {
                depth,
                queued,
                visited,
            } => (
                "expand",
                format!("↺ depth {depth} · queued {queued} · visited {visited}"),
            ),
            Self::ExpansionStop { reason } => ("expand", format!("■ expansion stopped · {reason}")),
            Self::EntityExcluded {
                kind,
                value,
                reason,
            } => (
                "expand",
                format!("⊘ not expanded · {kind} {value}  {reason}"),
            ),
            Self::CorrelationFound { correlation } => {
                let name = if correlation.rule_name.is_empty() {
                    &correlation.rule_id
                } else {
                    &correlation.rule_name
                };
                ("corr", format!("⚡ {name}"))
            }
            Self::CorrelationsDone { count } => ("corr", format!("correlations done · {count}")),
            Self::LiveStart {
                target_kind,
                target_value,
                interval_secs,
                ..
            } => (
                "live",
                format!(
                    "▶ live session started · {target_kind}={target_value}  every {interval_secs}s"
                ),
            ),
            Self::LiveTick { iteration, .. } => ("live", format!("↻ iteration {iteration}")),
            Self::LiveStop { reason, .. } => ("live", format!("■ live session stopped · {reason}")),
            Self::ScanComplete { entity_count, .. } => {
                ("scan", format!("✔ scan complete · {entity_count} entities"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
