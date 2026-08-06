//! Event bus + event types. Modules and the engine emit events; consumers
//! (CLI verbose mode, the SSE endpoint, the live UI) subscribe via
//! `EventBus::subscribe()`.

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use crate::core::entity::{Entity, unix_now};
use crate::core::scan::ScanStatus;

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

    /// One structured JSON-object line for the scan event log — the single
    /// machine- and human-readable rendering shared by the downloaded
    /// `events.log`, `hse export --format events`, the `hse live -v` stream, the
    /// browser Scan-Log view, and the operator debug bundle. Deliberately free
    /// of box-drawing, tree, and status glyphs: every event is `{"time":…,
    /// "level":…,"kind":…, …fields}` with the leading three keys in that fixed
    /// order, then the variant's own concise fields. `level` is one of
    /// `info`/`warn`/`error`. Pure and byte-stable (UTC time-of-day, no clock
    /// read), so a rendered log diffs cleanly.
    #[must_use]
    pub fn to_log_line(&self) -> String {
        // Built by hand (not a serde `Map`, which would sort keys alphabetically
        // without the `preserve_order` feature) so `time`/`level`/`kind` lead in
        // that order. Each value goes through `serde_json::Value`'s `Display`,
        // which emits correctly-escaped JSON, so arbitrary module/error/reason
        // text can never break the line.
        use serde_json::Value;
        let mut parts: Vec<String> = Vec::with_capacity(6);
        parts.push(format!(
            "\"time\":{}",
            Value::from(crate::util::timefmt::hms_utc(self.ts))
        ));
        parts.push(format!("\"level\":\"{}\"", self.kind.log_level()));
        parts.push(format!("\"kind\":\"{}\"", self.kind.event_type_str()));
        for (key, val) in self.kind.log_fields() {
            parts.push(format!("\"{key}\":{val}"));
        }
        format!("{{{}}}", parts.join(","))
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
    /// The final bulk breach sweep dispatched its compiled plan. Reports the
    /// plan's shape, INCLUDING what it declined to ask, so a sweep that hit its
    /// cap is distinguishable from one that simply had less to ask about.
    BreachSweep {
        anchors: usize,
        probes: usize,
        /// Probes the plan derived but could not fit under the cap.
        dropped: usize,
    },
    /// The autonomous audit of the breach corpus graded the scan's findings.
    /// `verdict` is the [`crate::core::breach_consensus::AuditVerdict`] label;
    /// `flags` counts every concern raised, so a `pass` with a high flag count
    /// still reads as one that needed looking at.
    ConsensusAudit {
        verdict: String,
        examined: usize,
        corroborated: usize,
        flags: usize,
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
        /// The scan's terminal status, so the event stream can tell a clean
        /// finish apart from an operator abort or a failure. Added after this
        /// event was found to render an aborted **or** failed scan's log as a
        /// green `✔ scan complete` — and the downloaded `events.log` is the one
        /// artifact marketed as client-safe (vs the operator-only debug
        /// bundle), so the abort was being hidden from exactly the audience the
        /// log is handed to. `#[serde(default)]` keeps event rows persisted
        /// before this field existed deserializable: they predate
        /// abort-awareness and every one was a genuine completion, so they
        /// default to [`ScanStatus::Complete`] and render exactly as before.
        #[serde(default = "terminal_status_default")]
        status: ScanStatus,
    },
}

/// Back-compat default for [`EventKind::ScanComplete`]'s `status` (see the field
/// doc): a row written before the field existed has no status and was always a
/// true completion, so it deserializes as [`ScanStatus::Complete`].
fn terminal_status_default() -> ScanStatus {
    ScanStatus::Complete
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
            Self::BreachSweep { .. } => "breach_sweep",
            Self::ConsensusAudit { .. } => "consensus_audit",
            Self::CorrelationFound { .. } => "correlation_found",
            Self::CorrelationsDone { .. } => "correlations_done",
            Self::LiveStart { .. } => "live_start",
            Self::LiveTick { .. } => "live_tick",
            Self::LiveStop { .. } => "live_stop",
            Self::ScanComplete { .. } => "scan_complete",
        }
    }

    /// Severity band for the structured log line's `level` field — one of
    /// `info`, `warn`, `error`. Only a genuine failure is `error` (a module that
    /// errored, or a scan that failed); an operator abort is `warn`; everything
    /// else — including normal skips, prunes, and expansion stops — is `info`.
    /// Pure.
    #[must_use]
    pub fn log_level(&self) -> &'static str {
        match self {
            Self::ModuleError { .. } => "error",
            Self::ScanComplete { status, .. } => match status {
                ScanStatus::Failed => "error",
                ScanStatus::Aborted => "warn",
                _ => "info",
            },
            _ => "info",
        }
    }

    /// The variant's own concise fields for the structured log line, in a fixed
    /// order, as `(key, json_value)` pairs. Deliberately flat and small: nested
    /// records ([`EntityFound`](Self::EntityFound)'s `Entity`,
    /// [`CorrelationFound`](Self::CorrelationFound)'s `Correlation`) are reduced
    /// to the few fields an operator reads, not serialised whole. `entity_kind`
    /// is used instead of `kind` for entity fields so it never collides with the
    /// line's top-level `kind`. Pure.
    #[must_use]
    fn log_fields(&self) -> Vec<(&'static str, serde_json::Value)> {
        use serde_json::json;
        match self {
            Self::ScanStart {
                target_kind,
                target_value,
            } => vec![
                ("target_kind", json!(target_kind)),
                ("target_value", json!(target_value)),
            ],
            Self::ModuleStart { module } => vec![("module", json!(module))],
            Self::ModuleDone { module, found } => {
                vec![("module", json!(module)), ("found", json!(found))]
            }
            Self::ModuleError { module, error } => {
                vec![("module", json!(module)), ("error", json!(error))]
            }
            Self::ModuleSkipped { module, reason } => {
                vec![("module", json!(module)), ("reason", json!(reason))]
            }
            Self::EntityFound { entity } => vec![
                ("entity_kind", json!(entity.kind.to_string())),
                ("value", json!(entity.value)),
                // Two decimals, matching the confidence precision shown
                // everywhere else, without trailing float noise.
                (
                    "confidence",
                    json!((entity.confidence * 100.0).round() / 100.0),
                ),
                (
                    "candidate",
                    json!(entity.has_tag(crate::core::tags::CANDIDATE)),
                ),
            ],
            Self::ExpansionTick {
                depth,
                queued,
                visited,
            } => vec![
                ("depth", json!(depth)),
                ("queued", json!(queued)),
                ("visited", json!(visited)),
            ],
            Self::ExpansionStop { reason } => vec![("reason", json!(reason))],
            Self::EntityExcluded {
                kind,
                value,
                reason,
            } => vec![
                ("entity_kind", json!(kind)),
                ("value", json!(value)),
                ("reason", json!(reason)),
            ],
            Self::BreachSweep {
                anchors,
                probes,
                dropped,
            } => vec![
                ("anchors", json!(anchors)),
                ("probes", json!(probes)),
                ("dropped", json!(dropped)),
            ],
            Self::ConsensusAudit {
                verdict,
                examined,
                corroborated,
                flags,
            } => vec![
                ("verdict", json!(verdict)),
                ("examined", json!(examined)),
                ("corroborated", json!(corroborated)),
                ("flags", json!(flags)),
            ],
            Self::CorrelationFound { correlation } => {
                let rule = if correlation.rule_name.is_empty() {
                    &correlation.rule_id
                } else {
                    &correlation.rule_name
                };
                vec![
                    ("rule_id", json!(correlation.rule_id)),
                    ("rule", json!(rule)),
                    ("severity", json!(correlation.severity.as_canonical())),
                    ("description", json!(correlation.description)),
                ]
            }
            Self::CorrelationsDone { count } => vec![("count", json!(count))],
            Self::LiveStart {
                live_id,
                target_kind,
                target_value,
                interval_secs,
            } => vec![
                ("live_id", json!(live_id)),
                ("target_kind", json!(target_kind)),
                ("target_value", json!(target_value)),
                ("interval_secs", json!(interval_secs)),
            ],
            Self::LiveTick {
                iteration, scan_id, ..
            } => vec![("iteration", json!(iteration)), ("scan_id", json!(scan_id))],
            Self::LiveStop { reason, .. } => vec![("reason", json!(reason))],
            Self::ScanComplete {
                entity_count,
                status,
                ..
            } => vec![
                ("status", json!(status.as_str())),
                ("entities", json!(entity_count)),
            ],
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
            Self::BreachSweep {
                anchors,
                probes,
                dropped,
            } => {
                // The dropped count is part of the headline, not a footnote: a
                // sweep that fit everything and one that was cut short read
                // identically without it.
                let over = if *dropped > 0 {
                    format!(" · {dropped} over cap")
                } else {
                    String::new()
                };
                (
                    "expand",
                    format!(
                        "⇉ breach sweep · {probes} probe{} from {anchors} anchor{}{over}",
                        plural(*probes),
                        plural(*anchors)
                    ),
                )
            }
            Self::ConsensusAudit {
                verdict,
                examined,
                corroborated,
                flags,
            } => (
                "corr",
                format!(
                    "⚖ breach audit · {verdict} · {corroborated}/{examined} corroborated · {flags} flag{}",
                    plural(*flags)
                ),
            ),
            Self::CorrelationFound { correlation } => {
                let name = if correlation.rule_name.is_empty() {
                    &correlation.rule_id
                } else {
                    &correlation.rule_name
                };
                // The rule name alone does not identify the finding. Rules that
                // fire per-entity — AU-003 "High cross-source corroboration"
                // emits one `Correlation` for every corroborated entity — repeat
                // the same headline as many times as they matched: a real
                // 47-event scan logged nine consecutive, byte-identical
                // `⚡ High cross-source corroboration` lines, leaving the
                // operator no way to tell which entities they referred to.
                // `description` is what distinguishes them (it names the entity
                // and its C_eff) and was being discarded here, though
                // `cli::live` has always rendered both.
                if correlation.description.is_empty() {
                    ("corr", format!("⚡ {name}"))
                } else {
                    ("corr", format!("⚡ {name} · {}", correlation.description))
                }
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
            Self::ScanComplete {
                entity_count,
                status,
                ..
            } => match status {
                // A cancelled or failed scan still emits this single terminal
                // event; branch so its log line states what actually happened
                // instead of asserting success. `mapEvent` in
                // `web/js/scan_info/log.js` mirrors these three cases.
                ScanStatus::Aborted => (
                    "scan",
                    format!("■ scan aborted — stopped early · {entity_count} entities"),
                ),
                ScanStatus::Failed => ("scan", "✗ scan failed".to_string()),
                // `Complete`, and the back-compat default for pre-field rows:
                // the historical success line, unchanged.
                _ => ("scan", format!("✔ scan complete · {entity_count} entities")),
            },
        }
    }
}

/// Module accounting observed directly from a scan's persisted event stream.
///
/// This exists because [`Scan`](crate::core::scan::Scan)'s `modules_*` columns
/// are written once, at finalise: a dossier or debug bundle exported while the
/// scan is still `Running` reads six zeros no matter how much work has already
/// happened. The event log, by contrast, is persisted continuously — so for a
/// non-terminal scan it is the only honest source of "what has run so far".
///
/// # These are event counts, not the engine's counters
///
/// Every field is a straight tally of how many events of one kind the stream
/// holds. It deliberately stops there rather than reconstructing the engine's
/// six columns, because the event stream cannot support that reconstruction:
///
/// - There is no distinct event kind for a timeout, a cache replay, or a
///   dedup, so `timed_out` / `cached` / `deduped` are simply not derivable.
///   A timeout arrives as a `ModuleError` like any other failure.
/// - `skipped` is not disjoint from `started`. Gate-skips are emitted without
///   a preceding `ModuleStart` (`Engine::emit_module_skipped`), whereas a
///   module that dispatched and then cleanly opted out for a missing API key
///   emits `ModuleSkipped` *after* its `ModuleStart` (`dispatch.rs`). So
///   `started - done - errored - skipped` is not an in-flight count, and no
///   in-flight figure is offered.
///
/// Presenting these as the real counters would be a guess dressed as a
/// measurement; presenting them as event counts is exactly what they are.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ModuleEventTally {
    /// `module_start` events — modules that reached dispatch.
    pub started: usize,
    /// `module_done` events — modules that completed and reported a find count.
    pub done: usize,
    /// `module_error` events — failures, timeouts included (they are not
    /// distinguishable at this layer).
    pub errored: usize,
    /// `module_skipped` events — gate-skips plus dispatched-then-opted-out.
    pub skipped: usize,
}

impl ModuleEventTally {
    /// Tally `events` by kind. Pure; every non-module event is ignored.
    #[must_use]
    pub fn from_events(events: &[Event]) -> Self {
        let mut t = Self::default();
        for ev in events {
            match ev.kind {
                EventKind::ModuleStart { .. } => t.started += 1,
                EventKind::ModuleDone { .. } => t.done += 1,
                EventKind::ModuleError { .. } => t.errored += 1,
                EventKind::ModuleSkipped { .. } => t.skipped += 1,
                _ => {}
            }
        }
        t
    }

    /// True when the stream carried no module activity at all — the case where
    /// printing the tally would add nothing over the counters.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.started == 0 && self.done == 0 && self.errored == 0 && self.skipped == 0
    }

    /// The tally as one human sentence, named after the events it counts so a
    /// reader can never mistake it for the engine's `modules_*` columns.
    #[must_use]
    pub fn summary_line(&self) -> String {
        format!(
            "{} module_start, {} module_done, {} module_error, {} module_skipped",
            self.started, self.done, self.errored, self.skipped
        )
    }
}

/// `""` or `"s"`, so a counted noun in a rendered event reads as English.
///
/// A live scan routinely reports exactly one of something, and "1 probes" is
/// the kind of detail that makes an operator distrust the number next to it.
const fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
