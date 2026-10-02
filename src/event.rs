//! Pure event types and structured log rendering.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::timefmt::format_unix;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipClass {
    Scoped,
    Unavailable,
    NotApplicable,
    AlreadyCovered,
}

impl SkipClass {
    #[must_use]
    pub const fn is_coverage_gap(self) -> bool {
        match self {
            Self::Scoped | Self::Unavailable => true,
            Self::NotApplicable | Self::AlreadyCovered => false,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Scoped => "scoped",
            Self::Unavailable => "unavailable",
            Self::NotApplicable => "not_applicable",
            Self::AlreadyCovered => "already_covered",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanStatus {
    Complete,
    Aborted,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub scan_id: String,
    pub ts: u64,
    pub kind: EventKind,
}

impl Event {
    #[must_use]
    pub fn new(scan_id: impl Into<String>, ts: u64, kind: EventKind) -> Self {
        Self {
            scan_id: scan_id.into(),
            ts,
            kind,
        }
    }

    #[must_use]
    pub fn to_log_line(&self) -> String {
        let mut parts = Vec::with_capacity(6);
        parts.push(format!("\"time\":{}", Value::from(hms_utc(self.ts))));
        parts.push(format!("\"level\":\"{}\"", self.kind.log_level()));
        parts.push(format!("\"kind\":\"{}\"", self.kind.event_type_str()));
        for (key, value) in self.kind.log_fields() {
            parts.push(format!("\"{key}\":{value}"));
        }
        format!("{{{}}}", parts.join(","))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
        #[serde(default)]
        class: Option<SkipClass>,
    },
    ScanComplete {
        scan_id: String,
        entity_count: usize,
        #[serde(default = "terminal_status_default")]
        status: ScanStatus,
    },
}

impl EventKind {
    #[must_use]
    pub const fn event_type_str(&self) -> &'static str {
        match self {
            Self::ScanStart { .. } => "scan_start",
            Self::ModuleStart { .. } => "module_start",
            Self::ModuleDone { .. } => "module_done",
            Self::ModuleError { .. } => "module_error",
            Self::ModuleSkipped { .. } => "module_skipped",
            Self::ScanComplete { .. } => "scan_complete",
        }
    }

    #[must_use]
    pub const fn log_level(&self) -> &'static str {
        match self {
            Self::ModuleError { .. }
            | Self::ScanComplete {
                status: ScanStatus::Failed,
                ..
            } => "error",
            Self::ScanComplete {
                status: ScanStatus::Aborted,
                ..
            } => "warn",
            _ => "info",
        }
    }

    #[must_use]
    fn log_fields(&self) -> Vec<(&'static str, Value)> {
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
            Self::ModuleSkipped {
                module,
                reason,
                class,
            } => {
                let mut out = vec![("module", json!(module)), ("reason", json!(reason))];
                if let Some(class) = class {
                    out.push(("class", json!(class.as_str())));
                }
                out
            }
            Self::ScanComplete {
                scan_id,
                entity_count,
                status,
            } => vec![
                ("scan_id", json!(scan_id)),
                ("entity_count", json!(entity_count)),
                (
                    "status",
                    json!(match status {
                        ScanStatus::Complete => "complete",
                        ScanStatus::Aborted => "aborted",
                        ScanStatus::Failed => "failed",
                    }),
                ),
            ],
        }
    }
}

const fn terminal_status_default() -> ScanStatus {
    ScanStatus::Complete
}

fn hms_utc(ts: u64) -> String {
    let rendered = format_unix(i64::try_from(ts).unwrap_or(i64::MAX));
    rendered[11..].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skip_classes_keep_gap_semantics() {
        assert!(SkipClass::Scoped.is_coverage_gap());
        assert!(SkipClass::Unavailable.is_coverage_gap());
        assert!(!SkipClass::NotApplicable.is_coverage_gap());
        assert!(!SkipClass::AlreadyCovered.is_coverage_gap());
    }

    #[test]
    fn log_lines_are_structured_and_stable() {
        let event = Event::new(
            "scan-1",
            3_723,
            EventKind::ModuleSkipped {
                module: "shodan".to_string(),
                reason: "free-only".to_string(),
                class: Some(SkipClass::Scoped),
            },
        );
        let line = event.to_log_line();
        assert!(line.starts_with('{'));
        assert!(line.contains(r#""time":"01:02:03Z""#));
        assert!(line.contains(r#""level":"info""#));
        assert!(line.contains(r#""kind":"module_skipped""#));
        assert!(line.contains(r#""class":"scoped""#));
    }

    #[test]
    fn log_levels_track_failures_and_aborts() {
        assert_eq!(
            EventKind::ModuleError {
                module: "mod".to_string(),
                error: "boom".to_string(),
            }
            .log_level(),
            "error"
        );
        assert_eq!(
            EventKind::ScanComplete {
                scan_id: "x".to_string(),
                entity_count: 0,
                status: ScanStatus::Aborted,
            }
            .log_level(),
            "warn"
        );
    }
}
