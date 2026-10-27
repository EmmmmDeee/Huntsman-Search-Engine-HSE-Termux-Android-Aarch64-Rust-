//! Whether a later scan of a target warrants an operator's attention, decided from how it differs
//! from the scan before it, so a schedule can act on the result without reading the report.
//!
//! Running a scan again on the same target is how an operator watches it, and [`compare`] already
//! says what changed. This module only decides which changes raise an alert: a new correlation at
//! or above a chosen risk and, when asked, any value the earlier scan did not find. Values that
//! have gone are left to the comparison and never raise one, because a source that stops
//! answering is not evidence that a value stopped being true.
//!
//! [`compare`]: crate::scan_compare::compare

use std::path::Path;

use serde::Serialize;
use serde_json::{Value, json};

use crate::error::Error;
use crate::fsio::{read_bounded, write_atomic_private};
use crate::scan_compare::Comparison;
use crate::sf_correlate::Risk;
use crate::textnorm::one_line;

/// The most entries the alert history keeps; the oldest go first.
pub const MAX_ALERT_HISTORY_ENTRIES: usize = 1_000;
/// The file, beside the scans, that keeps every alert decision.
pub const HISTORY_FILE: &str = "alerts.jsonl";
/// The largest history file read or written.
const MAX_ALERT_HISTORY_BYTES: u64 = 2 * 1024 * 1024;

/// What raises an alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    /// The least severe risk that raises an alert. A new correlation at this risk or at any more
    /// severe one raises one; a risk ranks High, then Medium, Low and Info.
    pub min_risk: Risk,
    /// Whether any value the earlier scan did not find raises an alert as well.
    pub new_values: bool,
}

/// One reason an alert was raised.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Reason {
    /// A correlation the later scan has and the earlier scan does not, at or above the policy's risk.
    Correlation {
        risk: Risk,
        rule: String,
        title: String,
    },
    /// Distinct values the earlier scan did not find.
    NewValues { count: usize },
}

/// The decision for one later scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Alert {
    pub raised: bool,
    pub reasons: Vec<Reason>,
}

/// One decision as the history records it: when it was made, the two scans and whether an alert
/// was raised, with each reason's risk and rule. The target and a correlation's title are left
/// out: the target is the scan's own, and a title can carry the value it names, so the history
/// holds neither a second copy of an identifier nor the text of a finding.
#[must_use]
pub fn history_entry(at_ms: u64, earlier: &str, later: &str, alert: &Alert) -> Value {
    let reasons: Vec<Value> = alert
        .reasons
        .iter()
        .map(|reason| match reason {
            Reason::Correlation { risk, rule, .. } => {
                json!({ "kind": "correlation", "risk": risk, "rule": rule })
            }
            Reason::NewValues { count } => json!({ "kind": "new_values", "count": count }),
        })
        .collect();
    json!({
        "at": at_ms,
        "earlier": earlier,
        "later": later,
        "raised": alert.raised,
        "reasons": reasons,
    })
}

/// Append `entry` to the history at `path`, keeping only the newest [`MAX_ALERT_HISTORY_ENTRIES`].
/// The file is rewritten atomically, so an interrupted write leaves the previous history intact.
///
/// # Errors
/// [`Error::Store`] when the existing history cannot be read or the new one cannot be written.
pub fn append_history(path: &Path, entry: &Value) -> Result<(), Error> {
    let mut lines: Vec<String> = read_history(path)?.iter().map(Value::to_string).collect();
    lines.push(entry.to_string());
    let excess = lines.len().saturating_sub(MAX_ALERT_HISTORY_ENTRIES);
    lines.drain(..excess);
    let mut body = lines.join("\n");
    body.push('\n');
    write_atomic_private(path, body.as_bytes(), MAX_ALERT_HISTORY_BYTES)
}

/// Every entry in the history at `path`, oldest first; none when there is no history yet.
///
/// # Errors
/// [`Error::Store`] when the file cannot be read or a line is not an entry.
pub fn read_history(path: &Path) -> Result<Vec<Value>, Error> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let bytes = read_bounded(path, MAX_ALERT_HISTORY_BYTES)?;
    let text = String::from_utf8(bytes)
        .map_err(|_| Error::Store(format!("{}: alert history is not UTF-8", path.display())))?;
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str(line).map_err(|error| {
                Error::Store(format!(
                    "{}: unreadable alert history line: {error}",
                    path.display()
                ))
            })
        })
        .collect()
}

/// The title of the phone notification an alert raises.
pub const NOTIFICATION_TITLE: &str = "Huntsman alert";
/// The most characters a notification's text holds.
const MAX_NOTIFICATION_CHARS: usize = 240;

/// The text of the phone notification a raised alert posts: each reason's risk and rule, or the
/// count of new values, on one line. Like the history it never names the target or a finding's
/// text, because a notification shows on the lock screen.
#[must_use]
pub fn notification_text(alert: &Alert) -> String {
    let parts: Vec<String> = alert
        .reasons
        .iter()
        .map(|reason| match reason {
            Reason::Correlation { risk, rule, .. } => {
                format!("{} {}", risk.as_str(), one_line(rule))
            }
            Reason::NewValues { count } => format!("{count} new values"),
        })
        .collect();
    let text = parts.join("; ");
    if text.chars().count() <= MAX_NOTIFICATION_CHARS {
        return text;
    }
    let mut short: String = text.chars().take(MAX_NOTIFICATION_CHARS - 1).collect();
    short.push('\u{2026}');
    short
}

/// A risk level as an operator writes it: `HIGH`, `MEDIUM`, `LOW` or `INFO`, in any case.
#[must_use]
pub fn parse_min_risk(text: &str) -> Option<Risk> {
    match text.to_ascii_uppercase().as_str() {
        "HIGH" => Some(Risk::High),
        "MEDIUM" => Some(Risk::Medium),
        "LOW" => Some(Risk::Low),
        "INFO" => Some(Risk::Info),
        _ => None,
    }
}

/// Decide whether `comparison`, the later scan against the earlier one, raises an alert.
#[must_use]
pub fn assess(comparison: &Comparison<'_>, policy: Policy) -> Alert {
    let mut reasons: Vec<Reason> = comparison
        .correlations_added
        .iter()
        .filter(|correlation| correlation.risk <= policy.min_risk)
        .map(|correlation| Reason::Correlation {
            risk: correlation.risk,
            rule: correlation.rule.clone(),
            title: correlation.title.clone(),
        })
        .collect();
    let new_values: usize = comparison.types.iter().map(|change| change.added).sum();
    if policy.new_values && new_values > 0 {
        reasons.push(Reason::NewValues { count: new_values });
    }
    Alert {
        raised: !reasons.is_empty(),
        reasons,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan_compare::compare;
    use crate::scan_store::{ScanCorrelation, ScanResults};
    use crate::sf_elements::DataElement;

    fn element(id: &str, kind: &str, data: &str, source: Option<&str>) -> DataElement {
        DataElement {
            id: id.into(),
            kind: kind.into(),
            data: data.into(),
            source: source.map(str::to_owned),
            module: "m".into(),
            confidence: 100,
            created: 1_700_000_000_000,
            fp: false,
            entity: None,
            raw: serde_json::Value::Null,
        }
    }

    fn correlation(rule: &str, risk: Risk) -> ScanCorrelation {
        ScanCorrelation {
            id: rule.into(),
            rule: rule.into(),
            name: rule.into(),
            title: format!("{rule} found"),
            risk,
            description: String::new(),
            origin: "huntsman".into(),
            logic: String::new(),
            elements: Vec::new(),
        }
    }

    fn results(
        id: &str,
        elements: Vec<DataElement>,
        correlations: Vec<ScanCorrelation>,
    ) -> ScanResults {
        ScanResults {
            format_version: crate::scan_store::FORMAT_VERSION,
            scan_id: id.into(),
            text: String::new(),
            entities: Vec::new(),
            outcomes: Vec::new(),
            elements,
            correlations,
            lineage: Vec::new(),
            termination: None,
        }
    }

    fn policy(min_risk: Risk, new_values: bool) -> Policy {
        Policy {
            min_risk,
            new_values,
        }
    }

    /// An earlier scan with one IP and one correlation, and a later scan that adds a second IP and
    /// a correlation of the given risk, and drops the old correlation.
    fn later_with(risk: Risk) -> (ScanResults, ScanResults) {
        let base = results(
            "a",
            vec![
                element("r", "ROOT", "example.com", None),
                element("1", "IP_ADDRESS", "192.0.2.1", Some("r")),
            ],
            vec![correlation("stale", Risk::Low)],
        );
        let other = results(
            "b",
            vec![
                element("r", "ROOT", "example.com", None),
                element("1", "IP_ADDRESS", "192.0.2.1", Some("r")),
                element("2", "IP_ADDRESS", "192.0.2.2", Some("r")),
            ],
            vec![correlation("fresh", risk)],
        );
        (base, other)
    }

    #[test]
    fn a_new_correlation_at_or_above_the_minimum_risk_raises_an_alert() {
        let (base, other) = later_with(Risk::Medium);
        let alert = assess(&compare(&base, &other), policy(Risk::Medium, false));
        assert!(alert.raised);
        assert_eq!(
            alert.reasons,
            vec![Reason::Correlation {
                risk: Risk::Medium,
                rule: "fresh".into(),
                title: "fresh found".into(),
            }]
        );
    }

    #[test]
    fn a_new_correlation_below_the_minimum_risk_does_not() {
        let (base, other) = later_with(Risk::Low);
        let alert = assess(&compare(&base, &other), policy(Risk::Medium, false));
        assert!(!alert.raised);
        assert!(alert.reasons.is_empty());
    }

    #[test]
    fn a_more_severe_correlation_counts_for_a_lower_minimum() {
        let (base, other) = later_with(Risk::High);
        let alert = assess(&compare(&base, &other), policy(Risk::Low, false));
        assert!(alert.raised);
    }

    #[test]
    fn new_values_raise_only_when_asked_and_count_distinct_values() {
        let (base, other) = later_with(Risk::Info);
        let quiet = assess(&compare(&base, &other), policy(Risk::High, false));
        assert!(!quiet.raised);
        let loud = assess(&compare(&base, &other), policy(Risk::High, true));
        assert!(loud.raised);
        assert_eq!(loud.reasons, vec![Reason::NewValues { count: 1 }]);
    }

    #[test]
    fn values_that_have_gone_never_raise_an_alert() {
        let base = results(
            "a",
            vec![
                element("r", "ROOT", "example.com", None),
                element("1", "IP_ADDRESS", "192.0.2.1", Some("r")),
            ],
            Vec::new(),
        );
        let other = results(
            "b",
            vec![element("r", "ROOT", "example.com", None)],
            Vec::new(),
        );
        let alert = assess(&compare(&base, &other), policy(Risk::Info, true));
        assert!(!alert.raised);
    }

    #[test]
    fn a_scan_compared_with_itself_raises_nothing() {
        let (base, _) = later_with(Risk::High);
        let alert = assess(&compare(&base, &base), policy(Risk::Info, true));
        assert!(!alert.raised);
    }

    #[test]
    fn the_history_keeps_the_newest_entries_and_reads_back_in_order() {
        let dir = std::env::temp_dir().join(format!("scan-alert-history-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("alerts.jsonl");
        assert!(read_history(&path).unwrap().is_empty());
        for at in 0..=MAX_ALERT_HISTORY_ENTRIES as u64 {
            append_history(&path, &json!({ "at": at, "raised": false, "reasons": [] })).unwrap();
        }
        let entries = read_history(&path).unwrap();
        assert_eq!(entries.len(), MAX_ALERT_HISTORY_ENTRIES);
        assert_eq!(entries[0]["at"], 1, "the oldest entry is the one dropped");
        assert_eq!(
            entries[MAX_ALERT_HISTORY_ENTRIES - 1]["at"],
            MAX_ALERT_HISTORY_ENTRIES as u64
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_notification_names_risks_rules_and_counts_but_no_finding_text() {
        let alert = Alert {
            raised: true,
            reasons: vec![
                Reason::Correlation {
                    risk: Risk::High,
                    rule: "phone_present".into(),
                    title: "Phone number found: +61412345678".into(),
                },
                Reason::NewValues { count: 3 },
            ],
        };
        let text = notification_text(&alert);
        assert_eq!(text, "HIGH phone_present; 3 new values");
        assert!(!text.contains("+61412345678"));
    }

    #[test]
    fn a_long_notification_is_cut_to_its_bound() {
        let alert = Alert {
            raised: true,
            reasons: (0..100)
                .map(|n| Reason::Correlation {
                    risk: Risk::Low,
                    rule: format!("rule_{n}"),
                    title: String::new(),
                })
                .collect(),
        };
        let text = notification_text(&alert);
        assert_eq!(text.chars().count(), MAX_NOTIFICATION_CHARS);
        assert!(text.ends_with('\u{2026}'));
    }
}
