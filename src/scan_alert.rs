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

use serde::Serialize;

use crate::scan_compare::Comparison;
use crate::sf_correlate::Risk;

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
}
