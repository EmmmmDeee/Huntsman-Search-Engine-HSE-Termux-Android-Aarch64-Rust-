//! Conservative, source-independent trafficking-indicator triage.
//!
//! Evidence is used for human review, never for automated guilt attribution.
//! Multiple reproductions of one original publication count as one origin.

use super::{Assessment, AssessmentStatus, Indicator, Observation};
use std::collections::{BTreeMap, BTreeSet};

/// Accept only unambiguous ISO calendar dates; timestamps need separate validation.
fn valid_observation_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return false;
    }
    if !bytes
        .iter()
        .enumerate()
        .all(|(i, b)| i == 4 || i == 7 || b.is_ascii_digit())
    {
        return false;
    }
    let year = value[0..4].parse::<u32>().unwrap_or(0);
    let month = value[5..7].parse::<u32>().unwrap_or(0);
    let day = value[8..10].parse::<u32>().unwrap_or(0);
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let max_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    year > 0 && day >= 1 && day <= max_day
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReviewPolicy {
    /// Minimum independent original sources per indicator. Values below two are clamped.
    pub minimum_independent_origins: usize,
}

impl Default for ReviewPolicy {
    fn default() -> Self {
        Self {
            minimum_independent_origins: 2,
        }
    }
}

impl ReviewPolicy {
    #[must_use]
    pub fn assess(self, observations: &[Observation]) -> Assessment {
        // Fail closed: never silently assess a truncated subset of observations.
        const MAX_OBSERVATIONS: usize = 10_000;
        const MAX_FIELD_BYTES: usize = 2_048;
        if observations.len() > MAX_OBSERVATIONS
            || observations.iter().any(|observation| {
                [
                    &observation.source_id,
                    &observation.origin_id,
                    &observation.evidence_ref,
                    &observation.observed_at,
                ]
                .iter()
                .any(|field| field.len() > MAX_FIELD_BYTES)
            })
        {
            return Assessment {
                status: AssessmentStatus::InsufficientEvidence,
                supported_indicators: Vec::new(),
                independent_origins: 0,
                limitations: vec![
                    "Assessment input exceeds resource limits; no conclusions were produced."
                        .to_owned(),
                ],
                evidence_refs: Vec::new(),
            };
        }
        let minimum = self.minimum_independent_origins.max(2);
        let valid: Vec<&Observation> = observations
            .iter()
            .filter(|observation| {
                observation.corroborated
                    && !observation.source_id.trim().is_empty()
                    && !observation.origin_id.trim().is_empty()
                    && !observation.evidence_ref.trim().is_empty()
                    && valid_observation_date(&observation.observed_at)
            })
            .collect();

        let mut origins = BTreeSet::new();
        let mut by_indicator: BTreeMap<Indicator, BTreeSet<&str>> = BTreeMap::new();
        let mut evidence_refs = BTreeSet::new();

        for observation in &valid {
            origins.insert(observation.origin_id.as_str());
            by_indicator
                .entry(observation.indicator)
                .or_default()
                .insert(observation.origin_id.as_str());
            evidence_refs.insert(observation.evidence_ref.clone());
        }

        let supported_indicators: Vec<Indicator> = by_indicator
            .into_iter()
            .filter_map(|(indicator, independent_origins)| {
                (independent_origins.len() >= minimum).then_some(indicator)
            })
            .collect();

        let status = if supported_indicators.is_empty() {
            AssessmentStatus::InsufficientEvidence
        } else {
            AssessmentStatus::IndicatorsForHumanReview
        };

        let mut limitations = vec![
            "Indicators do not establish trafficking or criminal culpability.".to_owned(),
            "Assess coercion, exploitation, context, and alternative explanations manually."
                .to_owned(),
            "Do not publish potential victim identifiers or automate enforcement actions."
                .to_owned(),
        ];

        if valid.len() != observations.len() {
            limitations.push("Incomplete or uncorroborated observations were excluded.".to_owned());
        }
        if supported_indicators.is_empty() {
            limitations.push(format!(
                "No indicator has {minimum} independent corroborated origins."
            ));
        }

        Assessment {
            status,
            supported_indicators,
            independent_origins: origins.len(),
            limitations,
            evidence_refs: evidence_refs.into_iter().collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation(indicator: Indicator, origin: &str, source: &str) -> Observation {
        Observation {
            indicator,
            source_id: source.to_owned(),
            origin_id: origin.to_owned(),
            evidence_ref: format!("published-record-{source}"),
            observed_at: "2026-01-01".to_owned(),
            corroborated: true,
        }
    }

    #[test]
    fn invalid_dates_cannot_supply_corroboration() {
        let mut invalid = observation(Indicator::WageWithholding, "publisher-a", "a");
        invalid.observed_at = "2026-02-30".into();
        let valid = observation(Indicator::WageWithholding, "publisher-b", "b");
        let result = ReviewPolicy::default().assess(&[invalid, valid]);
        assert_eq!(result.status, AssessmentStatus::InsufficientEvidence);
        assert_eq!(result.independent_origins, 1);
    }

    #[test]
    fn leap_year_dates_are_checked() {
        assert!(valid_observation_date("2024-02-29"));
        assert!(!valid_observation_date("2026-02-29"));
        assert!(!valid_observation_date("2026-13-01"));
        assert!(!valid_observation_date("2026-01-01T00:00:00Z"));
    }

    #[test]
    fn oversized_observation_set_abstains_without_partial_assessment() {
        let observations =
            vec![observation(Indicator::WageWithholding, "publisher-a", "source-a"); 10_001];
        let result = ReviewPolicy::default().assess(&observations);
        assert_eq!(result.status, AssessmentStatus::InsufficientEvidence);
        assert!(result.evidence_refs.is_empty());
        assert!(result.supported_indicators.is_empty());
    }

    #[test]
    fn oversized_field_abstains_without_partial_assessment() {
        let mut input = observation(Indicator::WageWithholding, "a", "one");
        input.evidence_ref = "x".repeat(2_049);
        let result = ReviewPolicy::default().assess(&[input]);
        assert_eq!(result.status, AssessmentStatus::InsufficientEvidence);
        assert!(result.evidence_refs.is_empty());
    }

    #[test]
    fn syndication_is_not_independent_corroboration() {
        let observations = [
            observation(Indicator::WageWithholding, "publisher-a", "mirror-one"),
            observation(Indicator::WageWithholding, "publisher-a", "mirror-two"),
        ];
        assert_eq!(
            ReviewPolicy::default().assess(&observations).status,
            AssessmentStatus::InsufficientEvidence
        );
    }

    #[test]
    fn corroboration_is_per_indicator_not_across_unrelated_indicators() {
        let observations = [
            observation(Indicator::WageWithholding, "publisher-a", "source-a"),
            observation(Indicator::DocumentRetention, "publisher-b", "source-b"),
        ];
        assert_eq!(
            ReviewPolicy::default().assess(&observations).status,
            AssessmentStatus::InsufficientEvidence
        );
    }

    #[test]
    fn evidence_references_are_deterministic_and_unique() {
        let observations = [
            observation(Indicator::WageWithholding, "publisher-b", "source-b"),
            observation(Indicator::WageWithholding, "publisher-a", "source-a"),
            observation(Indicator::WageWithholding, "publisher-a", "source-a"),
        ];
        let result = ReviewPolicy::default().assess(&observations);
        assert_eq!(result.status, AssessmentStatus::IndicatorsForHumanReview);
        assert_eq!(
            result.evidence_refs,
            vec!["published-record-source-a", "published-record-source-b"]
        );
    }
}
