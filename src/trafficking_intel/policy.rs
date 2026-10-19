//! Conservative, source-independent trafficking-indicator triage.
//!
//! Evidence is used for human review, never for automated guilt attribution.
//! Multiple reproductions of one original publication count as one origin.

use super::{Assessment, AssessmentStatus, Indicator, Observation};
use std::collections::{BTreeMap, BTreeSet};

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
        let minimum = self.minimum_independent_origins.max(2);
        let valid: Vec<&Observation> = observations
            .iter()
            .filter(|observation| {
                observation.corroborated
                    && !observation.source_id.trim().is_empty()
                    && !observation.origin_id.trim().is_empty()
                    && !observation.evidence_ref.trim().is_empty()
                    && !observation.observed_at.trim().is_empty()
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
