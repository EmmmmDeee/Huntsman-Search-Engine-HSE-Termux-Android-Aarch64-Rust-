//! Evidence-gated human trafficking indicator assessment.
//! This module does not determine guilt, identify victims, or infer crimes from proximity.
//! Inputs should be drawn from lawfully accessible, documented public sources.
use serde::{Deserialize, Serialize};
pub mod entity_tree;
mod policy;
pub use policy::ReviewPolicy;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Indicator {
    RecruitmentDeception,
    DocumentRetention,
    MovementRestriction,
    ThreatsOrCoercion,
    DebtBondage,
    WageWithholding,
    ForcedLabour,
    SexualExploitation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    pub indicator: Indicator,
    /// Stable source ID, not a person identifier.
    pub source_id: String,
    /// A public citation or locally retained evidence reference.
    pub evidence_ref: String,
    /// The underlying publisher or originator, for independence checks.
    pub origin_id: String,
    pub observed_at: String,
    pub corroborated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssessmentStatus {
    InsufficientEvidence,
    IndicatorsForHumanReview,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Assessment {
    pub status: AssessmentStatus,
    pub supported_indicators: Vec<Indicator>,
    pub independent_origins: usize,
    pub limitations: Vec<String>,
    pub evidence_refs: Vec<String>,
}

/// Conservative triage; preserves the original public entry point.\n#[must_use]\npub fn assess(observations: &[Observation]) -> Assessment {\n    ReviewPolicy::default().assess(observations)\n}\n\n#[cfg(test)]
mod tests {
    use super::*;
    fn observation(origin: &str) -> Observation {
        Observation {
            indicator: Indicator::DocumentRetention,
            source_id: format!("source-{origin}"),
            evidence_ref: format!("case-{origin}"),
            origin_id: origin.to_owned(),
            observed_at: "2026-01-01".to_owned(),
            corroborated: true,
        }
    }
    #[test]
    fn abstains_without_independent_sources() {
        let result = assess(&[observation("a"), observation("a")]);
        assert_eq!(result.status, AssessmentStatus::InsufficientEvidence);
    }
    #[test]
    fn flags_independently_supported_indicator_for_review() {
        let result = assess(&[observation("a"), observation("b")]);
        assert_eq!(result.status, AssessmentStatus::IndicatorsForHumanReview);
        assert_eq!(result.supported_indicators, vec![Indicator::DocumentRetention]);
    }
    #[test]
    fn excludes_uncorroborated_or_incomplete_evidence() {
        let mut invalid = observation("b");
        invalid.corroborated = false;
        let result = assess(&[observation("a"), invalid]);
        assert_eq!(result.status, AssessmentStatus::InsufficientEvidence);
        assert_eq!(result.evidence_refs.len(), 1);
    }
    #[test]
    fn empty_input_abstains() {
        assert_eq!(assess(&[]).status, AssessmentStatus::InsufficientEvidence);
    }
}

#[cfg(test)]
mod policy_tests {
    use super::*;
    fn observation(origin: &str) -> Observation {
        Observation {
            indicator: Indicator::DebtBondage,
            source_id: origin.into(),
            evidence_ref: format!("public-case-{origin}"),
            origin_id: origin.into(),
            observed_at: "2026-01-01".into(),
            corroborated: true,
        }
    }
    #[test]
    fn configurable_threshold_requires_three_independent_origins() {
        let policy = ReviewPolicy { minimum_independent_origins: 3 };
        assert_eq!(policy.assess(&[observation("a"), observation("b")]).status, AssessmentStatus::InsufficientEvidence);
        assert_eq!(policy.assess(&[observation("a"), observation("b"), observation("c")]).status, AssessmentStatus::IndicatorsForHumanReview);
    }
    #[test]
    fn cannot_lower_minimum_below_two() {
        let policy = ReviewPolicy { minimum_independent_origins: 0 };
        assert_eq!(policy.assess(&[observation("a")]).status, AssessmentStatus::InsufficientEvidence);
    }
}
