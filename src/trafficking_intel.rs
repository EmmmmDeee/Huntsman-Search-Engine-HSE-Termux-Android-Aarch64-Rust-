//! Evidence-gated human trafficking indicator assessment.
//! This module does not determine guilt, identify victims, or infer crimes from proximity.
//! Inputs should be drawn from lawfully accessible, documented public sources.
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

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

/// Conservative triage only. Never label a person or organisation as a trafficker.
/// Repeated publications of the same original report count as one origin.
#[must_use]
pub fn assess(observations: &[Observation]) -> Assessment {
    let valid: Vec<&Observation> = observations.iter().filter(|o| {
        !o.source_id.trim().is_empty()
            && !o.origin_id.trim().is_empty()
            && !o.evidence_ref.trim().is_empty()
            && !o.observed_at.trim().is_empty()
            && o.corroborated
    }).collect();
    let origins: BTreeSet<&str> = valid.iter().map(|o| o.origin_id.as_str()).collect();
    let mut by_indicator: BTreeMap<Indicator, BTreeSet<&str>> = BTreeMap::new();
    for o in &valid {
        by_indicator.entry(o.indicator).or_default().insert(&o.origin_id);
    }
    let supported_indicators: Vec<Indicator> = by_indicator.iter()
        .filter(|(_, origins)| origins.len() >= 2)
        .map(|(indicator, _)| *indicator)
        .collect();
    let status = if !supported_indicators.is_empty() {
        AssessmentStatus::IndicatorsForHumanReview
    } else {
        AssessmentStatus::InsufficientEvidence
    };
    let mut limitations = vec![
        "Indicators do not establish trafficking or criminal culpability.".to_owned(),
        "Assess coercion, exploitation, context, and alternative explanations manually.".to_owned(),
        "Do not publish potential victim identifiers or automate enforcement actions.".to_owned(),
    ];
    if valid.len() != observations.len() {
        limitations.push("Incomplete or uncorroborated observations were excluded.".to_owned());
    }
    if supported_indicators.is_empty() {
        limitations.push("No indicator has two independent corroborated origins.".to_owned());
    }
    let evidence_refs = valid.iter().map(|o| o.evidence_ref.clone())
        .collect::<BTreeSet<_>>().into_iter().collect();
    Assessment { status, supported_indicators, independent_origins: origins.len(), limitations, evidence_refs }
}

#[cfg(test)]
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
