//! Configurable, conservative triage policy. No automated guilt inference.
use super::{Assessment, AssessmentStatus, Indicator, Observation};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy)]
pub struct ReviewPolicy {
    /// Number of distinct original sources required per indicator; minimum two.
    pub minimum_independent_origins: usize,
}
impl Default for ReviewPolicy {
    fn default() -> Self { Self { minimum_independent_origins: 2 } }
}
impl ReviewPolicy {
    #[must_use]
    pub fn assess(self, observations: &[Observation]) -> Assessment {
        let minimum = self.minimum_independent_origins.max(2);
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
            by_indicator.entry(o.indicator).or_default().insert(o.origin_id.as_str());
        }
        let supported_indicators = by_indicator.into_iter()
            .filter(|(_, sources)| sources.len() >= minimum)
            .map(|(indicator, _)| indicator).collect::<Vec<_>>();
        let status = if supported_indicators.is_empty() {
            AssessmentStatus::InsufficientEvidence
        } else {
            AssessmentStatus::IndicatorsForHumanReview
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
            limitations.push(format!("No indicator has {minimum} independent corroborated origins."));
        }
        let evidence_refs = valid.iter().map(|o| o.evidence_ref.clone())
            .collect::<BTreeSet<_>>().into_iter().collect();
        Assessment { status, supported_indicators, independent_origins: origins.len(), limitations, evidence_refs }
    }
}
