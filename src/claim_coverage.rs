//! Conservative admission of negative collection evidence.
//!
//! A provider returning no rows is not evidence of absence by itself. A clean
//! negative is admissible only when the observation addresses the same claim,
//! evidence class, query scope and temporal requirement with sufficient
//! completeness. Provider multiplicity is diagnostic only; this module does
//! not convert multiple negatives into stronger proof.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::intelligence::{ClaimId, TemporalValidity};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoverageOutcome {
    Positive,
    CleanNegative,
    Partial,
    Failed { reason: String },
    NotAttempted { reason: String },
    NotApplicable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoverageCompleteness {
    Complete,
    MateriallyComplete,
    Partial,
    Unknown,
}

impl CoverageCompleteness {
    #[must_use]
    fn satisfies(self, minimum: Self) -> bool {
        fn rank(value: CoverageCompleteness) -> u8 {
            match value {
                CoverageCompleteness::Unknown => 0,
                CoverageCompleteness::Partial => 1,
                CoverageCompleteness::MateriallyComplete => 2,
                CoverageCompleteness::Complete => 3,
            }
        }
        rank(self) >= rank(minimum)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageObservation {
    pub provider_id: String,
    pub claim_id: ClaimId,
    pub outcome: CoverageOutcome,
    pub evidence_classes: BTreeSet<String>,
    pub query_scope: String,
    pub temporal: TemporalValidity,
    pub completeness: CoverageCompleteness,
    pub recorded_at_unix: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageRequirement {
    pub evidence_class: String,
    pub query_scope: String,
    pub temporal: TemporalValidity,
    pub minimum_completeness: CoverageCompleteness,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CoverageBlocker {
    NoApplicableObservation,
    CollectionFailure,
    IncompleteCoverage,
    PositiveObservation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageAssessment {
    pub negative_admissible: bool,
    pub qualifying_providers: BTreeSet<String>,
    pub blockers: BTreeSet<CoverageBlocker>,
}

impl CoverageRequirement {
    #[must_use]
    pub fn evaluate(
        &self,
        claim_id: &ClaimId,
        observations: &[CoverageObservation],
    ) -> CoverageAssessment {
        let mut qualifying_providers = BTreeSet::new();
        let mut saw_applicable = false;
        let mut saw_failure = false;
        let mut saw_incomplete = false;
        let mut saw_positive = false;

        for observation in observations {
            if !self.applies_to(claim_id, observation) {
                continue;
            }
            saw_applicable = true;

            match observation.outcome {
                CoverageOutcome::Positive => saw_positive = true,
                CoverageOutcome::CleanNegative => {
                    if observation
                        .completeness
                        .satisfies(self.minimum_completeness)
                    {
                        qualifying_providers.insert(observation.provider_id.clone());
                    } else {
                        saw_incomplete = true;
                    }
                }
                CoverageOutcome::Partial => saw_incomplete = true,
                CoverageOutcome::Failed { .. } | CoverageOutcome::NotAttempted { .. } => {
                    saw_failure = true;
                }
                CoverageOutcome::NotApplicable => {}
            }
        }

        let negative_admissible = !saw_positive && !qualifying_providers.is_empty();
        let mut blockers = BTreeSet::new();
        if saw_positive {
            blockers.insert(CoverageBlocker::PositiveObservation);
        } else if !negative_admissible {
            if !saw_applicable {
                blockers.insert(CoverageBlocker::NoApplicableObservation);
            }
            if saw_failure {
                blockers.insert(CoverageBlocker::CollectionFailure);
            }
            if saw_incomplete {
                blockers.insert(CoverageBlocker::IncompleteCoverage);
            }
            if blockers.is_empty() {
                blockers.insert(CoverageBlocker::NoApplicableObservation);
            }
        }

        CoverageAssessment {
            negative_admissible,
            qualifying_providers,
            blockers,
        }
    }

    fn applies_to(&self, claim_id: &ClaimId, observation: &CoverageObservation) -> bool {
        observation.claim_id == *claim_id
            && observation.evidence_classes.contains(&self.evidence_class)
            && observation.query_scope == self.query_scope
            && temporal_covers(&observation.temporal, &self.temporal)
    }
}

fn temporal_covers(observed: &TemporalValidity, required: &TemporalValidity) -> bool {
    let covers_start = match required.not_before_unix {
        Some(required_start) => observed
            .not_before_unix
            .is_some_and(|observed_start| observed_start <= required_start),
        None => true,
    };
    let covers_end = match required.not_after_unix {
        Some(required_end) => observed
            .not_after_unix
            .is_some_and(|observed_end| observed_end >= required_end),
        None => true,
    };
    covers_start && covers_end
}
