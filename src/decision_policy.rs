//! Pure operational action-selection policy.
//!
//! This module consumes normalized facts resolved elsewhere. It performs no I/O and
//! does not own provider, dependency, credential, or evidence registries.

use std::collections::BTreeSet;

use crate::roi::DispatchUtilityInputs;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RequirementState {
    pub id: String,
    pub satisfied: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EligibilitySnapshot {
    pub hard_constraints: Vec<RequirementState>,
    pub dependencies: Vec<RequirementState>,
    pub permissions: Vec<RequirementState>,
    pub provider_executable: bool,
    pub preconditions: Vec<RequirementState>,
    pub blocked_reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ActionCandidate {
    pub id: String,
    pub capability: String,
    pub provider: Option<String>,
    pub target: String,
    pub eligibility: EligibilitySnapshot,
    pub satisfied_obligations: BTreeSet<String>,
    pub expected_decision_impact: f64,
    pub roi_inputs: DispatchUtilityInputs,
    pub resource_cost: f64,
    pub irreversible_risk: f64,
    pub blast_radius: f64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum IneligibilityReason {
    HardConstraintFailed(String),
    MissingDependency(String),
    MissingPermission(String),
    ProviderUnavailable,
    FailedPrecondition(String),
    ExplicitlyBlocked(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Eligibility {
    Eligible,
    Ineligible(Vec<IneligibilityReason>),
}

#[must_use]
pub fn evaluate_eligibility(candidate: &ActionCandidate) -> Eligibility {
    let mut reasons = Vec::new();

    reasons.extend(
        candidate
            .eligibility
            .hard_constraints
            .iter()
            .filter(|requirement| !requirement.satisfied)
            .map(|requirement| IneligibilityReason::HardConstraintFailed(requirement.id.clone())),
    );
    reasons.extend(
        candidate
            .eligibility
            .dependencies
            .iter()
            .filter(|requirement| !requirement.satisfied)
            .map(|requirement| IneligibilityReason::MissingDependency(requirement.id.clone())),
    );
    reasons.extend(
        candidate
            .eligibility
            .permissions
            .iter()
            .filter(|requirement| !requirement.satisfied)
            .map(|requirement| IneligibilityReason::MissingPermission(requirement.id.clone())),
    );
    if !candidate.eligibility.provider_executable {
        reasons.push(IneligibilityReason::ProviderUnavailable);
    }
    reasons.extend(
        candidate
            .eligibility
            .preconditions
            .iter()
            .filter(|requirement| !requirement.satisfied)
            .map(|requirement| IneligibilityReason::FailedPrecondition(requirement.id.clone())),
    );
    reasons.extend(
        candidate
            .eligibility
            .blocked_reasons
            .iter()
            .cloned()
            .map(IneligibilityReason::ExplicitlyBlocked),
    );

    reasons.sort();
    reasons.dedup();
    if reasons.is_empty() {
        Eligibility::Eligible
    } else {
        Eligibility::Ineligible(reasons)
    }
}
