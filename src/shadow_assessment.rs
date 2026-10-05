//! Read-only comparison between legacy claim state and policy-gated assessment.
//!
//! Shadow comparison records semantic differences without mutating the ledger or
//! influencing scheduling. Reason codes are explicit and stable so future
//! benchmark fixtures can compare behavior without depending on debug strings.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::claim_policy::{VerificationBlocker, VerificationPolicy};
use crate::evidence_ancestry::{EvidenceAncestryGraph, EvidenceNodeId};
use crate::intelligence::{ClaimId, ClaimState, EvidenceId, IntelligenceLedger, LedgerError};
use crate::proof::ProofEnvironmentSet;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowAssessment {
    pub legacy_state: ClaimState,
    pub policy_state: ClaimState,
    pub blockers: BTreeSet<VerificationBlocker>,
    pub reason_codes: BTreeSet<String>,
}

/// Compares the stored legacy claim state with the canonical ancestry + policy
/// assessment, then applies proof-environment completeness conservatively.
///
/// This function is observational only. It does not alter claim state, evidence,
/// provenance, coverage, or dispatch decisions.
///
/// # Errors
/// Returns the same missing claim/evidence errors as policy assessment.
pub fn compare_legacy_and_policy(
    ledger: &IntelligenceLedger,
    claim_id: &ClaimId,
    policy: &VerificationPolicy,
    graph: &EvidenceAncestryGraph,
    bindings: &BTreeMap<EvidenceId, EvidenceNodeId>,
    proof: &ProofEnvironmentSet,
) -> Result<ShadowAssessment, LedgerError> {
    let legacy_state = ledger
        .claims
        .get(claim_id)
        .ok_or_else(|| LedgerError::MissingClaim(claim_id.clone()))?
        .state;

    let assessment = ledger
        .assess_claim_with_ancestry(claim_id, policy, graph, bindings)?
        .with_proof_environments(proof);

    let mut reason_codes = assessment
        .blockers
        .iter()
        .map(|blocker| format!("blocker:{}", blocker_code(*blocker)))
        .collect::<BTreeSet<_>>();

    if legacy_state != assessment.epistemic {
        reason_codes.insert(format!(
            "state:{}->{}",
            state_code(legacy_state),
            state_code(assessment.epistemic)
        ));
    }

    Ok(ShadowAssessment {
        legacy_state,
        policy_state: assessment.epistemic,
        blockers: assessment.blockers,
        reason_codes,
    })
}

const fn state_code(state: ClaimState) -> &'static str {
    match state {
        ClaimState::Candidate => "candidate",
        ClaimState::Supported => "supported",
        ClaimState::Verified => "verified",
        ClaimState::Rejected => "rejected",
    }
}

const fn blocker_code(blocker: VerificationBlocker) -> &'static str {
    match blocker {
        VerificationBlocker::UnknownAncestry => "unknown_ancestry",
        VerificationBlocker::CanonicalAncestryRequired => "canonical_ancestry_required",
        VerificationBlocker::MissingRequiredEvidenceNature => "missing_required_evidence_nature",
        VerificationBlocker::InsufficientIndependentSupport => "insufficient_independent_support",
        VerificationBlocker::UndefeatedDefeater => "undefeated_defeater",
        VerificationBlocker::MissingProofEnvironment => "missing_proof_environment",
        VerificationBlocker::IncompleteProof => "incomplete_proof",
    }
}
