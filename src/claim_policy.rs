//! Claim-specific verification policy and shadow assessment.
//!
//! This module is deliberately separate from exploration/confidence scoring.
//! A claim reaches `Verified` here only when every mandatory policy obligation
//! is satisfied by the evidence currently attached to that claim.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::intelligence::{
    ClaimId, ClaimState, EvidenceNature, IntelligenceLedger, LedgerError,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationPolicy {
    pub id: String,
    pub version: u32,
    pub min_proven_roots: usize,
    pub require_resolved_ancestry: bool,
    pub required_natures: Vec<EvidenceNature>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum VerificationBlocker {
    UnknownAncestry,
    MissingRequiredEvidenceNature,
    InsufficientIndependentSupport,
    UndefeatedDefeater,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimAssessment {
    pub epistemic: ClaimState,
    pub blockers: BTreeSet<VerificationBlocker>,
    pub proven_roots: usize,
    pub unresolved_support: usize,
}

impl IntelligenceLedger {
    /// Evaluates one claim against explicit, non-compensatory verification
    /// obligations. Confidence dimensions and provider count are intentionally
    /// excluded from this decision.
    ///
    /// The current generic contradiction list is treated conservatively as an
    /// undefeated blocker until structured defeat semantics replace it.
    ///
    /// # Errors
    /// Returns [`LedgerError::MissingClaim`] or [`LedgerError::MissingEvidence`]
    /// when referenced records are absent.
    pub fn assess_claim(
        &self,
        claim_id: &ClaimId,
        policy: &VerificationPolicy,
    ) -> Result<ClaimAssessment, LedgerError> {
        let claim = self
            .claims
            .get(claim_id)
            .ok_or_else(|| LedgerError::MissingClaim(claim_id.clone()))?;

        let mut proven_roots = BTreeSet::new();
        let mut unresolved_support = 0usize;
        let mut present_natures = BTreeSet::new();

        for evidence_id in &claim.support {
            let evidence = self
                .evidence
                .get(evidence_id)
                .ok_or_else(|| LedgerError::MissingEvidence(evidence_id.clone()))?;
            if let Some(origin) = evidence.lineage.known_origin_key() {
                proven_roots.insert(origin.to_owned());
            } else {
                unresolved_support += 1;
            }
            present_natures.insert(evidence.nature.clone());
        }

        let mut blockers = BTreeSet::new();
        if policy.require_resolved_ancestry && unresolved_support > 0 {
            blockers.insert(VerificationBlocker::UnknownAncestry);
        }
        if proven_roots.len() < policy.min_proven_roots {
            blockers.insert(VerificationBlocker::InsufficientIndependentSupport);
        }
        if policy
            .required_natures
            .iter()
            .any(|required| !present_natures.contains(required))
        {
            blockers.insert(VerificationBlocker::MissingRequiredEvidenceNature);
        }
        if !claim.contradictions.is_empty() {
            blockers.insert(VerificationBlocker::UndefeatedDefeater);
        }

        let epistemic = if claim.support.is_empty() {
            ClaimState::Candidate
        } else if blockers.is_empty() {
            ClaimState::Verified
        } else {
            ClaimState::Supported
        };

        Ok(ClaimAssessment {
            epistemic,
            blockers,
            proven_roots: proven_roots.len(),
            unresolved_support,
        })
    }
}
