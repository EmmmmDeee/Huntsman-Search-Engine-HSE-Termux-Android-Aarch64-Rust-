//! Claim-specific verification policy and shadow assessment.
//!
//! This module is deliberately separate from exploration/confidence scoring.
//! A claim reaches `Verified` here only when every mandatory policy obligation
//! is satisfied by the evidence currently attached to that claim.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::evidence_ancestry::{EvidenceAncestryGraph, EvidenceNodeId};
use crate::intelligence::{
    ClaimId, ClaimState, Defeat, DefeatKind, EvidenceId, EvidenceNature, IntelligenceLedger,
    LedgerError,
};
use crate::proof::ProofEnvironmentSet;

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
    CanonicalAncestryRequired,
    MissingRequiredEvidenceNature,
    InsufficientIndependentSupport,
    UndefeatedDefeater,
    MissingProofEnvironment,
    IncompleteProof,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimAssessment {
    pub epistemic: ClaimState,
    pub blockers: BTreeSet<VerificationBlocker>,
    pub proven_roots: usize,
    pub unresolved_support: usize,
    #[serde(default)]
    pub proof_environment_count: usize,
    #[serde(default)]
    pub proof_incomplete: bool,
}

impl ClaimAssessment {
    /// Adds bounded proof-environment status without allowing proof bookkeeping
    /// to strengthen the evidence-derived assessment.
    ///
    /// An empty or truncated proof set blocks `Verified`. A complete, non-empty
    /// proof set can preserve an already-verified assessment but cannot promote
    /// a weaker one. This keeps resource limits epistemically conservative.
    #[must_use]
    pub fn with_proof_environments(mut self, proof: &ProofEnvironmentSet) -> Self {
        self.proof_environment_count = proof.environments.len();
        self.proof_incomplete = proof.incomplete;

        if proof.environments.is_empty() {
            self.blockers
                .insert(VerificationBlocker::MissingProofEnvironment);
        }
        if proof.incomplete {
            self.blockers.insert(VerificationBlocker::IncompleteProof);
        }

        if self.epistemic == ClaimState::Verified
            && (proof.environments.is_empty() || proof.incomplete)
        {
            self.epistemic = ClaimState::Supported;
        }
        self
    }
}

fn defeat_blocks_verification(defeat: &Defeat) -> bool {
    match defeat.kind {
        DefeatKind::Rebut => defeat.temporal_overlap != Some(false),
        DefeatKind::Undermine | DefeatKind::Undercut | DefeatKind::UnknownRelation => true,
        DefeatKind::Supersede | DefeatKind::Compatible => false,
    }
}

fn finish_assessment(
    policy: &VerificationPolicy,
    support_empty: bool,
    proven_roots: usize,
    unresolved_support: usize,
    present_natures: &[EvidenceNature],
    has_blocking_defeat: bool,
    canonical_ancestry: bool,
) -> ClaimAssessment {
    let mut blockers = BTreeSet::new();
    if policy.require_resolved_ancestry && unresolved_support > 0 {
        blockers.insert(VerificationBlocker::UnknownAncestry);
    }
    if !canonical_ancestry {
        blockers.insert(VerificationBlocker::CanonicalAncestryRequired);
    }
    if proven_roots < policy.min_proven_roots {
        blockers.insert(VerificationBlocker::InsufficientIndependentSupport);
    }
    if policy
        .required_natures
        .iter()
        .any(|required| !present_natures.contains(required))
    {
        blockers.insert(VerificationBlocker::MissingRequiredEvidenceNature);
    }
    if has_blocking_defeat {
        blockers.insert(VerificationBlocker::UndefeatedDefeater);
    }

    let epistemic = if support_empty {
        ClaimState::Candidate
    } else if blockers.is_empty() {
        ClaimState::Verified
    } else {
        ClaimState::Supported
    };

    ClaimAssessment {
        epistemic,
        blockers,
        proven_roots,
        unresolved_support,
        proof_environment_count: 0,
        proof_incomplete: false,
    }
}

impl IntelligenceLedger {
    /// Evaluates one claim against explicit, non-compensatory obligations using
    /// compatibility lineage fields.
    ///
    /// This path is diagnostic only: it can report support and blockers but can
    /// never produce `Verified`, because flat lineage metadata is not the
    /// canonical ancestry authority. Use [`Self::assess_claim_with_ancestry`]
    /// for verification-capable assessment.
    ///
    /// Confidence dimensions and provider count are intentionally excluded from
    /// this decision.
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
        let mut present_natures = Vec::new();

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
            if !present_natures.contains(&evidence.nature) {
                present_natures.push(evidence.nature.clone());
            }
        }

        Ok(finish_assessment(
            policy,
            claim.support.is_empty(),
            proven_roots.len(),
            unresolved_support,
            &present_natures,
            !claim.contradictions.is_empty()
                || claim.defeats.iter().any(defeat_blocks_verification),
            false,
        ))
    }

    /// Evaluates one claim using [`EvidenceAncestryGraph`] as the sole ancestry
    /// authority. The binding map is a projection from ledger evidence ids to
    /// graph nodes; legacy `source_id`, `origin_id`, and cached family labels do
    /// not contribute proof in this path.
    ///
    /// A missing binding, missing graph node, missing parent, cycle, or empty
    /// root result is unresolved ancestry and therefore fails closed whenever
    /// the policy requires resolved ancestry.
    ///
    /// # Errors
    /// Returns [`LedgerError::MissingClaim`] or [`LedgerError::MissingEvidence`]
    /// when the ledger itself references absent records.
    pub fn assess_claim_with_ancestry(
        &self,
        claim_id: &ClaimId,
        policy: &VerificationPolicy,
        graph: &EvidenceAncestryGraph,
        bindings: &BTreeMap<EvidenceId, EvidenceNodeId>,
    ) -> Result<ClaimAssessment, LedgerError> {
        let claim = self
            .claims
            .get(claim_id)
            .ok_or_else(|| LedgerError::MissingClaim(claim_id.clone()))?;

        let mut proven_roots = BTreeSet::new();
        let mut unresolved_support = 0usize;
        let mut present_natures = Vec::new();

        for evidence_id in &claim.support {
            let evidence = self
                .evidence
                .get(evidence_id)
                .ok_or_else(|| LedgerError::MissingEvidence(evidence_id.clone()))?;
            if !present_natures.contains(&evidence.nature) {
                present_natures.push(evidence.nature.clone());
            }

            let roots = bindings
                .get(evidence_id)
                .and_then(|node_id| graph.root_families(node_id).ok());
            match roots {
                Some(roots) if !roots.is_empty() => proven_roots.extend(roots),
                _ => unresolved_support += 1,
            }
        }

        Ok(finish_assessment(
            policy,
            claim.support.is_empty(),
            proven_roots.len(),
            unresolved_support,
            &present_natures,
            !claim.contradictions.is_empty()
                || claim.defeats.iter().any(defeat_blocks_verification),
            true,
        ))
    }
}
