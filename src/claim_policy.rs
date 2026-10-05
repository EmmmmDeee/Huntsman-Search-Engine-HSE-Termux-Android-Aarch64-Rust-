//! Claim-specific verification policy and shadow assessment.
//!
//! This module is deliberately separate from exploration/confidence scoring.
//! A claim reaches `Verified` here only when every mandatory policy obligation
//! is satisfied by the evidence currently attached to that claim.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::evidence_ancestry::{AncestryError, EvidenceAncestryGraph, EvidenceNodeId};
use crate::intelligence::{
    ClaimId, ClaimState, Defeat, DefeatKind, EvidenceId, EvidenceNature, IntelligenceLedger,
    LedgerError,
};
use crate::proof::ProofEnvironmentSet;

/// Hard cap on candidate subsets examined while proving independent support routes.
///
/// Exhausting this budget never strengthens a claim: the ancestry graph returns only
/// the strongest completed lower bound and marks the result incomplete.
const MAX_INDEPENDENCE_SEARCH_STATES: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationPolicy {
    pub id: String,
    pub version: u32,
    /// Compatibility field name. Canonical verification interprets this as the
    /// minimum number of proven independent evidence routes.
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
    IncompleteIndependenceProof,
    UndefeatedDefeater,
    MissingProofEnvironment,
    IncompleteProof,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimAssessment {
    pub epistemic: ClaimState,
    pub blockers: BTreeSet<VerificationBlocker>,
    /// Conservative count of proof routes established under independence semantics.
    pub proven_roots: usize,
    /// Raw count of distinct canonical ancestry roots resolved for diagnostics only.
    #[serde(default)]
    pub distinct_resolved_roots: usize,
    /// True when bounded independence search stopped before the requested cardinality
    /// was fully decided. An incomplete search cannot yield `Verified`.
    #[serde(default)]
    pub independence_incomplete: bool,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AncestryAuthority {
    Compatibility,
    Canonical,
}

struct AssessmentInputs<'a> {
    support_count: usize,
    proven_roots: usize,
    distinct_resolved_roots: usize,
    independence_incomplete: bool,
    unresolved_support: usize,
    present_natures: &'a [EvidenceNature],
    has_blocking_defeat: bool,
    ancestry_authority: AncestryAuthority,
}

fn finish_assessment(
    policy: &VerificationPolicy,
    inputs: &AssessmentInputs<'_>,
) -> ClaimAssessment {
    let mut blockers = BTreeSet::new();
    if policy.require_resolved_ancestry && inputs.unresolved_support > 0 {
        blockers.insert(VerificationBlocker::UnknownAncestry);
    }
    if inputs.ancestry_authority != AncestryAuthority::Canonical {
        blockers.insert(VerificationBlocker::CanonicalAncestryRequired);
    }
    if inputs.proven_roots < policy.min_proven_roots {
        blockers.insert(VerificationBlocker::InsufficientIndependentSupport);
    }
    if inputs.independence_incomplete {
        blockers.insert(VerificationBlocker::IncompleteIndependenceProof);
    }
    if policy
        .required_natures
        .iter()
        .any(|required| !inputs.present_natures.contains(required))
    {
        blockers.insert(VerificationBlocker::MissingRequiredEvidenceNature);
    }
    if inputs.has_blocking_defeat {
        blockers.insert(VerificationBlocker::UndefeatedDefeater);
    }

    let epistemic = if inputs.support_count == 0 {
        ClaimState::Candidate
    } else if blockers.is_empty() {
        ClaimState::Verified
    } else {
        ClaimState::Supported
    };

    ClaimAssessment {
        epistemic,
        blockers,
        proven_roots: inputs.proven_roots,
        distinct_resolved_roots: inputs.distinct_resolved_roots,
        independence_incomplete: inputs.independence_incomplete,
        unresolved_support: inputs.unresolved_support,
        proof_environment_count: 0,
        proof_incomplete: false,
    }
}

/// Resolve canonical root node ids for diagnostic accounting only.
///
/// Verification strength never depends on this helper; promotion is delegated to
/// `EvidenceAncestryGraph::proven_independent_route_count`. Keeping the diagnostic
/// traversal separate prevents source-family labels from becoming a proof authority.
fn diagnostic_root_ids(
    graph: &EvidenceAncestryGraph,
    id: &EvidenceNodeId,
) -> Result<BTreeSet<EvidenceNodeId>, AncestryError> {
    let mut roots = BTreeSet::new();
    let mut done = BTreeSet::new();
    let mut on_path = BTreeSet::new();
    let mut stack = vec![(id.clone(), false)];

    while let Some((current, expanded)) = stack.pop() {
        if expanded {
            on_path.remove(&current);
            done.insert(current);
            continue;
        }
        if done.contains(&current) {
            continue;
        }
        if !on_path.insert(current.clone()) {
            return Err(AncestryError::Cycle(current));
        }

        let node = graph
            .get(&current)
            .ok_or_else(|| AncestryError::MissingNode(current.clone()))?;
        stack.push((current.clone(), true));
        if node.parents.is_empty() {
            roots.insert(current);
            continue;
        }
        for parent in node.parents.iter().rev() {
            if on_path.contains(parent) {
                return Err(AncestryError::Cycle(parent.clone()));
            }
            if !done.contains(parent) {
                stack.push((parent.clone(), false));
            }
        }
    }

    Ok(roots)
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

        let compatibility_root_count = proven_roots.len();
        Ok(finish_assessment(
            policy,
            &AssessmentInputs {
                support_count: claim.support.len(),
                proven_roots: compatibility_root_count,
                distinct_resolved_roots: compatibility_root_count,
                independence_incomplete: false,
                unresolved_support,
                present_natures: &present_natures,
                has_blocking_defeat: !claim.contradictions.is_empty()
                    || claim.defeats.iter().any(defeat_blocks_verification),
                ancestry_authority: AncestryAuthority::Compatibility,
            },
        ))
    }

    /// Evaluates one claim using [`EvidenceAncestryGraph`] as the sole verification
    /// authority for ancestry and source independence. The binding map is only a
    /// projection from ledger evidence ids to graph nodes; legacy `source_id`,
    /// `origin_id`, cached family labels, provider counts, and conclusion confidence
    /// cannot satisfy multi-route corroboration in this path.
    ///
    /// A missing binding, missing graph node, missing parent, cycle, or empty root
    /// result is unresolved ancestry. Bounded independence-search exhaustion is
    /// represented explicitly and always blocks `Verified`.
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

        let mut resolved_root_ids = BTreeSet::new();
        let mut resolved_support_nodes = Vec::new();
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

            let Some(node_id) = bindings.get(evidence_id) else {
                unresolved_support += 1;
                continue;
            };

            match diagnostic_root_ids(graph, node_id) {
                Ok(roots) if !roots.is_empty() => {
                    resolved_root_ids.extend(roots);
                    resolved_support_nodes.push(node_id.clone());
                }
                _ => unresolved_support += 1,
            }
        }

        let route_count = graph
            .proven_independent_route_count(
                resolved_support_nodes.iter(),
                policy.min_proven_roots,
                MAX_INDEPENDENCE_SEARCH_STATES,
            )
            .unwrap_or(crate::evidence_ancestry::IndependenceRouteCount {
                proven: 0,
                incomplete: true,
            });

        Ok(finish_assessment(
            policy,
            &AssessmentInputs {
                support_count: claim.support.len(),
                proven_roots: route_count.proven,
                distinct_resolved_roots: resolved_root_ids.len(),
                independence_incomplete: route_count.incomplete,
                unresolved_support,
                present_natures: &present_natures,
                has_blocking_defeat: !claim.contradictions.is_empty()
                    || claim.defeats.iter().any(defeat_blocks_verification),
                ancestry_authority: AncestryAuthority::Canonical,
            },
        ))
    }
}
