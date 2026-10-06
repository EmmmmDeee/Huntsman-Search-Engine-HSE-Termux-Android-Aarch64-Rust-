//! Claim-specific verification policy and shadow assessment.
//!
//! This module is deliberately separate from exploration/confidence scoring.
//! A claim reaches `Verified` here only when every mandatory policy obligation
//! is satisfied by the evidence currently attached to that claim.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::evidence_ancestry::{
    EvidenceAncestryGraph, EvidenceNodeId, IndependenceRouteCount,
};
use crate::intelligence::{
    ClaimId, ClaimState, Defeat, DefeatKind, EvidenceId, EvidenceNature, IntelligenceLedger,
    LedgerError,
};
use crate::proof::ProofEnvironmentSet;

const MAX_INDEPENDENCE_SEARCH_STATES: usize = 4_096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationPolicy {
    pub id: String,
    pub version: u32,
    /// Compatibility field name retained for this migration slice. In the
    /// canonical ancestry path this is the minimum number of *proven independent*
    /// proof routes, not the number of provider/root labels observed.
    pub min_proven_roots: usize,
    pub require_resolved_ancestry: bool,
    pub required_natures: Vec<EvidenceNature>,
    /// Claim-specific semantic obligations. Each key must be observed with at
    /// least one of its explicitly accepted values in attached support evidence.
    /// Empty by default for backwards-compatible policies.
    #[serde(default)]
    pub required_attributes: BTreeMap<String, BTreeSet<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum VerificationBlocker {
    UnknownAncestry,
    CanonicalAncestryRequired,
    MissingRequiredEvidenceNature,
    MissingRequiredEvidenceAttribute,
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
    /// Conservative number of proof routes established under the governing
    /// independence semantics. This is intentionally not raw root cardinality.
    pub proven_roots: usize,
    pub unresolved_support: usize,
    /// Diagnostic cardinality of resolved provenance origins before independence
    /// proof. It can exceed `proven_roots` and cannot itself promote a claim.
    #[serde(default)]
    pub distinct_resolved_roots: usize,
    /// True when the bounded independence search exhausted its budget. Truncation
    /// is non-strengthening and therefore blocks `Verified`.
    #[serde(default)]
    pub independence_incomplete: bool,
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

fn observe_attributes(
    observed: &mut BTreeMap<String, BTreeSet<String>>,
    attributes: &BTreeMap<String, String>,
) {
    for (key, value) in attributes {
        observed
            .entry(key.clone())
            .or_default()
            .insert(value.clone());
    }
}

fn required_attributes_satisfied(
    policy: &VerificationPolicy,
    observed: &BTreeMap<String, BTreeSet<String>>,
) -> bool {
    policy.required_attributes.iter().all(|(key, accepted)| {
        !accepted.is_empty()
            && observed
                .get(key)
                .is_some_and(|values| values.iter().any(|value| accepted.contains(value)))
    })
}

#[allow(clippy::too_many_arguments)]
fn finish_assessment(
    policy: &VerificationPolicy,
    support_empty: bool,
    proven_roots: usize,
    distinct_resolved_roots: usize,
    unresolved_support: usize,
    independence_incomplete: bool,
    present_natures: &[EvidenceNature],
    observed_attributes: &BTreeMap<String, BTreeSet<String>>,
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
    if independence_incomplete {
        blockers.insert(VerificationBlocker::IncompleteIndependenceProof);
    }
    if policy
        .required_natures
        .iter()
        .any(|required| !present_natures.contains(required))
    {
        blockers.insert(VerificationBlocker::MissingRequiredEvidenceNature);
    }
    if !required_attributes_satisfied(policy, observed_attributes) {
        blockers.insert(VerificationBlocker::MissingRequiredEvidenceAttribute);
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
        distinct_resolved_roots,
        independence_incomplete,
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
        let mut observed_attributes = BTreeMap::new();

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
            observe_attributes(&mut observed_attributes, &evidence.attributes);
        }

        Ok(finish_assessment(
            policy,
            claim.support.is_empty(),
            proven_roots.len(),
            proven_roots.len(),
            unresolved_support,
            false,
            &present_natures,
            &observed_attributes,
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
    /// the policy requires resolved ancestry. Multiple resolved roots satisfy a
    /// multi-route policy only when the graph carries explicit evidence proving
    /// the required mutually independent routes. Semantic attribute obligations
    /// are checked independently and cannot be compensated by route volume.
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

        let mut distinct_resolved_roots = BTreeSet::new();
        let mut resolved_nodes = Vec::new();
        let mut unresolved_support = 0usize;
        let mut present_natures = Vec::new();
        let mut observed_attributes = BTreeMap::new();

        for evidence_id in &claim.support {
            let evidence = self
                .evidence
                .get(evidence_id)
                .ok_or_else(|| LedgerError::MissingEvidence(evidence_id.clone()))?;
            if !present_natures.contains(&evidence.nature) {
                present_natures.push(evidence.nature.clone());
            }
            observe_attributes(&mut observed_attributes, &evidence.attributes);

            let Some(node_id) = bindings.get(evidence_id) else {
                unresolved_support += 1;
                continue;
            };
            match graph.root_families(node_id) {
                Ok(roots) if !roots.is_empty() => {
                    distinct_resolved_roots.extend(roots);
                    resolved_nodes.push(node_id.clone());
                }
                _ => unresolved_support += 1,
            }
        }

        let route_count = match graph.proven_independent_route_count(
            resolved_nodes.iter(),
            policy.min_proven_roots,
            MAX_INDEPENDENCE_SEARCH_STATES,
        ) {
            Ok(count) => count,
            Err(_) => IndependenceRouteCount {
                proven: 0,
                incomplete: true,
            },
        };

        Ok(finish_assessment(
            policy,
            claim.support.is_empty(),
            route_count.proven,
            distinct_resolved_roots.len(),
            unresolved_support,
            route_count.incomplete,
            &present_natures,
            &observed_attributes,
            !claim.contradictions.is_empty()
                || claim.defeats.iter().any(defeat_blocks_verification),
            true,
        ))
    }
}
