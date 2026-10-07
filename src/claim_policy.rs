//! Claim-specific verification policy and shadow assessment.
//!
//! This module is deliberately separate from exploration/confidence scoring.
//! A claim reaches `Verified` here only when every mandatory policy obligation
//! is satisfied by the evidence currently attached to that claim.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::evidence_ancestry::{EvidenceAncestryGraph, EvidenceNodeId, IndependenceRouteCount};
use crate::intelligence::{
    Claim, ClaimId, ClaimState, Defeat, DefeatKind, EvidenceId, EvidenceNature, IntelligenceLedger,
    LedgerError,
};
use crate::proof::{MinimalProofEnvironment, ProofEnvironmentSet};

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
    InvalidProofEnvironment,
    UnresolvedProofAssumption,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AncestryMode {
    Compatibility,
    Canonical,
}

struct AssessmentInputs<'a> {
    support_count: usize,
    route_count: IndependenceRouteCount,
    distinct_resolved_roots: usize,
    unresolved_support: usize,
    present_natures: &'a [EvidenceNature],
    observed_attributes: &'a BTreeMap<String, BTreeSet<String>>,
    blocking_defeats: usize,
    ancestry_mode: AncestryMode,
}

fn finish_assessment(policy: &VerificationPolicy, input: &AssessmentInputs<'_>) -> ClaimAssessment {
    let mut blockers = BTreeSet::new();
    if policy.require_resolved_ancestry && input.unresolved_support > 0 {
        blockers.insert(VerificationBlocker::UnknownAncestry);
    }
    if input.ancestry_mode != AncestryMode::Canonical {
        blockers.insert(VerificationBlocker::CanonicalAncestryRequired);
    }
    if input.route_count.proven < policy.min_proven_roots {
        blockers.insert(VerificationBlocker::InsufficientIndependentSupport);
    }
    if input.route_count.incomplete {
        blockers.insert(VerificationBlocker::IncompleteIndependenceProof);
    }
    if policy
        .required_natures
        .iter()
        .any(|required| !input.present_natures.contains(required))
    {
        blockers.insert(VerificationBlocker::MissingRequiredEvidenceNature);
    }
    if !required_attributes_satisfied(policy, input.observed_attributes) {
        blockers.insert(VerificationBlocker::MissingRequiredEvidenceAttribute);
    }
    if input.blocking_defeats > 0 {
        blockers.insert(VerificationBlocker::UndefeatedDefeater);
    }

    let epistemic = if input.support_count == 0 {
        ClaimState::Candidate
    } else if blockers.is_empty() {
        ClaimState::Verified
    } else {
        ClaimState::Supported
    };

    ClaimAssessment {
        epistemic,
        blockers,
        proven_roots: input.route_count.proven,
        unresolved_support: input.unresolved_support,
        distinct_resolved_roots: input.distinct_resolved_roots,
        independence_incomplete: input.route_count.incomplete,
        proof_environment_count: 0,
        proof_incomplete: false,
    }
}

#[derive(Debug, Default)]
struct ProofEnvironmentEvaluation {
    malformed: bool,
    structurally_valid: bool,
    routes_sufficient: bool,
    natures_sufficient: bool,
    attributes_sufficient: bool,
    unresolved_assumption: bool,
    incomplete_route_search: bool,
    valid: bool,
}

#[derive(Debug, Default)]
struct ProofEvaluationSummary {
    malformed: bool,
    saw_structurally_valid: bool,
    saw_sufficient_routes: bool,
    saw_sufficient_natures: bool,
    saw_sufficient_attributes: bool,
    saw_unresolved_assumption: bool,
    saw_incomplete_route_search: bool,
    valid_environment: bool,
}

impl ProofEvaluationSummary {
    fn observe(&mut self, evaluation: ProofEnvironmentEvaluation) {
        self.malformed |= evaluation.malformed;
        self.saw_structurally_valid |= evaluation.structurally_valid;
        self.saw_sufficient_routes |= evaluation.routes_sufficient;
        self.saw_sufficient_natures |= evaluation.natures_sufficient;
        self.saw_sufficient_attributes |= evaluation.attributes_sufficient;
        self.saw_unresolved_assumption |= evaluation.unresolved_assumption;
        self.saw_incomplete_route_search |= evaluation.incomplete_route_search;
        self.valid_environment |= evaluation.valid;
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
            &AssessmentInputs {
                support_count: claim.support.len(),
                route_count: IndependenceRouteCount {
                    proven: proven_roots.len(),
                    incomplete: false,
                },
                distinct_resolved_roots: proven_roots.len(),
                unresolved_support,
                present_natures: &present_natures,
                observed_attributes: &observed_attributes,
                blocking_defeats: usize::from(
                    !claim.contradictions.is_empty()
                        || claim.defeats.iter().any(defeat_blocks_verification),
                ),
                ancestry_mode: AncestryMode::Compatibility,
            },
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
            match graph.resolved_root_ids(node_id) {
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
            &AssessmentInputs {
                support_count: claim.support.len(),
                route_count,
                distinct_resolved_roots: distinct_resolved_roots.len(),
                unresolved_support,
                present_natures: &present_natures,
                observed_attributes: &observed_attributes,
                blocking_defeats: usize::from(
                    !claim.contradictions.is_empty()
                        || claim.defeats.iter().any(defeat_blocks_verification),
                ),
                ancestry_mode: AncestryMode::Canonical,
            },
        ))
    }

    /// Evaluates one proof environment against one already-resolved claim.
    fn evaluate_proof_environment(
        &self,
        claim: &Claim,
        environment: &MinimalProofEnvironment,
        policy: &VerificationPolicy,
        graph: &EvidenceAncestryGraph,
        bindings: &BTreeMap<EvidenceId, EvidenceNodeId>,
    ) -> ProofEnvironmentEvaluation {
        if environment.assertions.is_empty() {
            return ProofEnvironmentEvaluation {
                malformed: true,
                ..ProofEnvironmentEvaluation::default()
            };
        }

        let mut canonical_roots = BTreeSet::new();
        let mut resolved_nodes = Vec::new();
        let mut environment_natures = Vec::new();
        let mut environment_attributes = BTreeMap::new();

        for evidence_id in &environment.assertions {
            if !claim.support.contains(evidence_id) {
                return ProofEnvironmentEvaluation {
                    malformed: true,
                    ..ProofEnvironmentEvaluation::default()
                };
            }
            let Some(evidence) = self.evidence.get(evidence_id) else {
                return ProofEnvironmentEvaluation {
                    malformed: true,
                    ..ProofEnvironmentEvaluation::default()
                };
            };
            if !environment_natures.contains(&evidence.nature) {
                environment_natures.push(evidence.nature.clone());
            }
            observe_attributes(&mut environment_attributes, &evidence.attributes);

            let Some(node_id) = bindings.get(evidence_id) else {
                return ProofEnvironmentEvaluation {
                    malformed: true,
                    ..ProofEnvironmentEvaluation::default()
                };
            };
            let Ok(roots) = graph.resolved_root_ids(node_id) else {
                return ProofEnvironmentEvaluation {
                    malformed: true,
                    ..ProofEnvironmentEvaluation::default()
                };
            };
            if roots.is_empty() {
                return ProofEnvironmentEvaluation {
                    malformed: true,
                    ..ProofEnvironmentEvaluation::default()
                };
            }
            canonical_roots.extend(roots.into_iter().map(|root| root.0));
            resolved_nodes.push(node_id.clone());
        }

        if canonical_roots != environment.roots {
            return ProofEnvironmentEvaluation {
                malformed: true,
                ..ProofEnvironmentEvaluation::default()
            };
        }

        let route_count = graph
            .proven_independent_route_count(
                resolved_nodes.iter(),
                policy.min_proven_roots,
                MAX_INDEPENDENCE_SEARCH_STATES,
            )
            .unwrap_or(IndependenceRouteCount {
                proven: 0,
                incomplete: true,
            });
        let routes_sufficient =
            !route_count.incomplete && route_count.proven >= policy.min_proven_roots;
        let natures_sufficient = policy
            .required_natures
            .iter()
            .all(|required| environment_natures.contains(required));
        let attributes_sufficient =
            required_attributes_satisfied(policy, &environment_attributes);
        let unresolved_assumption = !environment.assumptions.is_empty();

        ProofEnvironmentEvaluation {
            malformed: false,
            structurally_valid: true,
            routes_sufficient,
            natures_sufficient,
            attributes_sufficient,
            unresolved_assumption,
            incomplete_route_search: route_count.incomplete,
            valid: !unresolved_assumption
                && routes_sufficient
                && natures_sufficient
                && attributes_sufficient,
        }
    }

    fn apply_proof_blockers(
        assessment: &mut ClaimAssessment,
        summary: &ProofEvaluationSummary,
    ) {
        if summary.malformed {
            assessment
                .blockers
                .insert(VerificationBlocker::InvalidProofEnvironment);
        }
        if summary.saw_unresolved_assumption && !summary.valid_environment {
            assessment
                .blockers
                .insert(VerificationBlocker::UnresolvedProofAssumption);
        }
        if summary.saw_structurally_valid && !summary.saw_sufficient_routes {
            assessment
                .blockers
                .insert(VerificationBlocker::InsufficientIndependentSupport);
        }
        if summary.saw_incomplete_route_search && !summary.valid_environment {
            assessment
                .blockers
                .insert(VerificationBlocker::IncompleteIndependenceProof);
        }
        if summary.saw_structurally_valid && !summary.saw_sufficient_natures {
            assessment
                .blockers
                .insert(VerificationBlocker::MissingRequiredEvidenceNature);
        }
        if summary.saw_structurally_valid && !summary.saw_sufficient_attributes {
            assessment
                .blockers
                .insert(VerificationBlocker::MissingRequiredEvidenceAttribute);
        }
    }

    /// Evaluates a claim through a claim-scoped proof environment.
    ///
    /// This is the strict verification path when proof bookkeeping is available.
    /// Every proof assertion must belong to the claim's support set, every
    /// declared proof root must exactly match the canonical ancestry root id
    /// resolved from those assertions, semantic obligations must be satisfied
    /// inside one sufficient environment, and any required multi-route support
    /// must be explicitly proven independent by the ancestry graph. Unresolved
    /// assumptions, malformed environments, bounded-search truncation, or an
    /// incomplete proof set fail closed.
    ///
    /// `MinimalProofEnvironment::roots` is interpreted here as canonical
    /// `EvidenceNodeId` strings, never provider labels or cached family names.
    ///
    /// # Errors
    /// Returns [`LedgerError::MissingClaim`] or [`LedgerError::MissingEvidence`]
    /// when the ledger itself references absent support records.
    pub fn assess_claim_with_ancestry_and_proof(
        &self,
        claim_id: &ClaimId,
        policy: &VerificationPolicy,
        graph: &EvidenceAncestryGraph,
        bindings: &BTreeMap<EvidenceId, EvidenceNodeId>,
        proof: &ProofEnvironmentSet,
    ) -> Result<ClaimAssessment, LedgerError> {
        let claim = self
            .claims
            .get(claim_id)
            .ok_or_else(|| LedgerError::MissingClaim(claim_id.clone()))?;
        let mut assessment = self.assess_claim_with_ancestry(claim_id, policy, graph, bindings)?;

        assessment.proof_environment_count = proof.environments.len();
        assessment.proof_incomplete = proof.incomplete;
        if proof.incomplete {
            assessment
                .blockers
                .insert(VerificationBlocker::IncompleteProof);
        }
        if proof.environments.is_empty() {
            assessment
                .blockers
                .insert(VerificationBlocker::MissingProofEnvironment);
            assessment.epistemic = if claim.support.is_empty() {
                ClaimState::Candidate
            } else {
                ClaimState::Supported
            };
            return Ok(assessment);
        }

        let mut summary = ProofEvaluationSummary::default();
        for environment in &proof.environments {
            summary.observe(self.evaluate_proof_environment(
                claim,
                environment,
                policy,
                graph,
                bindings,
            ));
        }
        Self::apply_proof_blockers(&mut assessment, &summary);

        assessment.epistemic = if claim.support.is_empty() {
            ClaimState::Candidate
        } else if summary.valid_environment && !summary.malformed && assessment.blockers.is_empty() {
            ClaimState::Verified
        } else {
            ClaimState::Supported
        };
        Ok(assessment)
    }

}
