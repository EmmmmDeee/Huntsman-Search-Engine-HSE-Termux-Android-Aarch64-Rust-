//! Evidence-backed, reversible identity-resolution decisions. From refactor overlay feef60a (P3).
//!
//! Provider count and disjoint root labels are not source independence. Automatic
//! identity merge consumes the same explicit, bounded proven-independence authority as
//! claim verification: mirrors remain dependent, disjoint-but-unproven roots remain
//! unknown, and search truncation can only weaken a decision.
//! Any contradiction blocks an automatic merge; support cannot compensate for it.
//! `identity::resolve` stays the deterministic exact-key linker; this is the gate for
//! probabilistic links above it.
//!
//! The merge rule has one authority, [`IdentityResolutionDecision::hold_reasons`]:
//! an automatic merge needs a `Match` state, no contradiction or conflict, a present
//! match probability in `[0, 1]` at or above the policy floor, and at least the policy's
//! required number of mutually proven-independent routes. Anything short of that is a
//! held candidate with every reason stated, never a silent drop.

use serde::{Deserialize, Serialize};

use crate::evidence_ancestry::{
    EvidenceAncestryGraph, EvidenceNodeId, IndependenceRouteCount,
};

const MAX_INDEPENDENCE_SEARCH_STATES: usize = 4_096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionState {
    Match,
    Probable,
    Possible,
    NonMatch,
    Contradicted,
    Unresolved,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IdentityResolutionDecision {
    pub left_entity_uid: String,
    pub right_entity_uid: String,
    pub state: ResolutionState,
    pub probability: Option<f64>,
    /// Ancestry node ids. Independence is proven by the graph, not declared here.
    pub supporting: Vec<EvidenceNodeId>,
    pub contradicting: Vec<EvidenceNodeId>,
    pub temporal_conflict: bool,
    pub geographic_conflict: bool,
    pub decided_at_unix: u64,
}

/// Automatic-merge policy. The field name is retained for serialized/API compatibility;
/// `min_independent_support_families` now means the minimum number of mutually
/// **proven-independent proof routes**, not merely distinct family labels.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct AutoMergePolicy {
    pub min_independent_support_families: usize,
    pub min_match_probability: f64,
}

impl Default for AutoMergePolicy {
    fn default() -> Self {
        Self {
            min_independent_support_families: 2,
            min_match_probability: 0.90,
        }
    }
}

/// Why an automatic merge was withheld. The candidate itself is always kept.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum HoldReason {
    /// The policy floor is NaN, infinite, or outside `[0, 1]`. Kept as text so it
    /// survives JSON. An invalid policy admits nothing.
    InvalidPolicy {
        min_match_probability: String,
    },
    /// Empty or identical entity uids, or an empty evidence node id.
    InvalidCandidate,
    /// No match probability was supplied. Absence is not consent.
    ProbabilityMissing,
    /// NaN, infinite, or outside `[0, 1]`. Kept as text so NaN survives JSON.
    ProbabilityInvalid {
        value: String,
    },
    ProbabilityBelowThreshold {
        value: f64,
        min: f64,
    },
    NotAMatch {
        state: ResolutionState,
    },
    Contradicted {
        count: usize,
    },
    TemporalConflict,
    GeographicConflict,
    /// A supporting node is missing from the ancestry graph or sits on a cycle.
    UnknownAncestry {
        detail: String,
    },
    /// Bounded route search exhausted its state budget. This is non-strengthening.
    IncompleteIndependenceProof,
    InsufficientIndependentFamilies {
        found: usize,
        required: usize,
    },
}

impl IdentityResolutionDecision {
    #[must_use]
    pub fn is_valid(&self) -> bool {
        !self.left_entity_uid.trim().is_empty()
            && !self.right_entity_uid.trim().is_empty()
            && self.left_entity_uid != self.right_entity_uid
            && self
                .probability
                .is_none_or(|p| p.is_finite() && (0.0..=1.0).contains(&p))
            && self
                .supporting
                .iter()
                .chain(&self.contradicting)
                .all(|e| !e.0.trim().is_empty())
    }

    /// Compatibility/diagnostic count of distinct root-family labels. This no longer
    /// authorizes an automatic merge; verification-capable paths use
    /// [`Self::proven_independent_support_routes`].
    #[must_use]
    pub fn independent_support_families(&self, graph: &EvidenceAncestryGraph) -> Option<usize> {
        graph.independent_support_count(&self.supporting).ok()
    }

    /// Conservative lower bound of mutually proven-independent support routes.
    /// Search is bounded and truncation is surfaced explicitly.
    ///
    /// # Errors
    /// Missing nodes, parents, or ancestry cycles fail closed as an error string.
    pub fn proven_independent_support_routes(
        &self,
        graph: &EvidenceAncestryGraph,
        required: usize,
    ) -> Result<IndependenceRouteCount, String> {
        graph
            .proven_independent_route_count(
                &self.supporting,
                required.max(1),
                MAX_INDEPENDENCE_SEARCH_STATES,
            )
            .map_err(|error| error.to_string())
    }

    /// Automatic merge is stricter than "probable". A probable link stays a hypothesis
    /// unless an operator promotes it. Non-compensatory: one contradiction, one conflict,
    /// missing calibrated probability, unknown ancestry, unproven independence, or an
    /// incomplete independence search blocks regardless of support volume.
    #[must_use]
    pub fn allows_automatic_merge(
        &self,
        graph: &EvidenceAncestryGraph,
        policy: AutoMergePolicy,
    ) -> bool {
        self.hold_reasons(graph, policy).is_empty()
    }

    /// Every reason this decision may not merge automatically, in a fixed order.
    /// Empty means auto-merge. The single authority behind
    /// [`Self::allows_automatic_merge`].
    #[must_use]
    pub fn hold_reasons(
        &self,
        graph: &EvidenceAncestryGraph,
        policy: AutoMergePolicy,
    ) -> Vec<HoldReason> {
        let required = policy.min_independent_support_families.max(1);
        let routes = self.proven_independent_support_routes(graph, required);
        self.hold_reasons_with_routes(routes, policy)
    }

    /// Compatibility path for callers that only know a distinct-family count.
    /// A label count can prove at most one route, regardless of how many different
    /// labels it contains. This prevents older callers from manufacturing independence.
    pub(crate) fn hold_reasons_given(
        &self,
        families: Result<usize, String>,
        policy: AutoMergePolicy,
    ) -> Vec<HoldReason> {
        let routes = families.map(|found| IndependenceRouteCount {
            proven: usize::from(found > 0),
            incomplete: false,
        });
        self.hold_reasons_with_routes(routes, policy)
    }

    fn hold_reasons_with_routes(
        &self,
        routes: Result<IndependenceRouteCount, String>,
        policy: AutoMergePolicy,
    ) -> Vec<HoldReason> {
        let mut reasons = Vec::new();
        let floor = policy.min_match_probability;
        let floor_ok = floor.is_finite() && (0.0..=1.0).contains(&floor);
        if !floor_ok {
            reasons.push(HoldReason::InvalidPolicy {
                min_match_probability: floor.to_string(),
            });
        }
        let ids_ok = !self.left_entity_uid.trim().is_empty()
            && !self.right_entity_uid.trim().is_empty()
            && self.left_entity_uid != self.right_entity_uid
            && self
                .supporting
                .iter()
                .chain(&self.contradicting)
                .all(|e| !e.0.trim().is_empty());
        if !ids_ok {
            reasons.push(HoldReason::InvalidCandidate);
        }
        match self.probability {
            None => reasons.push(HoldReason::ProbabilityMissing),
            Some(p) if !(p.is_finite() && (0.0..=1.0).contains(&p)) => {
                reasons.push(HoldReason::ProbabilityInvalid {
                    value: p.to_string(),
                });
            }
            Some(p) if floor_ok && p < floor => {
                reasons.push(HoldReason::ProbabilityBelowThreshold {
                    value: p,
                    min: floor,
                });
            }
            Some(_) => {}
        }
        if self.state != ResolutionState::Match {
            reasons.push(HoldReason::NotAMatch { state: self.state });
        }
        if !self.contradicting.is_empty() {
            reasons.push(HoldReason::Contradicted {
                count: self.contradicting.len(),
            });
        }
        if self.temporal_conflict {
            reasons.push(HoldReason::TemporalConflict);
        }
        if self.geographic_conflict {
            reasons.push(HoldReason::GeographicConflict);
        }
        let required = policy.min_independent_support_families.max(1);
        match routes {
            Err(detail) => reasons.push(HoldReason::UnknownAncestry { detail }),
            Ok(result) => {
                if result.incomplete {
                    reasons.push(HoldReason::IncompleteIndependenceProof);
                }
                if result.proven < required {
                    reasons.push(HoldReason::InsufficientIndependentFamilies {
                        found: result.proven,
                        required,
                    });
                }
            }
        }
        reasons
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::evidence_ancestry::{
        EvidenceAncestryNode, IndependenceBasis, IndependenceEvidence,
    };
    use crate::retrieval_artifact::ArtifactId;

    fn graph() -> EvidenceAncestryGraph {
        let mut g = EvidenceAncestryGraph::default();
        let mut add = |id: &str, family: &str, parents: &[&str]| {
            g.insert(EvidenceAncestryNode {
                id: id.into(),
                source_family: family.into(),
                parents: parents
                    .iter()
                    .copied()
                    .map(EvidenceNodeId::from)
                    .collect::<BTreeSet<_>>(),
                derived: !parents.is_empty(),
            })
            .unwrap();
        };
        add("dump", "adobe 2013", &[]);
        add("mirror-a", "provider-a", &["dump"]);
        add("mirror-b", "provider-b", &["dump"]);
        add("registry", "company registry", &[]);
        add("first-party", "profile page", &[]);
        add("court", "court record", &[]);
        g.insert_independence_evidence(IndependenceEvidence {
            left_root: "registry".into(),
            right_root: "first-party".into(),
            basis: IndependenceBasis::ExplicitUpstreamProvenance,
            method_id: "test:fixture".into(),
            method_version: 1,
            supporting_artifact_ids: [ArtifactId::from("sha256:fixture-proof")]
                .into_iter()
                .collect(),
            observed_at_unix: 1,
        })
        .unwrap();
        g
    }

    fn decision(
        state: ResolutionState,
        supporting: &[&str],
        contradicting: &[&str],
    ) -> IdentityResolutionDecision {
        IdentityResolutionDecision {
            left_entity_uid: "a".into(),
            right_entity_uid: "b".into(),
            state,
            probability: Some(0.99),
            supporting: supporting
                .iter()
                .copied()
                .map(EvidenceNodeId::from)
                .collect(),
            contradicting: contradicting
                .iter()
                .copied()
                .map(EvidenceNodeId::from)
                .collect(),
            temporal_conflict: false,
            geographic_conflict: false,
            decided_at_unix: 1,
        }
    }

    #[test]
    fn two_proven_independent_roots_merge() {
        assert!(
            decision(ResolutionState::Match, &["registry", "first-party"], &[])
                .allows_automatic_merge(&graph(), AutoMergePolicy::default())
        );
    }

    #[test]
    fn disjoint_but_unproven_roots_do_not_merge() {
        assert!(
            !decision(ResolutionState::Match, &["registry", "court"], &[])
                .allows_automatic_merge(&graph(), AutoMergePolicy::default())
        );
    }

    #[test]
    fn missing_probability_never_auto_merges() {
        let mut d = decision(ResolutionState::Match, &["registry", "first-party"], &[]);
        d.probability = None;
        assert!(!d.allows_automatic_merge(&graph(), AutoMergePolicy::default()));
    }

    #[test]
    fn falsify_relabelled_mirrors_do_not_pass_two_source_gate() {
        let d = decision(ResolutionState::Match, &["mirror-a", "mirror-b"], &[]);
        assert_eq!(d.independent_support_families(&graph()), Some(1));
        assert!(!d.allows_automatic_merge(&graph(), AutoMergePolicy::default()));
    }

    #[test]
    fn contradiction_blocks_automatic_merge() {
        let d = decision(
            ResolutionState::Match,
            &["registry", "first-party"],
            &["court"],
        );
        assert!(!d.allows_automatic_merge(&graph(), AutoMergePolicy::default()));
    }

    #[test]
    fn probable_is_not_an_automatic_merge() {
        let d = decision(ResolutionState::Probable, &["registry", "first-party"], &[]);
        assert!(!d.allows_automatic_merge(&graph(), AutoMergePolicy::default()));
    }

    #[test]
    fn unknown_ancestry_or_zero_policy_fails_closed() {
        let d = decision(ResolutionState::Match, &["registry", "not-in-graph"], &[]);
        assert_eq!(d.independent_support_families(&graph()), None);
        assert!(!d.allows_automatic_merge(&graph(), AutoMergePolicy::default()));
        let none = decision(ResolutionState::Match, &[], &[]);
        let lax = AutoMergePolicy {
            min_independent_support_families: 0,
            min_match_probability: 0.0,
        };
        assert!(
            !none.allows_automatic_merge(&graph(), lax),
            "zero support never merges"
        );
    }

    #[test]
    fn hold_reasons_state_every_failure_in_order() {
        let mut d = decision(
            ResolutionState::Probable,
            &["mirror-a", "mirror-b"],
            &["court"],
        );
        d.probability = None;
        d.temporal_conflict = true;
        assert_eq!(
            d.hold_reasons(&graph(), AutoMergePolicy::default()),
            [
                HoldReason::ProbabilityMissing,
                HoldReason::NotAMatch {
                    state: ResolutionState::Probable
                },
                HoldReason::Contradicted { count: 1 },
                HoldReason::TemporalConflict,
                HoldReason::InsufficientIndependentFamilies {
                    found: 1,
                    required: 2
                },
            ]
        );
        let ok = decision(ResolutionState::Match, &["registry", "first-party"], &[]);
        assert_eq!(
            ok.hold_reasons(&graph(), AutoMergePolicy::default()),
            Vec::<HoldReason>::new()
        );
    }

    #[test]
    fn nan_infinite_and_out_of_range_probabilities_hold_with_their_value() {
        for (p, text) in [
            (f64::NAN, "NaN"),
            (f64::INFINITY, "inf"),
            (1.5, "1.5"),
            (-0.1, "-0.1"),
        ] {
            let mut d = decision(ResolutionState::Match, &["registry", "first-party"], &[]);
            d.probability = Some(p);
            let reasons = d.hold_reasons(&graph(), AutoMergePolicy::default());
            assert_eq!(
                reasons,
                [HoldReason::ProbabilityInvalid { value: text.into() }]
            );
            let json = serde_json::to_string(&reasons).unwrap();
            assert_eq!(
                serde_json::from_str::<Vec<HoldReason>>(&json).unwrap(),
                reasons
            );
        }
    }

    #[test]
    fn invalid_policy_floor_admits_nothing_and_round_trips() {
        let d = decision(ResolutionState::Match, &["registry", "first-party"], &[]);
        for (floor, text) in [
            (f64::NAN, "NaN"),
            (f64::INFINITY, "inf"),
            (1.5, "1.5"),
            (-0.1, "-0.1"),
        ] {
            let policy = AutoMergePolicy {
                min_match_probability: floor,
                ..AutoMergePolicy::default()
            };
            let reasons = d.hold_reasons(&graph(), policy);
            assert_eq!(
                reasons,
                [HoldReason::InvalidPolicy {
                    min_match_probability: text.into()
                }]
            );
            let json = serde_json::to_string(&reasons).unwrap();
            assert_eq!(
                serde_json::from_str::<Vec<HoldReason>>(&json).unwrap(),
                reasons
            );
        }
    }

    /// Case table ported from `feat/authorized-active-probe` (9f1cef87, d22cefa2:
    /// `tests/identity_resolution_adversarial.rs`), asserted directly on the merge rule
    /// instead of through that branch's `identity_benchmark` harness.
    #[test]
    fn adversarial_cases_from_active_probe_branch() {
        let case = |state, p: Option<f64>, support: &[&str], against: &[&str]| {
            let mut d = decision(state, support, against);
            d.probability = p;
            d.allows_automatic_merge(&graph(), AutoMergePolicy::default())
        };
        let m = ResolutionState::Match;
        let strong = ["registry", "first-party"];
        assert!(
            case(m, Some(0.99), &strong, &[]),
            "strong proven-independent match"
        );
        assert!(!case(m, None, &strong, &[]), "missing probability");
        assert!(
            !case(m, Some(0.99), &["mirror-a", "mirror-b"], &[]),
            "mirrors"
        );
        assert!(!case(m, Some(0.999), &strong, &["court"]), "contradiction");
        assert!(
            !case(ResolutionState::Probable, Some(0.99), &strong, &[]),
            "probable"
        );
        assert!(!case(m, Some(0.89), &strong, &[]), "below threshold");
    }

    #[test]
    fn invalid_probability_or_self_link_is_rejected() {
        let mut d = decision(ResolutionState::Match, &["registry", "first-party"], &[]);
        d.probability = Some(f64::NAN);
        assert!(!d.allows_automatic_merge(&graph(), AutoMergePolicy::default()));
        d.probability = Some(0.99);
        d.right_entity_uid = "a".into();
        assert!(!d.is_valid());
    }
}
