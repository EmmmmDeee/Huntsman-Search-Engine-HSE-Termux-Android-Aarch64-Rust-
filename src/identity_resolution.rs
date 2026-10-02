//! Evidence-backed, reversible identity-resolution decisions. From refactor overlay feef60a (P3).
//!
//! Support is counted in independent root families from `evidence_ancestry`, never in
//! caller-supplied labels: two mirrors of one dump are one source however they are named.
//! Any contradiction blocks an automatic merge; support cannot compensate for it.
//! `identity::resolve` stays the deterministic exact-key linker; this is the gate for
//! probabilistic links above it.

use serde::{Deserialize, Serialize};

use crate::evidence_ancestry::{EvidenceAncestryGraph, EvidenceNodeId};

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
    /// Ancestry node ids. Families are derived from the graph, not declared here.
    pub supporting: Vec<EvidenceNodeId>,
    pub contradicting: Vec<EvidenceNodeId>,
    pub temporal_conflict: bool,
    pub geographic_conflict: bool,
    pub decided_at_unix: u64,
}

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

    /// Independent root families behind the support. `None` when any supporting
    /// node is missing or sits on a cycle: unknown ancestry is not independence.
    #[must_use]
    pub fn independent_support_families(&self, graph: &EvidenceAncestryGraph) -> Option<usize> {
        graph.independent_support_count(&self.supporting).ok()
    }

    /// Automatic merge is stricter than "probable". A probable link stays a hypothesis
    /// unless an operator promotes it. Non-compensatory: one contradiction, one conflict,
    /// missing calibrated probability, or unknown ancestry blocks regardless of support count.
    #[must_use]
    pub fn allows_automatic_merge(
        &self,
        graph: &EvidenceAncestryGraph,
        policy: AutoMergePolicy,
    ) -> bool {
        self.is_valid()
            && self.state == ResolutionState::Match
            && self.contradicting.is_empty()
            && !self.temporal_conflict
            && !self.geographic_conflict
            && self
                .probability
                .is_some_and(|p| p >= policy.min_match_probability)
            && self
                .independent_support_families(graph)
                .is_some_and(|n| n >= policy.min_independent_support_families.max(1))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::evidence_ancestry::EvidenceAncestryNode;

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
    fn two_independent_roots_merge() {
        assert!(
            decision(ResolutionState::Match, &["registry", "first-party"], &[])
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
    fn invalid_probability_or_self_link_is_rejected() {
        let mut d = decision(ResolutionState::Match, &["registry", "first-party"], &[]);
        d.probability = Some(f64::NAN);
        assert!(!d.allows_automatic_merge(&graph(), AutoMergePolicy::default()));
        d.probability = Some(0.99);
        d.right_entity_uid = "a".into();
        assert!(!d.is_valid());
    }
}
