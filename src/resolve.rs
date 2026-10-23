//! Automatic identity-resolution clustering.

use serde::{Deserialize, Serialize};

use crate::evidence_ancestry::EvidenceAncestryGraph;
use crate::identity_resolution::{AutoMergePolicy, IdentityResolutionDecision};
use crate::union_find::UnionFind;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolutionCluster {
    pub members: Vec<String>,
    pub decision_count: usize,
}

#[must_use]
pub fn automatic_clusters(
    decisions: &[IdentityResolutionDecision],
    graph: &EvidenceAncestryGraph,
    policy: AutoMergePolicy,
) -> Vec<ResolutionCluster> {
    let mut ids = decisions
        .iter()
        .flat_map(|decision| [&decision.left_entity_uid, &decision.right_entity_uid])
        .cloned()
        .collect::<Vec<_>>();
    ids.sort();
    ids.dedup();
    let index = ids
        .iter()
        .enumerate()
        .map(|(i, id)| (id.clone(), i))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut uf = UnionFind::new(ids.len());
    let mut applied = Vec::new();
    for decision in decisions {
        if decision.allows_automatic_merge(graph, policy) {
            let left = index[&decision.left_entity_uid];
            let right = index[&decision.right_entity_uid];
            uf.union(left, right);
            applied.push((left, right));
        }
    }
    let mut counts = std::collections::BTreeMap::<usize, usize>::new();
    for (left, _) in &applied {
        *counts.entry(uf.find(*left)).or_default() += 1;
    }
    uf.groups()
        .into_iter()
        .map(|group| {
            let root = group[0];
            ResolutionCluster {
                members: group.into_iter().map(|idx| ids[idx].clone()).collect(),
                decision_count: counts.get(&uf.find(root)).copied().unwrap_or(0),
            }
        })
        .collect()
}


/** Project adjudicated lineage outcomes into deterministic identity clusters.
 *
 * This read-only projection does not re-evaluate or relax the lineage
 * independence gate. Held-only identities remain visible as singletons.
 */
#[must_use]
pub fn clusters_from_lineage(resolution: &crate::lineage::Resolution) -> Vec<ResolutionCluster> {
    let mut ids = resolution
        .candidates
        .iter()
        .flat_map(|candidate| {
            [
                candidate.decision.left_entity_uid.clone(),
                candidate.decision.right_entity_uid.clone(),
            ]
        })
        .collect::<Vec<_>>();
    ids.sort();
    ids.dedup();
    let index = ids
        .iter()
        .enumerate()
        .map(|(i, id)| (id.clone(), i))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut uf = UnionFind::new(ids.len());
    let mut approved = Vec::new();
    for candidate in &resolution.candidates {
        if !matches!(candidate.outcome, crate::lineage::MergeOutcome::AutoMerge) {
            continue;
        }
        let left = index[&candidate.decision.left_entity_uid];
        let right = index[&candidate.decision.right_entity_uid];
        uf.union(left, right);
        approved.push(left);
    }
    let mut counts = std::collections::BTreeMap::<usize, usize>::new();
    for left in approved {
        *counts.entry(uf.find(left)).or_default() += 1;
    }
    let mut clusters = uf
        .groups()
        .into_iter()
        .map(|group| {
            let root = group[0];
            ResolutionCluster {
                members: group.into_iter().map(|idx| ids[idx].clone()).collect(),
                decision_count: counts.get(&uf.find(root)).copied().unwrap_or(0),
            }
        })
        .collect::<Vec<_>>();
    clusters.sort_by(|a, b| a.members.cmp(&b.members));
    clusters
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence_ancestry::{
        EvidenceAncestryGraph, EvidenceAncestryNode, EvidenceNodeId, IndependenceBasis,
        IndependenceEvidence,
    };
    use crate::identity_resolution::{IdentityResolutionDecision, ResolutionState};
    use crate::retrieval_artifact::ArtifactId;

    fn graph() -> EvidenceAncestryGraph {
        let mut graph = EvidenceAncestryGraph::default();
        graph
            .insert(EvidenceAncestryNode {
                id: "registry".into(),
                source_family: "registry".into(),
                parents: std::collections::BTreeSet::default(),
                derived: false,
            })
            .unwrap();
        graph
            .insert(EvidenceAncestryNode {
                id: "profile".into(),
                source_family: "profile".into(),
                parents: std::collections::BTreeSet::default(),
                derived: false,
            })
            .unwrap();
        graph
            .insert_independence_evidence(IndependenceEvidence {
                left_root: "registry".into(),
                right_root: "profile".into(),
                basis: IndependenceBasis::ExplicitUpstreamProvenance,
                method_id: "resolve:test".into(),
                method_version: 1,
                supporting_artifact_ids: [ArtifactId::from("sha256:resolve-test")]
                    .into_iter()
                    .collect(),
                observed_at_unix: 1,
            })
            .unwrap();
        graph
    }

    fn decision(left: &str, right: &str) -> IdentityResolutionDecision {
        IdentityResolutionDecision {
            left_entity_uid: left.into(),
            right_entity_uid: right.into(),
            state: ResolutionState::Match,
            probability: Some(0.99),
            supporting: vec![
                EvidenceNodeId("registry".into()),
                EvidenceNodeId("profile".into()),
            ],
            contradicting: vec![],
            temporal_conflict: false,
            geographic_conflict: false,
            decided_at_unix: 1,
        }
    }

    #[test]
    fn automatic_matches_cluster() {
        let clusters =
            automatic_clusters(&[decision("a", "b")], &graph(), AutoMergePolicy::default());
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].members, ["a", "b"]);
    }

    #[test]
    fn cluster_order_does_not_depend_on_which_side_a_uid_is_on() {
        for decisions in [
            [decision("d", "a"), decision("b", "c")],
            [decision("a", "d"), decision("b", "c")],
        ] {
            let clusters = automatic_clusters(&decisions, &graph(), AutoMergePolicy::default());
            let members: Vec<_> = clusters.iter().map(|c| c.members.clone()).collect();
            assert_eq!(members, [["a", "d"], ["b", "c"]]);
            assert!(clusters.iter().all(|c| c.decision_count == 1));
        }
    }

    #[test]
    fn lineage_projection_preserves_held_candidates() {
        use crate::lineage::{CandidateOutcome, MergeOutcome, Resolution};
        let accepted = CandidateOutcome {
            decision: decision("b", "a"),
            independent_families: vec![],
            unattributed_support: vec![],
            outcome: MergeOutcome::AutoMerge,
        };
        let held = CandidateOutcome {
            decision: decision("b", "c"),
            independent_families: vec![],
            unattributed_support: vec![],
            outcome: MergeOutcome::Held { reasons: vec![] },
        };
        let resolution = Resolution {
            policy: AutoMergePolicy::default(),
            observations: vec![],
            candidates: vec![held, accepted],
        };
        let clusters = clusters_from_lineage(&resolution);
        assert_eq!(clusters.len(), 2);
        assert_eq!(clusters[0].members, ["a", "b"]);
        assert_eq!(clusters[0].decision_count, 1);
        assert_eq!(clusters[1].members, ["c"]);
        assert_eq!(clusters[1].decision_count, 0);
    }

}
