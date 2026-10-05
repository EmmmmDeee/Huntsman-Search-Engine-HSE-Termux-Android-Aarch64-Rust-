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

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

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
                parents: BTreeSet::default(),
                derived: false,
            })
            .unwrap();
        graph
            .insert(EvidenceAncestryNode {
                id: "profile".into(),
                source_family: "profile".into(),
                parents: BTreeSet::default(),
                derived: false,
            })
            .unwrap();
        graph
            .insert_independence_evidence(IndependenceEvidence {
                left_root: "registry".into(),
                right_root: "profile".into(),
                basis: IndependenceBasis::ExplicitUpstreamProvenance,
                method_id: "fixture:resolver-independence".into(),
                method_version: 1,
                supporting_artifact_ids: BTreeSet::from([ArtifactId::from(
                    "sha256:resolver-proof",
                )]),
                observed_at_unix: 1,
            })
            .unwrap();
        graph
    }

    #[test]
    fn automatic_matches_cluster() {
        let decision = IdentityResolutionDecision {
            left_entity_uid: "a".into(),
            right_entity_uid: "b".into(),
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
        };
        let clusters = automatic_clusters(&[decision], &graph(), AutoMergePolicy::default());
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].members, ["a", "b"]);
    }
}
