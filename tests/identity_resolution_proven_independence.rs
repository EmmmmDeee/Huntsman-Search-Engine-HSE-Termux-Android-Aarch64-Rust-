use std::collections::BTreeSet;

use huntsman_recon::evidence_ancestry::{
    EvidenceAncestryGraph, EvidenceAncestryNode, EvidenceNodeId, IndependenceBasis,
    IndependenceEvidence,
};
use huntsman_recon::identity_resolution::{
    AutoMergePolicy, HoldReason, IdentityResolutionDecision, ResolutionState,
};
use huntsman_recon::retrieval_artifact::ArtifactId;

fn root(id: &str) -> EvidenceAncestryNode {
    EvidenceAncestryNode {
        id: id.into(),
        source_family: id.to_owned(),
        parents: BTreeSet::new(),
        derived: false,
    }
}

fn decision(supporting: &[&str]) -> IdentityResolutionDecision {
    IdentityResolutionDecision {
        left_entity_uid: "subject:a".into(),
        right_entity_uid: "profile:b".into(),
        state: ResolutionState::Match,
        probability: Some(0.99),
        supporting: supporting
            .iter()
            .copied()
            .map(EvidenceNodeId::from)
            .collect(),
        contradicting: Vec::new(),
        temporal_conflict: false,
        geographic_conflict: false,
        decided_at_unix: 1_790_000_000,
    }
}

fn independence(left: &str, right: &str) -> IndependenceEvidence {
    IndependenceEvidence {
        left_root: left.into(),
        right_root: right.into(),
        basis: IndependenceBasis::ExplicitUpstreamProvenance,
        method_id: "test:explicit-upstream".into(),
        method_version: 1,
        supporting_artifact_ids: [ArtifactId::from("sha256:proof")].into_iter().collect(),
        observed_at_unix: 1_790_000_000,
    }
}

#[test]
fn disjoint_labels_without_proof_do_not_auto_merge() {
    let mut graph = EvidenceAncestryGraph::default();
    graph.insert(root("registry-a")).unwrap();
    graph.insert(root("registry-b")).unwrap();
    let d = decision(&["registry-a", "registry-b"]);

    assert!(!d.allows_automatic_merge(&graph, AutoMergePolicy::default()));
    assert_eq!(
        d.hold_reasons(&graph, AutoMergePolicy::default()),
        [HoldReason::InsufficientIndependentFamilies {
            found: 1,
            required: 2,
        }]
    );
}

#[test]
fn explicit_independence_can_unlock_auto_merge() {
    let mut graph = EvidenceAncestryGraph::default();
    graph.insert(root("registry-a")).unwrap();
    graph.insert(root("registry-b")).unwrap();
    graph
        .insert_independence_evidence(independence("registry-a", "registry-b"))
        .unwrap();
    let d = decision(&["registry-a", "registry-b"]);

    assert!(d.allows_automatic_merge(&graph, AutoMergePolicy::default()));
    assert!(
        d.hold_reasons(&graph, AutoMergePolicy::default())
            .is_empty()
    );
}

#[test]
fn bounded_independence_search_never_strengthens_auto_merge() {
    let mut graph = EvidenceAncestryGraph::default();
    let ids: Vec<String> = (0..100).map(|index| format!("root-{index}")).collect();
    for id in &ids {
        graph.insert(root(id)).unwrap();
    }
    let refs: Vec<&str> = ids.iter().map(String::as_str).collect();
    let d = decision(&refs);

    assert!(!d.allows_automatic_merge(&graph, AutoMergePolicy::default()));
    assert!(
        d.hold_reasons(&graph, AutoMergePolicy::default())
            .iter()
            .any(|reason| matches!(reason, HoldReason::IncompleteIndependenceProof))
    );
}
