use std::collections::BTreeSet;

use huntsman_recon::confidence::effective_from_ancestry;
use huntsman_recon::evidence_ancestry::{
    EvidenceAncestryGraph, EvidenceAncestryNode, EvidenceNodeId, IndependenceBasis,
    IndependenceEvidence,
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

fn independence(left: &str, right: &str) -> IndependenceEvidence {
    IndependenceEvidence {
        left_root: left.into(),
        right_root: right.into(),
        basis: IndependenceBasis::ExplicitUpstreamProvenance,
        method_id: "test:confidence-provenance".into(),
        method_version: 1,
        supporting_artifact_ids: [ArtifactId::from("sha256:confidence-proof")]
            .into_iter()
            .collect(),
        observed_at_unix: 1,
    }
}

#[test]
fn disjoint_unproven_roots_do_not_boost_confidence() {
    let mut graph = EvidenceAncestryGraph::default();
    graph.insert(root("a")).unwrap();
    graph.insert(root("b")).unwrap();
    let support = [EvidenceNodeId::from("a"), EvidenceNodeId::from("b")];

    let boosted = effective_from_ancestry(0.6, &graph, &support).unwrap();
    assert!((boosted - 0.6).abs() < 1e-12, "unexpected boost: {boosted}");
}

#[test]
fn explicit_independence_unlocks_confidence_boost() {
    let mut graph = EvidenceAncestryGraph::default();
    graph.insert(root("a")).unwrap();
    graph.insert(root("b")).unwrap();
    graph
        .insert_independence_evidence(independence("a", "b"))
        .unwrap();
    let support = [EvidenceNodeId::from("a"), EvidenceNodeId::from("b")];

    let boosted = effective_from_ancestry(0.6, &graph, &support).unwrap();
    assert!(boosted > 0.7, "proven independence did not boost: {boosted}");
}

#[test]
fn large_unproven_support_set_is_non_strengthening() {
    let mut graph = EvidenceAncestryGraph::default();
    let support: Vec<EvidenceNodeId> = (0..100)
        .map(|index| EvidenceNodeId(format!("root-{index}")))
        .collect();
    for id in &support {
        graph.insert(root(&id.0)).unwrap();
    }

    let boosted = effective_from_ancestry(0.6, &graph, &support).unwrap();
    assert!((boosted - 0.6).abs() < 1e-12, "budget uncertainty boosted: {boosted}");
}
