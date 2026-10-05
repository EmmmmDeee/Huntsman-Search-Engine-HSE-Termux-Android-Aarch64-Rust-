use std::collections::BTreeSet;

use huntsman_recon::confidence::effective_from_ancestry;
use huntsman_recon::evidence_ancestry::{
    EvidenceAncestryGraph, EvidenceAncestryNode, EvidenceNodeId, IndependenceBasis,
    IndependenceEvidence,
};
use huntsman_recon::retrieval_artifact::ArtifactId;

fn root(id: &str, family: &str) -> EvidenceAncestryNode {
    EvidenceAncestryNode {
        id: EvidenceNodeId::from(id),
        source_family: family.to_owned(),
        parents: BTreeSet::new(),
        derived: false,
    }
}

#[test]
fn disjoint_unproven_roots_do_not_boost_confidence() {
    let mut graph = EvidenceAncestryGraph::default();
    graph.insert(root("registry", "company registry")).unwrap();
    graph.insert(root("profile", "profile page")).unwrap();
    let support = [
        EvidenceNodeId::from("registry"),
        EvidenceNodeId::from("profile"),
    ];

    let effective = effective_from_ancestry(0.6, &graph, &support).unwrap();
    assert!(
        (effective - 0.6).abs() < 1e-12,
        "unproven diversity boosted to {effective}"
    );
}

#[test]
fn explicit_independence_can_boost_confidence() {
    let mut graph = EvidenceAncestryGraph::default();
    graph.insert(root("registry", "same label")).unwrap();
    graph.insert(root("profile", "same label")).unwrap();
    graph
        .insert_independence_evidence(IndependenceEvidence {
            left_root: "registry".into(),
            right_root: "profile".into(),
            basis: IndependenceBasis::ExplicitUpstreamProvenance,
            method_id: "fixture:confidence-independence".into(),
            method_version: 1,
            supporting_artifact_ids: BTreeSet::from([ArtifactId::from("sha256:confidence-proof")]),
            observed_at_unix: 1,
        })
        .unwrap();
    let support = [
        EvidenceNodeId::from("registry"),
        EvidenceNodeId::from("profile"),
    ];

    let effective = effective_from_ancestry(0.6, &graph, &support).unwrap();
    assert!(
        effective > 0.7,
        "proven independence did not corroborate: {effective}"
    );
}
