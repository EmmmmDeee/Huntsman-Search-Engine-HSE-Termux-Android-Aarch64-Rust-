use std::collections::BTreeSet;

use huntsman_recon::evidence_ancestry::{
    EvidenceAncestryGraph, EvidenceAncestryNode, EvidenceNodeId, IndependenceBasis,
    IndependenceEvidence, IndependenceState,
};
use huntsman_recon::retrieval_artifact::ArtifactId;

fn node(id: &str, family: &str, parents: &[&str], derived: bool) -> EvidenceAncestryNode {
    EvidenceAncestryNode {
        id: id.into(),
        source_family: family.to_owned(),
        parents: parents.iter().copied().map(EvidenceNodeId::from).collect(),
        derived,
    }
}

fn evidence(left: &str, right: &str) -> IndependenceEvidence {
    IndependenceEvidence {
        left_root: left.into(),
        right_root: right.into(),
        basis: IndependenceBasis::ExplicitUpstreamProvenance,
        method_id: "test:explicit-upstream-provenance".to_owned(),
        method_version: 1,
        supporting_artifact_ids: BTreeSet::from([ArtifactId::from("sha256:proof")]),
        observed_at_unix: 1,
    }
}

#[test]
fn disjoint_root_labels_are_unknown_without_explicit_independence() {
    let mut graph = EvidenceAncestryGraph::default();
    graph.insert(node("a", "registry", &[], false)).unwrap();
    graph.insert(node("b", "court-record", &[], false)).unwrap();

    assert_eq!(
        graph.independence_state(&"a".into(), &"b".into()).unwrap(),
        IndependenceState::Unknown
    );
}

#[test]
fn shared_root_is_known_dependent_even_if_labels_differ() {
    let mut graph = EvidenceAncestryGraph::default();
    graph.insert(node("root", "primary", &[], false)).unwrap();
    graph
        .insert(node("a", "provider-a", &["root"], true))
        .unwrap();
    graph
        .insert(node("b", "provider-b", &["root"], true))
        .unwrap();

    assert_eq!(
        graph.independence_state(&"a".into(), &"b".into()).unwrap(),
        IndependenceState::KnownDependent
    );
}

#[test]
fn explicit_valid_independence_is_symmetric() {
    let mut graph = EvidenceAncestryGraph::default();
    graph.insert(node("a", "registry", &[], false)).unwrap();
    graph.insert(node("b", "court-record", &[], false)).unwrap();
    graph
        .insert_independence_evidence(evidence("a", "b"))
        .unwrap();

    assert_eq!(
        graph.independence_state(&"a".into(), &"b".into()).unwrap(),
        IndependenceState::ProvenIndependent
    );
    assert_eq!(
        graph.independence_state(&"b".into(), &"a".into()).unwrap(),
        IndependenceState::ProvenIndependent
    );
}

#[test]
fn invalid_independence_evidence_is_rejected() {
    let mut graph = EvidenceAncestryGraph::default();
    graph.insert(node("a", "registry", &[], false)).unwrap();
    graph.insert(node("b", "court-record", &[], false)).unwrap();
    graph
        .insert(node("derived", "mirror", &["a"], true))
        .unwrap();

    assert!(
        graph
            .insert_independence_evidence(evidence("a", "a"))
            .is_err()
    );
    assert!(
        graph
            .insert_independence_evidence(evidence("a", "missing"))
            .is_err()
    );
    assert!(
        graph
            .insert_independence_evidence(evidence("a", "derived"))
            .is_err()
    );

    let mut empty_method = evidence("a", "b");
    empty_method.method_id = "   ".to_owned();
    assert!(graph.insert_independence_evidence(empty_method).is_err());

    let mut zero_version = evidence("a", "b");
    zero_version.method_version = 0;
    assert!(graph.insert_independence_evidence(zero_version).is_err());

    let mut no_artifacts = evidence("a", "b");
    no_artifacts.supporting_artifact_ids.clear();
    assert!(graph.insert_independence_evidence(no_artifacts).is_err());
}

#[test]
fn deserialization_cannot_bypass_independence_validation() {
    let mut graph = EvidenceAncestryGraph::default();
    graph.insert(node("a", "registry", &[], false)).unwrap();
    graph.insert(node("b", "court-record", &[], false)).unwrap();
    graph
        .insert_independence_evidence(evidence("a", "b"))
        .unwrap();

    let mut value = serde_json::to_value(&graph).unwrap();
    value["independence_evidence"][0]["method_version"] = serde_json::json!(0);

    assert!(serde_json::from_value::<EvidenceAncestryGraph>(value).is_err());
}
