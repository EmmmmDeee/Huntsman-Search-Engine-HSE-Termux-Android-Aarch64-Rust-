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
        method_id: "fixture:upstream-provenance".to_owned(),
        method_version: 1,
        supporting_artifact_ids: BTreeSet::from([ArtifactId::from("sha256:fixture")]),
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
fn shared_root_is_known_dependent_even_if_leaf_labels_differ() {
    let mut graph = EvidenceAncestryGraph::default();
    graph.insert(node("root", "origin", &[], false)).unwrap();
    graph
        .insert(node("left", "provider-a", &["root"], true))
        .unwrap();
    graph
        .insert(node("right", "provider-b", &["root"], true))
        .unwrap();

    assert_eq!(
        graph
            .independence_state(&"left".into(), &"right".into())
            .unwrap(),
        IndependenceState::KnownDependent
    );
}

#[test]
fn explicit_valid_independence_is_symmetric_and_label_agnostic() {
    let mut graph = EvidenceAncestryGraph::default();
    graph.insert(node("a", "registry", &[], false)).unwrap();
    graph.insert(node("b", "registry", &[], false)).unwrap();
    graph
        .insert_independence_evidence(evidence("b", "a"))
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
fn unknown_other_versioned_rule_fails_closed() {
    let mut graph = EvidenceAncestryGraph::default();
    graph.insert(node("a", "registry", &[], false)).unwrap();
    graph.insert(node("b", "court-record", &[], false)).unwrap();

    let mut candidate = evidence("a", "b");
    candidate.basis = IndependenceBasis::OtherVersionedRule("future-rule".to_owned());
    graph.insert_independence_evidence(candidate).unwrap();

    assert_eq!(
        graph.independence_state(&"a".into(), &"b".into()).unwrap(),
        IndependenceState::Unknown
    );
}

#[test]
fn invalid_independence_evidence_is_rejected() {
    let mut graph = EvidenceAncestryGraph::default();
    graph.insert(node("a", "registry", &[], false)).unwrap();
    graph.insert(node("b", "court-record", &[], false)).unwrap();
    graph.insert(node("derived", "copy", &["a"], true)).unwrap();

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
    empty_method.method_id = "  ".to_owned();
    assert!(graph.insert_independence_evidence(empty_method).is_err());

    let mut zero_version = evidence("a", "b");
    zero_version.method_version = 0;
    assert!(graph.insert_independence_evidence(zero_version).is_err());

    let mut no_artifact = evidence("a", "b");
    no_artifact.supporting_artifact_ids.clear();
    assert!(graph.insert_independence_evidence(no_artifact).is_err());

    let mut blank_artifact = evidence("a", "b");
    blank_artifact.supporting_artifact_ids = BTreeSet::from([ArtifactId::from("  ")]);
    assert!(graph.insert_independence_evidence(blank_artifact).is_err());

    let mut blank_rule = evidence("a", "b");
    blank_rule.basis = IndependenceBasis::OtherVersionedRule("  ".to_owned());
    assert!(graph.insert_independence_evidence(blank_rule).is_err());
}

#[test]
fn conflicting_duplicate_independence_evidence_is_rejected_but_identical_is_idempotent() {
    let mut graph = EvidenceAncestryGraph::default();
    graph.insert(node("a", "registry", &[], false)).unwrap();
    graph.insert(node("b", "court-record", &[], false)).unwrap();

    let first = evidence("a", "b");
    graph.insert_independence_evidence(first.clone()).unwrap();
    graph.insert_independence_evidence(first).unwrap();

    let mut conflicting = evidence("b", "a");
    conflicting.method_version = 2;
    assert!(graph.insert_independence_evidence(conflicting).is_err());
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
    let independence = value
        .get_mut("independence")
        .and_then(serde_json::Value::as_object_mut)
        .expect("serialized independence map");
    let original_key = independence.keys().next().cloned().unwrap();
    let record = independence.remove(&original_key).unwrap();
    independence.insert("tampered-key".to_owned(), record);

    assert!(serde_json::from_value::<EvidenceAncestryGraph>(value).is_err());
}
