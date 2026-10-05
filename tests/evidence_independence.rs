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

fn support(id: &str) -> BTreeSet<ArtifactId> {
    [ArtifactId::from(id)].into_iter().collect()
}

fn evidence(left: &str, right: &str) -> IndependenceEvidence {
    IndependenceEvidence {
        left_root: left.into(),
        right_root: right.into(),
        basis: IndependenceBasis::ExplicitUpstreamProvenance,
        method_id: "fixture:explicit-upstream".to_owned(),
        method_version: 1,
        supporting_artifact_ids: support("sha256:fixture"),
        observed_at_unix: 1_700_000_000,
    }
}

#[test]
fn disjoint_root_labels_are_unknown_without_explicit_independence() {
    let mut graph = EvidenceAncestryGraph::default();
    graph.insert(node("a", "registry-a", &[], false)).unwrap();
    graph.insert(node("b", "registry-b", &[], false)).unwrap();

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
        .insert(node("mirror-a", "provider-a", &["root"], true))
        .unwrap();
    graph
        .insert(node("mirror-b", "provider-b", &["root"], true))
        .unwrap();

    assert_eq!(
        graph
            .independence_state(&"mirror-a".into(), &"mirror-b".into())
            .unwrap(),
        IndependenceState::KnownDependent
    );
}

#[test]
fn explicit_valid_independence_is_symmetric() {
    let mut graph = EvidenceAncestryGraph::default();
    graph.insert(node("a", "registry-a", &[], false)).unwrap();
    graph.insert(node("b", "registry-b", &[], false)).unwrap();
    graph.insert_independence_evidence(evidence("a", "b")).unwrap();

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
    graph.insert(node("a", "registry-a", &[], false)).unwrap();
    graph.insert(node("b", "registry-b", &[], false)).unwrap();
    graph.insert(node("derived", "copy", &["a"], true)).unwrap();

    assert!(graph.insert_independence_evidence(evidence("a", "a")).is_err());
    assert!(graph.insert_independence_evidence(evidence("a", "missing")).is_err());
    assert!(graph.insert_independence_evidence(evidence("a", "derived")).is_err());

    let mut blank_method = evidence("a", "b");
    blank_method.method_id = "   ".to_owned();
    assert!(graph.insert_independence_evidence(blank_method).is_err());

    let mut zero_version = evidence("a", "b");
    zero_version.method_version = 0;
    assert!(graph.insert_independence_evidence(zero_version).is_err());

    let mut no_artifact = evidence("a", "b");
    no_artifact.supporting_artifact_ids.clear();
    assert!(graph.insert_independence_evidence(no_artifact).is_err());

    let mut blank_artifact = evidence("a", "b");
    blank_artifact.supporting_artifact_ids = support("   ");
    assert!(graph.insert_independence_evidence(blank_artifact).is_err());
}

#[test]
fn deserialization_cannot_bypass_independence_validation() {
    let invalid = r#"{
        "nodes": {
            "a": {"id":"a","source_family":"registry-a","parents":[],"derived":false},
            "b": {"id":"b","source_family":"registry-b","parents":[],"derived":false}
        },
        "independence_evidence": {
            "a": {
                "b": {
                    "left_root":"a",
                    "right_root":"b",
                    "basis":"ExplicitUpstreamProvenance",
                    "method_id":"",
                    "method_version":1,
                    "supporting_artifact_ids":["sha256:fixture"],
                    "observed_at_unix":1700000000
                }
            }
        }
    }"#;
    assert!(serde_json::from_str::<EvidenceAncestryGraph>(invalid).is_err());

    let mut graph = EvidenceAncestryGraph::default();
    graph.insert(node("a", "registry-a", &[], false)).unwrap();
    graph.insert(node("b", "registry-b", &[], false)).unwrap();
    graph.insert_independence_evidence(evidence("a", "b")).unwrap();
    let json = serde_json::to_string(&graph).unwrap();
    let round_trip: EvidenceAncestryGraph = serde_json::from_str(&json).unwrap();
    assert_eq!(round_trip, graph);
}
