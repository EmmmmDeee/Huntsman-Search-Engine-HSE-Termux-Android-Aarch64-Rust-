use std::collections::BTreeSet;

use huntsman_recon::evidence_ancestry::{
    AncestryError, EvidenceAncestryGraph, EvidenceAncestryNode, EvidenceNodeId, IndependenceBasis,
    IndependenceEvidence, IndependenceState, METHOD_EXPLICIT_UPSTREAM_PROVENANCE_V1,
};
use huntsman_recon::retrieval_artifact::ArtifactId;

fn node(id: &str, family: &str, parents: &[&str]) -> EvidenceAncestryNode {
    EvidenceAncestryNode {
        id: EvidenceNodeId::from(id),
        source_family: family.to_owned(),
        parents: parents.iter().copied().map(EvidenceNodeId::from).collect(),
        derived: !parents.is_empty(),
    }
}

fn proof(left: &str, right: &str) -> IndependenceEvidence {
    IndependenceEvidence {
        left_root: EvidenceNodeId::from(left),
        right_root: EvidenceNodeId::from(right),
        basis: IndependenceBasis::ExplicitUpstreamProvenance,
        method_id: METHOD_EXPLICIT_UPSTREAM_PROVENANCE_V1.to_owned(),
        method_version: 1,
        supporting_artifact_ids: BTreeSet::from([ArtifactId::from("sha256:proof")]),
        observed_at_unix: 1,
    }
}

#[test]
fn artifact_id_round_trips_as_transparent_string() {
    let id = ArtifactId::from("sha256:abc");
    let json = serde_json::to_string(&id).unwrap();
    assert_eq!(json, "\"sha256:abc\"");
    assert_eq!(serde_json::from_str::<ArtifactId>(&json).unwrap(), id);
}

#[test]
fn shared_root_is_known_dependent() {
    let mut graph = EvidenceAncestryGraph::default();
    graph.insert(node("root", "one", &[])).unwrap();
    graph.insert(node("a", "relay-a", &["root"])).unwrap();
    graph.insert(node("b", "relay-b", &["root"])).unwrap();

    assert_eq!(
        graph
            .independence_state(&EvidenceNodeId::from("a"), &EvidenceNodeId::from("b"))
            .unwrap(),
        IndependenceState::KnownDependent
    );
}

#[test]
fn disjoint_labels_without_proof_are_unknown() {
    let mut graph = EvidenceAncestryGraph::default();
    graph.insert(node("a", "registry", &[])).unwrap();
    graph.insert(node("b", "court", &[])).unwrap();

    assert_eq!(
        graph
            .independence_state(&EvidenceNodeId::from("a"), &EvidenceNodeId::from("b"))
            .unwrap(),
        IndependenceState::Unknown
    );
}

#[test]
fn exact_admissible_pair_is_symmetric_and_other_pair_stays_unknown() {
    let mut graph = EvidenceAncestryGraph::default();
    for id in ["a", "b", "c"] {
        graph.insert(node(id, id, &[])).unwrap();
    }
    graph.insert_independence_evidence(proof("b", "a")).unwrap();

    assert_eq!(
        graph
            .independence_state(&EvidenceNodeId::from("a"), &EvidenceNodeId::from("b"))
            .unwrap(),
        IndependenceState::ProvenIndependent
    );
    assert_eq!(
        graph
            .independence_state(&EvidenceNodeId::from("b"), &EvidenceNodeId::from("a"))
            .unwrap(),
        IndependenceState::ProvenIndependent
    );
    assert_eq!(
        graph
            .independence_state(&EvidenceNodeId::from("a"), &EvidenceNodeId::from("c"))
            .unwrap(),
        IndependenceState::Unknown
    );
}

#[test]
fn invalid_independence_evidence_is_rejected_and_conflicts_are_not_overwritten() {
    let mut graph = EvidenceAncestryGraph::default();
    graph.insert(node("a", "a", &[])).unwrap();
    graph.insert(node("b", "b", &[])).unwrap();
    graph.insert(node("derived", "relay", &["a"])).unwrap();

    let valid = proof("a", "b");
    graph.insert_independence_evidence(valid.clone()).unwrap();
    graph.insert_independence_evidence(valid).unwrap();

    let mut conflicting = proof("a", "b");
    conflicting.observed_at_unix = 2;
    assert!(graph.insert_independence_evidence(conflicting).is_err());

    for mut invalid in [
        proof("a", "a"),
        proof("a", "missing"),
        proof("a", "derived"),
    ] {
        assert!(graph.insert_independence_evidence(invalid.clone()).is_err());
        invalid.left_root = EvidenceNodeId::from("a");
    }

    let mut empty_method = proof("a", "b");
    empty_method.method_id.clear();
    assert!(graph.insert_independence_evidence(empty_method).is_err());

    let mut unknown_version = proof("a", "b");
    unknown_version.method_version = 99;
    assert!(graph.insert_independence_evidence(unknown_version).is_err());

    let mut no_artifact = proof("a", "b");
    no_artifact.supporting_artifact_ids.clear();
    assert!(graph.insert_independence_evidence(no_artifact).is_err());

    let mut unknown_rule = proof("a", "b");
    unknown_rule.basis = IndependenceBasis::OtherVersionedRule("future-rule".into());
    unknown_rule.method_id = "future-rule".into();
    assert!(graph.insert_independence_evidence(unknown_rule).is_err());
}

#[test]
fn deserialization_revalidates_independence_records() {
    let mut graph = EvidenceAncestryGraph::default();
    graph.insert(node("a", "a", &[])).unwrap();
    graph.insert(node("b", "b", &[])).unwrap();
    graph.insert_independence_evidence(proof("a", "b")).unwrap();

    let mut value = serde_json::to_value(&graph).unwrap();
    value["independence"]["a"]["b"]["method_version"] = serde_json::json!(99);
    assert!(serde_json::from_value::<EvidenceAncestryGraph>(value).is_err());
}

#[test]
fn missing_parent_and_cycle_never_become_independent() {
    let mut graph = EvidenceAncestryGraph::default();
    graph.insert(node("good", "good", &[])).unwrap();
    graph.insert(node("orphan", "copy", &["ghost"])).unwrap();
    assert!(matches!(
        graph.independence_state(
            &EvidenceNodeId::from("good"),
            &EvidenceNodeId::from("orphan")
        ),
        Err(AncestryError::MissingNode(_))
    ));

    let mut cyclic = EvidenceAncestryGraph::default();
    cyclic.insert(node("x", "x", &["y"])).unwrap();
    cyclic.insert(node("y", "y", &["x"])).unwrap();
    cyclic.insert(node("z", "z", &[])).unwrap();
    assert!(matches!(
        cyclic.independence_state(&EvidenceNodeId::from("x"), &EvidenceNodeId::from("z")),
        Err(AncestryError::Cycle(_))
    ));
}

#[test]
fn route_count_is_a_conservative_proven_lower_bound() {
    let mut graph = EvidenceAncestryGraph::default();
    for id in ["a", "b", "c"] {
        graph.insert(node(id, id, &[])).unwrap();
    }
    let ids = [
        EvidenceNodeId::from("a"),
        EvidenceNodeId::from("b"),
        EvidenceNodeId::from("c"),
    ];

    let unproven = graph
        .proven_independent_route_count(ids.iter(), 2, 100)
        .unwrap();
    assert_eq!(unproven.proven, 1);
    assert!(!unproven.incomplete);

    graph.insert_independence_evidence(proof("a", "b")).unwrap();
    let enough_for_two = graph
        .proven_independent_route_count(ids.iter(), 2, 100)
        .unwrap();
    assert_eq!(enough_for_two.proven, 2);
    assert!(!enough_for_two.incomplete);

    let not_enough_for_three = graph
        .proven_independent_route_count(ids.iter(), 3, 100)
        .unwrap();
    assert_eq!(not_enough_for_three.proven, 2);
    assert!(!not_enough_for_three.incomplete);

    graph.insert_independence_evidence(proof("a", "c")).unwrap();
    graph.insert_independence_evidence(proof("b", "c")).unwrap();
    let all_three = graph
        .proven_independent_route_count(ids.iter(), 3, 100)
        .unwrap();
    assert_eq!(all_three.proven, 3);
    assert!(!all_three.incomplete);
}

#[test]
fn copies_do_not_increase_proven_routes() {
    let mut graph = EvidenceAncestryGraph::default();
    graph.insert(node("root", "root", &[])).unwrap();
    for id in ["a", "b", "c"] {
        graph.insert(node(id, id, &["root"])).unwrap();
    }
    let ids = [
        EvidenceNodeId::from("a"),
        EvidenceNodeId::from("b"),
        EvidenceNodeId::from("c"),
    ];
    let count = graph
        .proven_independent_route_count(ids.iter(), 3, 100)
        .unwrap();
    assert_eq!(count.proven, 1);
    assert!(!count.incomplete);
}

#[test]
fn bounded_search_never_strengthens_on_exhaustion() {
    let mut graph = EvidenceAncestryGraph::default();
    for id in ["a", "b", "c"] {
        graph.insert(node(id, id, &[])).unwrap();
    }
    let ids = [
        EvidenceNodeId::from("a"),
        EvidenceNodeId::from("b"),
        EvidenceNodeId::from("c"),
    ];

    let truncated = graph
        .proven_independent_route_count(ids.iter(), 2, 1)
        .unwrap();
    assert_eq!(truncated.proven, 1);
    assert!(truncated.incomplete);

    let zero = graph
        .proven_independent_route_count(ids.iter(), 0, 0)
        .unwrap();
    assert_eq!(zero.proven, 0);
    assert!(!zero.incomplete);

    let one = graph
        .proven_independent_route_count(ids.iter(), 1, 0)
        .unwrap();
    assert_eq!(one.proven, 1);
    assert!(!one.incomplete);
}
