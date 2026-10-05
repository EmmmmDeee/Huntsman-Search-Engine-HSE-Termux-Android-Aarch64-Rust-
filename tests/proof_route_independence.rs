use std::collections::BTreeSet;

use huntsman_recon::evidence_ancestry::{
    AncestryError, EvidenceAncestryGraph, EvidenceAncestryNode, EvidenceNodeId,
    IndependenceBasis, IndependenceEvidence, IndependenceEvidenceSet, IndependenceState,
    METHOD_EXPLICIT_UPSTREAM_PROVENANCE_V1, MAX_PROOF_ROUTE_ROOTS,
};

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
        supporting_artifact_ids: BTreeSet::from([format!("artifact:{left}:{right}")]),
        observed_at_unix: 1,
    }
}

#[test]
fn shared_root_is_known_dependent() {
    let mut graph = EvidenceAncestryGraph::default();
    graph.insert(node("root", "one", &[])).unwrap();
    graph.insert(node("a", "relay-a", &["root"])).unwrap();
    graph.insert(node("b", "relay-b", &["root"])).unwrap();

    assert_eq!(
        graph
            .proof_route_relationship(
                &EvidenceNodeId::from("a"),
                &EvidenceNodeId::from("b"),
                &IndependenceEvidenceSet::default(),
            )
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
            .proof_route_relationship(
                &EvidenceNodeId::from("a"),
                &EvidenceNodeId::from("b"),
                &IndependenceEvidenceSet::default(),
            )
            .unwrap(),
        IndependenceState::Unknown
    );
}

#[test]
fn exact_admissible_pair_proves_independence_but_other_pair_does_not() {
    let mut graph = EvidenceAncestryGraph::default();
    for id in ["a", "b", "c"] {
        graph.insert(node(id, id, &[])).unwrap();
    }
    let mut independence = IndependenceEvidenceSet::default();
    independence.insert(&graph, proof("a", "b")).unwrap();

    assert_eq!(
        graph
            .proof_route_relationship(
                &EvidenceNodeId::from("a"),
                &EvidenceNodeId::from("b"),
                &independence,
            )
            .unwrap(),
        IndependenceState::ProvenIndependent
    );
    assert_eq!(
        graph
            .proof_route_relationship(
                &EvidenceNodeId::from("a"),
                &EvidenceNodeId::from("c"),
                &independence,
            )
            .unwrap(),
        IndependenceState::Unknown
    );
}

#[test]
fn unknown_method_version_fails_closed() {
    let mut graph = EvidenceAncestryGraph::default();
    graph.insert(node("a", "a", &[])).unwrap();
    graph.insert(node("b", "b", &[])).unwrap();
    let mut invalid = proof("a", "b");
    invalid.method_version = 99;

    let mut independence = IndependenceEvidenceSet::default();
    assert!(independence.insert(&graph, invalid).is_err());
    assert_eq!(
        graph
            .proof_route_relationship(
                &EvidenceNodeId::from("a"),
                &EvidenceNodeId::from("b"),
                &independence,
            )
            .unwrap(),
        IndependenceState::Unknown
    );
}

#[test]
fn missing_parent_and_cycle_never_become_independent() {
    let mut graph = EvidenceAncestryGraph::default();
    graph.insert(node("good", "good", &[])).unwrap();
    graph.insert(node("orphan", "copy", &["ghost"])).unwrap();
    assert!(matches!(
        graph.proof_route_relationship(
            &EvidenceNodeId::from("good"),
            &EvidenceNodeId::from("orphan"),
            &IndependenceEvidenceSet::default(),
        ),
        Err(AncestryError::MissingNode(_))
    ));

    let mut cyclic = EvidenceAncestryGraph::default();
    cyclic.insert(node("x", "x", &["y"])).unwrap();
    cyclic.insert(node("y", "y", &["x"])).unwrap();
    cyclic.insert(node("z", "z", &[])).unwrap();
    assert!(matches!(
        cyclic.proof_route_relationship(
            &EvidenceNodeId::from("x"),
            &EvidenceNodeId::from("z"),
            &IndependenceEvidenceSet::default(),
        ),
        Err(AncestryError::Cycle(_))
    ));
}

#[test]
fn proven_route_count_requires_a_fully_proven_clique() {
    let mut graph = EvidenceAncestryGraph::default();
    for id in ["a", "b", "c"] {
        graph.insert(node(id, id, &[])).unwrap();
    }
    let ids = [
        EvidenceNodeId::from("a"),
        EvidenceNodeId::from("b"),
        EvidenceNodeId::from("c"),
    ];

    let mut independence = IndependenceEvidenceSet::default();
    independence.insert(&graph, proof("a", "b")).unwrap();
    assert_eq!(
        graph
            .proven_independent_support_count(ids.iter(), &independence)
            .unwrap(),
        2
    );

    independence.insert(&graph, proof("a", "c")).unwrap();
    independence.insert(&graph, proof("b", "c")).unwrap();
    assert_eq!(
        graph
            .proven_independent_support_count(ids.iter(), &independence)
            .unwrap(),
        3
    );
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
    assert_eq!(
        graph
            .proven_independent_support_count(ids.iter(), &IndependenceEvidenceSet::default())
            .unwrap(),
        1
    );
}

#[test]
fn search_bound_fails_closed_instead_of_returning_partial_count() {
    let mut graph = EvidenceAncestryGraph::default();
    let mut ids = Vec::new();
    for index in 0..=MAX_PROOF_ROUTE_ROOTS {
        let id = format!("root-{index}");
        graph.insert(node(&id, &id, &[])).unwrap();
        ids.push(EvidenceNodeId(id));
    }

    assert!(matches!(
        graph.proven_independent_support_count(ids.iter(), &IndependenceEvidenceSet::default()),
        Err(AncestryError::ProofRouteSearchLimit { .. })
    ));
}
