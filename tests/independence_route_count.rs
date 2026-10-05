use std::collections::BTreeSet;

use huntsman_recon::evidence_ancestry::{
    EvidenceAncestryGraph, EvidenceAncestryNode, EvidenceNodeId, IndependenceBasis,
    IndependenceEvidence, IndependenceRouteCount,
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

fn prove(graph: &mut EvidenceAncestryGraph, left: &str, right: &str) {
    graph
        .insert_independence_evidence(IndependenceEvidence {
            left_root: left.into(),
            right_root: right.into(),
            basis: IndependenceBasis::ExplicitUpstreamProvenance,
            method_id: "fixture:route-proof".to_owned(),
            method_version: 1,
            supporting_artifact_ids: BTreeSet::from([ArtifactId::from("sha256:route-proof")]),
            observed_at_unix: 1,
        })
        .unwrap();
}

fn count(
    graph: &EvidenceAncestryGraph,
    ids: &[EvidenceNodeId],
    required: usize,
    budget: usize,
) -> IndependenceRouteCount {
    graph
        .proven_independent_route_count(ids.iter(), required, budget)
        .unwrap()
}

#[test]
fn two_disjoint_unproven_roots_count_as_one_route() {
    let mut graph = EvidenceAncestryGraph::default();
    graph.insert(node("a", "registry", &[], false)).unwrap();
    graph.insert(node("b", "court", &[], false)).unwrap();

    assert_eq!(
        count(&graph, &["a".into(), "b".into()], 2, 100),
        IndependenceRouteCount {
            proven: 1,
            incomplete: false,
        }
    );
}

#[test]
fn two_explicitly_independent_roots_count_as_two_routes() {
    let mut graph = EvidenceAncestryGraph::default();
    graph.insert(node("a", "registry", &[], false)).unwrap();
    graph.insert(node("b", "court", &[], false)).unwrap();
    prove(&mut graph, "a", "b");

    assert_eq!(
        count(&graph, &["a".into(), "b".into()], 2, 100),
        IndependenceRouteCount {
            proven: 2,
            incomplete: false,
        }
    );
}

#[test]
fn mirror_nodes_over_one_root_count_as_one_route() {
    let mut graph = EvidenceAncestryGraph::default();
    graph.insert(node("root", "origin", &[], false)).unwrap();
    graph
        .insert(node("left", "mirror-a", &["root"], true))
        .unwrap();
    graph
        .insert(node("right", "mirror-b", &["root"], true))
        .unwrap();

    assert_eq!(
        count(&graph, &["left".into(), "right".into()], 2, 100),
        IndependenceRouteCount {
            proven: 1,
            incomplete: false,
        }
    );
}

#[test]
fn three_roots_can_satisfy_two_when_one_proven_pair_exists() {
    let mut graph = EvidenceAncestryGraph::default();
    graph.insert(node("a", "a", &[], false)).unwrap();
    graph.insert(node("b", "b", &[], false)).unwrap();
    graph.insert(node("c", "c", &[], false)).unwrap();
    prove(&mut graph, "b", "c");

    assert_eq!(
        count(&graph, &["a".into(), "b".into(), "c".into()], 2, 100),
        IndependenceRouteCount {
            proven: 2,
            incomplete: false,
        }
    );
}

#[test]
fn search_budget_exhaustion_is_incomplete_and_never_strengthens() {
    let mut graph = EvidenceAncestryGraph::default();
    graph.insert(node("a", "a", &[], false)).unwrap();
    graph.insert(node("b", "b", &[], false)).unwrap();
    graph.insert(node("c", "c", &[], false)).unwrap();
    prove(&mut graph, "b", "c");
    let ids = ["a".into(), "b".into(), "c".into()];

    assert_eq!(
        count(&graph, &ids, 2, 1),
        IndependenceRouteCount {
            proven: 1,
            incomplete: true,
        }
    );
    assert_eq!(
        count(&graph, &ids, 2, 100),
        IndependenceRouteCount {
            proven: 2,
            incomplete: false,
        }
    );
}

#[test]
fn required_zero_and_one_have_bounded_semantics() {
    let mut graph = EvidenceAncestryGraph::default();
    graph.insert(node("a", "a", &[], false)).unwrap();

    assert_eq!(
        count(&graph, &[], 0, 0),
        IndependenceRouteCount {
            proven: 0,
            incomplete: false,
        }
    );
    assert_eq!(
        count(&graph, &["a".into()], 1, 0),
        IndependenceRouteCount {
            proven: 1,
            incomplete: false,
        }
    );
    assert_eq!(
        count(&graph, &["a".into(), "a".into()], 2, 0),
        IndependenceRouteCount {
            proven: 1,
            incomplete: false,
        }
    );
}
