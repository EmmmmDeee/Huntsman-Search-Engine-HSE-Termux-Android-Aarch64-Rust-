use super::*;
use crate::core::entity::{Entity, EntityKind};
use crate::core::relation::{Relation, RelationKind};

fn ent(name: &str) -> Entity {
    Entity::new(EntityKind::Username, name, 0.6, "graph-scan")
}

fn rel(a: &Entity, b: &Entity) -> Relation {
    Relation::new(
        a.uid.as_str(),
        b.uid.as_str(),
        RelationKind::AssociatedWith,
        0.6,
        "graph-scan",
    )
}

#[test]
fn build_indexes_all_entities_and_collapses_parallel_self_edges() {
    let a = ent("a");
    let b = ent("b");
    let c = ent("c"); // isolated — still a node
    // Two parallel a–b edges and a b self-loop: the parallels collapse, the loop drops.
    let relations = vec![
        rel(&a, &b),
        Relation::new(a.uid.as_str(), b.uid.as_str(), RelationKind::AliasOf, 0.6, "graph-scan"),
        Relation::new(b.uid.as_str(), b.uid.as_str(), RelationKind::AliasOf, 0.6, "graph-scan"),
    ];
    let g = Graph::build(&[a.clone(), b.clone(), c.clone()], &relations);
    assert_eq!(g.node_count(), 3, "every entity is a node, including the isolated one");
    let ai = g.index_of(&a.uid).unwrap();
    let bi = g.index_of(&b.uid).unwrap();
    let ci = g.index_of(&c.uid).unwrap();
    assert_eq!(g.degree(ai), 1, "parallel edges collapse to one neighbour");
    assert_eq!(g.degree(bi), 1, "the self-loop is dropped");
    assert_eq!(g.degree(ci), 0, "an isolated entity has degree 0");
    assert_eq!(g.neighbours(ai), &[bi]);
    assert!(g.index_of("no-such-uid").is_none());
}

#[test]
fn bfs_levels_are_cycle_safe_and_report_unreachable() {
    // A triangle a-b-c (a cycle) plus an isolated d.
    let a = ent("a");
    let b = ent("b");
    let c = ent("c");
    let d = ent("d");
    let relations = vec![rel(&a, &b), rel(&b, &c), rel(&a, &c)];
    let g = Graph::build(&[a.clone(), b.clone(), c.clone(), d.clone()], &relations);
    let src = g.index_of(&a.uid).unwrap();
    let dist = g.bfs_levels(src);
    assert_eq!(dist[src], 0);
    assert_eq!(dist[g.index_of(&b.uid).unwrap()], 1);
    assert_eq!(dist[g.index_of(&c.uid).unwrap()], 1, "the cycle does not inflate the distance");
    assert_eq!(
        dist[g.index_of(&d.uid).unwrap()],
        UNREACHABLE,
        "a different component is unreachable"
    );
}

#[test]
fn build_is_deterministic_under_input_shuffling() {
    let a = ent("a");
    let b = ent("b");
    let c = ent("c");
    let entities = vec![a.clone(), b.clone(), c.clone()];
    let relations = vec![rel(&a, &b), rel(&b, &c)];
    let g1 = Graph::build(&entities, &relations);

    let mut e2 = entities.clone();
    e2.reverse();
    let mut r2 = relations.clone();
    r2.reverse();
    let g2 = Graph::build(&e2, &r2);

    // Identical node order and adjacency regardless of input order.
    assert_eq!(g1.node_count(), g2.node_count());
    for i in 0..g1.node_count() {
        assert_eq!(g1.uid(i), g2.uid(i), "node order is input-independent");
        assert_eq!(g1.neighbours(i), g2.neighbours(i), "adjacency is input-independent");
    }
}

#[test]
fn empty_graph_has_no_nodes() {
    let g = Graph::build(&[], &[]);
    assert!(g.is_empty());
    assert_eq!(g.node_count(), 0);
    assert!(g.bfs_levels(0).is_empty(), "BFS from an out-of-range source is empty, no panic");
}
