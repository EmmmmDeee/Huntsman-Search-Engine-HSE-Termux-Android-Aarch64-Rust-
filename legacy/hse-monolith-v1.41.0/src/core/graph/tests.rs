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
    let ai = g.index_of(&a.uid).expect("should succeed");
    let bi = g.index_of(&b.uid).expect("should succeed");
    let ci = g.index_of(&c.uid).expect("should succeed");
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
    let src = g.index_of(&a.uid).expect("should succeed");
    let dist = g.bfs_levels(src);
    assert_eq!(dist[src], 0);
    assert_eq!(dist[g.index_of(&b.uid).expect("should succeed")], 1);
    assert_eq!(dist[g.index_of(&c.uid).expect("should succeed")], 1, "the cycle does not inflate the distance");
    assert_eq!(
        dist[g.index_of(&d.uid).expect("should succeed")],
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

/// Map a graph's cut structure back to UIDs for readable assertions. Cut vertices and
/// bridge pairs both come out in ascending index order, which is ascending-UID order.
fn cut_uids(g: &Graph) -> (Vec<String>, Vec<(String, String)>) {
    let (cuts, bridges) = g.cut_vertices_and_bridges();
    let cv = cuts.iter().map(|&i| g.uid(i).to_string()).collect();
    let br = bridges
        .iter()
        .map(|&(a, b)| (g.uid(a).to_string(), g.uid(b).to_string()))
        .collect();
    (cv, br)
}

/// A canonical `(min, max)` UID edge for building expected bridge lists.
fn edge(x: &str, y: &str) -> (String, String) {
    if x <= y {
        (x.to_string(), y.to_string())
    } else {
        (y.to_string(), x.to_string())
    }
}

#[test]
fn cut_vertices_and_bridges_on_a_path() {
    // a — b — c — d: the interior nodes are cut vertices; every edge is a bridge.
    let a = ent("a");
    let b = ent("b");
    let c = ent("c");
    let d = ent("d");
    let rels = vec![rel(&a, &b), rel(&b, &c), rel(&c, &d)];
    let g = Graph::build(&[a.clone(), b.clone(), c.clone(), d.clone()], &rels);
    // Results come out in ascending-UID (index) order; sort the expectations the same
    // way, since the entity UIDs are content hashes, not value-ordered.
    let (cuts, bridges) = cut_uids(&g);
    let mut expect_cuts = vec![b.uid.clone(), c.uid.clone()];
    expect_cuts.sort();
    assert_eq!(cuts, expect_cuts, "the interior nodes cut the path");
    let mut expect_bridges = vec![edge(&a.uid, &b.uid), edge(&b.uid, &c.uid), edge(&c.uid, &d.uid)];
    expect_bridges.sort();
    assert_eq!(bridges, expect_bridges, "every edge on a path is a bridge");
}

#[test]
fn a_cycle_has_no_cut_vertices_or_bridges() {
    // A triangle is 2-connected: removing any single node or edge keeps it whole.
    let a = ent("a");
    let b = ent("b");
    let c = ent("c");
    let rels = vec![rel(&a, &b), rel(&b, &c), rel(&a, &c)];
    let g = Graph::build(&[a, b, c], &rels);
    let (cuts, bridges) = g.cut_vertices_and_bridges();
    assert!(cuts.is_empty(), "no node in a cycle is a single point of failure");
    assert!(bridges.is_empty(), "no edge in a cycle is a bridge");
}

#[test]
fn shared_vertex_of_two_triangles_is_the_only_cut_vertex() {
    // Triangle a-b-c and triangle c-d-e share the hinge c.
    let a = ent("a");
    let b = ent("b");
    let c = ent("c");
    let d = ent("d");
    let e = ent("e");
    let rels = vec![
        rel(&a, &b),
        rel(&b, &c),
        rel(&a, &c),
        rel(&c, &d),
        rel(&d, &e),
        rel(&c, &e),
    ];
    let g = Graph::build(&[a, b, c.clone(), d, e], &rels);
    let (cuts, bridges) = cut_uids(&g);
    assert_eq!(cuts, vec![c.uid.clone()], "only the shared hinge fragments the graph");
    assert!(bridges.is_empty(), "each 2-connected lobe contributes no bridge");
}

#[test]
fn cut_structure_is_computed_per_component() {
    // Component 1: path x-y-z (y cuts; both edges bridge). Component 2: isolated w.
    // Component 3: triangle p-q-r (neither cuts nor bridges).
    let x = ent("x");
    let y = ent("y");
    let z = ent("z");
    let w = ent("w");
    let p = ent("p");
    let q = ent("q");
    let r = ent("r");
    let rels = vec![
        rel(&x, &y),
        rel(&y, &z),
        rel(&p, &q),
        rel(&q, &r),
        rel(&p, &r),
    ];
    let g = Graph::build(
        &[x.clone(), y.clone(), z.clone(), w, p, q, r],
        &rels,
    );
    let (cuts, bridges) = cut_uids(&g);
    assert_eq!(cuts, vec![y.uid.clone()], "only the path's interior node cuts");
    let mut expect_bridges = vec![edge(&x.uid, &y.uid), edge(&y.uid, &z.uid)];
    expect_bridges.sort();
    assert_eq!(
        bridges, expect_bridges,
        "only the path's two edges are bridges; the triangle and isolate add none"
    );
}

#[test]
fn cut_structure_is_deterministic_under_input_shuffling() {
    // A path tail a-b-c into a triangle c-d-e: b and c cut, a-b and b-c bridge.
    let a = ent("a");
    let b = ent("b");
    let c = ent("c");
    let d = ent("d");
    let e = ent("e");
    let entities = vec![a.clone(), b.clone(), c.clone(), d.clone(), e.clone()];
    let rels = vec![rel(&a, &b), rel(&b, &c), rel(&c, &d), rel(&d, &e), rel(&c, &e)];
    let g1 = Graph::build(&entities, &rels);
    let r1 = g1.cut_vertices_and_bridges();

    let mut e2 = entities.clone();
    e2.reverse();
    let mut rl2 = rels.clone();
    rl2.reverse();
    let g2 = Graph::build(&e2, &rl2);
    let r2 = g2.cut_vertices_and_bridges();

    assert_eq!(r1, r2, "cut structure is independent of input order");
    let (cuts, bridges) = cut_uids(&g1);
    let mut expect_cuts = vec![b.uid.clone(), c.uid.clone()];
    expect_cuts.sort();
    assert_eq!(cuts, expect_cuts, "b and c are the cut vertices");
    let mut expect_bridges = vec![edge(&a.uid, &b.uid), edge(&b.uid, &c.uid)];
    expect_bridges.sort();
    assert_eq!(bridges, expect_bridges, "the path tail's two edges are the bridges");
}

#[test]
fn empty_graph_has_no_cut_structure() {
    let g = Graph::build(&[], &[]);
    let (cuts, bridges) = g.cut_vertices_and_bridges();
    assert!(cuts.is_empty(), "no nodes ⇒ no cut vertices");
    assert!(bridges.is_empty(), "no edges ⇒ no bridges");
}

/// Coreness keyed by UID, for readable assertions independent of the content-hash
/// node order.
fn coreness_by_uid(g: &Graph) -> std::collections::HashMap<String, usize> {
    let core = g.coreness();
    (0..g.node_count())
        .map(|i| (g.uid(i).to_string(), core[i]))
        .collect()
}

#[test]
fn empty_and_edgeless_graphs_have_zero_degeneracy() {
    let empty = Graph::build(&[], &[]);
    assert!(empty.coreness().is_empty(), "no nodes ⇒ no core numbers");
    assert_eq!(empty.degeneracy(), 0);

    // Two entities, no relation: both isolated, coreness 0, degeneracy 0.
    let g = Graph::build(&[ent("a"), ent("b")], &[]);
    assert_eq!(g.coreness(), vec![0, 0], "an isolated node belongs to no k-core");
    assert_eq!(g.degeneracy(), 0);
}

#[test]
fn a_path_is_one_degenerate() {
    // a — b — c — d: a tree, so every connected node has coreness 1 and the
    // graph degeneracy is 1 (no redundant/cyclic structure anywhere).
    let (a, b, c, d) = (ent("a"), ent("b"), ent("c"), ent("d"));
    let rels = vec![rel(&a, &b), rel(&b, &c), rel(&c, &d)];
    let g = Graph::build(&[a.clone(), b.clone(), c.clone(), d.clone()], &rels);
    let core = coreness_by_uid(&g);
    for u in [&a, &b, &c, &d] {
        assert_eq!(core[&u.uid], 1, "every node of a path sits in the 1-core only");
    }
    assert_eq!(g.degeneracy(), 1, "a path/tree is 1-degenerate");
}

#[test]
fn a_triangle_is_two_degenerate() {
    // A 3-cycle: every node has two neighbours inside the cycle, so the whole
    // triangle is a 2-core and nothing reaches a 3-core.
    let (a, b, c) = (ent("a"), ent("b"), ent("c"));
    let rels = vec![rel(&a, &b), rel(&b, &c), rel(&a, &c)];
    let g = Graph::build(&[a.clone(), b.clone(), c.clone()], &rels);
    let core = coreness_by_uid(&g);
    for u in [&a, &b, &c] {
        assert_eq!(core[&u.uid], 2, "each triangle node is in the 2-core");
    }
    assert_eq!(g.degeneracy(), 2, "a cycle is 2-degenerate");
}

#[test]
fn a_four_clique_is_three_degenerate() {
    // K4: every node is adjacent to the other three, so all four sit in a 3-core —
    // the densest, most redundantly-corroborated structure of this size.
    let nodes: Vec<Entity> = (0..4).map(|i| ent(&format!("k{i}"))).collect();
    let mut rels = Vec::new();
    for i in 0..4 {
        for j in (i + 1)..4 {
            rels.push(rel(&nodes[i], &nodes[j]));
        }
    }
    let g = Graph::build(&nodes, &rels);
    let core = coreness_by_uid(&g);
    for u in &nodes {
        assert_eq!(core[&u.uid], 3, "every K4 node is in the 3-core");
    }
    assert_eq!(g.degeneracy(), 3, "K4 is 3-degenerate");
}

#[test]
fn star_centre_has_low_coreness_despite_high_degree() {
    // The defining case for *why* coreness is not degree/betweenness: a star's centre
    // has the highest degree and carries every path (max betweenness, and it is a cut
    // vertex), yet its coreness is 1 — a star is a tree, with no redundant structure.
    // This is exactly the fragile-hub-vs-cohesive-core distinction coreness adds.
    let centre = ent("centre");
    let leaves: Vec<Entity> = (0..5).map(|i| ent(&format!("leaf{i}"))).collect();
    let mut entities = vec![centre.clone()];
    entities.extend(leaves.iter().cloned());
    let rels: Vec<Relation> = leaves.iter().map(|l| rel(&centre, l)).collect();
    let g = Graph::build(&entities, &rels);
    let core = coreness_by_uid(&g);
    assert_eq!(core[&centre.uid], 1, "a high-degree hub in a tree still has coreness 1");
    for l in &leaves {
        assert_eq!(core[&l.uid], 1);
    }
    assert_eq!(g.degeneracy(), 1, "a star is 1-degenerate");
}

#[test]
fn coreness_separates_a_dense_core_from_its_pendant_periphery() {
    // A 2-connected triangle core (a-b-c) with a pendant tail c — d — e hanging off it.
    // The triangle is a 2-core; the tail is fragile periphery in the 1-core. Coreness
    // pinpoints the cohesive heart that degree alone (c has degree 3, like a tail node
    // pair) would blur.
    let (a, b, c, d, e) = (ent("a"), ent("b"), ent("c"), ent("d"), ent("e"));
    let rels = vec![
        rel(&a, &b),
        rel(&b, &c),
        rel(&a, &c), // triangle core
        rel(&c, &d),
        rel(&d, &e), // pendant tail
    ];
    let g = Graph::build(&[a.clone(), b.clone(), c.clone(), d.clone(), e.clone()], &rels);
    let core = coreness_by_uid(&g);
    assert_eq!(core[&a.uid], 2, "triangle members form the 2-core");
    assert_eq!(core[&b.uid], 2);
    assert_eq!(core[&c.uid], 2, "the hinge is part of the dense core");
    assert_eq!(core[&d.uid], 1, "the tail is fragile 1-core periphery");
    assert_eq!(core[&e.uid], 1);
    assert_eq!(g.degeneracy(), 2);
}

#[test]
fn coreness_is_deterministic_under_input_shuffling() {
    // Triangle core a-b-c plus a pendant tail c-d-e; coreness is a graph invariant, so
    // shuffling the entity/relation order must yield an identical per-UID result.
    let (a, b, c, d, e) = (ent("a"), ent("b"), ent("c"), ent("d"), ent("e"));
    let entities = vec![a.clone(), b.clone(), c.clone(), d.clone(), e.clone()];
    let rels = vec![rel(&a, &b), rel(&b, &c), rel(&a, &c), rel(&c, &d), rel(&d, &e)];
    let g1 = Graph::build(&entities, &rels);

    let mut e2 = entities.clone();
    e2.reverse();
    let mut r2 = rels.clone();
    r2.reverse();
    let g2 = Graph::build(&e2, &r2);

    assert_eq!(coreness_by_uid(&g1), coreness_by_uid(&g2), "coreness is input-order-independent");
    assert_eq!(g1.degeneracy(), g2.degeneracy());
}
