use super::*;
use crate::core::entity::{Entity, EntityKind};
use crate::core::relation::{Relation, RelationKind};

fn ent(name: &str) -> Entity {
    Entity::new(EntityKind::Username, name, 0.6, "pivot-scan")
}

fn rel(a: &Entity, b: &Entity) -> Relation {
    Relation::new(
        a.uid.as_str(),
        b.uid.as_str(),
        RelationKind::AssociatedWith,
        0.6,
        "pivot-scan",
    )
}

#[test]
fn star_centre_is_the_pivot() {
    // Every shortest path between two leaves routes through the centre, so its
    // normalised betweenness is exactly 1.0 and it is the top pivot.
    let centre = ent("centre");
    let leaves: Vec<Entity> = (0..4).map(|i| ent(&format!("leaf{i}"))).collect();
    let mut entities = vec![centre.clone()];
    let mut relations = Vec::new();
    for l in &leaves {
        relations.push(rel(&centre, l));
        entities.push(l.clone());
    }
    let pivots = detect(&entities, &relations);
    assert_eq!(pivots[0].uid, centre.uid, "the hub is the top pivot");
    assert!(
        (pivots[0].betweenness - 1.0).abs() < 1e-9,
        "centre carries every leaf-pair path: {}",
        pivots[0].betweenness
    );
    assert_eq!(pivots[0].degree, 4);
    for p in pivots.iter().filter(|p| p.uid != centre.uid) {
        assert!(p.betweenness.abs() < 1e-9, "a leaf bridges nothing");
    }
}

#[test]
fn path_middle_is_the_pivot() {
    // a — b — c: the only a↔c route passes through b.
    let a = ent("a");
    let b = ent("b");
    let c = ent("c");
    let entities = vec![a.clone(), b.clone(), c.clone()];
    let relations = vec![rel(&a, &b), rel(&b, &c)];
    let pivots = detect(&entities, &relations);
    assert_eq!(pivots[0].uid, b.uid, "the middle node is the top pivot");
    let pb = pivots.iter().find(|p| p.uid == b.uid).unwrap();
    assert!(
        (pb.betweenness - 1.0).abs() < 1e-9,
        "the middle carries the only a–c route: {}",
        pb.betweenness
    );
    let pa = pivots.iter().find(|p| p.uid == a.uid).unwrap();
    assert!(pa.betweenness.abs() < 1e-9, "an endpoint bridges nothing");
}

#[test]
fn bridge_node_between_clusters_ranks_top() {
    // Two triangles joined by a single bridge edge a0—b0: all cross-cluster shortest
    // paths route through that bridge, so a0 and b0 are the top pivots.
    let t1: Vec<Entity> = (0..3).map(|i| ent(&format!("a{i}"))).collect();
    let t2: Vec<Entity> = (0..3).map(|i| ent(&format!("b{i}"))).collect();
    let mut entities = Vec::new();
    entities.extend(t1.iter().cloned());
    entities.extend(t2.iter().cloned());
    let relations = vec![
        rel(&t1[0], &t1[1]),
        rel(&t1[1], &t1[2]),
        rel(&t1[0], &t1[2]),
        rel(&t2[0], &t2[1]),
        rel(&t2[1], &t2[2]),
        rel(&t2[0], &t2[2]),
        rel(&t1[0], &t2[0]), // the bridge
    ];
    let pivots = detect(&entities, &relations);
    let top2: Vec<&str> = pivots.iter().take(2).map(|p| p.uid.as_str()).collect();
    assert!(
        top2.contains(&t1[0].uid.as_str()) && top2.contains(&t2[0].uid.as_str()),
        "the bridge endpoints are the top pivots, got {:?}",
        pivots
            .iter()
            .map(|p| (&p.uid, p.betweenness))
            .collect::<Vec<_>>()
    );
    assert!(pivots[0].betweenness > 0.0);
}

#[test]
fn isolated_and_lone_nodes_are_not_pivots() {
    let a = ent("a");
    let b = ent("b");
    let lonely = ent("lonely");
    let entities = vec![a.clone(), b.clone(), lonely.clone()];
    let relations = vec![rel(&a, &b)];
    let pivots = detect(&entities, &relations);
    assert!(
        pivots.iter().all(|p| p.uid != lonely.uid),
        "a node with no edges pivots nothing"
    );
    // Empty / edgeless graphs yield no pivots, no panic.
    assert!(detect(&[], &[]).is_empty());
    assert!(detect(&[ent("x")], &[]).is_empty());
}

#[test]
fn detection_is_deterministic_under_input_shuffling() {
    let centre = ent("centre");
    let leaves: Vec<Entity> = (0..5).map(|i| ent(&format!("leaf{i}"))).collect();
    let mut entities = vec![centre.clone()];
    entities.extend(leaves.iter().cloned());
    let relations: Vec<Relation> = leaves.iter().map(|l| rel(&centre, l)).collect();

    let p1 = detect(&entities, &relations);
    let mut e2 = entities.clone();
    e2.reverse();
    let mut r2 = relations.clone();
    r2.reverse();
    let p2 = detect(&e2, &r2);
    assert_eq!(p1, p2, "pivots are independent of input order");
}
