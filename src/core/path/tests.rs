use super::*;
use crate::core::entity::{Entity, EntityKind};
use crate::core::relation::{Relation, RelationKind};

fn ent(kind: EntityKind, value: &str) -> Entity {
    Entity::new(kind, value, 0.6, "path-scan")
}

fn rel(from: &Entity, to: &Entity, kind: RelationKind, conf: f64) -> Relation {
    Relation::new(from.uid.as_str(), to.uid.as_str(), kind, conf, "path-scan")
}

#[test]
fn shortest_path_finds_a_direct_link() {
    let kyle = ent(EntityKind::Person, "Kyle Diegmann");
    let erik = ent(EntityKind::Person, "Erik Diegmann");
    let relations = vec![rel(&kyle, &erik, RelationKind::AssociatedWith, 0.5)];
    let entities = vec![kyle.clone(), erik.clone()];
    let p = shortest_path(&entities, &relations, &kyle.uid, &erik.uid).unwrap();
    assert_eq!(p.hops, 1);
    assert_eq!(p.nodes, vec![kyle.uid.clone(), erik.uid.clone()]);
    assert_eq!(p.edges.len(), 1);
    assert_eq!(p.edges[0].kind, "associated_with");
    assert!((p.strength - 0.5).abs() < 1e-9);
}

#[test]
fn shortest_path_links_two_people_through_a_shared_address() {
    // The Kyle/Erik case: neither directly named with the other, but both placed at
    // the same address — a two-hop connection the recursion must surface.
    let kyle = ent(EntityKind::Person, "Kyle Diegmann");
    let erik = ent(EntityKind::Person, "Erik Diegmann");
    let addr = ent(EntityKind::Address, "10 Example St, Brisbane QLD 4000");
    let relations = vec![
        rel(&kyle, &addr, RelationKind::LocatedAt, 0.7),
        rel(&erik, &addr, RelationKind::LocatedAt, 0.6),
    ];
    let entities = vec![kyle.clone(), erik.clone(), addr.clone()];
    let p = shortest_path(&entities, &relations, &kyle.uid, &erik.uid).unwrap();
    assert_eq!(p.hops, 2);
    assert_eq!(
        p.nodes,
        vec![kyle.uid.clone(), addr.uid.clone(), erik.uid.clone()]
    );
    // The weakest link governs path strength.
    assert!((p.strength - 0.6).abs() < 1e-9);
}

#[test]
fn no_path_between_disconnected_entities() {
    let kyle = ent(EntityKind::Person, "Kyle Diegmann");
    let erik = ent(EntityKind::Person, "Erik Diegmann");
    let other = ent(EntityKind::Email, "stranger@example.com");
    let relations = vec![rel(&kyle, &other, RelationKind::IdentifiedBy, 0.5)];
    let entities = vec![kyle.clone(), erik.clone(), other];
    assert!(shortest_path(&entities, &relations, &kyle.uid, &erik.uid).is_none());
    // An absent endpoint is also unconnected — never a panic.
    assert!(shortest_path(&entities, &relations, &kyle.uid, "no-such-uid").is_none());
}

#[test]
fn paths_between_returns_edge_disjoint_alternatives() {
    let kyle = ent(EntityKind::Person, "Kyle Diegmann");
    let erik = ent(EntityKind::Person, "Erik Diegmann");
    let addr = ent(EntityKind::Address, "10 Example St, Brisbane QLD 4000");
    // Two independent routes: a direct associate edge AND a shared address.
    let relations = vec![
        rel(&kyle, &erik, RelationKind::AssociatedWith, 0.5),
        rel(&kyle, &addr, RelationKind::LocatedAt, 0.7),
        rel(&erik, &addr, RelationKind::LocatedAt, 0.6),
    ];
    let entities = vec![kyle.clone(), erik.clone(), addr.clone()];
    let paths = paths_between(&entities, &relations, &kyle.uid, &erik.uid, 3);
    assert_eq!(paths.len(), 2, "the direct edge and the via-address route");
    assert_eq!(paths[0].hops, 1, "shortest first");
    assert_eq!(paths[1].hops, 2);
    assert!(
        paths[1].nodes.contains(&addr.uid),
        "the alternative routes through the address"
    );
}

#[test]
fn resolve_value_matches_case_insensitively() {
    let kyle = ent(EntityKind::Person, "Kyle Diegmann");
    let entities = vec![kyle.clone()];
    assert_eq!(resolve_value(&entities, "kyle diegmann"), vec![kyle.uid.clone()]);
    assert_eq!(
        resolve_value(&entities, "  KYLE DIEGMANN  "),
        vec![kyle.uid.clone()]
    );
    assert!(resolve_value(&entities, "nobody").is_empty());
    assert!(resolve_value(&entities, "   ").is_empty());
}

#[test]
fn connect_values_links_two_people_by_name() {
    let kyle = ent(EntityKind::Person, "Kyle Diegmann");
    let erik = ent(EntityKind::Person, "Erik Diegmann");
    let addr = ent(EntityKind::Address, "10 Example St, Brisbane QLD 4000");
    let relations = vec![
        rel(&kyle, &addr, RelationKind::LocatedAt, 0.7),
        rel(&erik, &addr, RelationKind::LocatedAt, 0.6),
    ];
    let entities = vec![kyle.clone(), erik.clone(), addr.clone()];
    let paths = connect_values(
        &entities,
        &relations,
        "Kyle Diegmann",
        "Erik Diegmann",
        DEFAULT_MAX_PATHS,
    );
    assert!(!paths.is_empty(), "the two named people are connected");
    assert_eq!(paths[0].hops, 2);
    assert_eq!(paths[0].nodes.first().unwrap(), &kyle.uid);
    assert_eq!(paths[0].nodes.last().unwrap(), &erik.uid);
    // Unknown value ⇒ no path, no panic.
    assert!(
        connect_values(
            &entities,
            &relations,
            "Kyle Diegmann",
            "Ghost Person",
            DEFAULT_MAX_PATHS
        )
        .is_empty()
    );
}

#[test]
fn self_path_is_zero_hops() {
    let kyle = ent(EntityKind::Person, "Kyle Diegmann");
    let entities = vec![kyle.clone()];
    let p = shortest_path(&entities, &[], &kyle.uid, &kyle.uid).unwrap();
    assert_eq!(p.hops, 0);
    assert_eq!(p.nodes, vec![kyle.uid.clone()]);
    assert!(p.edges.is_empty());
    assert!((p.strength - 1.0).abs() < 1e-9);
    // paths_between returns exactly the one self-path, not an infinite loop.
    let ps = paths_between(&entities, &[], &kyle.uid, &kyle.uid, 3);
    assert_eq!(ps.len(), 1);
    assert_eq!(ps[0].hops, 0);
}

#[test]
fn respects_the_max_hops_bound() {
    // A chain node00 - node01 - … - node07 (seven hops). node00→node07 exceeds
    // MAX_HOPS; node00→node06 sits exactly at it.
    let chain: Vec<Entity> = (0..=7)
        .map(|i| ent(EntityKind::Username, &format!("node{i:02}")))
        .collect();
    let relations: Vec<Relation> = (0..7)
        .map(|i| rel(&chain[i], &chain[i + 1], RelationKind::AssociatedWith, 0.5))
        .collect();
    let entities = chain.clone();
    assert_eq!(MAX_HOPS, 6);
    assert!(
        shortest_path(&entities, &relations, &chain[0].uid, &chain[7].uid).is_none(),
        "seven hops exceeds the bound"
    );
    let p = shortest_path(&entities, &relations, &chain[0].uid, &chain[6].uid).unwrap();
    assert_eq!(p.hops, 6, "exactly at the bound is reachable");
}

#[test]
fn pathfinding_is_deterministic_under_input_shuffling() {
    let kyle = ent(EntityKind::Person, "Kyle Diegmann");
    let erik = ent(EntityKind::Person, "Erik Diegmann");
    let addr = ent(EntityKind::Address, "10 Example St, Brisbane QLD 4000");
    let email = ent(EntityKind::Email, "shared@example.com");
    let mk_rels = || {
        vec![
            rel(&kyle, &addr, RelationKind::LocatedAt, 0.7),
            rel(&erik, &addr, RelationKind::LocatedAt, 0.6),
            rel(&kyle, &email, RelationKind::IdentifiedBy, 0.8),
            rel(&erik, &email, RelationKind::IdentifiedBy, 0.8),
        ]
    };
    let e1 = vec![kyle.clone(), erik.clone(), addr.clone(), email.clone()];
    let mut e2 = e1.clone();
    e2.reverse();
    let r1 = mk_rels();
    let mut r2 = mk_rels();
    r2.reverse();
    let p1 = paths_between(&e1, &r1, &kyle.uid, &erik.uid, 3);
    let p2 = paths_between(&e2, &r2, &kyle.uid, &erik.uid, 3);
    assert!(!p1.is_empty());
    assert_eq!(
        p1, p2,
        "the result is independent of entity / relation input order"
    );
}

#[test]
fn connect_cross_scan_bridges_two_separate_investigations() {
    use crate::core::test_support::InMemoryStore;
    let store = InMemoryStore::new();
    // Scan A discovered one email tied to a shared bridge entity; an INDEPENDENT scan B
    // discovered a different email tied to the SAME bridge. Neither scan alone connects
    // the two emails — only the merged cross-scan graph does.
    let from_e = Entity::new(EntityKind::Email, "from@example.com", 0.7, "scan-a");
    let bridge = Entity::new(EntityKind::Domain, "bridge.example", 0.6, "scan-a");
    let to_e = Entity::new(EntityKind::Email, "to@example.com", 0.7, "scan-b");
    store.upsert_entity(&from_e).unwrap();
    store.upsert_entity(&bridge).unwrap();
    store.upsert_entity(&to_e).unwrap();
    store
        .upsert_relation(&Relation::new(
            from_e.uid.as_str(),
            bridge.uid.as_str(),
            RelationKind::AssociatedWith,
            0.6,
            "scan-a",
        ))
        .unwrap();
    store
        .upsert_relation(&Relation::new(
            to_e.uid.as_str(),
            bridge.uid.as_str(),
            RelationKind::AssociatedWith,
            0.6,
            "scan-b",
        ))
        .unwrap();

    let paths = connect_cross_scan(&store, "from@example.com", "to@example.com", 3);
    assert!(
        !paths.is_empty(),
        "the two emails connect through the shared bridge across scans"
    );
    assert_eq!(paths[0].hops, 2);
    assert_eq!(paths[0].nodes.first().unwrap(), &from_e.uid);
    assert_eq!(paths[0].nodes.last().unwrap(), &to_e.uid);
    assert!(
        paths[0].nodes.contains(&bridge.uid),
        "the route passes through the cross-scan bridge"
    );
}

#[test]
fn connect_cross_scan_is_empty_without_a_bridge_or_endpoint() {
    use crate::core::test_support::InMemoryStore;
    let store = InMemoryStore::new();
    store
        .upsert_entity(&Entity::new(
            EntityKind::Email,
            "lonely-a@example.com",
            0.7,
            "scan-a",
        ))
        .unwrap();
    store
        .upsert_entity(&Entity::new(
            EntityKind::Email,
            "lonely-b@example.com",
            0.7,
            "scan-b",
        ))
        .unwrap();
    // No shared bridge ⇒ no connection.
    assert!(
        connect_cross_scan(&store, "lonely-a@example.com", "lonely-b@example.com", 3).is_empty()
    );
    // An unknown endpoint ⇒ empty, never a panic.
    assert!(connect_cross_scan(&store, "lonely-a@example.com", "ghost@example.com", 3).is_empty());
}
