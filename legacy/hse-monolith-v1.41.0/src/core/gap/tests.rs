use super::*;
use crate::core::entity::{Entity, EntityKind};
use crate::core::relation::{Relation, RelationKind};

fn ent(kind: EntityKind, value: &str, conf: f64) -> Entity {
    Entity::new(kind, value, conf, "gap-scan")
}

#[test]
fn empty_scan_is_the_explicit_null_state() {
    let r = analyze(&[], &[]);
    assert!(r.null_state, "no seeds → explicit null state, not invented data");
    assert_eq!(r.total_seeds, 0);
    assert_eq!(r.linked_seeds, 0);
    assert_eq!(r.isolated_seeds, 0);
    assert_eq!(r.linked_fraction, 0.0);
    assert!(r.orphans.is_empty());
}

#[test]
fn a_linked_pair_has_no_orphans() {
    let a = ent(EntityKind::Email, "a@example.test", 0.8);
    let b = ent(EntityKind::Domain, "example.test", 0.8);
    let rels = vec![Relation::new(
        a.uid.as_str(),
        b.uid.as_str(),
        RelationKind::BelongsToDomain,
        0.7,
        "gap-scan",
    )];
    let r = analyze(&[a, b], &rels);
    assert!(!r.null_state);
    assert_eq!(r.total_seeds, 2);
    assert_eq!(r.linked_seeds, 2, "both endpoints are linked");
    assert_eq!(r.isolated_seeds, 0);
    assert!((r.linked_fraction - 1.0).abs() < 1e-9);
}

#[test]
fn a_scannable_high_confidence_orphan_is_unexpanded_with_a_target() {
    // An email at full confidence, but no relation → the actionable coverage gap.
    let e = ent(EntityKind::Email, "lonely@example.test", 0.9);
    let r = analyze(std::slice::from_ref(&e), &[]);
    assert_eq!(r.isolated_seeds, 1);
    assert_eq!(r.isolation.unexpanded, 1);
    let o = &r.orphans[0];
    assert_eq!(o.isolation, Isolation::Unexpanded);
    assert_eq!(o.kind, "email");
    assert_eq!(o.reinjection_target.as_deref(), Some("email"), "re-injects as an email target");
    assert!(o.action.contains("re-inject"));
}

#[test]
fn a_low_confidence_orphan_is_below_the_expand_floor() {
    let e = ent(EntityKind::Domain, "weak.example.test", 0.30);
    let r = analyze(std::slice::from_ref(&e), &[]);
    assert_eq!(r.isolation.below_expand_floor, 1);
    assert_eq!(r.orphans[0].isolation, Isolation::BelowExpandFloor);
    assert_eq!(r.orphans[0].reinjection_target.as_deref(), Some("domain"));
}

#[test]
fn a_non_scannable_orphan_is_terminal_with_no_target() {
    // A password is a terminal leaf — isolation is expected, not a blind spot.
    let e = ent(EntityKind::Password, "hunter2", 0.9);
    let r = analyze(std::slice::from_ref(&e), &[]);
    assert_eq!(r.isolation.terminal, 1);
    let o = &r.orphans[0];
    assert_eq!(o.isolation, Isolation::Terminal);
    assert_eq!(o.reinjection_target, None, "a password is not independently scannable");
}

#[test]
fn self_loops_and_dangling_relations_do_not_count_as_links() {
    let a = ent(EntityKind::Username, "solo", 0.8);
    let rels = vec![
        // self-loop: links nothing
        Relation::new(a.uid.as_str(), a.uid.as_str(), RelationKind::AliasOf, 0.6, "gap-scan"),
        // dangling: the other endpoint is not a present seed
        Relation::new(a.uid.as_str(), "uid:absent", RelationKind::AssociatedWith, 0.6, "gap-scan"),
    ];
    let r = analyze(std::slice::from_ref(&a), &rels);
    assert_eq!(r.linked_seeds, 0, "neither a self-loop nor a dangling edge is a real link");
    assert_eq!(r.isolated_seeds, 1);
}

#[test]
fn orphans_are_ordered_most_actionable_first_and_deterministic() {
    let unexpanded = ent(EntityKind::Email, "a@example.test", 0.9); // Unexpanded
    let below = ent(EntityKind::Domain, "b.example.test", 0.2); // BelowExpandFloor
    let terminal = ent(EntityKind::Password, "p", 0.9); // Terminal
    let entities = vec![terminal.clone(), below.clone(), unexpanded.clone()];

    let r1 = analyze(&entities, &[]);
    let order: Vec<Isolation> = r1.orphans.iter().map(|o| o.isolation).collect();
    assert_eq!(
        order,
        vec![Isolation::Unexpanded, Isolation::BelowExpandFloor, Isolation::Terminal],
        "actionable gaps surface before expected terminal isolation"
    );

    // Order-independent.
    let mut shuffled = entities.clone();
    shuffled.reverse();
    let r2 = analyze(&shuffled, &[]);
    assert_eq!(r1, r2, "the gap report is independent of input order");
}

#[test]
fn linked_fraction_reflects_partial_connectivity() {
    // a—b linked; c orphan. 2 of 3 linked.
    let a = ent(EntityKind::Email, "a@example.test", 0.8);
    let b = ent(EntityKind::Domain, "example.test", 0.8);
    let c = ent(EntityKind::Phone, "+15551230000", 0.8);
    let rels = vec![Relation::new(
        a.uid.as_str(),
        b.uid.as_str(),
        RelationKind::BelongsToDomain,
        0.7,
        "gap-scan",
    )];
    let r = analyze(&[a, b, c], &rels);
    assert_eq!(r.linked_seeds, 2);
    assert_eq!(r.isolated_seeds, 1);
    assert!((r.linked_fraction - (2.0 / 3.0)).abs() < 1e-9);
}
