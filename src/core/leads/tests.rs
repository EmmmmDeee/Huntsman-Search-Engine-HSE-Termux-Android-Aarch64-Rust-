use super::*;
use crate::core::entity::EntityKind;
use crate::core::relation::RelationKind;

fn ent(kind: EntityKind, value: &str, conf: f64) -> Entity {
    Entity::new(kind, value, conf, "leads-scan")
}

fn rel(from: &Entity, to: &Entity, kind: RelationKind, conf: f64) -> Relation {
    Relation::new(from.uid.as_str(), to.uid.as_str(), kind, conf, "leads-scan")
}

/// The headline case: an untapped relative (below the expansion floor, so the
/// engine never pivoted it) outranks an already-strong owned identifier, and its
/// reason names both the relationship and that it is uninvestigated.
#[test]
fn recommend_ranks_untapped_relatives() {
    let mut subject = ent(EntityKind::Person, "Kyle Diegmann", 0.85);
    subject.tag("subject");
    let mut erik = ent(EntityKind::Person, "Erik Diegmann", 0.35); // sub-floor → untapped
    erik.tag("family-candidate");
    let email = ent(EntityKind::Email, "kyle@example.com", 0.8); // above floor, owned
    let addr = ent(EntityKind::Address, "QLD 4552, Australia", 0.5); // not pivotable

    let relations = vec![
        rel(&subject, &erik, RelationKind::AssociatedWith, 0.5),
        rel(&subject, &email, RelationKind::IdentifiedBy, 0.8),
        rel(&subject, &addr, RelationKind::LocatedAt, 0.5),
    ];
    let entities = vec![subject, erik.clone(), email.clone(), addr];

    let leads = recommend(&entities, &relations, 0.50);
    // Two pivotable leads (person, email); the address is not pivotable.
    assert_eq!(leads.len(), 2, "address is not an actionable lead");
    let erik_lead = leads.iter().find(|l| l.value == "Erik Diegmann").unwrap();
    let email_lead = leads
        .iter()
        .find(|l| l.value == "kyle@example.com")
        .unwrap();
    assert_eq!(erik_lead.target_kind, "full_name");
    assert_eq!(email_lead.target_kind, "email");
    assert_eq!(erik_lead.action, "scan");
    assert!(
        erik_lead.reason.contains("relative") && erik_lead.reason.contains("not yet investigated"),
        "reason: {}",
        erik_lead.reason
    );
    // The untapped relative is boosted above the strong-but-tapped identifier.
    assert!(
        leads[0].value == "Erik Diegmann",
        "an untapped relative is the top next step, got {:?}",
        leads.iter().map(|l| &l.value).collect::<Vec<_>>()
    );
}

/// Aliases and infrastructure are pivotable too, but a non-pivotable kind (or no
/// connections at all) yields nothing — no speculative noise.
#[test]
fn recommend_covers_pivotable_kinds_only() {
    let mut subject = ent(EntityKind::Username, "kdiegmann", 0.7);
    subject.tag("subject");
    let alias = ent(EntityKind::Email, "kd@example.com", 0.6);
    let dom = ent(EntityKind::Domain, "example.com", 0.6);
    let relations = vec![
        rel(&subject, &alias, RelationKind::AliasOf, 0.6),
        rel(&alias, &dom, RelationKind::BelongsToDomain, 0.6),
    ];
    let leads = recommend(&[subject, alias, dom], &relations, 0.50);
    let kinds: std::collections::BTreeSet<&str> = leads.iter().map(|l| l.kind.as_str()).collect();
    assert!(kinds.contains("email"), "alias email is a lead");

    // No connections → no leads (and no panic on an empty graph).
    let lone = ent(EntityKind::Person, "Nobody Connected", 0.9);
    assert!(recommend(std::slice::from_ref(&lone), &[], 0.50).is_empty());
    assert!(recommend(&[], &[], 0.50).is_empty());
}

/// Leads are a bounded, ranked shortlist (deterministic), never an unbounded
/// second entity dump, even on a large family.
#[test]
fn recommend_is_bounded_and_ranked() {
    let mut subject = ent(EntityKind::Person, "Hub Person", 0.9);
    subject.tag("subject");
    let mut entities = vec![subject.clone()];
    let mut relations = Vec::new();
    for i in 0..60 {
        // Distinct surnames so kinship doesn't cross-link them; each is a direct
        // declared associate of the subject.
        let p = ent(EntityKind::Person, &format!("Person Number{i:02}"), 0.3);
        relations.push(rel(&subject, &p, RelationKind::AssociatedWith, 0.4));
        entities.push(p);
    }
    let leads = recommend(&entities, &relations, 0.50);
    assert!(leads.len() <= LEAD_CAP, "leads are capped at {LEAD_CAP}");
    // Sorted by score descending.
    for w in leads.windows(2) {
        assert!(w[0].score >= w[1].score, "leads are ranked by score");
    }
    // Deterministic: a second run yields the identical ordered value list.
    let again = recommend(&entities, &relations, 0.50);
    let v1: Vec<&str> = leads.iter().map(|l| l.value.as_str()).collect();
    let v2: Vec<&str> = again.iter().map(|l| l.value.as_str()).collect();
    assert_eq!(v1, v2);
}
