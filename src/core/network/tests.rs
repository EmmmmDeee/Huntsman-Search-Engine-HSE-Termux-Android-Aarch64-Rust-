use super::*;
use crate::core::entity::EntityKind;

fn ent(kind: EntityKind, value: &str, conf: f64) -> Entity {
    Entity::new(kind, value, conf, "net-scan")
}

fn rel(from: &Entity, to: &Entity, kind: RelationKind, conf: f64) -> Relation {
    Relation::new(from.uid.as_str(), to.uid.as_str(), kind, conf, "net-scan")
}

/// A person scan: the subject hub plus a relative, an owned email, a cross-
/// platform alias and a home address — each must land in the right group, the
/// subject card is the seed-anchored Person, and the reach stats are correct.
#[test]
fn synthesize_groups_connections_by_relationship() {
    let mut subject = ent(EntityKind::Person, "Kyle Diegmann", 0.85);
    subject.tag("subject");
    subject.tag("seed");
    let mut erik = ent(EntityKind::Person, "Erik Diegmann", 0.4);
    erik.tag("family-candidate");
    let email = ent(EntityKind::Email, "kyle@example.com", 0.7);
    let alias = ent(EntityKind::Username, "kdiegmann", 0.6);
    let addr = ent(EntityKind::Address, "QLD 4552, Australia", 0.5);

    let relations = vec![
        rel(&subject, &erik, RelationKind::AssociatedWith, 0.4),
        rel(&subject, &email, RelationKind::IdentifiedBy, 0.7),
        rel(&subject, &alias, RelationKind::AliasOf, 0.6),
        rel(&subject, &addr, RelationKind::LocatedAt, 0.5),
    ];
    let entities = vec![
        subject.clone(),
        erik.clone(),
        email.clone(),
        alias.clone(),
        addr.clone(),
    ];

    let net = synthesize(&entities, &relations);
    let card = net.subject.expect("a subject hub");
    assert_eq!(card.value, "Kyle Diegmann");
    assert_eq!(card.kind, "person");
    assert_eq!(net.direct_count, 4, "four direct connections");
    assert_eq!(
        net.reachable_count, 4,
        "all four reachable from the subject"
    );
    assert_eq!(net.edge_count, 4);

    let group = |key: &str| net.groups.iter().find(|g| g.key == key);
    let people = group("people").expect("people group");
    assert_eq!(people.items[0].value, "Erik Diegmann");
    assert_eq!(
        people.items[0].label, "relative",
        "family-candidate → relative"
    );
    assert_eq!(
        group("identifiers").unwrap().items[0].value,
        "kyle@example.com"
    );
    assert_eq!(group("identifiers").unwrap().items[0].label, "email");
    assert_eq!(group("aliases").unwrap().items[0].value, "kdiegmann");
    assert_eq!(
        group("locations").unwrap().items[0].value,
        "QLD 4552, Australia"
    );

    // Analyst order: people first.
    assert_eq!(net.groups.first().unwrap().key, "people");
}

/// Items within a group are ranked strongest-edge-first, and a pair linked by two
/// edges of the same kind collapses to one connection at the best confidence.
#[test]
fn synthesize_ranks_and_dedups() {
    let mut subject = ent(EntityKind::Person, "Subject Person", 0.9);
    subject.tag("subject");
    let weak = ent(EntityKind::Person, "Weak Associate", 0.3);
    let strong = ent(EntityKind::Person, "Strong Associate", 0.3);

    let relations = vec![
        rel(&subject, &weak, RelationKind::AssociatedWith, 0.30),
        rel(&subject, &strong, RelationKind::AssociatedWith, 0.80),
        // A second, weaker edge to `strong` (e.g. a surname guess on top of a
        // declared link) — must NOT double-count; the strongest wins.
        rel(&strong, &subject, RelationKind::AssociatedWith, 0.50),
    ];
    let entities = vec![subject, weak, strong.clone()];

    let net = synthesize(&entities, &relations);
    let people = net.groups.iter().find(|g| g.key == "people").unwrap();
    assert_eq!(people.total, 2, "two distinct people, not three edges");
    assert_eq!(people.items.len(), 2);
    assert_eq!(
        people.items[0].value, "Strong Associate",
        "strongest edge first"
    );
    assert!(
        (people.items[0].edge_confidence - 0.80).abs() < 1e-9,
        "kept the best edge"
    );
    assert_eq!(people.items[1].value, "Weak Associate");
}

/// With no seed-anchor tag, the synthesis still centres on the strongest node;
/// and a missing endpoint or empty input never panics.
#[test]
fn synthesize_falls_back_and_survives_bad_input() {
    // Fallback subject = highest effective confidence (no tags present).
    let hub = ent(EntityKind::Email, "hub@example.com", 0.9);
    let leaf = ent(EntityKind::Username, "leaf", 0.5);
    let net = synthesize(
        &[hub.clone(), leaf.clone()],
        &[rel(&hub, &leaf, RelationKind::AliasOf, 0.5)],
    );
    assert_eq!(net.subject.unwrap().value, "hub@example.com");

    // Dangling edge (the `to` endpoint isn't in the entity set) is skipped.
    let only = ent(EntityKind::Person, "Lonely Subject", 0.8);
    let ghost = ent(EntityKind::Person, "Ghost", 0.5);
    let net = synthesize(
        std::slice::from_ref(&only),
        &[rel(&only, &ghost, RelationKind::AssociatedWith, 0.5)],
    );
    assert_eq!(
        net.direct_count, 0,
        "the dangling neighbour is not a connection"
    );
    assert_eq!(net.edge_count, 1);
    assert!(net.groups.is_empty());

    // Empty input → an empty network, no subject, no panic.
    let net = synthesize(&[], &[]);
    assert!(net.subject.is_none());
    assert_eq!(net.reachable_count, 0);
}

/// Reach spans the whole connected component, not just direct neighbours: a
/// friend-of-a-friend is reachable (2 hops) even though it is not a direct
/// connection.
#[test]
fn reachable_count_spans_multiple_hops() {
    let mut subject = ent(EntityKind::Person, "Hub", 0.9);
    subject.tag("subject");
    let mid = ent(EntityKind::Person, "Middle", 0.5);
    let far = ent(EntityKind::Person, "Far", 0.5);
    let relations = vec![
        rel(&subject, &mid, RelationKind::AssociatedWith, 0.5),
        rel(&mid, &far, RelationKind::AssociatedWith, 0.5),
    ];
    let net = synthesize(&[subject, mid, far], &relations);
    assert_eq!(net.direct_count, 1, "only Middle is a direct connection");
    assert_eq!(net.reachable_count, 2, "Middle and Far are both reachable");
}

/// The per-group item ranking must be a TOTAL order. Its keys are edge
/// confidence, entity confidence, then `value` — but a bucket holds distinct-uid
/// connections and two of different kinds can carry the SAME stored value, tying
/// on all three. Without a final unique tie-break, their order — and so which
/// survive `truncate(GROUP_CAP)` — falls to the `best` HashMap's iteration order.
/// `uid` ascending pins it: same snapshot ⇒ same order, every run.
#[test]
fn synthesize_tie_breaks_equal_value_connections_by_uid() {
    let mut subject = ent(EntityKind::Person, "Tie Subject", 0.9);
    subject.tag("subject");

    // Eleven identifiers, each IdentifiedBy the subject at the same edge and
    // entity confidence, all keeping one stored value but each a different kind →
    // distinct uid. They tie on every ranking key except uid. (Kinds whose
    // constructor canonicalises the raw value — e.g. Phone strips non-digits to
    // "" — are excluded so the value key genuinely ties and only uid decides.)
    let kinds = [
        EntityKind::Email,
        EntityKind::Username,
        EntityKind::Credential,
        EntityKind::ApiKey,
        EntityKind::Password,
        EntityKind::IpAddress,
        EntityKind::Domain,
        EntityKind::Url,
        EntityKind::Asn,
        EntityKind::Address,
        EntityKind::Organisation,
    ];
    let expected = kinds.len();
    let mut entities = vec![subject.clone()];
    let mut relations = Vec::new();
    for k in kinds {
        let e = ent(k, "sharedhandle", 0.7);
        relations.push(rel(&subject, &e, RelationKind::IdentifiedBy, 0.7));
        entities.push(e);
    }

    let ids = |net: &SubjectNetwork| -> Vec<String> {
        net.groups
            .iter()
            .find(|g| g.key == "identifiers")
            .expect("identifiers group")
            .items
            .iter()
            .map(|c| c.uid.clone())
            .collect::<Vec<_>>()
    };

    let net = synthesize(&entities, &relations);
    let identifiers = &net
        .groups
        .iter()
        .find(|g| g.key == "identifiers")
        .expect("identifiers group")
        .items;
    // Premise guard: every connection really does tie on the confidence and value
    // keys, so uid is the ONLY discriminator and the assertions below are not
    // vacuous. Catches a future kind whose constructor rewrites the raw value.
    for c in identifiers {
        assert_eq!(c.value, "sharedhandle", "fixture value must survive intact");
        assert!((c.edge_confidence - 0.7).abs() < 1e-9);
        assert!((c.entity_confidence - 0.7).abs() < 1e-9);
    }

    let first_ids = ids(&net);
    assert_eq!(
        first_ids.len(),
        expected,
        "every identifier is retained (well under GROUP_CAP)"
    );
    let mut sorted = first_ids.clone();
    sorted.sort();
    assert_eq!(
        first_ids, sorted,
        "equal-ranked connections order by uid, not HashMap iteration"
    );
    // Re-synthesis rebuilds the `best`/`buckets` HashMaps (fresh seed) yet must
    // return the identical order.
    assert_eq!(
        first_ids,
        ids(&synthesize(&entities, &relations)),
        "the per-group order is deterministic across runs"
    );
}
