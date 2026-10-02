use super::*;
use crate::core::entity::EntityKind;
use crate::core::relation::RelationKind;

const SCAN: &str = "community-scan";

fn ent(kind: EntityKind, value: &str) -> Entity {
    Entity::new(kind, value, 0.8, SCAN)
}

fn rel(from: &Entity, to: &Entity, kind: RelationKind) -> Relation {
    Relation::new(from.uid.as_str(), to.uid.as_str(), kind, 0.5, SCAN)
}

/// All member UIDs across every detected community, sorted — the partition's
/// flattened coverage, for asserting which nodes were placed.
fn all_members(cs: &[Community]) -> Vec<String> {
    let mut uids: Vec<String> = cs.iter().flat_map(|c| c.uids.clone()).collect();
    uids.sort();
    uids
}

/// Two fully-disjoint clusters (no edge between them) are detected as exactly two
/// communities, each holding its own members — the core OSINT split (a family
/// triangle vs a separate infrastructure triangle).
#[test]
fn two_disjoint_clusters_are_two_communities() {
    // Family triangle: three mutually-linked people.
    let p1 = ent(EntityKind::Person, "Alice Example");
    let p2 = ent(EntityKind::Person, "Bob Example");
    let p3 = ent(EntityKind::Person, "Carol Example");
    // Infrastructure triangle: a domain, a subdomain, an IP — mutually linked.
    let d1 = ent(EntityKind::Domain, "example.com");
    let d2 = ent(EntityKind::Domain, "mail.example.com");
    let ip = ent(EntityKind::IpAddress, "203.0.113.7");

    let relations = vec![
        rel(&p1, &p2, RelationKind::AssociatedWith),
        rel(&p2, &p3, RelationKind::AssociatedWith),
        rel(&p1, &p3, RelationKind::AssociatedWith),
        rel(&d2, &d1, RelationKind::SubdomainOf),
        rel(&d1, &ip, RelationKind::ResolvesTo),
        rel(&d2, &ip, RelationKind::ResolvesTo),
    ];
    let entities = vec![
        p1.clone(),
        p2.clone(),
        p3.clone(),
        d1.clone(),
        d2.clone(),
        ip.clone(),
    ];

    let communities = detect(&entities, &relations);
    assert_eq!(
        communities.len(),
        2,
        "two disjoint clusters → two communities"
    );
    assert_eq!(communities[0].size, 3);
    assert_eq!(communities[1].size, 3);

    // Each community is exactly one of the two triangles (no cross-contamination).
    let person_uids = {
        let mut v = vec![p1.uid.clone(), p2.uid.clone(), p3.uid.clone()];
        v.sort();
        v
    };
    let infra_uids = {
        let mut v = vec![d1.uid.clone(), d2.uid.clone(), ip.uid.clone()];
        v.sort();
        v
    };
    let got: Vec<Vec<String>> = communities.iter().map(|c| c.uids.clone()).collect();
    assert!(
        got.contains(&person_uids),
        "the three people form one community"
    );
    assert!(
        got.contains(&infra_uids),
        "the three infra nodes form the other community"
    );

    // ids assigned from the (deterministic) output order, starting at 0.
    assert_eq!(communities[0].id, 0);
    assert_eq!(communities[1].id, 1);
}

/// A fully-connected (clique) set of nodes collapses to a single community: every
/// node sees the same dominant label, so the partition is one cluster.
#[test]
fn fully_connected_set_is_one_community() {
    let a = ent(EntityKind::Person, "A Person");
    let b = ent(EntityKind::Person, "B Person");
    let c = ent(EntityKind::Person, "C Person");
    let d = ent(EntityKind::Person, "D Person");
    let nodes = [&a, &b, &c, &d];

    // Every distinct pair linked → a 4-clique.
    let mut relations = Vec::new();
    for i in 0..nodes.len() {
        for j in (i + 1)..nodes.len() {
            relations.push(rel(nodes[i], nodes[j], RelationKind::AssociatedWith));
        }
    }
    let entities = vec![a.clone(), b.clone(), c.clone(), d.clone()];

    let communities = detect(&entities, &relations);
    assert_eq!(communities.len(), 1, "a clique is a single community");
    assert_eq!(communities[0].size, 4);
    assert_eq!(
        all_members(&communities),
        all_members(&[Community {
            id: 0,
            uids: {
                let mut v = vec![a.uid, b.uid, c.uid, d.uid];
                v.sort();
                v
            },
            size: 4,
            label: String::new(),
        }]),
        "all four nodes are in the one community"
    );
}

/// Isolated entities (present in the entity set but in no relation) are NOT a
/// community — only nodes that participate in at least one relation are placed.
#[test]
fn isolated_entities_are_not_communities() {
    let a = ent(EntityKind::Person, "Linked One");
    let b = ent(EntityKind::Person, "Linked Two");
    let lonely = ent(EntityKind::Email, "nobody@example.com");

    let relations = vec![rel(&a, &b, RelationKind::AssociatedWith)];
    let entities = vec![a.clone(), b.clone(), lonely.clone()];

    let communities = detect(&entities, &relations);
    assert_eq!(
        communities.len(),
        1,
        "only the linked pair forms a community"
    );
    assert_eq!(communities[0].size, 2);
    assert!(
        !communities[0].uids.contains(&lonely.uid),
        "the isolated entity is omitted entirely"
    );
    assert_eq!(all_members(&communities), {
        let mut v = vec![a.uid, b.uid];
        v.sort();
        v
    });
}

/// Empty / relationless input yields no communities (per the documented choice
/// that an isolated node is not a community).
#[test]
fn empty_and_relationless_input_yields_nothing() {
    // No entities, no relations.
    assert!(detect(&[], &[]).is_empty());

    // Entities but no relations → every node is isolated → nothing.
    let a = ent(EntityKind::Person, "Alone A");
    let b = ent(EntityKind::Domain, "alone-b.com");
    assert!(
        detect(&[a, b], &[]).is_empty(),
        "with no relations, no node participates in a community"
    );
}

/// A relation whose endpoints aren't in the entity set is dangling: it is skipped
/// without panicking, and a self-loop never forms a community.
#[test]
fn dangling_endpoints_and_self_loops_are_ignored() {
    let real = ent(EntityKind::Person, "Real Subject");
    let ghost = ent(EntityKind::Person, "Ghost"); // never added to entities

    // (a) Edge to a ghost endpoint — dangling, skipped → no community.
    let dangling = detect(
        std::slice::from_ref(&real),
        &[rel(&real, &ghost, RelationKind::AssociatedWith)],
    );
    assert!(
        dangling.is_empty(),
        "an edge to a missing endpoint forms no community"
    );

    // (b) A self-loop is not a link between two nodes → no community.
    let selfloop = detect(
        std::slice::from_ref(&real),
        &[rel(&real, &real, RelationKind::AssociatedWith)],
    );
    assert!(selfloop.is_empty(), "a self-loop forms no community");
}

/// Determinism: the result is identical regardless of the order entities and
/// relations are supplied in — the partition, member sets, ids, sizes and labels
/// must all match exactly.
#[test]
fn result_is_independent_of_input_order() {
    let p1 = ent(EntityKind::Person, "Dana Example");
    let p2 = ent(EntityKind::Person, "Evan Example");
    let p3 = ent(EntityKind::Person, "Faye Example");
    let d1 = ent(EntityKind::Domain, "acme.test");
    let d2 = ent(EntityKind::Domain, "cdn.acme.test");

    let entities = vec![p1.clone(), p2.clone(), p3.clone(), d1.clone(), d2.clone()];
    let relations = vec![
        rel(&p1, &p2, RelationKind::AssociatedWith),
        rel(&p2, &p3, RelationKind::AssociatedWith),
        rel(&d1, &d2, RelationKind::SubdomainOf),
    ];

    let baseline = detect(&entities, &relations);

    // Reverse both inputs (and direction-flip the edges via from/to swap) and
    // re-run several times — every run must equal the baseline byte-for-byte.
    let mut entities_rev = entities.clone();
    entities_rev.reverse();
    let mut relations_rev = relations.clone();
    relations_rev.reverse();

    for _ in 0..5 {
        let again = detect(&entities_rev, &relations_rev);
        assert_eq!(
            again, baseline,
            "community detection must be order-independent and reproducible"
        );
    }

    // Two disjoint clusters here (the people vs the two domains).
    assert_eq!(baseline.len(), 2);
}

/// The label is deterministic and meaningful: a person-dominated cluster is
/// labelled by its dominant kind plus the smallest-UID person's value as the
/// exemplar.
#[test]
fn label_reflects_dominant_kind_and_a_stable_exemplar() {
    let p1 = ent(EntityKind::Person, "Grace Hopper");
    let p2 = ent(EntityKind::Person, "Henry Ford");
    let email = ent(EntityKind::Email, "grace@example.com");

    // Two people + one email, all mutually connected: people dominate the kind
    // tally (2 vs 1), so the label names the person kind.
    let relations = vec![
        rel(&p1, &p2, RelationKind::AssociatedWith),
        rel(&p1, &email, RelationKind::IdentifiedBy),
        rel(&p2, &email, RelationKind::IdentifiedBy),
    ];
    let entities = vec![p1.clone(), p2.clone(), email.clone()];

    let communities = detect(&entities, &relations);
    assert_eq!(communities.len(), 1);
    let label = &communities[0].label;
    assert!(
        label.starts_with("person cluster:"),
        "dominant kind (person) leads the label, got {label:?}"
    );

    // The exemplar is the smallest-UID PERSON's value — recompute that expectation
    // directly so the test doesn't hard-code a specific name.
    let exemplar_person = [&p1, &p2]
        .into_iter()
        .min_by(|a, b| a.uid.cmp(&b.uid))
        .expect("should succeed");
    assert_eq!(
        label,
        &format!("person cluster: {}", exemplar_person.value),
        "exemplar is the smallest-UID member of the dominant kind"
    );
}

/// A two-lobe graph joined by a single bridge edge is split into TWO communities
/// — the property weakly-connected components could not provide and the reason
/// label propagation was chosen. Each dense lobe outvotes the lone bridge.
#[test]
fn weakly_bridged_lobes_split_into_two_communities() {
    // Lobe A: a 4-clique of people (the family).
    let a1 = ent(EntityKind::Person, "Fam One");
    let a2 = ent(EntityKind::Person, "Fam Two");
    let a3 = ent(EntityKind::Person, "Fam Three");
    let a4 = ent(EntityKind::Person, "Fam Four");
    // Lobe B: a 4-clique of infrastructure (the estate). Four genuinely DISTINCT
    // nodes — note an `Entity`'s UID is its identity, and `Domain` normalisation
    // strips a leading `www.`, so "estate.example" and "www.estate.example" would
    // collapse to ONE node; the names below stay distinct.
    let b1 = ent(EntityKind::Domain, "estate.example");
    let b2 = ent(EntityKind::Domain, "cdn.estate.example");
    let b3 = ent(EntityKind::IpAddress, "198.51.100.4");
    let b4 = ent(EntityKind::IpAddress, "198.51.100.5");

    let lobe_a = [&a1, &a2, &a3, &a4];
    let lobe_b = [&b1, &b2, &b3, &b4];

    let mut relations = Vec::new();
    for lobe in [&lobe_a, &lobe_b] {
        for i in 0..lobe.len() {
            for j in (i + 1)..lobe.len() {
                relations.push(rel(lobe[i], lobe[j], RelationKind::AssociatedWith));
            }
        }
    }
    // One thin bridge joining the two lobes (a person who owns a domain).
    relations.push(rel(&a1, &b1, RelationKind::RegisteredBy));

    let entities = vec![
        a1.clone(),
        a2.clone(),
        a3.clone(),
        a4.clone(),
        b1.clone(),
        b2.clone(),
        b3.clone(),
        b4.clone(),
    ];

    let communities = detect(&entities, &relations);
    assert_eq!(
        communities.len(),
        2,
        "a single bridge between two dense lobes must NOT merge them into one \
         community — this is why label propagation is used over connected components"
    );
    // Both lobes are fully captured (all eight nodes placed, four per community).
    assert_eq!(communities[0].size, 4);
    assert_eq!(communities[1].size, 4);

    let family = {
        let mut v: Vec<String> = lobe_a.iter().map(|e| e.uid.clone()).collect();
        v.sort();
        v
    };
    let estate = {
        let mut v: Vec<String> = lobe_b.iter().map(|e| e.uid.clone()).collect();
        v.sort();
        v
    };
    let got: Vec<Vec<String>> = communities.iter().map(|c| c.uids.clone()).collect();
    assert!(got.contains(&family), "the family lobe stays one community");
    assert!(got.contains(&estate), "the estate lobe stays one community");
}
