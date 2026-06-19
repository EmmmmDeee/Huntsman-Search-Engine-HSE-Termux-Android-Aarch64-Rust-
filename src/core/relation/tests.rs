use super::*;

#[test]
fn relation_kind_as_str_matches_serde() {
    // CONVENTIONS.md §3: the type owns its canonical string and a test
    // pins it to the serde wire form so the two can't drift. as_str is the
    // stored `relations.kind` column and the API edge label; the serde
    // derive is what crosses the wire — a rename that touched only one
    // would silently split the DB form from the JSON form.
    for k in [
        RelationKind::SubdomainOf,
        RelationKind::BelongsToDomain,
        RelationKind::HostedOn,
        RelationKind::ResolvesTo,
        RelationKind::RegisteredBy,
        RelationKind::CoLocatedWith,
        RelationKind::DerivedFrom,
        RelationKind::IdentifiedBy,
        RelationKind::AliasOf,
        RelationKind::LocatedAt,
        RelationKind::AssociatedWith,
    ] {
        let json = serde_json::to_string(&k).unwrap();
        assert_eq!(json.trim_matches('"'), k.as_str(), "{k:?}");
    }
}
use crate::core::entity::{Entity, EntityKind};

fn ent(kind: EntityKind, value: &str, conf: f64) -> Entity {
    Entity::new(kind, value, conf, "rel-scan")
}

#[test]
fn name_lineage_links_derived_handles_to_the_subject_person() {
    use crate::core::entity::Evidence;
    let person = ent(EntityKind::Person, "Jane Smith", 0.6);

    // Two name-derived handles carrying the subject as `source_name`.
    let mut uname = ent(EntityKind::Username, "jsmith", 0.38);
    uname.tag("name-derived");
    uname.add_evidence(
        Evidence::new("name_intel", "derived").with_attr("source_name", "Jane Smith"),
    );
    let mut email = ent(EntityKind::Email, "jane.smith@gmail.com", 0.30);
    email.tag("name-derived");
    email.add_evidence(
        Evidence::new("name_intel", "permuted").with_attr("source_name", "jane smith"), // case-insensitive
    );

    // An unrelated handle: not name-derived → must NOT link.
    let other = ent(EntityKind::Username, "unrelated", 0.5);

    let ents = vec![person.clone(), uname.clone(), email.clone(), other];
    let rels = derive_name_lineage(&ents, "s");

    assert_eq!(
        rels.len(),
        2,
        "both name-derived handles link, the orphan does not"
    );
    for r in &rels {
        assert_eq!(r.kind, RelationKind::DerivedFrom);
        assert_eq!(r.to_uid, person.uid, "edge points at the subject Person");
    }
    assert!(rels.iter().any(|r| r.from_uid == uname.uid));
    assert!(rels.iter().any(|r| r.from_uid == email.uid));

    // No Person present → no edges (and no panic).
    assert!(derive_name_lineage(&[uname, email], "s").is_empty());
}

#[test]
fn co_residence_links_different_surname_household_at_a_specific_address() {
    use crate::core::entity::Evidence;

    // Two separate register records at ONE specific address name two
    // DIFFERENT-surname people — the household the surname kinship can't link.
    let mut addr = ent(
        EntityKind::Address,
        "12 Rose Street, Brisbane QLD 4000",
        0.6,
    );
    addr.add_evidence(Evidence::new("qld_unclaimed", "rec1").with_attr("owner", "Jane Citizen"));
    addr.add_evidence(Evidence::new("qld_unclaimed", "rec2").with_attr("owner", "Mark Roe"));
    let jane = ent(EntityKind::Person, "Jane Citizen", 0.7);
    let mark = ent(EntityKind::Person, "Mark Roe", 0.6);

    let ents = vec![addr, jane.clone(), mark.clone()];
    let edges = derive_co_residence(&ents, "s");
    assert_eq!(
        edges.len(),
        1,
        "one household edge between the two co-residents"
    );
    let e = &edges[0];
    assert_eq!(e.kind, RelationKind::AssociatedWith);
    assert!(
        (e.from_uid == jane.uid && e.to_uid == mark.uid)
            || (e.from_uid == mark.uid && e.to_uid == jane.uid),
        "links the two co-residents"
    );
    // Evidence-grounded co-residence sits between a surname guess (×0.5) and a
    // declared link (×1.0); the surname kinship can't see it (different surnames).
    let min_conf = 0.6; // min(jane 0.7, mark 0.6)
    assert!(
        e.confidence > min_conf * 0.5 && e.confidence < min_conf,
        "confidence {} is evidence-grounded but damped",
        e.confidence
    );
    assert!(derive_kinship(&ents, "s").is_empty());

    // A COARSE postcode/suburb is never a household, even with two named owners.
    let mut coarse = ent(EntityKind::Address, "QLD 4000, Australia", 0.4);
    coarse.tag("postcode-only");
    coarse.add_evidence(Evidence::new("qld_unclaimed", "a").with_attr("owner", "Jane Citizen"));
    coarse.add_evidence(Evidence::new("qld_unclaimed", "b").with_attr("owner", "Mark Roe"));
    assert!(
        derive_co_residence(&[coarse, jane.clone(), mark.clone()], "s").is_empty(),
        "a postcode centroid is not a dwelling"
    );

    // A single resident is no household, and a same-surname co-resident gets BOTH
    // this edge and the kinship one (two angles agreeing on the same pair).
    let solo = {
        let mut a = ent(EntityKind::Address, "9 Lone Way, Cairns QLD 4870", 0.6);
        a.add_evidence(Evidence::new("qld_unclaimed", "r").with_attr("owner", "Jane Citizen"));
        a
    };
    assert!(
        derive_co_residence(&[solo, jane], "s").is_empty(),
        "one name is not a household"
    );
}

/// A Person carrying a `url` source attribute, the join key for co-mention.
fn person_in_source(name: &str, conf: f64, url: &str) -> Entity {
    use crate::core::entity::Evidence;
    let mut e = ent(EntityKind::Person, name, conf);
    e.add_evidence(Evidence::new("search_engines", "result").with_attr("url", url));
    e
}

#[test]
fn co_mention_links_two_people_named_in_the_same_source() {
    // The reverse-engineered Kyle/Erik case: a single source names both, and the
    // engine extracted each separately — co-mention recovers the shared-source tie.
    let kyle = person_in_source("Kyle Diegmann", 0.6, "https://example.com/obituary");
    let erik = person_in_source("Erik Diegmann", 0.5, "https://example.com/obituary");
    let edges = derive_co_mention(&[kyle.clone(), erik.clone()], "s");
    assert_eq!(edges.len(), 1, "one co-mention edge between the two");
    let e = &edges[0];
    assert_eq!(e.kind, RelationKind::AssociatedWith);
    let mut got = [e.from_uid.clone(), e.to_uid.clone()];
    got.sort();
    let mut want = [kyle.uid.clone(), erik.uid.clone()];
    want.sort();
    assert_eq!(got, want, "endpoints are the two co-mentioned persons");
    // Damped: min(0.6, 0.5) × CO_MENTION_DAMP (0.45).
    assert!((e.confidence - 0.5 * 0.45).abs() < 1e-9);
}

#[test]
fn co_mention_ignores_people_in_different_sources() {
    let kyle = person_in_source("Kyle Diegmann", 0.6, "https://a.example/x");
    let erik = person_in_source("Erik Diegmann", 0.5, "https://b.example/y");
    assert!(
        derive_co_mention(&[kyle, erik], "s").is_empty(),
        "no shared source ⇒ no co-mention"
    );
}

#[test]
fn co_mention_skips_crowded_list_sources() {
    // Six people (one more than the cap of 5) ⇒ a directory / round-up, not a
    // relationship document.
    let url = "https://example.com/directory";
    let ents: Vec<Entity> = (0..6)
        .map(|i| person_in_source(&format!("Person Number{i:02}"), 0.6, url))
        .collect();
    assert!(
        derive_co_mention(&ents, "s").is_empty(),
        "a crowded source mints no edges"
    );
}

#[test]
fn co_mention_pairs_a_small_group_deterministically() {
    let url = "https://example.com/family-notice";
    let ents = vec![
        person_in_source("Aaron Diegmann", 0.6, url),
        person_in_source("Beth Diegmann", 0.6, url),
        person_in_source("Carl Diegmann", 0.6, url),
    ];
    let e1 = derive_co_mention(&ents, "s");
    assert_eq!(e1.len(), 3, "three people in one source → C(3,2) = 3 edges");
    // Deterministic under input reordering.
    let mut shuffled = ents.clone();
    shuffled.reverse();
    let e2 = derive_co_mention(&shuffled, "s");
    let ids1: Vec<&str> = e1.iter().map(|r| r.id.as_str()).collect();
    let ids2: Vec<&str> = e2.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(ids1, ids2, "edge set is independent of input order");
}

#[test]
fn derive_all_aggregates_every_structural_derivation() {
    use crate::core::entity::Evidence;
    // A mixed set exercising two independent derivations: a subdomain edge
    // (structural) and a name-lineage edge. `derive_all` must surface both,
    // and exactly the union of the individual passes — so the import paths
    // and the live scan can't diverge on which edges a finished scan carries.
    let parent = ent(EntityKind::Domain, "acme.com", 0.7);
    let sub = ent(EntityKind::Domain, "mail.acme.com", 0.6);
    let person = ent(EntityKind::Person, "Jane Smith", 0.6);
    let mut handle = ent(EntityKind::Username, "jsmith", 0.38);
    handle.tag("name-derived");
    handle.add_evidence(
        Evidence::new("name_intel", "derived").with_attr("source_name", "Jane Smith"),
    );

    let ents = vec![parent, sub, person, handle];
    let all = derive_all(&ents, "s");
    let expected = derive_structural(&ents, "s").len()
        + derive_colocation(&ents, "s").len()
        + derive_resolution(&ents, "s").len()
        + derive_registration(&ents, "s").len()
        + derive_name_lineage(&ents, "s").len()
        + derive_handles(&ents, "s").len()
        + derive_identity_ownership(&ents, "s").len()
        + derive_residency(&ents, "s").len()
        + derive_kinship(&ents, "s").len()
        + derive_co_residence(&ents, "s").len()
        + derive_co_mention(&ents, "s").len()
        + derive_declared_associations(&ents, "s").len();
    assert_eq!(all.len(), expected, "derive_all is the union of every pass");
    assert!(all.iter().any(|r| r.kind == RelationKind::SubdomainOf));
    assert!(all.iter().any(|r| r.kind == RelationKind::DerivedFrom));
    // The handle's `source_name` evidence names the subject, so the identity
    // layer also binds it (Person → handle) — the union must include that pass.
    assert!(all.iter().any(|r| r.kind == RelationKind::IdentifiedBy));

    // No entities → no edges, no panic.
    assert!(derive_all(&[], "s").is_empty());
}

#[test]
fn relation_id_is_deterministic_and_idempotent() {
    let a = Relation::new("uidA", "uidB", RelationKind::SubdomainOf, 0.8, "s1");
    let b = Relation::new("uidA", "uidB", RelationKind::SubdomainOf, 0.8, "s1");
    assert_eq!(a.id, b.id, "same edge → same id (idempotent upsert)");
    assert_eq!(a.id.len(), 64);
}

#[test]
fn relation_id_differs_by_kind_and_direction() {
    let sub = Relation::new("a", "b", RelationKind::SubdomainOf, 1.0, "s");
    let host = Relation::new("a", "b", RelationKind::HostedOn, 1.0, "s");
    let rev = Relation::new("b", "a", RelationKind::SubdomainOf, 1.0, "s");
    assert_ne!(sub.id, host.id);
    assert_ne!(sub.id, rev.id);
}

#[test]
fn confidence_is_clamped() {
    let r = Relation::new("a", "b", RelationKind::HostedOn, 1.5, "s");
    assert!((r.confidence - 1.0).abs() < 1e-9);
}

#[test]
fn subdomain_edge_links_to_closest_present_parent() {
    // a.b.example.com, b.example.com, example.com all present →
    // a.b.example.com should link to b.example.com (closest), not example.com.
    let entities = vec![
        ent(EntityKind::Domain, "a.b.example.com", 0.9),
        ent(EntityKind::Domain, "b.example.com", 0.8),
        ent(EntityKind::Domain, "example.com", 0.7),
    ];
    let rels = derive_structural(&entities, "s");
    let subs: Vec<_> = rels
        .iter()
        .filter(|r| r.kind == RelationKind::SubdomainOf)
        .collect();
    // a.b.example.com → b.example.com ; b.example.com → example.com
    assert_eq!(subs.len(), 2, "got: {subs:?}");
    let a = &entities[0];
    let b = &entities[1];
    let apex = &entities[2];
    assert!(
        subs.iter()
            .any(|r| r.from_uid == a.uid && r.to_uid == b.uid),
        "a.b.example.com should link to closest parent b.example.com"
    );
    assert!(
        subs.iter()
            .any(|r| r.from_uid == b.uid && r.to_uid == apex.uid)
    );
    // It must NOT also link the deepest straight to the apex.
    assert!(
        !subs
            .iter()
            .any(|r| r.from_uid == a.uid && r.to_uid == apex.uid),
        "should link to closest parent only, not skip-level to apex"
    );
}

#[test]
fn email_links_to_present_domain_only() {
    let entities = vec![
        ent(EntityKind::Email, "alice@example.com", 0.8),
        ent(EntityKind::Domain, "example.com", 0.9),
        ent(EntityKind::Email, "bob@absent.com", 0.8), // domain not in set
    ];
    let rels = derive_structural(&entities, "s");
    let belongs: Vec<_> = rels
        .iter()
        .filter(|r| r.kind == RelationKind::BelongsToDomain)
        .collect();
    assert_eq!(
        belongs.len(),
        1,
        "only the email whose domain is present links"
    );
    assert_eq!(belongs[0].from_uid, entities[0].uid);
    assert_eq!(belongs[0].to_uid, entities[1].uid);
    // Edge confidence is the weaker endpoint (0.8).
    assert!((belongs[0].confidence - 0.8).abs() < 1e-9);
}

#[test]
fn url_links_to_domain_stripping_www() {
    let entities = vec![
        ent(EntityKind::Url, "https://www.example.com/path", 0.6),
        ent(EntityKind::Domain, "example.com", 0.9),
    ];
    let rels = derive_structural(&entities, "s");
    let hosted: Vec<_> = rels
        .iter()
        .filter(|r| r.kind == RelationKind::HostedOn)
        .collect();
    assert_eq!(hosted.len(), 1);
    assert_eq!(hosted[0].from_uid, entities[0].uid);
    assert_eq!(hosted[0].to_uid, entities[1].uid);
}

#[test]
fn url_host_matches_domain_exactly_like_entity_normalisation() {
    // domain_key must be the SAME normalisation Domain entities get —
    // including the fixed-point `www.` strip. A hand-rolled single strip
    // left `www.www.example.com` unmatched against `example.com`.
    let entities = vec![
        ent(EntityKind::Url, "https://www.www.example.com/x", 0.6),
        ent(EntityKind::Domain, "example.com", 0.9),
    ];
    let hosted: Vec<_> = derive_structural(&entities, "s")
        .into_iter()
        .filter(|r| r.kind == RelationKind::HostedOn)
        .collect();
    assert_eq!(hosted.len(), 1, "stacked www. labels must still match");
}

#[test]
fn name_lineage_collision_is_deterministic_under_entity_order() {
    use crate::core::entity::Evidence;
    // Person values are not case-folded at normalisation, so two distinct
    // Person entities can share one folded lookup key. The edge target must
    // not depend on input order: highest confidence wins, ties by uid.
    let strong = ent(EntityKind::Person, "Jane Smith", 0.8);
    let weak = ent(EntityKind::Person, "jane smith", 0.4);
    let mut handle = ent(EntityKind::Username, "jsmith", 0.38);
    handle.tag("name-derived");
    handle.add_evidence(
        Evidence::new("name_intel", "derived").with_attr("source_name", "JANE SMITH"),
    );

    let fwd = vec![strong.clone(), weak.clone(), handle.clone()];
    let rev = vec![weak.clone(), strong.clone(), handle.clone()];
    let r1 = derive_name_lineage(&fwd, "s");
    let r2 = derive_name_lineage(&rev, "s");
    assert_eq!(r1.len(), 1);
    assert_eq!(r2.len(), 1);
    assert_eq!(
        r1[0].to_uid, strong.uid,
        "the higher-confidence Person must win the collision"
    );
    assert_eq!(
        r1[0].to_uid, r2[0].to_uid,
        "edge target must be identical regardless of entity order"
    );
}

#[test]
fn no_edges_without_matching_endpoints() {
    // No Domain entities at all → no structural edges.
    let entities = vec![
        ent(EntityKind::Email, "a@x.com", 0.8),
        ent(EntityKind::Url, "https://y.com/", 0.7),
    ];
    let rels = derive_structural(&entities, "s");
    assert!(rels.is_empty());
}

#[test]
fn subdomain_edges_are_label_aligned() {
    // "notexample.com" must NOT be treated as a subdomain of "example.com"
    // (the label-strip walks dot boundaries, so it never matches mid-label).
    let entities = vec![
        ent(EntityKind::Domain, "notexample.com", 0.9),
        ent(EntityKind::Domain, "example.com", 0.8),
    ];
    let subs: Vec<_> = derive_structural(&entities, "s")
        .into_iter()
        .filter(|r| r.kind == RelationKind::SubdomainOf)
        .collect();
    assert!(
        subs.is_empty(),
        "notexample.com is not a subdomain of example.com, got: {subs:?}"
    );
}

#[test]
fn colocation_links_nearby_coordinates() {
    // ~0.24 km apart (Brisbane CBD) → linked.
    let a = ent(EntityKind::Coordinates, "-27.470000,153.020000", 0.9);
    let b = ent(EntityKind::Coordinates, "-27.472000,153.021000", 0.7);
    let rels = derive_colocation(&[a.clone(), b.clone()], "s");
    assert_eq!(rels.len(), 1, "nearby coords should yield one edge");
    assert_eq!(rels[0].kind, RelationKind::CoLocatedWith);
    // Canonical direction: smaller uid → larger.
    let (lo, hi) = if a.uid <= b.uid { (&a, &b) } else { (&b, &a) };
    assert_eq!(rels[0].from_uid, lo.uid);
    assert_eq!(rels[0].to_uid, hi.uid);
    // Edge confidence is the weaker endpoint.
    assert!((rels[0].confidence - 0.7).abs() < 1e-9);
}

#[test]
fn colocation_skips_distant_coordinates() {
    // Brisbane vs Sydney (~730 km) → no edge.
    let a = ent(EntityKind::Coordinates, "-27.470000,153.020000", 0.9);
    let b = ent(EntityKind::Coordinates, "-33.870000,151.210000", 0.9);
    assert!(derive_colocation(&[a, b], "s").is_empty());
}

#[test]
fn colocation_ignores_non_coordinates() {
    let a = ent(EntityKind::Email, "a@x.com", 0.9);
    let b = ent(EntityKind::Domain, "x.com", 0.9);
    assert!(derive_colocation(&[a, b], "s").is_empty());
}

#[test]
fn colocation_one_edge_per_pair() {
    let a = ent(EntityKind::Coordinates, "-27.470000,153.020000", 0.9);
    let b = ent(EntityKind::Coordinates, "-27.470500,153.020500", 0.8);
    assert_eq!(
        derive_colocation(&[a, b], "s").len(),
        1,
        "one edge per pair, not two reversed"
    );
}

// ── derive_resolution (Domain → Ip via DNS evidence) ───────────────────

#[test]
fn resolution_links_domain_to_ip_dns_intel_shape() {
    use crate::core::entity::Evidence;
    // Realistic dns_intel A-record fixture: IpAddress entity carrying a
    // `domain` attribute + the "<TYPE> record for <domain>" summary.
    let mut ip = Entity::new(EntityKind::IpAddress, "93.184.216.34", 0.95, "rel-scan");
    ip.add_evidence(
        Evidence::new("dns_intel", "A record for example.com")
            .with_attr("record_type", "A")
            .with_attr("domain", "example.com")
            .with_attr("ttl_secs", "3600")
            .with_attr("ip_version", "ipv4"),
    );
    let dom = ent(EntityKind::Domain, "example.com", 0.9);
    let rels = derive_resolution(&[ip.clone(), dom.clone()], "s");
    assert_eq!(rels.len(), 1);
    assert_eq!(rels[0].kind, RelationKind::ResolvesTo);
    assert_eq!(rels[0].from_uid, dom.uid, "edge points domain -> ip");
    assert_eq!(rels[0].to_uid, ip.uid);
    assert!((rels[0].confidence - 0.9).abs() < 1e-9); // weaker endpoint
}

#[test]
fn resolution_links_via_summary_only_doh_shape() {
    use crate::core::entity::Evidence;
    // Realistic doh_resolver fixture: domain only in the summary, the sole
    // attribute is record_type. The summary-token path must still link it.
    let mut ip = Entity::new(EntityKind::IpAddress, "1.2.3.4", 0.8, "rel-scan");
    ip.add_evidence(
        Evidence::new("doh_resolver", "A record for example.com").with_attr("record_type", "A"),
    );
    let dom = ent(EntityKind::Domain, "example.com", 0.9);
    let rels = derive_resolution(&[ip, dom], "s");
    assert_eq!(rels.len(), 1, "summary-only domain must still link");
    assert_eq!(rels[0].kind, RelationKind::ResolvesTo);
}

#[test]
fn resolution_no_edge_without_matching_domain_entity() {
    use crate::core::entity::Evidence;
    let mut ip = Entity::new(EntityKind::IpAddress, "1.2.3.4", 0.8, "rel-scan");
    ip.add_evidence(
        Evidence::new("dns_intel", "A record for absent.com").with_attr("domain", "absent.com"),
    );
    // Only an unrelated domain is present.
    let other = ent(EntityKind::Domain, "example.com", 0.9);
    assert!(derive_resolution(&[ip, other], "s").is_empty());
}

#[test]
fn resolution_dedups_repeated_domain_mentions() {
    use crate::core::entity::Evidence;
    let mut ip = Entity::new(EntityKind::IpAddress, "1.2.3.4", 0.9, "rel-scan");
    // Domain appears in both an attr and the summary, across two records.
    ip.add_evidence(
        Evidence::new("dns_intel", "A record for example.com").with_attr("domain", "example.com"),
    );
    ip.add_evidence(
        Evidence::new("dns_intel", "AAAA record for example.com")
            .with_attr("domain", "example.com"),
    );
    let dom = ent(EntityKind::Domain, "example.com", 0.9);
    assert_eq!(
        derive_resolution(&[ip, dom], "s").len(),
        1,
        "one edge per (domain, ip) pair"
    );
}

#[test]
fn resolution_trims_punctuation_from_summary_tokens() {
    use crate::core::entity::Evidence;
    let mut ip = Entity::new(EntityKind::IpAddress, "1.2.3.4", 0.8, "rel-scan");
    // Domain appears wrapped in punctuation in the summary token.
    ip.add_evidence(Evidence::new("doh_resolver", "A record for (example.com),"));
    let dom = ent(EntityKind::Domain, "example.com", 0.9);
    let rels = derive_resolution(&[ip, dom], "s");
    assert_eq!(
        rels.len(),
        1,
        "punctuation-wrapped domain token must still link"
    );
    assert_eq!(rels[0].kind, RelationKind::ResolvesTo);
}

// ── derive_registration (Domain → registrant via WHOIS evidence) ───────

#[test]
fn registration_links_domain_to_registrant_org_and_email() {
    use crate::core::entity::Evidence;
    // Realistic whois fixture: the Domain carries registrant_org +
    // registrant_email attrs (and a registrar that is NOT a registrant),
    // and whois also emits the Organisation + Email entities.
    let mut dom = Entity::new(EntityKind::Domain, "example.com", 0.92, "rel-scan");
    dom.add_evidence(
        Evidence::new("whois", "WHOIS for example.com")
            .with_attr("registrar", "MarkMonitor Inc.")
            .with_attr("registrant_org", "Example Org LLC")
            .with_attr("registrant_email", "admin@example.com"),
    );
    let org = ent(EntityKind::Organisation, "Example Org LLC", 0.72);
    let email = ent(EntityKind::Email, "admin@example.com", 0.78);
    // The registrar is ALSO present as an Organisation entity (as happens
    // in multi-domain scans) — it must NOT be linked as the registrant.
    let registrar = ent(EntityKind::Organisation, "MarkMonitor Inc.", 0.70);
    let rels = derive_registration(
        &[dom.clone(), org.clone(), email.clone(), registrar.clone()],
        "s",
    );
    assert_eq!(
        rels.len(),
        2,
        "registrant org + registrant email; NOT registrar"
    );
    assert!(rels.iter().all(|r| r.kind == RelationKind::RegisteredBy));
    assert!(
        rels.iter().all(|r| r.from_uid == dom.uid),
        "domain -> registrant"
    );
    let targets: Vec<&str> = rels.iter().map(|r| r.to_uid.as_str()).collect();
    assert!(targets.contains(&org.uid.as_str()));
    assert!(targets.contains(&email.uid.as_str()));
    assert!(
        !targets.contains(&registrar.uid.as_str()),
        "registrar must be excluded from registered_by"
    );
}

#[test]
fn registration_no_edge_when_registrant_not_an_entity() {
    use crate::core::entity::Evidence;
    let mut dom = Entity::new(EntityKind::Domain, "example.com", 0.92, "rel-scan");
    dom.add_evidence(
        Evidence::new("whois", "WHOIS for example.com")
            .with_attr("registrant_org", "Nonexistent Org"),
    );
    // No Organisation/Email entity matches → no edge.
    assert!(derive_registration(&[dom], "s").is_empty());
}

#[test]
fn registration_dedups_repeated_registrant() {
    use crate::core::entity::Evidence;
    let mut dom = Entity::new(EntityKind::Domain, "example.com", 0.9, "rel-scan");
    dom.add_evidence(
        Evidence::new("whois", "WHOIS for example.com")
            .with_attr("registrant_org", "Acme Inc")
            .with_attr("admin_org", "Acme Inc"),
    );
    let org = ent(EntityKind::Organisation, "Acme Inc", 0.72);
    assert_eq!(
        derive_registration(&[dom, org], "s").len(),
        1,
        "one edge per (domain, registrant)"
    );
}

// ── Identity relations ───────────────────────────────────────────────────────

#[test]
fn handles_alias_shared_persona_across_platforms() {
    // One persona ("jsmith") across two mailboxes and a username → a 3-clique of
    // AliasOf edges. A different persona and a numeric handle stay unlinked.
    let g1 = ent(EntityKind::Email, "jsmith@gmail.com", 0.7);
    let o1 = ent(EntityKind::Email, "jsmith@outlook.com", 0.6);
    let u1 = ent(EntityKind::Username, "jsmith", 0.5);
    let other = ent(EntityKind::Email, "bobjones@gmail.com", 0.8);
    let numeric = ent(EntityKind::Username, "12345", 0.9); // excluded by persona_key

    let rels = derive_handles(&[g1.clone(), o1.clone(), u1.clone(), other, numeric], "s");
    assert_eq!(rels.len(), 3, "C(3,2) alias edges for the one persona");
    for r in &rels {
        assert_eq!(r.kind, RelationKind::AliasOf);
        assert!(
            r.from_uid <= r.to_uid,
            "canonical direction (smaller uid first)"
        );
    }
    // Idempotent + deterministic: re-deriving yields the same id set & order.
    let again = derive_handles(&[g1, o1, u1], "s");
    let ids: Vec<&str> = rels.iter().map(|r| r.id.as_str()).collect();
    let ids2: Vec<&str> = again.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(ids, ids2);
}

#[test]
fn identity_ownership_evidence_then_fingerprint() {
    use crate::core::entity::Evidence;
    // Subject Person (seed-anchor tagged) + an evidence-named mailbox + a
    // fingerprint-only handle + an unrelated handle that must NOT bind.
    let mut subject = ent(EntityKind::Person, "Kyle Diegmann", 0.9);
    subject.tag("subject");

    // Evidence path: owner attribute names the subject → full-confidence edge.
    let mut owned = ent(EntityKind::Email, "k.d@acme.com", 0.6);
    owned.add_evidence(Evidence::new("breach", "dump").with_attr("owner", "Kyle Diegmann"));

    // Fingerprint path: identity overlap with the subject, no evidence → damped.
    let fp = ent(EntityKind::Username, "kdiegmann", 0.5);

    // Unrelated handle: no evidence, no fingerprint overlap → no edge.
    let unrelated = ent(EntityKind::Username, "zztopfan", 0.5);

    let rels = derive_identity_ownership(
        &[subject.clone(), owned.clone(), fp.clone(), unrelated],
        "s",
    );
    assert_eq!(
        rels.len(),
        2,
        "the named mailbox and the fingerprinted handle"
    );
    for r in &rels {
        assert_eq!(r.kind, RelationKind::IdentifiedBy);
        assert_eq!(
            r.from_uid, subject.uid,
            "Person is the `from` (owner) endpoint"
        );
    }
    let owned_edge = rels.iter().find(|r| r.to_uid == owned.uid).unwrap();
    let fp_edge = rels.iter().find(|r| r.to_uid == fp.uid).unwrap();
    // Evidence edge carries full endpoint trust; fingerprint edge is damped.
    assert!((owned_edge.confidence - 0.6_f64.min(0.9)).abs() < 1e-9);
    assert!(
        fp_edge.confidence < 0.5_f64.min(0.9),
        "fingerprint ownership is a damped candidate"
    );
}

#[test]
fn identity_ownership_fingerprint_only_binds_the_subject() {
    // A NON-subject Person must not accrete a handle by fingerprint alone — only
    // the seed-anchored subject does, so an incidental namesake stays unlinked.
    let nonsubject = ent(EntityKind::Person, "Kyle Diegmann", 0.9); // no `subject` tag
    let handle = ent(EntityKind::Username, "kdiegmann", 0.5);
    assert!(
        derive_identity_ownership(&[nonsubject, handle], "s").is_empty(),
        "fingerprint ownership requires the subject tag"
    );
}

#[test]
fn residency_links_person_to_place_by_owner_and_tag() {
    use crate::core::entity::Evidence;
    // Owner-named address (qld_unclaimed style) → LocatedAt to that Person.
    let person = ent(EntityKind::Person, "Erik Diegmann", 0.5);
    let mut addr = ent(EntityKind::Address, "QLD 4552, Australia", 0.5);
    addr.add_evidence(
        Evidence::new("qld_unclaimed", "unclaimed money").with_attr("owner", "Erik Diegmann"),
    );

    // A coordinate the scan already flagged as the subject's by name → subject.
    let mut subject = ent(EntityKind::Person, "Kyle Diegmann", 0.8);
    subject.tag("subject");
    let mut coord = ent(EntityKind::Coordinates, "-26.65,152.95", 0.4);
    coord.tag("exact-name-match");

    let rels = derive_residency(
        &[person.clone(), addr.clone(), subject.clone(), coord.clone()],
        "s",
    );
    assert_eq!(rels.len(), 2);
    assert!(rels.iter().all(|r| r.kind == RelationKind::LocatedAt));
    assert!(
        rels.iter()
            .any(|r| r.from_uid == person.uid && r.to_uid == addr.uid),
        "owner attribute binds the named person to the address"
    );
    assert!(
        rels.iter()
            .any(|r| r.from_uid == subject.uid && r.to_uid == coord.uid),
        "exact-name-match place binds to the subject"
    );
}

#[test]
fn kinship_links_same_surname_distinct_people() {
    let kyle = ent(EntityKind::Person, "Kyle Diegmann", 0.8);
    let erik = ent(EntityKind::Person, "Erik Diegmann", 0.5);
    let stranger = ent(EntityKind::Person, "Jane Smith", 0.6); // different surname

    let rels = derive_kinship(&[kyle.clone(), erik.clone(), stranger], "s");
    assert_eq!(rels.len(), 1, "one kinship candidate (Kyle ↔ Erik)");
    let r = &rels[0];
    assert_eq!(r.kind, RelationKind::AssociatedWith);
    assert!(r.from_uid <= r.to_uid, "canonical direction");
    // Damped: a surname match is a candidate, not endpoint-strength certainty.
    assert!(
        r.confidence < 0.8_f64.min(0.5),
        "kinship confidence is damped below the endpoints"
    );
}

#[test]
fn kinship_skips_one_person_two_spellings() {
    // The SAME person under two spellings (different uids, identical folded name)
    // is not their own kin — the normalised-name guard drops the pair.
    let a = ent(EntityKind::Person, "Kyle Diegmann", 0.8);
    let b = ent(EntityKind::Person, "kyle diegmann", 0.7); // distinct entity, same identity
    assert!(
        derive_kinship(&[a, b], "s").is_empty(),
        "two spellings of one person are not a kinship pair"
    );
}

#[test]
fn kinship_excludes_short_surnames() {
    // Two-letter surnames alias far too readily (Ng, Le, Xu) — excluded.
    let a = ent(EntityKind::Person, "Bob Ng", 0.6);
    let b = ent(EntityKind::Person, "Al Ng", 0.6);
    assert!(derive_kinship(&[a, b], "s").is_empty());
}

#[test]
fn declared_associations_link_related_and_co_owners() {
    use crate::core::entity::Evidence;
    // A SeekNow relative (related_to) and a qld joint record (co_owner) each
    // declare a relationship to a present Person — bound at FULL trust (declared,
    // not the surname guess), so the edge confidence is the endpoint minimum.
    let subject = ent(EntityKind::Person, "Kyle Diegmann", 0.8);
    let mut rel = ent(EntityKind::Person, "Erik Diegmann", 0.55);
    rel.add_evidence(
        Evidence::new("see_know", "relative").with_attr("related_to", "Kyle Diegmann"),
    );
    let mut curt = ent(EntityKind::Person, "Curt Diegmann", 0.35);
    curt.add_evidence(
        Evidence::new("qld_unclaimed", "owner").with_attr("co_owner", "Hayley Diegmann"),
    );
    let hayley = ent(EntityKind::Person, "Hayley Diegmann", 0.35);

    let rels = derive_declared_associations(
        &[subject.clone(), rel.clone(), curt.clone(), hayley.clone()],
        "s",
    );
    assert_eq!(rels.len(), 2, "related_to + co_owner");
    assert!(rels.iter().all(|r| r.kind == RelationKind::AssociatedWith));
    let connects = |a: &Entity, b: &Entity| {
        let (lo, hi) = if a.uid <= b.uid {
            (&a.uid, &b.uid)
        } else {
            (&b.uid, &a.uid)
        };
        rels.iter().find(|r| &r.from_uid == lo && &r.to_uid == hi)
    };
    let ke = connects(&subject, &rel).expect("related_to binds relative → subject");
    assert!(
        (ke.confidence - 0.55_f64).abs() < 1e-9,
        "declared edge carries full endpoint trust, not a damped guess"
    );
    assert!(
        connects(&curt, &hayley).is_some(),
        "co_owner binds joint owners"
    );
}

#[test]
fn diegmann_family_connects_from_any_seed_angle() {
    // Ground truth: Kyle, Erik, Curt and Hayley Diegmann are connected. A scan
    // seeded on ANY of them surfaces the others (qld_unclaimed surname-broadened
    // search emits each owner as a Person, name_intel anchors the subject), and
    // the relation layer must connect all four regardless of which is the seed —
    // the free, angle-independent family guarantee, proven via graph reachability.
    let family = [
        "Kyle Diegmann",
        "Erik Diegmann",
        "Curt Diegmann",
        "Hayley Diegmann",
    ];
    for &seed in &family {
        // The entity set this seed produces: the subject (exact-name-match) plus
        // the rest as surname family-candidates, exactly as qld_unclaimed emits.
        let ents: Vec<Entity> = family
            .iter()
            .map(|&name| {
                let mut p = ent(
                    EntityKind::Person,
                    name,
                    if name == seed { 0.6 } else { 0.35 },
                );
                p.tag(if name == seed {
                    "exact-name-match"
                } else {
                    "family-candidate"
                });
                p
            })
            .collect();

        let rels = derive_all(&ents, "s");
        // Build an undirected graph over the association edges and BFS from seed.
        let mut adj: std::collections::HashMap<&str, Vec<&str>> = std::collections::HashMap::new();
        for r in rels
            .iter()
            .filter(|r| r.kind == RelationKind::AssociatedWith)
        {
            adj.entry(&r.from_uid).or_default().push(&r.to_uid);
            adj.entry(&r.to_uid).or_default().push(&r.from_uid);
        }
        let subject = ents.iter().find(|e| e.value == seed).unwrap();
        let mut reached = std::collections::HashSet::new();
        let mut stack = vec![subject.uid.as_str()];
        while let Some(u) = stack.pop() {
            if reached.insert(u)
                && let Some(neighbours) = adj.get(u)
            {
                stack.extend(neighbours.iter().copied());
            }
        }
        for e in &ents {
            assert!(
                reached.contains(e.uid.as_str()),
                "seeding on '{seed}': '{}' must be connected to the family graph",
                e.value
            );
        }
    }
}
