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
        RelationKind::SameOperator,
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
    // Rebuild the expected count exactly as derive_all does internally:
    // base passes first, then co-ownership over those base relations.
    let mut base = derive_structural(&ents, "s");
    base.extend(derive_colocation(&ents, "s"));
    base.extend(derive_resolution(&ents, "s"));
    base.extend(derive_registration(&ents, "s"));
    base.extend(derive_name_lineage(&ents, "s"));
    let expected = base.len() + derive_co_ownership(&ents, &base, "s").len();
    assert_eq!(all.len(), expected, "derive_all is the union of every pass");
    assert!(all.iter().any(|r| r.kind == RelationKind::SubdomainOf));
    assert!(all.iter().any(|r| r.kind == RelationKind::DerivedFrom));

    // No entities → no edges, no panic.
    assert!(derive_all(&[], "s").is_empty());
}

// ── derive_co_ownership (SameOperator structural edges) ─────────────────────

fn reg_edge(dom: &Entity, who: &Entity) -> crate::core::relation::Relation {
    Relation::new(
        dom.uid.as_str(),
        who.uid.as_str(),
        RelationKind::RegisteredBy,
        dom.confidence.min(who.confidence),
        "s",
    )
}

fn resolves_edge(dom: &Entity, ip: &Entity) -> Relation {
    Relation::new(
        dom.uid.as_str(),
        ip.uid.as_str(),
        RelationKind::ResolvesTo,
        dom.confidence.min(ip.confidence),
        "s",
    )
}

#[test]
fn co_ownership_shared_registrant_links_two_domains() {
    let dom_a = ent(EntityKind::Domain, "alpha-site.com", 0.8);
    let dom_b = ent(EntityKind::Domain, "beta-site.org", 0.8);
    let registrant = ent(EntityKind::Organisation, "Haigen Enterprises Pty Ltd", 0.9);
    let relations = vec![reg_edge(&dom_a, &registrant), reg_edge(&dom_b, &registrant)];
    let rels = derive_co_ownership(&[dom_a.clone(), dom_b.clone(), registrant], &relations, "s");
    assert_eq!(rels.len(), 1, "one SameOperator edge for the pair");
    assert_eq!(rels[0].kind, RelationKind::SameOperator);
    // Canonical direction: smaller uid → larger uid.
    let (exp_from, exp_to) = if dom_a.uid <= dom_b.uid {
        (&dom_a.uid, &dom_b.uid)
    } else {
        (&dom_b.uid, &dom_a.uid)
    };
    assert_eq!(&rels[0].from_uid, exp_from);
    assert_eq!(&rels[0].to_uid, exp_to);
    assert!((rels[0].confidence - 0.8).abs() < 1e-9);
}

#[test]
fn co_ownership_proxy_registrant_excluded() {
    let dom_a = ent(EntityKind::Domain, "alpha-site.com", 0.8);
    let dom_b = ent(EntityKind::Domain, "beta-site.org", 0.8);
    // "Domains By Proxy" contains "domains by proxy" — a known proxy marker.
    let proxy = ent(EntityKind::Organisation, "Domains By Proxy, LLC", 0.9);
    let relations = vec![reg_edge(&dom_a, &proxy), reg_edge(&dom_b, &proxy)];
    let rels = derive_co_ownership(&[dom_a, dom_b, proxy], &relations, "s");
    assert!(rels.is_empty(), "privacy-proxy registrant must be excluded");
}

#[test]
fn co_ownership_shared_dedicated_ip_links_two_distinct_sites() {
    // 45.33.32.156 — Linode/Akamai static IP; not in CDN prefix table, routable.
    let dom_a = ent(EntityKind::Domain, "alpha-site.com", 0.8);
    let dom_b = ent(EntityKind::Domain, "beta-site.org", 0.8);
    let ip = ent(EntityKind::IpAddress, "45.33.32.156", 0.9);
    let relations = vec![resolves_edge(&dom_a, &ip), resolves_edge(&dom_b, &ip)];
    let rels = derive_co_ownership(&[dom_a.clone(), dom_b.clone(), ip], &relations, "s");
    assert_eq!(rels.len(), 1, "one SameOperator edge for co-hosted pair");
    assert_eq!(rels[0].kind, RelationKind::SameOperator);
}

#[test]
fn co_ownership_cdn_ip_excluded() {
    // 104.16.5.5 — Cloudflare CDN prefix (is_cdn_edge_ip returns true).
    let dom_a = ent(EntityKind::Domain, "alpha-site.com", 0.8);
    let dom_b = ent(EntityKind::Domain, "beta-site.org", 0.8);
    let cdn_ip = ent(EntityKind::IpAddress, "104.16.5.5", 0.9);
    let relations = vec![
        resolves_edge(&dom_a, &cdn_ip),
        resolves_edge(&dom_b, &cdn_ip),
    ];
    let rels = derive_co_ownership(&[dom_a, dom_b, cdn_ip], &relations, "s");
    assert!(rels.is_empty(), "CDN/anycast IP must be excluded");
}

#[test]
fn co_ownership_single_site_subdomains_not_co_owned() {
    // www.example.com and api.example.com on the same IP collapse to one
    // registrable domain (example.com) — must NOT fire.
    let dom_a = ent(EntityKind::Domain, "www.example.com", 0.8);
    let dom_b = ent(EntityKind::Domain, "api.example.com", 0.8);
    let ip = ent(EntityKind::IpAddress, "45.33.32.156", 0.9);
    let relations = vec![resolves_edge(&dom_a, &ip), resolves_edge(&dom_b, &ip)];
    let rels = derive_co_ownership(&[dom_a, dom_b, ip], &relations, "s");
    assert!(
        rels.is_empty(),
        "subdomains of the same registrable domain must not fire as co-ownership"
    );
}

#[test]
fn co_ownership_shared_tracking_id_links_carrying_domains() {
    use crate::core::entity::Evidence;
    let dom_a = ent(EntityKind::Domain, "alpha-site.com", 0.8);
    let dom_b = ent(EntityKind::Domain, "beta-site.org", 0.8);
    let mut tid = ent(EntityKind::TrackingId, "UA-12345678-1", 0.85);
    // Both domains carried the same Google Analytics ID.
    tid.add_evidence(
        Evidence::new("web_crawler", "GA tag on alpha-site.com")
            .with_attr("source_domain", "alpha-site.com"),
    );
    tid.add_evidence(
        Evidence::new("web_crawler", "GA tag on beta-site.org")
            .with_attr("source_domain", "beta-site.org"),
    );
    let rels = derive_co_ownership(&[dom_a.clone(), dom_b.clone(), tid], &[], "s");
    assert_eq!(
        rels.len(),
        1,
        "shared analytics ID links the carrying domains"
    );
    assert_eq!(rels[0].kind, RelationKind::SameOperator);
    let (exp_from, exp_to) = if dom_a.uid <= dom_b.uid {
        (&dom_a.uid, &dom_b.uid)
    } else {
        (&dom_b.uid, &dom_a.uid)
    };
    assert_eq!(&rels[0].from_uid, exp_from);
    assert_eq!(&rels[0].to_uid, exp_to);
}

#[test]
fn co_ownership_same_pair_from_two_sources_emits_one_edge() {
    use crate::core::entity::Evidence;
    // Domains share BOTH a registrant AND a tracking ID — only one SameOperator
    // edge should be produced (the global dedup guard).
    let dom_a = ent(EntityKind::Domain, "alpha-site.com", 0.8);
    let dom_b = ent(EntityKind::Domain, "beta-site.org", 0.8);
    let registrant = ent(EntityKind::Organisation, "Haigen Enterprises Pty Ltd", 0.9);
    let mut tid = ent(EntityKind::TrackingId, "GTM-ABC123", 0.85);
    tid.add_evidence(
        Evidence::new("web_crawler", "GTM on alpha-site.com")
            .with_attr("source_domain", "alpha-site.com"),
    );
    tid.add_evidence(
        Evidence::new("web_crawler", "GTM on beta-site.org")
            .with_attr("source_domain", "beta-site.org"),
    );
    let relations = vec![reg_edge(&dom_a, &registrant), reg_edge(&dom_b, &registrant)];
    let rels = derive_co_ownership(&[dom_a, dom_b, registrant, tid], &relations, "s");
    assert_eq!(
        rels.len(),
        1,
        "same pair from registrant + tracking ID must deduplicate to one edge"
    );
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
