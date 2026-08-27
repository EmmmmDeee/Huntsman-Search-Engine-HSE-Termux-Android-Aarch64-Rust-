#[test]
fn au031_no_fire_when_both_endpoints_flagged() {
    use crate::core::relation::{Relation, RelationKind};
    let a = tagged(
        EntityKind::Domain,
        "evil.example",
        &[crate::core::tags::MALICIOUS],
    );
    let b = tagged(
        EntityKind::Domain,
        "bad.example",
        &[crate::core::tags::THREAT_INTEL],
    );
    let rel = Relation::new(
        a.uid.clone(),
        b.uid.clone(),
        RelationKind::CoLocatedWith,
        0.8,
        "s",
    );
    assert!(rule_au_031_malicious_adjacency(&RuleContext::new(&[a, b]), &[rel], "s", 0).is_empty());
}

#[test]
fn au031_skips_edges_with_missing_endpoints() {
    use crate::core::relation::{Relation, RelationKind};
    // Edge references a uid not in the entity set → no fire, no panic.
    let bad = tagged(
        EntityKind::Domain,
        "evil.example",
        &[crate::core::tags::MALICIOUS],
    );
    let rel = Relation::new(
        "ghost-uid",
        bad.uid.clone(),
        RelationKind::DerivedFrom,
        0.8,
        "s",
    );
    assert!(rule_au_031_malicious_adjacency(&RuleContext::new(&[bad]), &[rel], "s", 0).is_empty());
}

#[test]
fn au031_aggregates_high_fanout_shared_infra() {
    use crate::core::relation::{Relation, RelationKind};
    // One flagged shared IP (CDN) with 30 distinct co-hosted domains: the
    // real-world noise case. Must collapse to ONE Medium aggregate, not 30
    // High rows — while a dedicated node (≤ cap) still fires per-neighbour.
    let bad = tagged(
        EntityKind::IpAddress,
        "104.20.37.187",
        &[crate::core::tags::VULNERABLE],
    );
    let mut entities = vec![bad.clone()];
    let mut rels = Vec::new();
    for i in 0..30 {
        let d = tagged(EntityKind::Domain, &format!("site{i}-merch.example"), &[]);
        rels.push(Relation::new(
            d.uid.clone(),
            bad.uid.clone(),
            RelationKind::DerivedFrom,
            0.8,
            "s",
        ));
        entities.push(d);
    }
    let r = rule_au_031_malicious_adjacency(&RuleContext::new(&entities), &rels, "s", 0);
    assert_eq!(r.len(), 1, "30-way fan-out must aggregate to one finding");
    assert_eq!(r[0].rule_id, "AU-031");
    assert_eq!(r[0].severity, Severity::Medium);
    assert!(r[0].description.contains("30 entities"));
    assert!(r[0].description.contains("shared infrastructure"));
    assert!(r[0].entity_uids.contains(&bad.uid));

    // Deterministic across input orderings (BTreeMap-keyed).
    let mut shuffled = rels.clone();
    shuffled.reverse();
    let r2 = rule_au_031_malicious_adjacency(&RuleContext::new(&entities), &shuffled, "s", 0);
    assert_eq!(r[0].description, r2[0].description);
    assert_eq!(r[0].entity_uids, r2[0].entity_uids);

    // Control: a flagged node with few neighbours stays per-neighbour/High.
    let r3 = rule_au_031_malicious_adjacency(&RuleContext::new(&entities[..4]), &rels[..3], "s", 0);
    assert_eq!(r3.len(), 3);
    assert!(r3.iter().all(|c| c.severity == Severity::High));
}

#[test]
fn au031_benign_infra_verdict_vetoes_adjacency() {
    use crate::core::relation::{Relation, RelationKind};
    // The real case: a Cloudflare edge IP tagged BOTH `vulnerable` (CVE scan
    // of the shared edge) AND `greynoise-riot` (catalogued benign). The
    // GreyNoise verdict wins — no adjacency fires at all (not exploded, not
    // aggregated), and the explosion is killed at its root, not its symptom.
    let bad = tagged(
        EntityKind::IpAddress,
        "104.20.37.187",
        &[crate::core::tags::VULNERABLE, "greynoise-riot"],
    );
    let mut entities = vec![bad.clone()];
    let mut rels = Vec::new();
    for i in 0..30 {
        let d = tagged(EntityKind::Domain, &format!("site{i}.example"), &[]);
        rels.push(Relation::new(
            d.uid.clone(),
            bad.uid.clone(),
            RelationKind::DerivedFrom,
            0.8,
            "s",
        ));
        entities.push(d);
    }
    assert!(
        rule_au_031_malicious_adjacency(&RuleContext::new(&entities), &rels, "s", 0).is_empty(),
        "a GreyNoise-benign shared edge must not anchor adjacency"
    );

    // A genuine high-fan-out MALICIOUS cluster (no benign verdict) stays
    // loud: aggregated, but High — not silently downgraded.
    let evil = tagged(
        EntityKind::Domain,
        "evil.apex",
        &[crate::core::tags::MALICIOUS],
    );
    let mut ents = vec![evil.clone()];
    let mut er = Vec::new();
    for i in 0..20 {
        let s = tagged(EntityKind::Domain, &format!("n{i}.evil.apex"), &[]);
        er.push(Relation::new(
            s.uid.clone(),
            evil.uid.clone(),
            RelationKind::SubdomainOf,
            0.8,
            "s",
        ));
        ents.push(s);
    }
    let rm = rule_au_031_malicious_adjacency(&RuleContext::new(&ents), &er, "s", 0);
    assert_eq!(rm.len(), 1);
    assert_eq!(
        rm[0].severity,
        Severity::High,
        "malicious cluster stays High"
    );
}

// ── AU-032 (graph-aware: co-location cluster) ───────────────────────────

#[test]
fn au032_fires_on_three_node_colocation_cluster() {
    use crate::core::relation::{Relation, RelationKind};
    // Anchored to a real person-fixing source (device GPS) so the coordinates are
    // NOT infrastructure geo; otherwise the co-location edges are (correctly)
    // dropped. See au032_excludes_infrastructure_colocations.
    let mut c1 = Entity::new(EntityKind::Coordinates, "-27.470000,153.020000", 0.9, "s");
    c1.add_evidence(Evidence::new("device_sensors", "gps"));
    let mut c2 = Entity::new(EntityKind::Coordinates, "-27.470500,153.020500", 0.8, "s");
    c2.add_evidence(Evidence::new("device_sensors", "gps"));
    let mut c3 = Entity::new(EntityKind::Coordinates, "-27.471000,153.021000", 0.7, "s");
    c3.add_evidence(Evidence::new("device_sensors", "gps"));
    // Chain c1–c2–c3 → one connected component of 3.
    let rels = vec![
        Relation::new(
            c1.uid.clone(),
            c2.uid.clone(),
            RelationKind::CoLocatedWith,
            0.9,
            "s",
        ),
        Relation::new(
            c2.uid.clone(),
            c3.uid.clone(),
            RelationKind::CoLocatedWith,
            0.9,
            "s",
        ),
    ];
    let r = rule_au_032_colocation_cluster(&RuleContext::new(&[c1, c2, c3]), &rels, "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-032");
    assert_eq!(r[0].severity, Severity::Medium);
    assert_eq!(r[0].entity_uids.len(), 3);
    assert!(r[0].description.contains("3 coordinates"));
}

#[test]
fn au032_excludes_infrastructure_colocations() {
    use crate::core::relation::{Relation, RelationKind};
    // Three co-located datacentre coordinates are infrastructure, not a personal
    // convergence — the co-location edges between them are dropped, so no cluster
    // forms. The same chain, person-anchored, still fires (control).
    let colo = |a: &Entity, b: &Entity| {
        Relation::new(
            a.uid.clone(),
            b.uid.clone(),
            RelationKind::CoLocatedWith,
            0.9,
            "s",
        )
    };

    let mut h1 = Entity::new(EntityKind::Coordinates, "-27.470000,153.020000", 0.9, "s");
    h1.tag(crate::core::tags::HOSTING);
    let mut h2 = Entity::new(EntityKind::Coordinates, "-27.470500,153.020500", 0.8, "s");
    h2.tag(crate::core::tags::HOSTING);
    let mut h3 = Entity::new(EntityKind::Coordinates, "-27.471000,153.021000", 0.7, "s");
    h3.tag(crate::core::tags::HOSTING);
    let rels = vec![colo(&h1, &h2), colo(&h2, &h3)];
    assert!(
        rule_au_032_colocation_cluster(&RuleContext::new(&[h1, h2, h3]), &rels, "s", 0).is_empty(),
        "co-located datacentres must not form a convergence cluster"
    );

    // Control: the same chain, person-anchored, fires.
    let mut a1 = Entity::new(EntityKind::Coordinates, "-27.470000,153.020000", 0.9, "s");
    a1.add_evidence(Evidence::new("device_sensors", "gps"));
    let mut a2 = Entity::new(EntityKind::Coordinates, "-27.470500,153.020500", 0.8, "s");
    a2.add_evidence(Evidence::new("device_sensors", "gps"));
    let mut a3 = Entity::new(EntityKind::Coordinates, "-27.471000,153.021000", 0.7, "s");
    a3.add_evidence(Evidence::new("device_sensors", "gps"));
    let rels2 = vec![colo(&a1, &a2), colo(&a2, &a3)];
    assert_eq!(
        rule_au_032_colocation_cluster(&RuleContext::new(&[a1, a2, a3]), &rels2, "s", 0).len(),
        1,
        "person-anchored co-located coordinates still cluster"
    );
}

#[test]
fn au032_no_fire_on_pair() {
    use crate::core::relation::{Relation, RelationKind};
    let c1 = Entity::new(EntityKind::Coordinates, "-27.470000,153.020000", 0.9, "s");
    let c2 = Entity::new(EntityKind::Coordinates, "-27.470500,153.020500", 0.8, "s");
    let rels = vec![Relation::new(
        c1.uid.clone(),
        c2.uid.clone(),
        RelationKind::CoLocatedWith,
        0.9,
        "s",
    )];
    assert!(rule_au_032_colocation_cluster(&RuleContext::new(&[c1, c2]), &rels, "s", 0).is_empty());
}

#[test]
fn au032_ignores_non_colocation_edges() {
    use crate::core::relation::{Relation, RelationKind};
    // Three domains chained by SubdomainOf — not co-location → no cluster.
    let a = Entity::new(EntityKind::Domain, "a.b.c.com", 0.9, "s");
    let b = Entity::new(EntityKind::Domain, "b.c.com", 0.9, "s");
    let c = Entity::new(EntityKind::Domain, "c.com", 0.9, "s");
    let rels = vec![
        Relation::new(
            a.uid.clone(),
            b.uid.clone(),
            RelationKind::SubdomainOf,
            0.9,
            "s",
        ),
        Relation::new(
            b.uid.clone(),
            c.uid.clone(),
            RelationKind::SubdomainOf,
            0.9,
            "s",
        ),
    ];
    assert!(
        rule_au_032_colocation_cluster(&RuleContext::new(&[a, b, c]), &rels, "s", 0).is_empty()
    );
}

// ── AU-060 (graph-aware: transitive identity closure) ──────────────────────────

#[test]
fn au060_fires_on_two_hop_identity_chain() {
    use crate::core::relation::{Relation, RelationKind};
    // email → domain → person: 2 hops, 1 intermediate node
    let email = Entity::new(EntityKind::Email, "alice@example.com", 0.8, "s");
    let domain = Entity::new(EntityKind::Domain, "example.com", 0.7, "s");
    let person = Entity::new(EntityKind::Person, "Alice Doe", 0.9, "s");
    let rels = [
        Relation::new(
            email.uid.clone(),
            domain.uid.clone(),
            RelationKind::BelongsToDomain,
            0.8,
            "s",
        ),
        Relation::new(
            domain.uid.clone(),
            person.uid.clone(),
            RelationKind::RegisteredBy,
            0.8,
            "s",
        ),
    ];
    let r = rule_au_060_transitive_identity_closure(
        &RuleContext::new(&[email.clone(), domain.clone(), person.clone()]),
        &rels,
        "s",
        0,
    );
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-060");
    assert_eq!(r[0].severity, Severity::Medium);
    assert!(r[0].entity_uids.contains(&email.uid));
    assert!(r[0].entity_uids.contains(&person.uid));
    assert!(r[0].entity_uids.contains(&domain.uid));
    assert!(r[0].description.contains("1 intermediate node"));
}

#[test]
fn au060_no_fire_when_identity_pair_directly_connected() {
    use crate::core::relation::{Relation, RelationKind};
    let email = Entity::new(EntityKind::Email, "alice@example.com", 0.8, "s");
    let person = Entity::new(EntityKind::Person, "Alice Doe", 0.9, "s");
    let rels = [Relation::new(
        email.uid.clone(),
        person.uid.clone(),
        RelationKind::DerivedFrom,
        0.8,
        "s",
    )];
    assert!(
        rule_au_060_transitive_identity_closure(&RuleContext::new(&[email, person]), &rels, "s", 0)
            .is_empty()
    );
}

// ── Crypto / identity / exposure rules (AU-039 … AU-043) ─────────────────────────

/// Build an entity with tags + a single evidence record (with optional attrs).
fn mk_tagged(kind: EntityKind, value: &str, src: &str, tags: &[&str]) -> Entity {
    let mut e = Entity::new(kind, value, 0.8, "scan");
    e.add_evidence(Evidence::new(src, "x".to_string()));
    for t in tags {
        e.tag(*t);
    }
    e
}

#[test]
fn au_039_links_wallet_to_source_related_identity() {
    // Genuine co-location: one stealer log ("hudsonrock") surfaced BOTH the wallet
    // and the account owner, so the same source is stamped on each entity — a real
    // attribution lead the rule reports.
    let ents = vec![
        mk_tagged(
            EntityKind::CryptoAddress,
            "1A1zP1eP...",
            "hudsonrock",
            &["crypto-address"],
        ),
        mk_tagged(EntityKind::Person, "Jordan Avery", "hudsonrock", &[]),
    ];
    let out = rule_au_039_wallet_identity(&RuleContext::new(&ents), "scan", 0);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].rule_id, "AU-039");
    assert_eq!(out[0].severity, Severity::High);
    assert_eq!(out[0].entity_uids.len(), 2);

    // No identity present ⇒ no firing.
    let only_wallet = vec![mk_tagged(
        EntityKind::CryptoAddress,
        "x",
        "chain_intel",
        &[],
    )];
    assert!(rule_au_039_wallet_identity(&RuleContext::new(&only_wallet), "scan", 0).is_empty());

    // Co-existence WITHOUT a shared source is not attribution (T2.39): a wallet
    // from a chain module and a person from a disjoint presence module co-occur in
    // the same scan but were never surfaced together, so no link is fabricated.
    let disjoint = vec![
        mk_tagged(
            EntityKind::CryptoAddress,
            "1A1zP1eP...",
            "chain_intel",
            &["crypto-address"],
        ),
        mk_tagged(EntityKind::Person, "Jordan Avery", "see_know", &[]),
    ];
    assert!(rule_au_039_wallet_identity(&RuleContext::new(&disjoint), "scan", 0).is_empty());
}

#[test]
fn au_039_does_not_attribute_wallet_to_source_unrelated_identity() {
    // T2.39 regression — the core defect: the pre-fix rule anchored every wallet to
    // the single smallest-UID Person across the whole scan, so an unrelated
    // bystander was reported as the wallet's owner purely by UID sort order. Here
    // the wallet + one person come from the same stealer log ("hudsonrock"); a
    // second, unrelated person comes from a disjoint source. We deliberately give
    // the UNRELATED person the smaller UID, so the buggy min-UID pick would name
    // them — the fix must instead pick the source-related person and never the
    // bystander.
    let a = Entity::new(EntityKind::Person, "Aaron Avery", 0.8, "scan");
    let z = Entity::new(EntityKind::Person, "Zoe Zimmer", 0.8, "scan");
    let (small_uid_name, large_uid_name) = if a.uid <= z.uid {
        (a.raw_value.clone(), z.raw_value.clone())
    } else {
        (z.raw_value.clone(), a.raw_value.clone())
    };
    let wallet = mk_tagged(
        EntityKind::CryptoAddress,
        "1A1zP1eP...",
        "hudsonrock",
        &["crypto-address"],
    );
    // Smaller-UID person: UNRELATED (disjoint source, would win the buggy pick).
    let unrelated = mk_tagged(EntityKind::Person, &small_uid_name, "see_know", &[]);
    // Larger-UID person: shares the wallet's source ⇒ the genuine attribution.
    let related = mk_tagged(EntityKind::Person, &large_uid_name, "hudsonrock", &[]);

    let out = rule_au_039_wallet_identity(
        &RuleContext::new(&[wallet.clone(), unrelated.clone(), related.clone()]),
        "scan",
        0,
    );
    assert_eq!(
        out.len(),
        1,
        "only the source-related identity is attributed"
    );
    assert!(out[0].entity_uids.contains(&wallet.uid));
    assert!(
        out[0].entity_uids.contains(&related.uid),
        "attributed to the shared-source person"
    );
    assert!(
        !out[0].entity_uids.contains(&unrelated.uid),
        "never the min-UID bystander"
    );
    // Order-independent: same result whichever order the entities arrive in (the
    // live HashMap-ordered pass and the finalise pass must agree).
    let rev = rule_au_039_wallet_identity(
        &RuleContext::new(&[wallet.clone(), related.clone(), unrelated.clone()]),
        "scan",
        0,
    );
    assert_eq!(out[0].entity_uids, rev[0].entity_uids);
}

#[test]
fn au_039_prefers_tied_person_over_email_and_reports_each_tie() {
    // One stealer log surfaced the wallet, two people, and an email — all sharing
    // the "hudsonrock" source. Person is the more specific identity, so both tied
    // people are reported (each an independent, genuine lead) and the redundant
    // email is suppressed.
    let src = "hudsonrock";
    let wallet = mk_tagged(
        EntityKind::CryptoAddress,
        "1A1zP1eP...",
        src,
        &["crypto-address"],
    );
    let p1 = mk_tagged(EntityKind::Person, "Aaron Avery", src, &[]);
    let p2 = mk_tagged(EntityKind::Person, "Zoe Zimmer", src, &[]);
    let em = mk_tagged(EntityKind::Email, "z@example.com", src, &[]);
    let out = rule_au_039_wallet_identity(
        &RuleContext::new(&[wallet.clone(), p1.clone(), p2.clone(), em.clone()]),
        "scan",
        0,
    );
    assert_eq!(out.len(), 2, "both tied people reported");
    let uids: std::collections::HashSet<_> = out
        .iter()
        .flat_map(|c| c.entity_uids.iter().cloned())
        .collect();
    assert!(uids.contains(&p1.uid) && uids.contains(&p2.uid));
    assert!(
        !uids.contains(&em.uid),
        "email not emitted when a person is tied"
    );

    // Falls back to an email anchor only when NO person is tied.
    let out2 =
        rule_au_039_wallet_identity(&RuleContext::new(&[wallet.clone(), em.clone()]), "scan", 0);
    assert_eq!(out2.len(), 1);
    assert!(out2[0].entity_uids.contains(&em.uid));
}

#[test]
fn au_040_fires_only_on_breach_harvested_wallets() {
    let found_keys_from = |value: &str, provider: &str| {
        let mut e = Entity::new(EntityKind::CryptoAddress, value, 0.8, "scan");
        e.tag("retrieved");
        e.add_evidence(Evidence::new("found_keys", "x").with_attr("source_provider", provider));
        e
    };
    let ents = vec![
        // found_keys harvest from an actual breach pool → genuine exposure.
        found_keys_from("0xleaked", "see-know"),
        // found_keys harvest from chain_intel's OWN explorer response → an
        // explorer artifact, NOT a breach leak (the precision case).
        found_keys_from("0xexplorer", "chain_intel"),
        // Breach-record-field harvest via the shared key-harvest path.
        mk_tagged(
            EntityKind::CryptoAddress,
            "0xfield",
            "oathnet_pro",
            &["crypto-address"],
        ),
        // Pure chain_intel enrichment of a pasted seed — not an exposure.
        mk_tagged(
            EntityKind::CryptoAddress,
            "0xseed",
            "chain_intel",
            &["crypto-address"],
        ),
    ];
    let out = rule_au_040_wallet_breach_exposure(&RuleContext::new(&ents), "scan", 0);
    let fired: HashSet<&String> = out.iter().flat_map(|c| c.entity_uids.iter()).collect();
    let uid = |v: &str| {
        ents.iter()
            .find(|e| e.value == v)
            .expect("should succeed")
            .uid
            .clone()
    };
    assert_eq!(out.len(), 2, "only genuine breach exposures fire: {out:?}");
    assert!(fired.contains(&uid("0xleaked")) && fired.contains(&uid("0xfield")));
    assert!(!fired.contains(&uid("0xexplorer")) && !fired.contains(&uid("0xseed")));
    assert!(out.iter().all(|c| c.severity == Severity::High));
}

#[test]
fn au_041_fires_on_ens_handle() {
    let mut ens = Entity::new(EntityKind::Username, "vitalik", 0.7, "scan");
    ens.tag("ens");
    ens.add_evidence(Evidence::new("chain_intel", "x").with_attr("ens_name", "vitalik.eth"));
    let out = rule_au_041_ens_identity(&RuleContext::new(&[ens]), "scan", 0);
    assert_eq!(out.len(), 1);
    assert!(out[0].description.contains("vitalik.eth"));
    // A plain username (no ens tag) must not fire.
    let plain = mk_tagged(EntityKind::Username, "bob", "username_search", &[]);
    assert!(rule_au_041_ens_identity(&RuleContext::new(&[plain]), "scan", 0).is_empty());
}

// A pgp-linked email carrying the `key_fingerprint` evidence attribute the real
// `pgp` module attaches — the fingerprint AU-042 now partitions on.
fn pgp_email(addr: &str, fpr: &str) -> Entity {
    let mut e = Entity::new(EntityKind::Email, addr, 0.8, "scan");
    e.tag("pgp-linked");
    e.add_evidence(Evidence::new("pgp", "PGP keyserver User ID").with_attr("key_fingerprint", fpr));
    e
}

#[test]
fn au_042_groups_pgp_linked_emails() {
    // Two emails bound to the SAME PGP key group into one same-owner finding.
    let ents = vec![
        pgp_email("alt@work.com", "AAAA1111BBBB2222"),
        pgp_email("other@home.com", "AAAA1111BBBB2222"),
        mk_tagged(EntityKind::Email, "unrelated@x.com", "hibp", &[]),
    ];
    let out = rule_au_042_pgp_email_identity(&RuleContext::new(&ents), "scan", 0);
    assert_eq!(out.len(), 1, "one grouped firing for the shared key");
    assert_eq!(
        out[0].entity_uids.len(),
        2,
        "only the two same-key pgp-linked emails"
    );
    assert_eq!(out[0].severity, Severity::High);
    assert!(out[0].description.contains("AAAA1111BBBB2222"));
}

#[test]
fn au042_does_not_fuse_emails_from_two_distinct_keys() {
    // Key A binds two emails; key B binds two others — potentially two different
    // people. They must NOT be fused into a single four-email "one owner"; each key
    // fires its own finding over only its own emails.
    let ents = vec![
        pgp_email("a1@x.com", "KEYAAAA00000000"),
        pgp_email("a2@x.com", "KEYAAAA00000000"),
        pgp_email("b1@y.com", "KEYBBBB11111111"),
        pgp_email("b2@y.com", "KEYBBBB11111111"),
    ];
    let out = rule_au_042_pgp_email_identity(&RuleContext::new(&ents), "scan", 0);
    assert_eq!(
        out.len(),
        2,
        "one finding per key, not a single fused owner"
    );
    assert!(
        out.iter().all(|c| c.entity_uids.len() == 2),
        "each key binds exactly its own two emails, never all four"
    );
    let key_a = out
        .iter()
        .find(|c| c.description.contains("KEYAAAA00000000"))
        .expect("a finding for key A");
    assert!(
        key_a.description.contains("a1@x.com") && key_a.description.contains("a2@x.com"),
        "key A's finding lists its own two emails: {}",
        key_a.description
    );
    assert!(
        !key_a.description.contains("b1@y.com") && !key_a.description.contains("b2@y.com"),
        "key A's finding must not carry key B's emails: {}",
        key_a.description
    );
}

#[test]
fn au_054_locates_pii_corroboration_scaled_never_high() {
    use super::rules::rule_au_054_data_broker_exposure;

    // Subject across TWO distinct brokers (2 Spokeo URLs + 1 Whitepages) plus an
    // unrelated public URL that must NOT count. One grouped finding.
    let multi = vec![
        mk_tagged(
            EntityKind::Url,
            "https://www.spokeo.com/John-Doe",
            "search_engines",
            &[],
        ),
        mk_tagged(
            EntityKind::Url,
            "https://www.spokeo.com/John-Doe/2",
            "search_engines",
            &[],
        ),
        mk_tagged(
            EntityKind::Url,
            "https://www.whitepages.com/name/John-Doe",
            "search_engines",
            &[],
        ),
        mk_tagged(
            EntityKind::Url,
            "https://github.com/jdoe",
            "github_user",
            &[],
        ),
    ];
    let out = rule_au_054_data_broker_exposure(&RuleContext::new(&multi), "scan", 0);
    assert_eq!(out.len(), 1, "one grouped finding, not one per broker");
    assert_eq!(out[0].rule_id, "AU-054");
    // ≥2 independent brokers → Medium (corroborated), but NEVER High/Critical —
    // brokers are not preferenced over other OSINT.
    assert_eq!(out[0].severity, super::Severity::Medium);
    assert!(out[0].description.contains("Spokeo") && out[0].description.contains("Whitepages"));
    assert!(out[0].description.contains("brokered on"));
    assert!(
        out[0].description.contains("not confirmation"),
        "must caveat broker data as a lead, not confirmation"
    );
    assert!(
        !out[0].description.contains("http"),
        "location finding only — no opt-out/takedown surface"
    );
    assert_eq!(
        out[0].entity_uids.len(),
        3,
        "all broker URLs (2 Spokeo + 1 Whitepages) under one finding"
    );

    // A LONE broker is weak/uncorroborated → Low, so it never outranks real
    // OSINT and is never treated as credible in isolation.
    let single = vec![mk_tagged(
        EntityKind::Url,
        "https://www.spokeo.com/John-Doe",
        "search_engines",
        &[],
    )];
    let out = rule_au_054_data_broker_exposure(&RuleContext::new(&single), "scan", 0);
    assert_eq!(out.len(), 1);
    assert_eq!(
        out[0].severity,
        super::Severity::Low,
        "a single broker listing is low-credibility, never preferenced"
    );

    // No broker exposure → no finding.
    let clean = vec![mk_tagged(
        EntityKind::Url,
        "https://github.com/jdoe",
        "github_user",
        &[],
    )];
    assert!(rule_au_054_data_broker_exposure(&RuleContext::new(&clean), "scan", 0).is_empty());
}

#[test]
fn au_055_flags_owned_primary_accounts_excluding_brokers() {
    use super::rules::rule_au_055_primary_source_accounts;

    // A single confirmed primary-source profile fires (AU-038 needs ≥2 platforms,
    // so a lone owned account was previously invisible) — High, outranking the
    // Low/Medium broker findings of AU-054.
    let single = vec![mk_tagged(
        EntityKind::Url,
        "https://github.com/jdoe",
        "github_user",
        &["public-profile"],
    )];
    let out = rule_au_055_primary_source_accounts(&RuleContext::new(&single), "scan", 0);
    assert_eq!(out.len(), 1, "one grouped finding");
    assert_eq!(out[0].rule_id, "AU-055");
    assert_eq!(out[0].severity, super::Severity::High);
    assert!(out[0].description.contains("github.com"));
    assert!(out[0].description.contains("primary source"));
    assert_eq!(out[0].entity_uids.len(), 1);

    // ≥3 distinct platforms → Critical.
    let many = vec![
        mk_tagged(
            EntityKind::Url,
            "https://github.com/jdoe",
            "github_user",
            &["public-profile"],
        ),
        mk_tagged(
            EntityKind::Url,
            "https://twitter.com/jdoe",
            "search_engines",
            &["social-profile"],
        ),
        mk_tagged(
            EntityKind::Url,
            "https://jdoe.dev/",
            "web_crawler",
            &["personal-site"],
        ),
    ];
    let out = rule_au_055_primary_source_accounts(&RuleContext::new(&many), "scan", 0);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].severity, super::Severity::Critical);
    assert_eq!(out[0].entity_uids.len(), 3);

    // A broker listing tagged as a profile is NOT an owned account — excluded.
    let broker = vec![mk_tagged(
        EntityKind::Url,
        "https://www.spokeo.com/John-Doe",
        "search_engines",
        &["social-profile"],
    )];
    assert!(
        rule_au_055_primary_source_accounts(&RuleContext::new(&broker), "scan", 0).is_empty(),
        "broker host must not count as a subject-controlled account"
    );

    // No owned-account URL → no finding.
    let none = vec![mk_tagged(
        EntityKind::Url,
        "https://github.com/jdoe",
        "github_user",
        &[],
    )];
    assert!(rule_au_055_primary_source_accounts(&RuleContext::new(&none), "scan", 0).is_empty());
}

#[test]
fn au_055_excludes_weak_detection_status_only_guesses() {
    // Regression: a real scan against a guessed username handle produced a
    // CRITICAL "primary-source accounts... the subject controls" finding
    // across 60+ platforms where nearly every hit was `username_search`'s
    // bare-status-code guess (`weak-detection`) — a soft-404/SPA-shell can
    // return HTTP 200 for almost any handle, so this is not a confirmed
    // account. `weak-detection`-tagged hits, even 3+ of them, must not fire
    // this rule at all — a pile of unverified guesses is not a primary
    // source, confirmed or otherwise.
    use super::rules::rule_au_055_primary_source_accounts;

    let all_weak = vec![
        mk_tagged(
            EntityKind::Url,
            "https://onlyfans.com/rob_dorito",
            "streaming_probe",
            &["fans-profile", "weak-detection"],
        ),
        mk_tagged(
            EntityKind::Url,
            "https://twitch.tv/rob_dorito",
            "username_search",
            &["social-profile", "weak-detection"],
        ),
        mk_tagged(
            EntityKind::Url,
            "https://tiktok.com/@rob_dorito",
            "username_search",
            &["social-profile", "weak-detection"],
        ),
    ];
    assert!(
        rule_au_055_primary_source_accounts(&RuleContext::new(&all_weak), "scan", 0).is_empty(),
        "weak-detection (status-only) hits must never count as confirmed primary-source accounts"
    );

    // A single body-marker-verified hit alongside the weak guesses still
    // fires — only the unverified ones are excluded, not the whole rule.
    let mut mixed = all_weak.clone();
    mixed.push(mk_tagged(
        EntityKind::Url,
        "https://github.com/rob_dorito",
        "username_search",
        &["social-profile", "verified-detection"],
    ));
    let out = rule_au_055_primary_source_accounts(&RuleContext::new(&mixed), "scan", 0);
    assert_eq!(out.len(), 1);
    assert_eq!(
        out[0].entity_uids.len(),
        1,
        "only the verified-detection hit counts, none of the weak-detection ones"
    );
    assert!(out[0].description.contains("github.com"));
    assert_eq!(
        out[0].severity,
        super::Severity::High,
        "one confirmed platform is High, not Critical"
    );
}
