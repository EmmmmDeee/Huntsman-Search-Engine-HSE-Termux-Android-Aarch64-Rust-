#[test]
fn au020_fires_for_two_person_entities() {
    let ents = vec![
        Entity::new(EntityKind::Person, "Jane Doe", 0.6, "s"),
        Entity::new(EntityKind::Person, "John Roe", 0.6, "s"),
    ];
    let r = rule_au_020_person_entity_cluster(&RuleContext::new(&ents), "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-020");
    assert_eq!(r[0].severity, Severity::Medium);
}

#[test]
fn au022_fires_for_org_co_located_with_breach() {
    let org = Entity::new(EntityKind::Organisation, "Acme Pty Ltd", 0.7, "s");
    let mut breached = Entity::new(EntityKind::Email, "x@acme.com", 0.6, "s");
    breached.tag("breach");
    let r = rule_au_022_organisation_with_breach(&RuleContext::new(&[org, breached]), "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-022");
    assert_eq!(r[0].severity, Severity::High);
}

#[test]
fn au023_fires_for_person_from_two_identity_sources() {
    let mut p = Entity::new(EntityKind::Person, "Jane Doe", 0.7, "s");
    p.add_evidence(Evidence::new("keybase", "x"));
    p.add_evidence(Evidence::new("github_user", "x"));
    let r = rule_au_023_cross_platform_identity(&RuleContext::new(&[p]), "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-023");
    assert_eq!(r[0].severity, Severity::High);
}

#[test]
fn au024_fires_for_email_with_two_risk_signals() {
    let mut e = Entity::new(EntityKind::Email, "x@y.com", 0.6, "s");
    e.tag("breach");
    e.tag("disposable");
    let r = rule_au_024_email_fraud_signal(&RuleContext::new(&[e]), "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-024");
    assert_eq!(r[0].severity, Severity::High);
}

#[test]
fn au025_fires_for_opencorporates_org_with_person() {
    let mut org = Entity::new(EntityKind::Organisation, "Acme Pty Ltd", 0.7, "s");
    org.tag("opencorporates");
    let person = Entity::new(EntityKind::Person, "Jane Doe", 0.7, "s");
    let r = rule_au_025_corporate_identity_link(&RuleContext::new(&[org, person]), "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-025");
    assert_eq!(r[0].severity, Severity::Medium);
}

#[test]
fn au026_fires_for_address_from_two_geo_sources() {
    let mut a = Entity::new(EntityKind::Address, "1 Main St, Sydney NSW 2000", 0.6, "s");
    a.add_evidence(Evidence::new("geocode", "x"));
    a.add_evidence(Evidence::new("photon", "x"));
    let r = rule_au_026_validated_address(&RuleContext::new(&[a]), "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-026");
    assert_eq!(r[0].severity, Severity::High);
}

#[test]
fn au026_does_not_validate_a_registrant_address_as_the_subjects_own() {
    // Same two independent GEO_SOURCES as the positive case above, but the
    // Address is tagged REGISTRANT (opencorporates/gleif_lei both emit exactly
    // this shape) — an infra/company address, not the subject's own. Must not
    // fire, the same infra-must-not-seed-identity discipline AU-030/018/056/085
    // already apply.
    let mut a = Entity::new(EntityKind::Address, "1 Main St, Sydney NSW 2000", 0.6, "s");
    a.tag(crate::core::tags::REGISTRANT);
    a.add_evidence(Evidence::new("opencorporates", "x"));
    a.add_evidence(Evidence::new("gleif_lei", "x"));
    assert!(
        rule_au_026_validated_address(&RuleContext::new(&[a]), "s", 0).is_empty(),
        "a registrant-tagged address must not be validated as the subject's own"
    );
}

#[test]
fn au028_fires_for_subdomain_takeover_tag() {
    let mut d = Entity::new(EntityKind::Domain, "ghost.example.com", 0.6, "s");
    d.tag("subdomain-takeover");
    let r = rule_au_028_subdomain_takeover_risk(&RuleContext::new(&[d]), "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-028");
    assert_eq!(r[0].severity, Severity::Critical);
}

#[test]
fn au029_fires_for_cloud_storage_vulnerable_tags() {
    let mut e = Entity::new(EntityKind::Url, "https://bucket.s3.amazonaws.com", 0.6, "s");
    e.tag("cloud-storage");
    e.tag(crate::core::tags::VULNERABLE);
    let r = rule_au_029_cloud_storage_exposure(&RuleContext::new(&[e]), "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-029");
    assert_eq!(r[0].severity, Severity::Critical);
}

#[test]
fn au040_fires_for_breach_exposed_wallet() {
    let mut w = Entity::new(EntityKind::CryptoAddress, "0xdeadbeef", 0.6, "s");
    w.add_evidence(Evidence::new("oathnet_pro", "leak"));
    let r = rule_au_040_wallet_breach_exposure(&RuleContext::new(&[w]), "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-040");
    assert_eq!(r[0].severity, Severity::High);
}

#[test]
fn au041_fires_for_ens_tagged_username() {
    let mut u = Entity::new(EntityKind::Username, "vitalik.eth", 0.6, "s");
    u.tag("ens");
    let r = rule_au_041_ens_identity(&RuleContext::new(&[u]), "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-041");
    assert_eq!(r[0].severity, Severity::Medium);
}

#[test]
fn au042_does_not_fire_for_a_single_pgp_linked_email() {
    // A lone pgp-linked email is not multi-email same-owner evidence — a "links 1
    // email to one owner" assertion is degenerate and must not fire (the rule's
    // contract is "two or more addresses bound to the same key").
    let mut e = Entity::new(EntityKind::Email, "x@y.com", 0.6, "s");
    e.tag("pgp-linked");
    e.add_evidence(Evidence::new("pgp", "uid").with_attr("key_fingerprint", "DEADBEEF00000000"));
    assert!(
        rule_au_042_pgp_email_identity(&RuleContext::new(&[e]), "s", 0).is_empty(),
        "one email bound to a key is not a multi-email identity link"
    );
}

#[test]
fn au021_fires_for_api_key_entity() {
    let e = Entity::new(EntityKind::ApiKey, "AKIAIOSFODNN7EXAMPLE", 0.9, "s");
    let r = rule_au_021_api_key_exposure(&RuleContext::new(&[e]), "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-021");
    assert_eq!(r[0].severity, Severity::Critical);
}

#[test]
fn au030_fires_for_three_source_geo_cluster() {
    // Genuine person-anchoring geo sources converging — AU-030 fires.
    let mut c1 = Entity::new(EntityKind::Coordinates, "51.5,0.1", 0.7, "s");
    c1.add_evidence(Evidence::new("geocode", "x"));
    c1.add_evidence(Evidence::new("wigle", "x"));
    let mut c2 = Entity::new(EntityKind::Coordinates, "51.6,0.2", 0.7, "s");
    c2.add_evidence(Evidence::new("exif_geo", "x"));
    let r = rule_au_030_geo_convergence_score(&RuleContext::new(&[c1, c2]), "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-030");
    assert_eq!(r[0].severity, Severity::Medium);

    // H5: the same shape built from IP-geo lookups (the host's location, not the
    // subject's) is infrastructure geo and must NOT manufacture convergence.
    let mut ip1 = Entity::new(EntityKind::Coordinates, "51.5,0.1", 0.7, "s");
    ip1.add_evidence(Evidence::new("ip_geo", "x"));
    ip1.add_evidence(Evidence::new("ipinfo", "x"));
    let mut ip2 = Entity::new(EntityKind::Coordinates, "51.6,0.2", 0.7, "s");
    ip2.add_evidence(Evidence::new("maxmind", "x"));
    assert!(
        rule_au_030_geo_convergence_score(&RuleContext::new(&[ip1, ip2]), "s", 0).is_empty(),
        "IP-geo coordinates are the host's location, not subject geo convergence"
    );
}

#[test]
fn au030_escalates_to_high_for_four_source_geo_convergence() {
    // Four distinct person-anchoring corroborating source NAMES across two
    // coordinate entities → sources.len() == 4 → High. (The ladder counts
    // distinct corroborating source names, not source families or entity
    // count.) Each entity carries an anchoring geo source so neither is dropped
    // as infrastructure geo.
    let mut c1 = Entity::new(EntityKind::Coordinates, "51.5,0.1", 0.7, "s");
    c1.add_evidence(Evidence::new("geocode", "x"));
    c1.add_evidence(Evidence::new("wigle", "x"));
    let mut c2 = Entity::new(EntityKind::Coordinates, "51.6,0.2", 0.7, "s");
    c2.add_evidence(Evidence::new("exif_geo", "x"));
    c2.add_evidence(Evidence::new("photon", "x"));
    let r = rule_au_030_geo_convergence_score(&RuleContext::new(&[c1, c2]), "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-030");
    assert_eq!(r[0].severity, Severity::High);
}

#[test]
fn au030_escalates_to_critical_for_five_source_geo_convergence() {
    // Five distinct corroborating source names → sources.len() == 5 → Critical.
    let mut c1 = Entity::new(EntityKind::Coordinates, "51.5,0.1", 0.7, "s");
    c1.add_evidence(Evidence::new("geocode", "x"));
    c1.add_evidence(Evidence::new("wigle", "x"));
    c1.add_evidence(Evidence::new("mylnikov", "x"));
    let mut c2 = Entity::new(EntityKind::Coordinates, "51.6,0.2", 0.7, "s");
    c2.add_evidence(Evidence::new("exif_geo", "x"));
    c2.add_evidence(Evidence::new("photon", "x"));
    let r = rule_au_030_geo_convergence_score(&RuleContext::new(&[c1, c2]), "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-030");
    assert_eq!(r[0].severity, Severity::Critical);
}

#[test]
fn au062_multipath_corroboration_fires_on_orthogonal_routes() {
    use crate::core::relation::{Relation, RelationKind};
    let mk_rel = |from: &Entity, to: &Entity, kind: RelationKind| {
        Relation::new(from.uid.clone(), to.uid.clone(), kind, 0.8, "s")
    };
    // a↔b joined by two edge-disjoint routes through different source families:
    // a—domain(infra)—b and a—org(identity_registry)—b.
    let a = ent(EntityKind::Email, "a@x.com", 0.8, "s", false);
    let b = ent(EntityKind::Username, "bob", 0.8, "s", false);
    let d = ent(EntityKind::Domain, "x.com", 0.8, "dns_intel", false);
    let o = ent(
        EntityKind::Organisation,
        "Acme Pty",
        0.8,
        "opencorporates",
        false,
    );
    let rels = [
        mk_rel(&a, &d, RelationKind::BelongsToDomain),
        mk_rel(&d, &b, RelationKind::DerivedFrom),
        mk_rel(&a, &o, RelationKind::RegisteredBy),
        mk_rel(&o, &b, RelationKind::DerivedFrom),
    ];
    let out = rule_au_062_multipath_corroboration(&RuleContext::new(&[a, b, d, o]), &rels, "s", 0);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].rule_id, "AU-062");
}

#[test]
fn au063_corroboration_gap_flags_a_lone_transitive_link() {
    use crate::core::relation::{Relation, RelationKind};
    let mk_rel = |from: &Entity, to: &Entity, kind: RelationKind| {
        Relation::new(from.uid.clone(), to.uid.clone(), kind, 0.8, "s")
    };
    // a—domain(infra)—b: a single transitive route, no orthogonal corroboration.
    let a = ent(EntityKind::Email, "a@x.com", 0.8, "s", false);
    let b = ent(EntityKind::Username, "bob", 0.8, "s", false);
    let d = ent(EntityKind::Domain, "x.com", 0.8, "dns_intel", false);
    let rels = [
        mk_rel(&a, &d, RelationKind::BelongsToDomain),
        mk_rel(&d, &b, RelationKind::DerivedFrom),
    ];
    let out = rule_au_063_corroboration_gap(&RuleContext::new(&[a, b, d]), &rels, "s", 0);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].rule_id, "AU-063");
}

#[test]
fn au064_generalized_template_fires_on_a_repeated_route() {
    use crate::core::relation::{Relation, RelationKind};
    let mk_rel = |from: &Entity, to: &Entity, kind: RelationKind| {
        Relation::new(from.uid.clone(), to.uid.clone(), kind, 0.8, "s")
    };
    let mk = |kind: EntityKind, v: &str| Entity::new(kind, v, 0.8, "s");
    // Two pairs share the route Email→belongs_to_domain→Domain→registered_by→Person.
    let e1 = mk(EntityKind::Email, "a@x.com");
    let d1 = mk(EntityKind::Domain, "x.com");
    let p1 = mk(EntityKind::Person, "Alice");
    let e2 = mk(EntityKind::Email, "b@y.com");
    let d2 = mk(EntityKind::Domain, "y.com");
    let p2 = mk(EntityKind::Person, "Bob");
    let rels = [
        mk_rel(&e1, &d1, RelationKind::BelongsToDomain),
        mk_rel(&d1, &p1, RelationKind::RegisteredBy),
        mk_rel(&e2, &d2, RelationKind::BelongsToDomain),
        mk_rel(&d2, &p2, RelationKind::RegisteredBy),
    ];
    let out = rule_au_064_generalized_pathway_template(
        &RuleContext::new(&[e1, d1, p1, e2, d2, p2]),
        &rels,
        "s",
        0,
    );
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].rule_id, "AU-064");
}

#[test]
fn au067_resolved_identity_cluster_fires_on_three_linked_identities() {
    use crate::core::relation::{Relation, RelationKind};
    let mk_rel = |from: &Entity, to: &Entity, kind: RelationKind| {
        Relation::new(from.uid.clone(), to.uid.clone(), kind, 0.8, "s")
    };
    let mk = |kind: EntityKind, v: &str| Entity::new(kind, v, 0.8, "s");
    // Email, person and username all hang off one domain hub → a single
    // transitive equivalence class of three identities (a resolved identity).
    let email = mk(EntityKind::Email, "a@x.com");
    let domain = mk(EntityKind::Domain, "x.com");
    let person = mk(EntityKind::Person, "Alice");
    let uname = mk(EntityKind::Username, "alice");
    let rels = [
        mk_rel(&email, &domain, RelationKind::BelongsToDomain),
        mk_rel(&domain, &person, RelationKind::RegisteredBy),
        mk_rel(&domain, &uname, RelationKind::DerivedFrom),
    ];
    let out = rule_au_067_resolved_identity_cluster(
        &RuleContext::new(&[email, domain, person, uname]),
        &rels,
        "s",
        0,
    );
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].rule_id, "AU-067");
}

#[test]
fn au068_anonymous_sim_fires_on_a_voip_tagged_phone() {
    // hlr_cnam tags a VoIP/virtual-carrier phone `sim-voip`; AU-068 surfaces it.
    let mut phone = Entity::new(EntityKind::Phone, "+61400000000", 0.85, "s");
    phone.tag("sim-voip");
    let out = rule_au_068_anonymous_sim(&RuleContext::new(&[phone]), "s", 0);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].rule_id, "AU-068");
}

#[test]
fn au069_high_integrity_connection_fires_on_an_end_to_end_strong_route() {
    use crate::core::relation::{Relation, RelationKind};
    let edge = |from: &Entity, to: &Entity, c: f64| {
        Relation::new(
            from.uid.clone(),
            to.uid.clone(),
            RelationKind::DerivedFrom,
            c,
            "s",
        )
    };
    let mk = |k: EntityKind, v: &str| Entity::new(k, v, 0.8, "s");
    // email —0.9— person —0.9— username: every link on the route is strong.
    let a = mk(EntityKind::Email, "a@x.com");
    let mid = mk(EntityKind::Person, "Alice");
    let b = mk(EntityKind::Username, "alice");
    let rels = [edge(&a, &mid, 0.9), edge(&mid, &b, 0.9)];
    let out = rule_au_069_high_integrity_connection(&RuleContext::new(&[a, mid, b]), &rels, "s", 0);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].rule_id, "AU-069");
}

#[test]
fn au070_connection_broker_fires_on_a_hub_holding_three_identities() {
    use crate::core::relation::{Relation, RelationKind};
    let edge = |from: &Entity, to: &Entity| {
        Relation::new(
            from.uid.clone(),
            to.uid.clone(),
            RelationKind::DerivedFrom,
            0.8,
            "s",
        )
    };
    let mk = |k: EntityKind, v: &str| Entity::new(k, v, 0.8, "s");
    // A domain hub is the sole link between three identities — its removal would
    // fragment all three, so it is a connection broker.
    let hub = mk(EntityKind::Domain, "x.com");
    let email = mk(EntityKind::Email, "a@x.com");
    let uname = mk(EntityKind::Username, "alice");
    let person = mk(EntityKind::Person, "Bob");
    let rels = [edge(&email, &hub), edge(&uname, &hub), edge(&person, &hub)];
    let out = rule_au_070_connection_broker(
        &RuleContext::new(&[hub, email, uname, person]),
        &rels,
        "s",
        0,
    );
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].rule_id, "AU-070");
}

#[test]
fn au071_robust_identity_cluster_fires_on_a_redundantly_bound_cluster() {
    use crate::core::relation::{Relation, RelationKind};
    let edge = |from: &Entity, to: &Entity| {
        Relation::new(
            from.uid.clone(),
            to.uid.clone(),
            RelationKind::DerivedFrom,
            0.8,
            "s",
        )
    };
    let mk = |k: EntityKind, v: &str| Entity::new(k, v, 0.8, "s");
    // Three identities each bound to TWO shared anchors — removing either leaves
    // them connected via the other, so the cluster has no single point of failure.
    let email = mk(EntityKind::Email, "a@x.com");
    let uname = mk(EntityKind::Username, "alice");
    let person = mk(EntityKind::Person, "Alice");
    let d1 = mk(EntityKind::Domain, "x.com");
    let d2 = mk(EntityKind::Domain, "y.com");
    let rels = [
        edge(&email, &d1),
        edge(&uname, &d1),
        edge(&person, &d1),
        edge(&email, &d2),
        edge(&uname, &d2),
        edge(&person, &d2),
    ];
    let out = rule_au_071_robust_identity_cluster(
        &RuleContext::new(&[email, uname, person, d1, d2]),
        &rels,
        "s",
        0,
    );
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].rule_id, "AU-071");
}

// ── AU-109 — shared-registrant domain co-ownership (relation rule) ──────────

#[test]
fn au109_fires_on_shared_registrant_org() {
    use crate::core::relation::{Relation, RelationKind};
    // Two distinct domains both RegisteredBy the same genuine Organisation →
    // one High co-ownership finding naming both domains and the registrant.
    let d1 = Entity::new(EntityKind::Domain, "alpha-co.example", 0.8, "s");
    let d2 = Entity::new(EntityKind::Domain, "beta-co.example", 0.8, "s");
    let org = Entity::new(EntityKind::Organisation, "Acme Holdings Pty Ltd", 0.8, "s");
    let rels = vec![
        Relation::new(
            d1.uid.clone(),
            org.uid.clone(),
            RelationKind::RegisteredBy,
            0.8,
            "s",
        ),
        Relation::new(
            d2.uid.clone(),
            org.uid.clone(),
            RelationKind::RegisteredBy,
            0.8,
            "s",
        ),
    ];
    let r = rule_au_109_shared_registrant(
        &RuleContext::new(&[d1.clone(), d2.clone(), org.clone()]),
        &rels,
        "s",
        0,
    );
    assert_eq!(r.len(), 1, "shared registrant must fire one correlation");
    assert_eq!(r[0].rule_id, "AU-109");
    assert_eq!(r[0].severity, Severity::High);
    assert!(r[0].entity_uids.contains(&org.uid));
    assert!(r[0].entity_uids.contains(&d1.uid));
    assert!(r[0].entity_uids.contains(&d2.uid));
    assert!(r[0].description.contains("alpha-co.example"));
    assert!(r[0].description.contains("beta-co.example"));
    assert!(r[0].description.contains("Acme Holdings Pty Ltd"));
}

#[test]
fn au109_fires_on_shared_registrant_email() {
    use crate::core::relation::{Relation, RelationKind};
    // A personal (freemail) registrant email shared across two domains is a
    // genuine co-ownership signal — only infra/proxy mailboxes are excluded.
    let d1 = Entity::new(EntityKind::Domain, "one.example", 0.8, "s");
    let d2 = Entity::new(EntityKind::Domain, "two.example", 0.8, "s");
    let email = Entity::new(EntityKind::Email, "owner.person@protonmail.com", 0.8, "s");
    let rels = vec![
        Relation::new(
            d1.uid.clone(),
            email.uid.clone(),
            RelationKind::RegisteredBy,
            0.8,
            "s",
        ),
        Relation::new(
            d2.uid.clone(),
            email.uid.clone(),
            RelationKind::RegisteredBy,
            0.8,
            "s",
        ),
    ];
    let r =
        rule_au_109_shared_registrant(&RuleContext::new(&[d1, d2, email.clone()]), &rels, "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-109");
    assert!(r[0].description.contains("registrant email"));
    assert!(r[0].entity_uids.contains(&email.uid));
}

#[test]
fn au109_no_fire_on_privacy_proxy_registrant() {
    use crate::core::relation::{Relation, RelationKind};
    // The critical false-positive guard: domains sharing a WHOIS privacy proxy
    // (Domains By Proxy / WhoisGuard / an `abuse@` registrar role) must NOT be
    // linked — millions of unrelated domains share these.
    let d1 = Entity::new(EntityKind::Domain, "p1.example", 0.8, "s");
    let d2 = Entity::new(EntityKind::Domain, "p2.example", 0.8, "s");
    let proxy_org = Entity::new(EntityKind::Organisation, "Domains By Proxy, LLC", 0.8, "s");
    let proxy_email = Entity::new(EntityKind::Email, "abuse@whoisguard.com", 0.8, "s");
    for who in [&proxy_org, &proxy_email] {
        let rels = vec![
            Relation::new(
                d1.uid.clone(),
                who.uid.clone(),
                RelationKind::RegisteredBy,
                0.8,
                "s",
            ),
            Relation::new(
                d2.uid.clone(),
                who.uid.clone(),
                RelationKind::RegisteredBy,
                0.8,
                "s",
            ),
        ];
        let r = rule_au_109_shared_registrant(
            &RuleContext::new(&[d1.clone(), d2.clone(), who.clone()]),
            &rels,
            "s",
            0,
        );
        assert!(
            r.is_empty(),
            "privacy-proxy registrant '{}' must not link domains, got {r:?}",
            who.value
        );
    }
}

#[test]
fn au109_no_fire_on_single_domain_or_redacted() {
    use crate::core::relation::{Relation, RelationKind};
    let d1 = Entity::new(EntityKind::Domain, "solo.example", 0.8, "s");
    let org = Entity::new(EntityKind::Organisation, "Solo Trader", 0.8, "s");
    // One domain → no co-ownership.
    let rels = vec![Relation::new(
        d1.uid.clone(),
        org.uid.clone(),
        RelationKind::RegisteredBy,
        0.8,
        "s",
    )];
    assert!(
        rule_au_109_shared_registrant(&RuleContext::new(&[d1.clone(), org]), &rels, "s", 0)
            .is_empty()
    );
    // A "REDACTED FOR PRIVACY" placeholder registrant is excluded even with two
    // domains (substring marker `redacted`/`privacy`).
    let d2 = Entity::new(EntityKind::Domain, "solo2.example", 0.8, "s");
    let redacted = Entity::new(EntityKind::Organisation, "REDACTED FOR PRIVACY", 0.8, "s");
    let rels2 = vec![
        Relation::new(
            d1.uid.clone(),
            redacted.uid.clone(),
            RelationKind::RegisteredBy,
            0.8,
            "s",
        ),
        Relation::new(
            d2.uid.clone(),
            redacted.uid.clone(),
            RelationKind::RegisteredBy,
            0.8,
            "s",
        ),
    ];
    assert!(
        rule_au_109_shared_registrant(&RuleContext::new(&[d1, d2, redacted]), &rels2, "s", 0)
            .is_empty()
    );
}

#[test]
fn au109_deterministic_across_edge_order() {
    use crate::core::relation::{Relation, RelationKind};
    let d1 = Entity::new(EntityKind::Domain, "x.example", 0.8, "s");
    let d2 = Entity::new(EntityKind::Domain, "y.example", 0.8, "s");
    let org = Entity::new(EntityKind::Organisation, "Shared Owner Inc", 0.8, "s");
    let mk = |a: &Entity, b: &Entity| {
        Relation::new(
            a.uid.clone(),
            b.uid.clone(),
            RelationKind::RegisteredBy,
            0.8,
            "s",
        )
    };
    let ents = [d1.clone(), d2.clone(), org.clone()];
    let r1 = rule_au_109_shared_registrant(
        &RuleContext::new(&ents),
        &[mk(&d1, &org), mk(&d2, &org)],
        "s",
        0,
    );
    let r2 = rule_au_109_shared_registrant(
        &RuleContext::new(&ents),
        &[mk(&d2, &org), mk(&d1, &org)],
        "s",
        0,
    );
    assert_eq!(r1.len(), 1);
    assert_eq!(
        r1[0].description, r2[0].description,
        "member-domain ordering must be edge-order-independent"
    );
    assert_eq!(r1[0].entity_uids, r2[0].entity_uids);
}

// ── AU-110 — shared dedicated-IP co-hosting (relation rule) ─────────────────

/// Build a Domain→IpAddress `ResolvesTo` edge for the AU-110 fixtures.
fn resolves(d: &Entity, ip: &Entity) -> crate::core::relation::Relation {
    use crate::core::relation::{Relation, RelationKind};
    Relation::new(
        d.uid.clone(),
        ip.uid.clone(),
        RelationKind::ResolvesTo,
        0.8,
        "s",
    )
}

#[test]
fn au110_fires_on_two_distinct_sites_one_dedicated_ip() {
    // Two DIFFERENT sites on one non-CDN, routable IP → Medium co-hosting lead.
    let d1 = Entity::new(EntityKind::Domain, "alpha-site.com", 0.8, "s");
    let d2 = Entity::new(EntityKind::Domain, "beta-site.org", 0.8, "s");
    let ip = Entity::new(EntityKind::IpAddress, "45.33.32.156", 0.8, "s");
    let rels = vec![resolves(&d1, &ip), resolves(&d2, &ip)];
    let r = rule_au_110_shared_hosting_ip(
        &RuleContext::new(&[d1.clone(), d2.clone(), ip.clone()]),
        &rels,
        "s",
        0,
    );
    assert_eq!(
        r.len(),
        1,
        "two distinct sites on one dedicated IP must fire"
    );
    assert_eq!(r[0].rule_id, "AU-110");
    assert_eq!(r[0].severity, Severity::Medium);
    assert!(r[0].entity_uids.contains(&ip.uid));
    assert!(r[0].entity_uids.contains(&d1.uid));
    assert!(r[0].entity_uids.contains(&d2.uid));
    assert!(r[0].description.contains("45.33.32.156"));
    assert!(r[0].description.contains("alpha-site.com"));
    assert!(r[0].description.contains("beta-site.org"));
}

#[test]
fn au110_no_fire_on_subdomains_of_one_site() {
    // Co-RESIDENCE, not co-ownership: www/api/blog of ONE site share its origin
    // IP. All reduce to one registrable domain → must NOT fire.
    let d1 = Entity::new(EntityKind::Domain, "www.example.com", 0.8, "s");
    let d2 = Entity::new(EntityKind::Domain, "api.example.com", 0.8, "s");
    let d3 = Entity::new(EntityKind::Domain, "blog.example.com", 0.8, "s");
    let ip = Entity::new(EntityKind::IpAddress, "45.33.32.156", 0.8, "s");
    let rels = vec![resolves(&d1, &ip), resolves(&d2, &ip), resolves(&d3, &ip)];
    let r = rule_au_110_shared_hosting_ip(&RuleContext::new(&[d1, d2, d3, ip]), &rels, "s", 0);
    assert!(
        r.is_empty(),
        "one site's own subdomains are co-residence, not co-ownership: {r:?}"
    );
}

#[test]
fn au110_no_fire_on_cdn_or_nonroutable_ip() {
    // Guard 1: a Cloudflare edge (104.16/13) and non-routable IPs each front
    // unrelated sites — co-tenancy, never co-ownership.
    let d1 = Entity::new(EntityKind::Domain, "alpha-site.com", 0.8, "s");
    let d2 = Entity::new(EntityKind::Domain, "beta-site.org", 0.8, "s");
    for ip_val in ["104.16.5.5", "192.168.1.10", "203.0.113.7"] {
        let ip = Entity::new(EntityKind::IpAddress, ip_val, 0.8, "s");
        let rels = vec![resolves(&d1, &ip), resolves(&d2, &ip)];
        let r = rule_au_110_shared_hosting_ip(
            &RuleContext::new(&[d1.clone(), d2.clone(), ip.clone()]),
            &rels,
            "s",
            0,
        );
        assert!(
            r.is_empty(),
            "{ip_val}: CDN/non-routable IP must not link, got {r:?}"
        );
    }
}

#[test]
fn au110_no_fire_on_shared_hosting_fanout() {
    // Guard 3: many distinct sites on one IP → shared hosting, skipped.
    let ip = Entity::new(EntityKind::IpAddress, "45.33.32.156", 0.8, "s");
    let mut ents = vec![ip.clone()];
    let mut rels = Vec::new();
    for i in 0..8 {
        let d = Entity::new(
            EntityKind::Domain,
            format!("site{i}-distinct.com"),
            0.8,
            "s",
        );
        rels.push(resolves(&d, &ip));
        ents.push(d);
    }
    let r = rule_au_110_shared_hosting_ip(&RuleContext::new(&ents), &rels, "s", 0);
    assert!(
        r.is_empty(),
        "8 distinct sites on one IP is shared hosting, not co-ownership: {r:?}"
    );
}

// ── AU-113 — direct-connect origin-candidate unmasking (relation rule) ─────

#[test]
fn au113_fires_when_cdn_apex_has_a_direct_connect_sibling() {
    // apex.com resolves ONLY to a Cloudflare edge; mail.apex.com (an MX
    // sibling) resolves directly to a real, routable IP — a genuine
    // origin-candidate lead.
    let apex = Entity::new(EntityKind::Domain, "apex.com", 0.8, "s");
    let cdn_ip = Entity::new(EntityKind::IpAddress, "104.16.5.5", 0.8, "s");
    let mut mx = Entity::new(EntityKind::Domain, "mail.apex.com", 0.8, "s");
    mx.tag("mx");
    let origin_ip = Entity::new(EntityKind::IpAddress, "45.33.32.156", 0.8, "s");

    let ents = vec![apex.clone(), cdn_ip.clone(), mx.clone(), origin_ip.clone()];
    let rels = vec![resolves(&apex, &cdn_ip), resolves(&mx, &origin_ip)];

    let r = rule_au_113_direct_connect_origin_candidate(&RuleContext::new(&ents), &rels, "s", 0);
    assert_eq!(
        r.len(),
        1,
        "a CDN apex with a direct-connect sibling must fire: {r:?}"
    );
    assert_eq!(r[0].rule_id, "AU-113");
    assert_eq!(r[0].severity, Severity::Medium);
    assert!(r[0].entity_uids.contains(&apex.uid));
    assert!(r[0].entity_uids.contains(&mx.uid));
    assert!(r[0].entity_uids.contains(&origin_ip.uid));
    assert!(r[0].description.contains("apex.com"));
    assert!(r[0].description.contains("mail.apex.com"));
    assert!(r[0].description.contains("45.33.32.156"));
}

#[test]
fn au113_fires_for_a_direct_connect_subdomain_brute_hit() {
    // cpanel.apex.org (subdomain + dns-brute, a direct-connect label) is the
    // sibling here, instead of an MX record.
    let apex = Entity::new(EntityKind::Domain, "apex.org", 0.8, "s");
    let cdn_ip = Entity::new(EntityKind::IpAddress, "172.64.1.1", 0.8, "s");
    let mut cpanel = Entity::new(EntityKind::Domain, "cpanel.apex.org", 0.8, "s");
    cpanel.tag("subdomain");
    cpanel.tag("dns-brute");
    let origin_ip = Entity::new(EntityKind::IpAddress, "45.33.32.156", 0.8, "s");

    let ents = vec![
        apex.clone(),
        cdn_ip.clone(),
        cpanel.clone(),
        origin_ip.clone(),
    ];
    let rels = vec![resolves(&apex, &cdn_ip), resolves(&cpanel, &origin_ip)];

    let r = rule_au_113_direct_connect_origin_candidate(&RuleContext::new(&ents), &rels, "s", 0);
    assert_eq!(
        r.len(),
        1,
        "a direct-connect dns-brute sibling must fire: {r:?}"
    );
    assert!(r[0].description.contains("cpanel.apex.org"));
}

#[test]
fn au113_no_fire_when_apex_is_not_cdn_fronted() {
    // apex.com resolves to an ordinary, non-CDN IP — nothing to unmask.
    let apex = Entity::new(EntityKind::Domain, "apex.com", 0.8, "s");
    let apex_ip = Entity::new(EntityKind::IpAddress, "45.33.32.156", 0.8, "s");
    let mut mx = Entity::new(EntityKind::Domain, "mail.apex.com", 0.8, "s");
    mx.tag("mx");
    let mx_ip = Entity::new(EntityKind::IpAddress, "45.33.32.200", 0.8, "s");

    let ents = vec![apex.clone(), apex_ip.clone(), mx.clone(), mx_ip.clone()];
    let rels = vec![resolves(&apex, &apex_ip), resolves(&mx, &mx_ip)];

    let r = rule_au_113_direct_connect_origin_candidate(&RuleContext::new(&ents), &rels, "s", 0);
    assert!(r.is_empty(), "a non-CDN apex has nothing to unmask: {r:?}");
}

#[test]
fn au113_no_fire_when_sibling_also_resolves_to_a_cdn_edge() {
    // Both apex and its MX sibling sit behind the CDN — no leak.
    let apex = Entity::new(EntityKind::Domain, "apex.com", 0.8, "s");
    let cdn_ip = Entity::new(EntityKind::IpAddress, "104.16.5.5", 0.8, "s");
    let mut mx = Entity::new(EntityKind::Domain, "mail.apex.com", 0.8, "s");
    mx.tag("mx");
    let mx_cdn_ip = Entity::new(EntityKind::IpAddress, "104.16.9.9", 0.8, "s");

    let ents = vec![apex.clone(), cdn_ip.clone(), mx.clone(), mx_cdn_ip.clone()];
    let rels = vec![resolves(&apex, &cdn_ip), resolves(&mx, &mx_cdn_ip)];

    let r = rule_au_113_direct_connect_origin_candidate(&RuleContext::new(&ents), &rels, "s", 0);
    assert!(
        r.is_empty(),
        "an equally CDN-fronted sibling leaks nothing: {r:?}"
    );
}

// ─── AU-111 tests (CDN origin candidate) ──────────────────────────────────────────
