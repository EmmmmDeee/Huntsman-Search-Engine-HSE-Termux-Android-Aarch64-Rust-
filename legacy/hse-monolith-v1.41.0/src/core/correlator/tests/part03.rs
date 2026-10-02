#[test]
fn au013_no_fire_on_one_lan_entity() {
    let entities = vec![tagged(
        EntityKind::IpAddress,
        "192.168.1.1",
        &[crate::core::tags::LOCAL_ARP],
    )];
    assert!(rule_au_013_local_network_discovery(&RuleContext::new(&entities), "s", 0).is_empty());
}

// ── AU-014 ──────────────────────────────────────────────────────────

#[test]
fn au014_fires_on_two_geo_sources() {
    // A real coordinate — not the "0,0" radar sentinel, which is infrastructure
    // geo — anchored by two ANCHORING sources (wigle + device GPS).
    let mut e = Entity::new(EntityKind::Coordinates, "-27.4698,153.0251", 0.9, "s");
    e.add_evidence(Evidence::new("wigle", "test"));
    e.add_evidence(Evidence::new("device_sensors", "test"));
    let r = rule_au_014_geo_cluster(&RuleContext::new(&[e]), "s", 0);
    assert_eq!(r.len(), 1);
}

#[test]
fn au014_excludes_infrastructure_coordinates() {
    // A datacentre/hosting centroid — even corroborated by two geo sources — is
    // NOT a personal geo lead (parity with AU-017). A HOSTING-tagged coordinate,
    // and a bare coordinate whose sources are non-anchoring (ip_geo/ipinfo), are
    // both infrastructure_geo and must be filtered; the same point, person-
    // anchored, still fires.
    let mut hosting = Entity::new(EntityKind::Coordinates, "-27.4698,153.0251", 0.9, "s");
    hosting.tag(crate::core::tags::HOSTING);
    hosting.add_evidence(Evidence::new("ip_geo", "geolocated"));
    hosting.add_evidence(Evidence::new("ipinfo", "geolocated"));
    assert!(
        rule_au_014_geo_cluster(&RuleContext::new(&[hosting]), "s", 0).is_empty(),
        "a hosting-tagged coordinate must not fire AU-014"
    );

    let mut bare = Entity::new(EntityKind::Coordinates, "-27.4698,153.0251", 0.9, "s");
    bare.add_evidence(Evidence::new("ip_geo", "geolocated"));
    bare.add_evidence(Evidence::new("ipinfo", "geolocated"));
    assert!(
        rule_au_014_geo_cluster(&RuleContext::new(&[bare]), "s", 0).is_empty(),
        "a bare IP-geo coordinate (no anchoring source) must not fire AU-014"
    );

    // Control: the same point, anchored by real person-fixing sources, fires.
    let mut anchored = Entity::new(EntityKind::Coordinates, "-27.4698,153.0251", 0.9, "s");
    anchored.add_evidence(Evidence::new("exif_geo", "photo GPS"));
    anchored.add_evidence(Evidence::new("device_sensors", "gps"));
    assert_eq!(
        rule_au_014_geo_cluster(&RuleContext::new(&[anchored]), "s", 0).len(),
        1,
        "an anchored two-source coordinate still fires AU-014"
    );
}

#[test]
fn au014_does_not_count_cooccurring_tags_as_two_sources() {
    // Regression: the `hits.len() >= 2` disjunct bypasses the "corroborating
    // sources only" guard the function's own comment describes, because it
    // counts co-occurring TAGS on one entity rather than independent evidence
    // sources. `wigle::wifi_ap_entities` mints exactly this shape for every
    // WiGLE-trilaterated Wi-Fi AP: ONE Coordinates entity from ONE evidence
    // record (source "wigle"), tagged with BOTH "wifi-observed" and "geoint"
    // (see wigle/mod.rs's own emit site and its test asserting both tags).
    // Before the fix this fired "confirmed by 2 geo source(s)" from a single,
    // uncorroborated database lookup.
    let mut e = Entity::new(
        EntityKind::Coordinates,
        "-27.4766,153.0280",
        crate::core::confidence::HIGH_PLUS,
        "s",
    );
    e.tag("wigle");
    e.tag("wifi-observed");
    e.tag("geoint");
    e.add_evidence(Evidence::new(
        "wigle",
        "WiGLE-observed position of WiFi AP AA:BB:CC:DD:EE:01",
    ));
    assert!(
        rule_au_014_geo_cluster(&RuleContext::new(&[e]), "s", 0).is_empty(),
        "a single WiGLE evidence record must not fire AU-014 on tag co-occurrence alone"
    );
}

#[test]
fn geo_normalize_alone_does_not_over_fire_corroboration_rules() {
    // Regression: a coarse qld_unclaimed geo set, each entity touched only
    // by the deterministic `geo_normalize` enrichment pass, must NOT light
    // up the corroboration rules. Before the fix, geo_normalize counted as a
    // phantom second source and fired AU-003 on every address/centroid plus
    // AU-014 on every centroid and AU-030 across the set — ~20 spurious
    // correlations from a single name search.
    let coarse = |kind, val: &str| -> Entity {
        let mut e = Entity::new(kind, val, 0.30, "s");
        e.add_evidence(Evidence::new("qld_unclaimed", "register record"));
        e.add_evidence(Evidence::new("geo_normalize", "enrichment"));
        e.tag("geoint");
        e
    };
    let ents = vec![
        coarse(EntityKind::Address, "QLD 4552, Australia"),
        coarse(EntityKind::Address, "Maleny, QLD 4552, Australia"),
        coarse(EntityKind::Address, "Booroobin, QLD 4552, Australia"),
        coarse(EntityKind::Coordinates, "-26.72900,152.75540"),
    ];
    let firings = evaluate_rules(&ents, "s");
    let fired = |id: &str| firings.iter().any(|c| c.rule_id == id);
    assert!(
        !fired("AU-003"),
        "geo_normalize must not fabricate high-corroboration (AU-003)"
    );
    assert!(
        !fired("AU-014"),
        "a single-source centroid must not look like a geo cluster (AU-014)"
    );
    assert!(
        !fired("AU-030"),
        "geo_normalize must not be the 3rd source for convergence (AU-030)"
    );
}

// ── AU-015 ──────────────────────────────────────────────────────────

#[test]
fn au015_fires_on_threat_intel_tag() {
    let e = tagged(
        EntityKind::Domain,
        "bad.example",
        &[crate::core::tags::THREAT_INTEL, "ti:malware"],
    );
    let r = rule_au_015_threat_intel_hit(&RuleContext::new(&[e]), "s", 0);
    assert_eq!(r.len(), 1);
    assert!(r[0].description.contains("malware"));
}

#[test]
fn au015_attribution_names_evidence_source_not_otx() {
    let mut e = Entity::new(EntityKind::Domain, "bad.example", 0.9, "s");
    e.tag(crate::core::tags::THREAT_INTEL);
    e.add_evidence(Evidence::new("threatfox", "t"));
    let r = rule_au_015_threat_intel_hit(&RuleContext::new(&[e]), "s", 0);
    assert_eq!(r.len(), 1);
    assert!(r[0].description.contains("threatfox"));
    assert!(!r[0].description.contains("OTX"));
}

#[test]
fn au015_attribution_excludes_non_ti_evidence() {
    let mut e = Entity::new(EntityKind::Domain, "bad.example", 0.9, "s");
    e.tag(crate::core::tags::THREAT_INTEL);
    e.add_evidence(Evidence::new("ip_reputation", "ti-hit"));
    e.add_evidence(Evidence::new("whois", "registry-data"));
    e.add_evidence(Evidence::new("dns_resolver", "a-record"));
    let r = rule_au_015_threat_intel_hit(&RuleContext::new(&[e]), "s", 0);
    assert_eq!(r.len(), 1);
    assert!(r[0].description.contains("ip_reputation"));
    assert!(!r[0].description.contains("whois"));
    assert!(!r[0].description.contains("dns_resolver"));
}

#[test]
fn au015_attribution_falls_back_when_source_unknown() {
    let e = tagged(
        EntityKind::Domain,
        "bad.example",
        &[crate::core::tags::THREAT_INTEL],
    );
    let r = rule_au_015_threat_intel_hit(&RuleContext::new(&[e]), "s", 0);
    assert_eq!(r.len(), 1);
    assert!(r[0].description.contains("curated threat-intel feed"));
}

// ── Cross-cutting ───────────────────────────────────────────────────

#[test]
fn severity_orders_correctly() {
    assert!(Severity::Low < Severity::Medium);
    assert!(Severity::Medium < Severity::High);
    assert!(Severity::High < Severity::Critical);
}

#[test]
fn evaluate_rules_fires_expected_subset() {
    let mut email = Entity::new(EntityKind::Email, "x@y.com", 0.9, "s");
    email.add_evidence(Evidence::new("hudsonrock", "t"));
    email.add_evidence(Evidence::new("xposed_or_not", "t"));
    email.tag("stealer-log");
    let mut domain = tagged(
        EntityKind::Domain,
        "evil.example",
        &[
            crate::core::tags::MALICIOUS,
            crate::core::tags::VULNERABLE,
            crate::core::tags::THREAT_INTEL,
        ],
    );
    domain.add_evidence(Evidence::new(
        "ip_reputation",
        "flagged malicious".to_string(),
    ));
    domain.add_evidence(Evidence::new("threatfox", "c2 domain".to_string()));
    let ip = tagged(EntityKind::IpAddress, "1.1.1.1", &["tor-exit"]);
    let firings = evaluate_rules(&[email, domain, ip], "s");
    let ids: HashSet<&str> = firings.iter().map(|c| c.rule_id.as_str()).collect();
    for expected in &["AU-001", "AU-004", "AU-005", "AU-008", "AU-009", "AU-015"] {
        assert!(
            ids.contains(expected),
            "expected {expected} in firings, got {ids:?}"
        );
    }
}

/// Ground-truth regression guard (real data as a fixture, operator-
/// confirmed): the `jordanavery@gmail.com` identity and the
/// Maleny/Booroobin (QLD 4552) locality are the accurate results, and the
/// engine must cross-correlate them. This pins the full path so a future
/// refactor of the rule set can't silently sever it.
#[test]
fn ground_truth_jordan_avery_identity_and_booroobin_geo() {
    let scan = "ground-truth";
    let id = |kind, val: &str, sources: &[&str]| -> Entity {
        let mut e = Entity::new(kind, val, 0.80, scan);
        for s in sources {
            e.add_evidence(Evidence::new(*s, "ground-truth fixture"));
        }
        e
    };

    // Identity anchor — the email cross-confirmed by two independent
    // modules, plus the username and phone that complete the cluster.
    // NB both sources are genuine *observations* (two breach corpora): a
    // `name_intel` name-permutation is a derivation of the seed, not an
    // independent sighting, so it must not be one of the corroborating two
    // (see `ENRICHMENT_ONLY_SOURCES`) — otherwise a `name × freemail` guess
    // would self-confirm into AU-003.
    let email = id(
        EntityKind::Email,
        "jordanavery@gmail.com",
        &["oathnet_pro", "hibp"],
    );
    let username = id(
        EntityKind::Username,
        "javery88",
        &["username_search", "oathnet_pro"],
    );
    let phone = id(EntityKind::Phone, "+61400000111", &["oathnet_pro"]);
    let person = id(EntityKind::Person, "Jordan Avery", &["name_intel"]);

    // qld_unclaimed surfaces Booroobin at *candidate* confidence (0.40,
    // below the 0.50 expand floor) — a coarse postcode-centroid lead.
    let booroobin_candidate = {
        let mut a = Entity::new(
            EntityKind::Address,
            "Booroobin, QLD 4552, Australia",
            0.40,
            scan,
        );
        a.tag("qld_unclaimed");
        a.tag("geoint");
        a.tag("candidate-suburb");
        a
    };

    // ── Phase 1: identity cross-correlation always holds; the unconfirmed
    //    suburb must NOT yet claim an email↔location linkage. ──
    let mut ents = vec![
        email.clone(),
        username.clone(),
        phone.clone(),
        person.clone(),
        booroobin_candidate,
    ];
    let firings = evaluate_rules(&ents, scan);
    let ids: HashSet<&str> = firings.iter().map(|c| c.rule_id.as_str()).collect();

    // AU-002 ties the email and username into one identity cluster.
    let au002 = firings
        .iter()
        .find(|c| c.rule_id == "AU-002")
        .expect("identity cluster (AU-002) must fire");
    assert!(
        au002.entity_uids.contains(&email.uid),
        "cluster must include the email"
    );
    assert!(
        au002.entity_uids.contains(&username.uid),
        "cluster must include javery88"
    );

    // AU-003 flags the two-source email as high cross-source corroboration.
    assert!(
        firings
            .iter()
            .any(|c| c.rule_id == "AU-003" && c.entity_uids.contains(&email.uid)),
        "the cross-confirmed email must be flagged high-corroboration"
    );

    // Accurate hedging: a 0.40 candidate suburb is below AU-018's 0.50 gate,
    // so the engine must not yet assert identity↔location linkage.
    assert!(
        !ids.contains("AU-018"),
        "unconfirmed candidate suburb must not fire email-location colocation"
    );

    // ── Phase 2: once a second geo source corroborates Booroobin to >=0.50,
    //    the email↔Booroobin linkage the operator validated must fire. ──
    let booroobin_confirmed = {
        let mut a = Entity::new(
            EntityKind::Address,
            "Booroobin, QLD 4552, Australia",
            0.72,
            scan,
        );
        a.tag("qld_unclaimed");
        a.tag("geoint");
        a.add_evidence(Evidence::new("qld_unclaimed", "unclaimed-money register"));
        a.add_evidence(Evidence::new("geocode", "address confirmed"));
        a
    };
    ents.pop(); // drop the candidate
    ents.push(booroobin_confirmed.clone());
    let firings2 = evaluate_rules(&ents, scan);
    let au018 = firings2
        .iter()
        .find(|c| c.rule_id == "AU-018")
        .expect("email-location linkage (AU-018) must fire once geo is corroborated");
    assert!(
        au018.entity_uids.contains(&email.uid),
        "linkage must include jordanavery@gmail.com"
    );
    assert!(
        au018.entity_uids.contains(&booroobin_confirmed.uid),
        "linkage must include the confirmed Booroobin address"
    );
}

/// Ground-truth regression guard (the operator's own `name` scan, after the
/// geo_normalize / qld_unclaimed / name_intel quality fixes). BEFORE the fix
/// this entity set produced **28** correlations — ~19 spurious AU-003 + 4
/// AU-014 + 1 AU-030 fabricated by the `geo_normalize` phantom source over
/// coarse `qld_unclaimed` geo. It must now yield exactly the **four** real
/// cross-source findings (person corroboration, peekyou infra consensus +
/// AU-003, local Wi-Fi) and never resurrect the geo over-fire or fuse the
/// single-source candidate guesses (suburbs / permuted handles+emails) into a
/// false identity (AU-002) or identity↔location (AU-018) cluster.
#[test]
fn ground_truth_erik_avery_scan_yields_only_real_correlations() {
    use std::collections::HashMap;

    let mk = |kind, value: &str, conf: f64, sources: &[&str], tags: &[&str]| -> Entity {
        let mut e = Entity::new(kind, value, conf, "erik");
        for s in sources {
            e.add_evidence(Evidence::new(*s, "ground-truth fixture"));
        }
        for t in tags {
            e.tag(*t);
        }
        e
    };

    let mut ents: Vec<Entity> = Vec::new();
    // ── Genuine cross-source signal ──
    ents.push(mk(
        EntityKind::Person,
        "Erik Avery",
        0.90,
        &["oathnet_pro", "social_probe"],
        &["breach", "social-probed"],
    ));
    // The people-search PLATFORM the scan profiled (its own infra) — well-
    // corroborated infrastructure, but about the platform, not the person.
    ents.push(mk(
        EntityKind::Domain,
        "www.peekyou.com",
        0.95,
        &[
            "cert_intel",
            "crtsh",
            "dns_intel",
            "hackertarget",
            "rdap_domain",
            "shodan",
            "social_probe",
            "urlscan",
            "waf_detect",
            "web_crawler",
            "webserver_banner",
        ],
        &["social-platform", "cloudflare"],
    ));
    ents.push(mk(
        EntityKind::Url,
        "https://www.peekyou.com/erik-avery",
        0.80,
        &["social_probe"],
        &["social-profile"],
    ));
    // Operator's own device / local network (single-source, local-only).
    for m in [
        "94:a6:7e:7d:49:76",
        "94:a6:7e:7d:49:77",
        "ec:d9:09:2c:66:40",
        "96:2a:6f:fc:98:dd",
        "94:a6:7e:7d:49:74",
        "9a:49:14:d1:f3:14",
    ] {
        ents.push(mk(
            EntityKind::MacAddress,
            m,
            0.95,
            &["wifi_intel"],
            &[crate::core::tags::WIFI_AP],
        ));
    }
    ents.push(mk(
        EntityKind::Coordinates,
        "-27.2690125,153.0179605",
        0.97,
        &["device_sensors", "geo_normalize"],
        &["geoint", "device-sensor"],
    ));
    // ── Coarse qld_unclaimed geo — every entity ALSO touched by the
    //    deterministic geo_normalize pass (the phantom-source trap). ──
    ents.push(mk(
        EntityKind::Address,
        "QLD 4552, Australia",
        0.38,
        &["qld_unclaimed", "geo_normalize"],
        &[
            "postcode-only",
            "geoint",
            crate::core::tags::COARSE,
            "exact-name-match",
        ],
    ));
    for pc in ["QLD 4555, Australia", "QLD 4557, Australia"] {
        ents.push(mk(
            EntityKind::Address,
            pc,
            0.32,
            &["qld_unclaimed", "geo_normalize"],
            &[
                "postcode-only",
                "geoint",
                crate::core::tags::COARSE,
                "family-candidate",
            ],
        ));
    }
    for s in [
        "Conondale, QLD 4552, Australia",
        "Curramore, QLD 4552, Australia",
        "Booroobin, QLD 4552, Australia",
        "Maleny, QLD 4552, Australia",
        "Mooloolaba, QLD 4557, Australia",
        "Palmwoods, QLD 4555, Australia",
    ] {
        ents.push(mk(
            EntityKind::Address,
            s,
            0.30,
            &["qld_unclaimed", "geo_normalize"],
            &["candidate-suburb", "geoint", crate::core::tags::COARSE],
        ));
    }
    for c in [
        "-26.68330,152.96670",
        "-26.72900,152.75540",
        "-26.68330,153.11670",
    ] {
        ents.push(mk(
            EntityKind::Coordinates,
            c,
            0.30,
            &["qld_unclaimed", "geo_normalize"],
            &["geoint", "postcode-centroid", crate::core::tags::COARSE],
        ));
    }
    // ── name_intel permutations (single-source Candidate guesses) ──
    for u in ["erikavery", "eavery", "erik_avery", "erik.avery", "erikd"] {
        ents.push(mk(
            EntityKind::Username,
            u,
            0.38,
            &["name_intel"],
            &["derived", "name-derived"],
        ));
    }
    for em in [
        "erikavery@gmail.com",
        "erik.avery@gmail.com",
        "eavery@gmail.com",
    ] {
        ents.push(mk(
            EntityKind::Email,
            em,
            0.30,
            &["name_intel"],
            &["derived", "permuted"],
        ));
    }

    let firings = evaluate_rules(&ents, "erik");
    let summary: Vec<(&str, &str)> = firings
        .iter()
        .map(|c| (c.rule_id.as_str(), c.description.as_str()))
        .collect();

    // Real correlations — nothing fabricated. AU-045: "Erik Avery" is
    // corroborated by oathnet_pro (breach) AND social_probe (social) — two
    // independent service families. AU-054: the subject's own listing at
    // peekyou.com/erik-avery is a genuine data-location finding. AU-061: the
    // two family-candidate Avery addresses (QLD 4555/4557) resolve to within
    // ~150 km of the subject's confirmed Brisbane fix. AU-076: the email
    // local-parts of erikavery@gmail.com / erik.avery@gmail.com / eavery@
    // canonically match username entities in the fixture — free offline
    // identity bridges, all correct (the emails *are* the login handles).
    assert!(
        firings.len() >= 7,
        "expected at least 7 real correlations, got: {summary:#?}"
    );

    let fired: HashSet<&str> = firings.iter().map(|c| c.rule_id.as_str()).collect();
    assert!(
        fired.contains("AU-003"),
        "person + peekyou cross-source corroboration"
    );
    assert!(fired.contains("AU-010"), "peekyou infrastructure consensus");
    assert!(fired.contains("AU-013"), "local Wi-Fi AP discovery");
    assert!(
        fired.contains("AU-045"),
        "Erik Avery confirmed across breach + social families"
    );
    // The free family geo-corroboration: surname kin in the subject's area.
    assert!(
        fired.contains("AU-061"),
        "family-candidates geo-corroborated near the subject's fix"
    );
    let au061 = firings
        .iter()
        .find(|c| c.rule_id == "AU-061")
        .expect("family-candidates near the subject's fix → AU-061");
    assert!(
        au061.description.contains("family-candidate") && au061.description.contains("4555"),
        "AU-061 names the geo-corroborated relatives: {}",
        au061.description
    );
    // The location finding: subject's PII brokered on a people-search site.
    let au054 = firings
        .iter()
        .find(|c| c.rule_id == "AU-054")
        .expect("subject's PII located on peekyou.com → AU-054");
    assert!(
        au054.description.contains("PeekYou") && au054.description.contains("brokered on"),
        "AU-054 must name the broker as a data-location finding: {}",
        au054.description
    );

    // The fix holds: no geo over-fire, no fused identity/location from guesses.
    for absent in ["AU-002", "AU-014", "AU-018", "AU-030"] {
        assert!(
            !fired.contains(absent),
            "{absent} must not fire on coarse/candidate noise: {summary:#?}"
        );
    }

    // AU-003 may only flag the corroborated person + domain — NEVER a coarse
    // geo entity (the exact phantom-`geo_normalize`-source regression). Two
    // firings, both non-geo.
    let kind_by_uid: HashMap<&str, &EntityKind> =
        ents.iter().map(|e| (e.uid.as_str(), &e.kind)).collect();
    let au003: Vec<&Correlation> = firings.iter().filter(|c| c.rule_id == "AU-003").collect();
    assert_eq!(au003.len(), 2, "AU-003 only on the person + peekyou domain");
    for c in au003 {
        for uid in &c.entity_uids {
            let kind = kind_by_uid.get(uid.as_str()).expect("uid in fixture");
            assert!(
                matches!(kind, EntityKind::Person | EntityKind::Domain),
                "AU-003 must not flag a coarse {kind:?} as corroborated"
            );
        }
    }
}

#[test]
fn rule_016_breach_ip_geo_chain_fires() {
    let mut ip = Entity::new(EntityKind::IpAddress, "101.169.42.148", 0.72, "s");
    ip.tag("breach");
    let mut coord = Entity::new(EntityKind::Coordinates, "-27.5567,152.2767", 0.65, "s");
    coord.add_evidence(Evidence::new(
        "ip_geo",
        "Geolocation for 101.169.42.148: Gatton, QLD",
    ));
    let firings = rule_au_016_breach_ip_geo_chain(&RuleContext::new(&[ip, coord]), "s", 0);
    assert_eq!(firings.len(), 1);
    assert_eq!(firings[0].rule_id, "AU-016");
}

#[test]
fn rule_016_no_fire_without_breach_tag() {
    let ip = Entity::new(EntityKind::IpAddress, "1.2.3.4", 0.72, "s");
    let coord = Entity::new(EntityKind::Coordinates, "1.0,2.0", 0.65, "s");
    let firings = rule_au_016_breach_ip_geo_chain(&RuleContext::new(&[ip, coord]), "s", 0);
    assert!(firings.is_empty());
}

#[test]
fn rule_016_does_not_chain_on_substring_ip_match() {
    // Breach IP 1.2.3.4 must NOT chain to a coordinate geolocated from the
    // unrelated 11.2.3.45 (which contains "1.2.3.4" as a substring). A bare
    // `contains` would mis-fire this High finding.
    let mut breach = Entity::new(EntityKind::IpAddress, "1.2.3.4", 0.72, "s");
    breach.tag("breach");
    let mut coord = Entity::new(EntityKind::Coordinates, "-27.55,152.27", 0.65, "s");
    coord.add_evidence(Evidence::new(
        "ip_geo",
        "Geolocation for 11.2.3.45: Gatton, QLD",
    ));
    assert!(
        rule_au_016_breach_ip_geo_chain(&RuleContext::new(&[breach, coord]), "s", 0).is_empty(),
        "substring IP match must not chain"
    );

    // A trailing ':' (IP: city / IP:port) is still a legitimate whole-IP match.
    let mut breach2 = Entity::new(EntityKind::IpAddress, "1.2.3.4", 0.72, "s");
    breach2.tag("breach");
    let mut coord2 = Entity::new(EntityKind::Coordinates, "-27.55,152.27", 0.65, "s");
    coord2.add_evidence(Evidence::new(
        "ip_geo",
        "Geolocation for 1.2.3.4: Gatton, QLD",
    ));
    assert_eq!(
        rule_au_016_breach_ip_geo_chain(&RuleContext::new(&[breach2, coord2]), "s", 0).len(),
        1,
        "exact whole-IP match (even followed by ':') must still chain"
    );
}

// A coordinate anchored to a real person-fixing source (EXIF/device GPS), so it
// passes the is_infrastructure_geo guard AU-017/AU-057 now share with AU-030/099.
fn anchored_coord(value: &str, conf: f64) -> Entity {
    let mut e = Entity::new(EntityKind::Coordinates, value, conf, "s");
    e.add_evidence(crate::core::entity::Evidence::new("exif_geo", "photo GPS"));
    e
}

#[test]
fn rule_017_multi_geo_convergence_fires() {
    let c1 = anchored_coord("-27.55,152.27", 0.60);
    let c2 = anchored_coord("-27.60,152.30", 0.65);
    let firings = rule_au_017_multi_geo_convergence(&RuleContext::new(&[c1, c2]), "s", 0);
    assert_eq!(firings.len(), 1);
    assert_eq!(firings[0].rule_id, "AU-017");
    assert!(firings[0].description.contains("converge"));
}

#[test]
fn rule_017_no_fire_for_distant_coords() {
    let c1 = anchored_coord("-27.55,152.27", 0.60);
    let c2 = anchored_coord("-33.86,151.20", 0.65);
    let firings = rule_au_017_multi_geo_convergence(&RuleContext::new(&[c1, c2]), "s", 0);
    assert!(firings.is_empty());
}

#[test]
fn rule_017_excludes_infrastructure_coordinates() {
    // Two hosting-datacentre coordinates within convergence distance must NOT
    // fuse into a "subject physically located here" finding — parity with
    // AU-030/AU-099. A bare IP-geo/hosting coordinate locates the infra, not the
    // person. The same geometry, person-anchored, still fires (control).
    let mut h1 = Entity::new(EntityKind::Coordinates, "-27.55,152.27", 0.60, "s");
    h1.tag(crate::core::tags::HOSTING);
    let mut h2 = Entity::new(EntityKind::Coordinates, "-27.60,152.30", 0.65, "s");
    h2.tag(crate::core::tags::HOSTING);
    assert!(
        rule_au_017_multi_geo_convergence(&RuleContext::new(&[h1, h2]), "s", 0).is_empty(),
        "infrastructure coordinates must not converge into a subject location"
    );
    // A bare coordinate with no anchoring source is also infrastructure.
    let b1 = Entity::new(EntityKind::Coordinates, "-27.55,152.27", 0.60, "s");
    let b2 = Entity::new(EntityKind::Coordinates, "-27.60,152.30", 0.65, "s");
    assert!(rule_au_017_multi_geo_convergence(&RuleContext::new(&[b1, b2]), "s", 0).is_empty());
    // Control: the same points, person-anchored, DO converge.
    assert_eq!(
        rule_au_017_multi_geo_convergence(
            &RuleContext::new(&[
                anchored_coord("-27.55,152.27", 0.60),
                anchored_coord("-27.60,152.30", 0.65)
            ]),
            "s",
            0
        )
        .len(),
        1
    );
}

#[test]
fn rule_017_clustering_is_order_independent() {
    // Chain geometry: A-B within 0.5 deg, B-C within 0.5 deg, A-C beyond it.
    // The greedy assignment compares against each cluster's FOUNDING member,
    // so without a deterministic pre-sort the input order decided whether the
    // chain clustered as {A,B}+{C} or {A,B,C} — and the live pass feeds
    // entities in HashMap (randomised) order, persisting conflicting AU-017
    // uid sets across rounds. Every permutation must now produce identical
    // firings.
    let a = anchored_coord("1.00,0.00", 0.60);
    let b = anchored_coord("1.40,0.00", 0.60);
    let c = anchored_coord("1.80,0.00", 0.60);
    let uid_sets = |ents: &[Entity]| -> Vec<Vec<String>> {
        rule_au_017_multi_geo_convergence(&RuleContext::new(ents), "s", 0)
            .into_iter()
            .map(|f| {
                let mut u = f.entity_uids;
                u.sort();
                u
            })
            .collect()
    };
    let baseline = uid_sets(&[a.clone(), b.clone(), c.clone()]);
    for perm in [
        vec![a.clone(), c.clone(), b.clone()],
        vec![b.clone(), a.clone(), c.clone()],
        vec![b.clone(), c.clone(), a.clone()],
        vec![c.clone(), a.clone(), b.clone()],
        vec![c.clone(), b.clone(), a.clone()],
    ] {
        assert_eq!(
            uid_sets(&perm),
            baseline,
            "AU-017 clusters must not depend on entity iteration order"
        );
    }
}

#[test]
fn rule_017_drops_out_of_range_coordinates() {
    // Junk coordinates (lat/lon outside Earth's range) must be rejected by the
    // range-validating parse_coords helper, not clustered as a convergence.
    let junk1 = Entity::new(EntityKind::Coordinates, "200.0,300.0", 0.60, "s");
    let junk2 = Entity::new(EntityKind::Coordinates, "201.0,301.0", 0.65, "s");
    let firings = rule_au_017_multi_geo_convergence(&RuleContext::new(&[junk1, junk2]), "s", 0);
    assert!(firings.is_empty(), "out-of-range coords must not converge");
}

// ── AU-031 (graph-aware: relation edges) ────────────────────────────

#[test]
fn au031_fires_on_edge_to_malicious_node() {
    use crate::core::relation::{Relation, RelationKind};
    let bad = tagged(
        EntityKind::Domain,
        "evil.example",
        &[crate::core::tags::MALICIOUS],
    );
    let benign = tagged(EntityKind::Domain, "blog.evil.example", &[]);
    let rel = Relation::new(
        benign.uid.clone(),
        bad.uid.clone(),
        RelationKind::SubdomainOf,
        0.8,
        "s",
    );
    let r = rule_au_031_malicious_adjacency(
        &RuleContext::new(&[bad.clone(), benign.clone()]),
        &[rel],
        "s",
        0,
    );
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-031");
    assert_eq!(r[0].severity, Severity::High);
    assert!(r[0].entity_uids.contains(&benign.uid));
    assert!(r[0].entity_uids.contains(&bad.uid));
    assert!(r[0].description.contains("blog.evil.example"));
    assert!(r[0].description.contains("malicious"));
}

#[test]
fn au031_no_fire_when_neither_endpoint_flagged() {
    use crate::core::relation::{Relation, RelationKind};
    let a = tagged(EntityKind::Domain, "a.example", &[]);
    let b = tagged(EntityKind::Domain, "example", &[]);
    let rel = Relation::new(
        a.uid.clone(),
        b.uid.clone(),
        RelationKind::SubdomainOf,
        0.8,
        "s",
    );
    assert!(rule_au_031_malicious_adjacency(&RuleContext::new(&[a, b]), &[rel], "s", 0).is_empty());
}
