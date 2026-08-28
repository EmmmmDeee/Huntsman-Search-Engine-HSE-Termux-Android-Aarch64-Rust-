fn cdn_fronted_domain(value: &str, provider: &str) -> Entity {
    let mut d = Entity::new(EntityKind::Domain, value, 0.9, "s");
    d.tag("waf-detected");
    d.tag(format!("waf:{provider}"));
    d.add_evidence(Evidence::new(
        "waf_detect",
        format!("WAF/CDN detected: {provider}"),
    ));
    d
}

fn spf_ip(value: &str, for_domain: &str) -> Entity {
    let mut ip = Entity::new(EntityKind::IpAddress, value, 0.75, "s");
    ip.tag("dns");
    ip.tag("spf");
    ip.add_evidence(
        Evidence::new(
            "dns_intel",
            format!("SPF authorised sender for {for_domain}"),
        )
        .with_attr("domain", for_domain),
    );
    ip
}

#[test]
fn au111_fires_on_cloudflare_fronted_domain_with_spf_ip() {
    let dom = cdn_fronted_domain("example.com", "Cloudflare");
    let ip = spf_ip("203.0.113.9", "example.com");
    let r = rule_au_111_cdn_origin_candidate(&RuleContext::new(&[dom.clone(), ip.clone()]), "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-111");
    assert_eq!(r[0].severity, super::Severity::Medium);
    assert!(r[0].description.contains("example.com"));
    assert!(r[0].description.contains("203.0.113.9"));
    assert!(r[0].description.contains("Cloudflare"));
    assert_eq!(
        r[0].entity_uids,
        vec![dom.uid.clone(), ip.uid.clone()],
        "the fronted domain and the origin-candidate IP are both cited"
    );
}

#[test]
fn au111_matches_domain_identity_case_insensitively() {
    // The "domain" evidence attribute another module stamps is not uniformly
    // normalised (dns_intel::resolve sets it straight from the raw seed
    // value), while waf_detect's own Domain entity value IS lowercased. A
    // mixed-case seed must still match instead of silently non-matching on a
    // raw string `==`.
    let dom = cdn_fronted_domain("example.com", "Cloudflare");
    let ip = spf_ip("203.0.113.9", "Example.com");
    let r = rule_au_111_cdn_origin_candidate(&RuleContext::new(&[dom, ip]), "s", 0);
    assert_eq!(
        r.len(),
        1,
        "a case-differing but identical domain must still match"
    );
    assert_eq!(r[0].rule_id, "AU-111");
}

#[test]
fn au111_fires_for_cloudfront_and_incapsula_using_waf_detect_names() {
    // Regression: the fronting-provider list must use the EXACT strings
    // `waf_detect` emits (`AWS CloudFront`, `Imperva/Incapsula`). An earlier list
    // had `CloudFront`/`Incapsula`, so `has_tag("waf:CloudFront")` never matched
    // the real `waf:AWS CloudFront` tag and AU-111 silently never fired for those
    // two global CDNs — the SPF-origin-leak pivot was lost. `cdn_fronted_domain`
    // fabricates the tag exactly as `waf_detect` does (`waf:{provider}`), so this
    // exercises the real tag string.
    for provider in ["AWS CloudFront", "Imperva/Incapsula"] {
        let dom = cdn_fronted_domain("example.com", provider);
        let ip = spf_ip("203.0.113.9", "example.com");
        let r = rule_au_111_cdn_origin_candidate(&RuleContext::new(&[dom, ip]), "s", 0);
        assert_eq!(
            r.len(),
            1,
            "AU-111 must fire for a {provider}-fronted domain with an SPF IP"
        );
        assert_eq!(r[0].rule_id, "AU-111");
    }
}

#[test]
fn au111_does_not_fire_without_cdn_fingerprint() {
    // A domain with no `waf-detected` tag at all — no CDN evidence, no fire
    // even though an SPF IP exists for it.
    let mut dom = Entity::new(EntityKind::Domain, "plain.com", 0.9, "s");
    dom.tag("mx"); // some other, unrelated dns_intel tag
    let ip = spf_ip("203.0.113.9", "plain.com");
    assert!(rule_au_111_cdn_origin_candidate(&RuleContext::new(&[dom, ip]), "s", 0).is_empty());
}

#[test]
fn au111_does_not_fire_for_onprem_waf_appliances() {
    // F5 BIG-IP is fingerprinted by the same module but is NOT a global
    // anycast CDN — treating it as "the DNS record isn't the origin" would be
    // an unsupported generalisation, so it must not fire.
    let dom = cdn_fronted_domain("example.com", "F5 BIG-IP");
    let ip = spf_ip("203.0.113.9", "example.com");
    assert!(
        rule_au_111_cdn_origin_candidate(&RuleContext::new(&[dom, ip]), "s", 0).is_empty(),
        "an on-premise WAF appliance must not be treated as a DNS-fronting CDN"
    );
}

#[test]
fn au113_no_fire_for_a_generic_subdomain_or_unrelated_domain() {
    // A generic subdomain (no mx tag, no direct-connect label) resolving
    // off-CDN is not evidence of anything — deliberately narrow scope. A
    // domain under a DIFFERENT registrable domain must not cross-match either.
    let apex = Entity::new(EntityKind::Domain, "apex.com", 0.8, "s");
    let cdn_ip = Entity::new(EntityKind::IpAddress, "104.16.5.5", 0.8, "s");
    let mut generic = Entity::new(EntityKind::Domain, "assets.apex.com", 0.8, "s");
    generic.tag("subdomain");
    generic.tag("dns-brute");
    let generic_ip = Entity::new(EntityKind::IpAddress, "45.33.32.156", 0.8, "s");
    let other = Entity::new(EntityKind::Domain, "unrelated.net", 0.8, "s");
    let other_ip = Entity::new(EntityKind::IpAddress, "45.33.32.200", 0.8, "s");

    let ents = vec![
        apex.clone(),
        cdn_ip.clone(),
        generic.clone(),
        generic_ip.clone(),
        other.clone(),
        other_ip.clone(),
    ];
    let rels = vec![
        resolves(&apex, &cdn_ip),
        resolves(&generic, &generic_ip),
        resolves(&other, &other_ip),
    ];

    let r = rule_au_113_direct_connect_origin_candidate(&RuleContext::new(&ents), &rels, "s", 0);
    assert!(
        r.is_empty(),
        "a generic subdomain label / unrelated domain must not fire: {r:?}"
    );
}

#[test]
fn au111_does_not_fire_for_an_unrelated_domains_spf_ip() {
    // The SPF IP is authorised for a DIFFERENT domain than the CDN-fronted
    // one — must not cross-attribute.
    let dom = cdn_fronted_domain("example.com", "Cloudflare");
    let ip = spf_ip("203.0.113.9", "other-site.com");
    assert!(rule_au_111_cdn_origin_candidate(&RuleContext::new(&[dom, ip]), "s", 0).is_empty());
}

#[test]
fn au111_ignores_a_non_spf_ip_address() {
    // An IpAddress entity with no `spf` tag (e.g. a plain A record) must not
    // be treated as an origin candidate.
    let dom = cdn_fronted_domain("example.com", "Cloudflare");
    let mut ip = Entity::new(EntityKind::IpAddress, "203.0.113.9", 0.9, "s");
    ip.tag("ipv4");
    ip.add_evidence(
        Evidence::new("dns_intel", "A record for example.com").with_attr("domain", "example.com"),
    );
    assert!(rule_au_111_cdn_origin_candidate(&RuleContext::new(&[dom, ip]), "s", 0).is_empty());
}

// ─── AU-112 tests (shared CIDR infrastructure) ────────────────────────────────

fn cidr_block(value: &str) -> Entity {
    Entity::new(EntityKind::Cidr, value, 0.75, "s")
}

fn plain_ip(value: &str) -> Entity {
    let mut ip = Entity::new(EntityKind::IpAddress, value, 0.7, "s");
    ip.tag("banner-grab");
    ip.add_evidence(Evidence::new(
        "banner_grab",
        format!("Open port on {value}"),
    ));
    ip
}

#[test]
fn au112_fires_when_an_independently_discovered_ip_falls_in_a_narrow_block() {
    let block = cidr_block("203.0.113.0/24");
    let ip = plain_ip("203.0.113.42");
    let r = rule_au_112_shared_cidr_infrastructure(
        &RuleContext::new(&[block.clone(), ip.clone()]),
        "s",
        0,
    );
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-112");
    assert_eq!(r[0].severity, super::Severity::Medium);
    assert!(r[0].description.contains("203.0.113.42"));
    assert!(r[0].description.contains("203.0.113.0/24"));
    assert_eq!(r[0].entity_uids, vec![block.uid.clone(), ip.uid.clone()]);
}

#[test]
fn au112_does_not_fire_for_an_ip_outside_the_block() {
    let block = cidr_block("203.0.113.0/24");
    let ip = plain_ip("198.51.100.7");
    assert!(
        rule_au_112_shared_cidr_infrastructure(&RuleContext::new(&[block, ip]), "s", 0).is_empty()
    );
}

#[test]
fn au112_does_not_fire_for_a_broad_isp_scale_block() {
    // /16 is well above the MIN_IPV4_CIDR_PREFIX floor — an ISP/cloud
    // allocation spanning thousands of unrelated customers must not fire.
    let block = cidr_block("203.0.0.0/16");
    let ip = plain_ip("203.0.113.42");
    assert!(
        rule_au_112_shared_cidr_infrastructure(&RuleContext::new(&[block, ip]), "s", 0).is_empty(),
        "a broad /16 block must not be treated as a shared-infrastructure signal"
    );
}

#[test]
fn au112_does_not_fire_when_already_explicitly_linked() {
    // The `netblock` module already tags a host it expanded from this exact
    // block with a `cidr` evidence attribute — re-deriving that as a fresh
    // AU-112 inference would just restate an already-explicit relationship.
    let block = cidr_block("203.0.113.0/24");
    let mut ip = Entity::new(EntityKind::IpAddress, "203.0.113.42", 0.7, "s");
    ip.tag("netblock-member");
    ip.add_evidence(
        Evidence::new(
            "netblock",
            "Host 203.0.113.42 in network block 203.0.113.0/24",
        )
        .with_attr("cidr", "203.0.113.0/24"),
    );
    assert!(
        rule_au_112_shared_cidr_infrastructure(&RuleContext::new(&[block, ip]), "s", 0).is_empty()
    );
}

#[test]
fn au112_fires_for_a_narrow_ipv6_block() {
    let block = cidr_block("2001:db8:1::/64");
    let ip = plain_ip("2001:db8:1::42");
    let r = rule_au_112_shared_cidr_infrastructure(
        &RuleContext::new(&[block.clone(), ip.clone()]),
        "s",
        0,
    );
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].entity_uids, vec![block.uid.clone(), ip.uid.clone()]);
}

#[test]
fn au112_does_not_fire_for_a_broad_ipv6_allocation() {
    // /32 is a typical ISP-scale IPv6 allocation, well above the /48 floor.
    let block = cidr_block("2001:db8::/32");
    let ip = plain_ip("2001:db8:1::42");
    assert!(
        rule_au_112_shared_cidr_infrastructure(&RuleContext::new(&[block, ip]), "s", 0).is_empty()
    );
}

// ─── AU-114 tests (sanctions / debarment / PEP exposure) ──────────────────────

fn flagged_person(name: &str, conf: f64, tag: &str) -> Entity {
    let mut e = Entity::new(EntityKind::Person, name, conf, "s");
    e.tag("opensanctions");
    e.tag(tag);
    e
}

#[test]
fn au114_sanctioned_person_fires_critical() {
    // A definitive opensanctions match carries tags::SANCTIONED at MATCH_CONF
    // (0.60). The highest-consequence OSINT signal must surface as a Critical
    // finding rather than sitting un-named in the graph.
    let e = flagged_person(
        "Designated Test Subject",
        0.60,
        crate::core::tags::SANCTIONED,
    );
    let r = rule_au_114_sanctions_exposure(&RuleContext::new(std::slice::from_ref(&e)), "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-114");
    assert_eq!(r[0].severity, super::Severity::Critical);
    assert!(r[0].description.contains("sanctions designation"));
    assert!(r[0].description.contains("Designated Test Subject"));
    assert_eq!(r[0].entity_uids, vec![e.uid]);
}

#[test]
fn au114_debarred_only_fires_high() {
    let e = flagged_person("Barred Vendor Pty", 0.60, crate::core::tags::DEBARRED);
    let r = rule_au_114_sanctions_exposure(&RuleContext::new(&[e]), "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].severity, super::Severity::High);
    assert!(r[0].description.contains("debarred"));
}

#[test]
fn au114_pep_only_fires_medium_and_frames_as_a_lead() {
    // Wikidata's PEP signal (tags::PEP == "pep") is a due-diligence lead, not a
    // determination — it must fire only Medium and never assert guilt.
    let e = flagged_person("Public Office Holder", 0.72, crate::core::tags::PEP);
    let r = rule_au_114_sanctions_exposure(&RuleContext::new(&[e]), "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].severity, super::Severity::Medium);
    assert!(r[0].description.contains("politically-exposed"));
    assert!(
        r[0].description.contains("not a legal determination"),
        "a PEP finding must be framed as a signal, not a determination"
    );
}

#[test]
fn au114_takes_the_strongest_flag_when_several_are_present() {
    // A subject both sanctioned AND debarred is graded by the strongest flag
    // (Critical), with every flag enumerated in the description.
    let mut e = flagged_person("Dual Flagged Entity", 0.60, crate::core::tags::SANCTIONED);
    e.tag(crate::core::tags::DEBARRED);
    let r = rule_au_114_sanctions_exposure(&RuleContext::new(&[e]), "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].severity, super::Severity::Critical);
    assert!(r[0].description.contains("sanctioned"));
    assert!(r[0].description.contains("debarred"));
}

#[test]
fn au114_surfaces_the_sanctions_programme_from_evidence() {
    let mut e = flagged_person("Programme Listed", 0.60, crate::core::tags::SANCTIONED);
    e.add_evidence(
        Evidence::new("opensanctions", "OpenSanctions match").with_attr("program_id", "US-RUSHAR"),
    );
    let r = rule_au_114_sanctions_exposure(&RuleContext::new(&[e]), "s", 0);
    assert_eq!(r.len(), 1);
    assert!(
        r[0].description.contains("US-RUSHAR"),
        "the sanctions programme must be surfaced from evidence, got {:?}",
        r[0].description
    );
}

#[test]
fn au114_does_not_fire_for_an_unflagged_or_low_confidence_entity() {
    // No risk tag → no finding.
    let plain = Entity::new(EntityKind::Person, "Ordinary Person", 0.80, "s");
    assert!(rule_au_114_sanctions_exposure(&RuleContext::new(&[plain]), "s", 0).is_empty());
    // Flagged but below the 0.55 definitive-match floor → no finding (a weak,
    // speculative person must never be asserted as sanctioned).
    let weak = flagged_person("Weak Match", 0.40, crate::core::tags::SANCTIONED);
    assert!(
        rule_au_114_sanctions_exposure(&RuleContext::new(&[weak]), "s", 0).is_empty(),
        "a sub-floor confidence entity must not fire a sanctions finding"
    );
}

// ─── AU-115 tests (personal Wi-Fi geolocated) ─────────────────────────────────

#[test]
fn au115_joins_an_ssid_to_its_wigle_geolocation() {
    let ssid = Entity::new(EntityKind::Ssid, "Jordans_Home_5G", 0.85, "s");
    let mut coord = Entity::new(EntityKind::Coordinates, "-27.470000,153.020000", 0.72, "s");
    coord.tag("wigle");
    coord.tag("ssid-located");
    coord.tag("geoint");
    coord.add_evidence(
        Evidence::new("wigle", "WiGLE SSID observed").with_attr("ssid", "Jordans_Home_5G"),
    );
    let r = rule_au_115_personal_wifi_geolocated(
        &RuleContext::new(&[ssid.clone(), coord.clone()]),
        "s",
        0,
    );
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-115");
    assert_eq!(r[0].severity, super::Severity::High);
    assert!(r[0].description.contains("Jordans_Home_5G"));
    assert!(r[0].entity_uids.contains(&ssid.uid));
    assert!(r[0].entity_uids.contains(&coord.uid));
}

#[test]
fn au115_requires_a_name_match_and_the_wigle_ssid_located_tag() {
    let ssid = Entity::new(EntityKind::Ssid, "Jordans_Home_5G", 0.85, "s");
    // A WiGLE ssid-located fix for a DIFFERENT network → no join.
    let mut other = Entity::new(EntityKind::Coordinates, "-27.470000,153.020000", 0.72, "s");
    other.tag("ssid-located");
    other.add_evidence(Evidence::new("wigle", "x").with_attr("ssid", "SomeoneElse"));
    assert!(
        rule_au_115_personal_wifi_geolocated(&RuleContext::new(&[ssid.clone(), other]), "s", 0)
            .is_empty()
    );
    // A matching name but a non-WiGLE coordinate (no ssid-located tag) must NOT
    // fire — an IP-geo fix can't masquerade as a personal-network geolocation.
    let mut ipgeo = Entity::new(EntityKind::Coordinates, "-27.470000,153.020000", 0.6, "s");
    ipgeo.tag("geoint");
    ipgeo.add_evidence(Evidence::new("ip_geo", "x").with_attr("ssid", "Jordans_Home_5G"));
    assert!(
        rule_au_115_personal_wifi_geolocated(&RuleContext::new(&[ssid, ipgeo]), "s", 0).is_empty()
    );
}

// ─── AU-084 tests (cell tower dual-source) ────────────────────────────────────

fn cell_tower(tower_id: &str, sources: &[&str]) -> Entity {
    let mut e = Entity::new(EntityKind::DeviceId, tower_id, 0.78, "s");
    e.tag(crate::core::tags::CELL_TOWER);
    for src in sources {
        e.add_evidence(Evidence::new(*src, format!("tower {tower_id}")));
    }
    e
}

#[test]
fn au084_fires_when_both_sources_present() {
    use super::rules::rule_au_084_cell_tower_dual_source;
    let ents = vec![cell_tower(
        "505-1-1234-56789",
        &["cell_intel", "opencellid"],
    )];
    let r = rule_au_084_cell_tower_dual_source(&RuleContext::new(&ents), "s", 0);
    assert_eq!(r.len(), 1, "dual-source cell tower must fire AU-084");
    assert_eq!(r[0].rule_id, "AU-084");
}

#[test]
fn au084_does_not_fire_on_single_source() {
    use super::rules::rule_au_084_cell_tower_dual_source;
    let ents = vec![cell_tower("505-1-1234-56789", &["cell_intel"])];
    let r = rule_au_084_cell_tower_dual_source(&RuleContext::new(&ents), "s", 0);
    assert!(r.is_empty(), "single-source tower must not fire AU-084");
}

#[test]
fn au084_medium_severity_for_three_or_more_towers() {
    use super::rules::rule_au_084_cell_tower_dual_source;
    let ents = vec![
        cell_tower("505-1-1234-11111", &["cell_intel", "opencellid"]),
        cell_tower("505-1-1234-22222", &["cell_intel", "opencellid"]),
        cell_tower("505-1-1234-33333", &["cell_intel", "opencellid"]),
    ];
    let r = rule_au_084_cell_tower_dual_source(&RuleContext::new(&ents), "s", 0);
    assert_eq!(r.len(), 1, "three dual-source towers must fire one AU-084");
    assert_eq!(r[0].severity, Severity::Medium);
}

#[test]
fn au084_ignores_non_cell_tower_device_ids() {
    use super::rules::rule_au_084_cell_tower_dual_source;
    let mut e = Entity::new(EntityKind::DeviceId, "aa:bb:cc:dd:ee:ff", 0.8, "s");
    e.add_evidence(Evidence::new("cell_intel", "mac addr"));
    e.add_evidence(Evidence::new("opencellid", "mac addr"));
    // No cell-tower tag → must not fire.
    let r = rule_au_084_cell_tower_dual_source(&RuleContext::new(&[e]), "s", 0);
    assert!(r.is_empty(), "non-cell-tower DeviceId must not fire AU-084");
}

#[test]
fn au076_email_username_localpart_bridge_fires_on_canonical_match() {
    use super::rules::rule_au_076_email_username_localpart_bridge;
    // Local part "haigen_bamford" strips separators → "haigenbamford".
    // Username "haigen.bamford" also strips → "haigenbamford". They match.
    let mut email = Entity::new(EntityKind::Email, "haigen_bamford@acme.com", 0.9, "s");
    email.add_evidence(Evidence::new("breach", "x".to_string()));
    let mut uname = Entity::new(EntityKind::Username, "haigen.bamford", 0.8, "s");
    uname.add_evidence(Evidence::new("github_user", "x".to_string()));
    let r = rule_au_076_email_username_localpart_bridge(&RuleContext::new(&[email, uname]), "s", 0);
    assert!(
        !r.is_empty(),
        "AU-076 must fire when local-part canonicalises to a username"
    );
    assert_eq!(r[0].rule_id, "AU-076");
    assert_eq!(r[0].severity, super::Severity::High);
}

#[test]
fn au076_consolidates_permutation_flood_into_one_per_canonical_handle() {
    use super::rules::rule_au_076_email_username_localpart_bridge;
    // A name seed's flood: many email forms + many username forms that all
    // canonicalise to the SAME handle "matthewdiegmann". A naive per-pair emission
    // would fire len(emails)×len(usernames) High findings; consolidation must emit
    // exactly ONE, listing every form, with no value lost.
    // Each form carries a genuine, independent corroborating source — the emails
    // from a breach dump, the usernames from a live platform probe — so the bridge
    // clears AU-076's >= 2-distinct-source independence gate. This test exercises
    // the CONSOLIDATION of the permutation flood, not the gate itself.
    let mut ents = Vec::new();
    for host in ["yahoo.com", "msn.com", "gmail.com", "outlook.com"] {
        let mut e = Entity::new(
            EntityKind::Email,
            format!("matthew.diegmann@{host}"),
            0.3,
            "s",
        );
        e.add_evidence(Evidence::new("breach", "dump".to_string()));
        ents.push(e);
    }
    for u in ["matthew.diegmann", "matthewdiegmann", "matthew_diegmann"] {
        let mut e = Entity::new(EntityKind::Username, u, 0.3, "s");
        e.add_evidence(Evidence::new("github_user", "profile".to_string()));
        ents.push(e);
    }
    let r = rule_au_076_email_username_localpart_bridge(&RuleContext::new(&ents), "s", 0);
    assert_eq!(
        r.len(),
        1,
        "the 4×3 permutation flood must consolidate to ONE finding, got {}",
        r.len()
    );
    assert_eq!(r[0].rule_id, "AU-076");
    assert_eq!(r[0].severity, super::Severity::High);
    // No value is lost: the consolidated finding names every form and links them.
    assert!(r[0].description.contains("matthewdiegmann"));
    assert!(r[0].description.contains("4 email form"));
    assert!(r[0].description.contains("3 username form"));
    // All 7 contributing entities are referenced for pivoting.
    assert_eq!(r[0].entity_uids.len(), 7);
}

#[test]
fn au076_single_source_self_derivation_is_suppressed() {
    use super::rules::rule_au_076_email_username_localpart_bridge;
    // The false positive AU-076's independence gate closes: an email and a
    // username that canonicalise to the same handle but carry FEWER than two
    // distinct corroborating sources. Here both are attested only by a single
    // `name_intel` self-derivation (a non-corroborating pass), so the handles
    // match by construction, not by independent observation — exactly the
    // single-source name-seed flood that must NOT emit a High identity bridge.
    let mut email = Entity::new(EntityKind::Email, "cameron.tyler@acme.com", 0.3, "s");
    email.add_evidence(Evidence::new("name_intel", "derived".to_string()));
    let mut uname = Entity::new(EntityKind::Username, "cameron.tyler", 0.3, "s");
    uname.add_evidence(Evidence::new("name_intel", "derived".to_string()));
    let r = rule_au_076_email_username_localpart_bridge(&RuleContext::new(&[email, uname]), "s", 0);
    assert!(
        r.is_empty(),
        "AU-076 must not fire on a single-source (name_intel) self-derivation: {r:?}"
    );
}

#[test]
fn au077_name_derived_username_confirmed_fires_on_predict_plus_confirm() {
    use super::rules::rule_au_077_name_derived_username_confirmed;
    // Username that was BOTH predicted by name_intel and confirmed by github_user.
    let mut u = Entity::new(EntityKind::Username, "hbamford", 0.8, "s");
    u.add_evidence(Evidence::new(
        "name_intel",
        "Derived from Haigen Bamford".to_string(),
    ));
    u.add_evidence(Evidence::new(
        "github_user",
        "Found profile github.com/hbamford".to_string(),
    ));
    let r = rule_au_077_name_derived_username_confirmed(&RuleContext::new(&[u]), "s", 0);
    assert!(
        !r.is_empty(),
        "AU-077 must fire when derivation + live confirmation coexist"
    );
    assert_eq!(r[0].rule_id, "AU-077");
    assert_eq!(r[0].severity, super::Severity::High);
    // A username with only derivation (no discovery) must NOT fire.
    let mut derived_only = Entity::new(EntityKind::Username, "hbamford2", 0.8, "s");
    derived_only.add_evidence(Evidence::new("name_intel", "Derived handle".to_string()));
    let r2 =
        rule_au_077_name_derived_username_confirmed(&RuleContext::new(&[derived_only]), "s", 0);
    assert!(r2.is_empty(), "derivation alone must not fire AU-077");
}

#[test]
fn au077_does_not_fire_on_a_status_only_username_search_summary() {
    use super::rules::rule_au_077_name_derived_username_confirmed;
    // The false positive: name_intel DERIVES a handle, then username_search re-emits
    // a summary Username for it whose hits were ALL status-only guesses
    // (hits_verified == 0). The two merge by value — two stacked guesses with zero
    // verified confirmation must NOT fire a High "confirmed" identity bridge.
    let mut u = Entity::new(EntityKind::Username, "jsmith", 0.8, "s");
    u.add_evidence(Evidence::new(
        "name_intel",
        "Derived from John Smith".to_string(),
    ));
    u.add_evidence(
        Evidence::new(
            "username_search",
            "@jsmith found on 3 platform(s)".to_string(),
        )
        .with_attr("hits_verified", "0")
        .with_attr("hits_status_only", "3"),
    );
    let r = rule_au_077_name_derived_username_confirmed(&RuleContext::new(&[u]), "s", 0);
    assert!(
        r.is_empty(),
        "AU-077 must not confirm on an all-status-only username_search summary: {r:?}"
    );
}

#[test]
fn au077_fires_when_username_search_has_a_verified_hit() {
    use super::rules::rule_au_077_name_derived_username_confirmed;
    // The genuine case the guard must still allow: at least one platform VERIFIED
    // the derived handle (hits_verified >= 1) — a real prediction-confirmed bridge.
    let mut u = Entity::new(EntityKind::Username, "jsmith", 0.8, "s");
    u.add_evidence(Evidence::new(
        "name_intel",
        "Derived from John Smith".to_string(),
    ));
    u.add_evidence(
        Evidence::new(
            "username_search",
            "@jsmith found on 2 platform(s)".to_string(),
        )
        .with_attr("hits_verified", "2")
        .with_attr("hits_status_only", "1"),
    );
    let r = rule_au_077_name_derived_username_confirmed(&RuleContext::new(&[u]), "s", 0);
    assert_eq!(
        r.len(),
        1,
        "a verified username_search hit is a genuine confirmation"
    );
    assert_eq!(r[0].severity, super::Severity::High);
}

#[test]
fn au077_does_not_fire_on_a_social_probe_summary_with_zero_verified_hits() {
    use super::rules::rule_au_077_name_derived_username_confirmed;
    // OD-17: social_probe's real Username-entity evidence is its aggregate
    // target-summary record (checked/found/platforms_count/platforms plus
    // hits_verified/hits_status_only) — a per-record `detection` attribute
    // lives only on the separate Url entity social_probe emits per platform,
    // which AU-077 never inspects. (The previous version of this test hand-built
    // a `detection` attribute directly on the Username entity, a shape
    // social_probe's real summary path never produces.) All hits here are
    // status-only, so zero are verified.
    let mut u = Entity::new(EntityKind::Username, "jsmith", 0.8, "s");
    u.add_evidence(Evidence::new(
        "name_intel",
        "Derived from John Smith".to_string(),
    ));
    u.add_evidence(
        Evidence::new(
            "social_probe",
            "Probed 30 platforms, found 2 profiles".to_string(),
        )
        .with_attr("checked", "30")
        .with_attr("found", "2")
        .with_attr("platforms_count", "2")
        .with_attr("platforms", "reddit, tumblr")
        .with_attr("hits_verified", "0")
        .with_attr("hits_status_only", "2"),
    );
    let r = rule_au_077_name_derived_username_confirmed(&RuleContext::new(&[u]), "s", 0);
    assert!(
        r.is_empty(),
        "an all-status-only social_probe summary must not confirm AU-077: {r:?}"
    );
}

#[test]
fn au077_fires_when_social_probe_has_a_verified_hit() {
    use super::rules::rule_au_077_name_derived_username_confirmed;
    // The genuine case the guard must still allow: at least one platform in the
    // social_probe summary was body-marker VERIFIED (hits_verified >= 1).
    let mut u = Entity::new(EntityKind::Username, "jsmith", 0.8, "s");
    u.add_evidence(Evidence::new(
        "name_intel",
        "Derived from John Smith".to_string(),
    ));
    u.add_evidence(
        Evidence::new(
            "social_probe",
            "Probed 30 platforms, found 2 profiles".to_string(),
        )
        .with_attr("hits_verified", "1")
        .with_attr("hits_status_only", "1"),
    );
    let r = rule_au_077_name_derived_username_confirmed(&RuleContext::new(&[u]), "s", 0);
    assert_eq!(
        r.len(),
        1,
        "a verified social_probe hit is a genuine confirmation: {r:?}"
    );
    assert_eq!(r[0].severity, super::Severity::High);
}

#[test]
fn au086_name_derived_email_confirmed_fires_on_predict_plus_confirm() {
    use super::rules::rule_au_086_name_derived_email_confirmed;
    // An email name_intel permuted from the subject AND confirmed by a breach
    // corpus (HIBP) — the "guessed address verified real" signal.
    let mut e = Entity::new(EntityKind::Email, "moale.mcknight@gmail.com", 0.30, "s");
    e.tag("name-derived");
    e.add_evidence(Evidence::new(
        "name_intel",
        "Speculative email permuted from name",
    ));
    e.add_evidence(Evidence::new("hibp", "found in 2 breaches"));
    let r = rule_au_086_name_derived_email_confirmed(&RuleContext::new(&[e]), "s", 0);
    assert!(
        !r.is_empty(),
        "AU-086 must fire on derivation + breach confirmation"
    );
    assert_eq!(r[0].rule_id, "AU-086");
    assert_eq!(r[0].severity, super::Severity::High);
    assert!(r[0].description.contains("hibp"));

    // Derivation alone (an unconfirmed permutation) must NOT fire.
    let mut guess = Entity::new(EntityKind::Email, "mmcknight@gmail.com", 0.30, "s");
    guess.tag("name-derived");
    guess.add_evidence(Evidence::new("name_intel", "permuted"));
    assert!(
        rule_au_086_name_derived_email_confirmed(&RuleContext::new(&[guess]), "s", 0).is_empty(),
        "an unconfirmed permutation must not fire AU-086"
    );

    // A real (non-derived) breach email must not fire either — the rule is about
    // confirming a PREDICTION, not flagging every breached address.
    let mut found = Entity::new(EntityKind::Email, "someone@corp.com", 0.72, "s");
    found.add_evidence(Evidence::new("hibp", "breached"));
    assert!(
        rule_au_086_name_derived_email_confirmed(&RuleContext::new(&[found]), "s", 0).is_empty(),
        "a non-derived breach email must not fire AU-086"
    );
}

#[test]
fn au078_hub_entity_fires_for_hub_tagged_entity() {
    use super::rules::rule_au_078_hub_entity;
    let mut e = Entity::new(EntityKind::Email, "repeat@example.com", 0.9, "s");
    e.add_evidence(Evidence::new("history", "x".to_string()));
    e.tag("hub-entity");
    let r = rule_au_078_hub_entity(&RuleContext::new(&[e]), "s", 0);
    assert!(
        !r.is_empty(),
        "AU-078 must fire for hub-entity tagged entities"
    );
    assert_eq!(r[0].rule_id, "AU-078");
    assert_eq!(r[0].severity, super::Severity::Medium);
    // Untagged entity must NOT fire.
    let plain = Entity::new(EntityKind::Email, "other@example.com", 0.9, "s");
    let r2 = rule_au_078_hub_entity(&RuleContext::new(&[plain]), "s", 0);
    assert!(r2.is_empty(), "untagged entity must not fire AU-078");
}

#[test]
fn au079_bio_cross_mention_fires_on_structured_twitter_attr() {
    use super::rules::rule_au_079_bio_cross_mention;
    // GitHub entity carries a `twitter` attribute pointing to another username.
    let mut gh = Entity::new(EntityKind::Username, "hbamford_github", 0.85, "s");
    let ev = Evidence::new("github_user", "GitHub profile".to_string())
        .with_attr("twitter", "hbamford_tw");
    gh.add_evidence(ev);
    // The referenced Twitter handle is also in the scan as a Username entity.
    let mut tw = Entity::new(EntityKind::Username, "hbamford_tw", 0.80, "s");
    tw.add_evidence(Evidence::new("social_probe", "Twitter profile".to_string()));
    let r = rule_au_079_bio_cross_mention(&RuleContext::new(&[gh, tw]), "s", 0);
    assert!(
        !r.is_empty(),
        "AU-079 must fire when twitter attr names a known username"
    );
    assert_eq!(r[0].rule_id, "AU-079");
    assert_eq!(r[0].severity, super::Severity::High);
}

#[test]
fn au079_bio_cross_mention_fires_on_at_mention_in_bio() {
    use super::rules::rule_au_079_bio_cross_mention;
    let mut gh = Entity::new(EntityKind::Username, "hbamford", 0.85, "s");
    let ev = Evidence::new("github_user", "GitHub profile".to_string())
        .with_attr("bio", "Find me on Reddit: @hbamford_reddit");
    gh.add_evidence(ev);
    let mut reddit = Entity::new(EntityKind::Username, "hbamford_reddit", 0.80, "s");
    reddit.add_evidence(Evidence::new("reddit_user", "Reddit profile".to_string()));
    let r = rule_au_079_bio_cross_mention(&RuleContext::new(&[gh, reddit]), "s", 0);
    assert!(!r.is_empty(), "AU-079 must fire on @-mention in bio");
    assert_eq!(r[0].rule_id, "AU-079");
    // A free-text bio @-mention is a Medium lead — the mentioned handle may be a
    // third party the subject merely names, not a self-attribution — unlike the
    // structured-attribute path (twitter/instagram/…), which fires High.
    assert_eq!(r[0].severity, super::Severity::Medium);
    // Must NOT fire linking entity to itself (no self-loop)
    let no_self: Vec<_> = r
        .iter()
        .filter(|c| c.entity_uids[0] == c.entity_uids[1])
        .collect();
    assert!(
        no_self.is_empty(),
        "AU-079 must never produce a self-loop correlation"
    );
}
