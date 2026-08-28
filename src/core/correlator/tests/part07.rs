#[test]
fn au106_links_accounts_sharing_a_breach_router_bssid_or_imei() {
    // A stealer-logged router BSSID (a `device`-tagged MacAddress) shared across
    // two DISTINCT accounts is the same single-device co-location proof as a hwid.
    let mut mac = Entity::new(EntityKind::MacAddress, "aa:bb:cc:dd:ee:ff", 0.60, "scan");
    mac.tag("device");
    mac.add_evidence(Evidence::new("oathnet", "r1").with_attr("username", "ghost_91"));
    mac.add_evidence(Evidence::new("oathnet", "r2").with_attr("username", "nightcrawler"));
    let u1 = Entity::new(EntityKind::Username, "ghost_91", 0.6, "scan");
    let u2 = Entity::new(EntityKind::Username, "nightcrawler", 0.6, "scan");
    let hits = super::rules::rule_au_106_shared_device_identity(
        &RuleContext::new(&[mac.clone(), u1.clone(), u2.clone()]),
        "scan",
        0,
    );
    assert_eq!(
        hits.len(),
        1,
        "a shared BSSID across 2 accounts must link them"
    );
    assert_eq!(hits[0].rule_id, "AU-106");
    assert!(hits[0].entity_uids.contains(&mac.uid));

    // SAFETY: a LAN/Wi-Fi MAC surfaced by local_net/wifi_intel is NOT tagged
    // `device`, so the same address with the same accounts must not link people.
    let mut lan = Entity::new(EntityKind::MacAddress, "aa:bb:cc:dd:ee:ff", 0.60, "scan");
    lan.tag(crate::core::tags::WIFI_AP);
    lan.add_evidence(Evidence::new("wifi_intel", "r1").with_attr("username", "ghost_91"));
    lan.add_evidence(Evidence::new("wifi_intel", "r2").with_attr("username", "nightcrawler"));
    assert!(
        super::rules::rule_au_106_shared_device_identity(&RuleContext::new(&[lan]), "scan", 0)
            .is_empty(),
        "a non-`device` Wi-Fi MAC must never link identities"
    );

    // A shared 15-digit IMEI (typed DeviceId) across two accounts also fires.
    let mut imei = Entity::new(EntityKind::DeviceId, "359881234567890", 0.55, "scan");
    imei.tag("device");
    imei.add_evidence(Evidence::new("see-know", "r1").with_attr("username", "ghost_91"));
    imei.add_evidence(Evidence::new("see-know", "r2").with_attr("username", "nightcrawler"));
    assert!(
        !super::rules::rule_au_106_shared_device_identity(
            &RuleContext::new(&[imei, u1, u2]),
            "scan",
            0
        )
        .is_empty(),
        "a shared IMEI across 2 accounts must link them"
    );
}

#[test]
fn au107_names_the_breach_stated_employer() {
    // A breach-tagged Organisation (0.50) — the employer field of a breach record —
    // is named as the subject's affiliation; one source is Medium.
    let mut org = Entity::new(EntityKind::Organisation, "Globex Pty Ltd", 0.50, "scan");
    org.tag("breach");
    org.add_evidence(Evidence::new("oathnet", "breach record"));
    let r =
        super::rules::rule_au_107_breach_employer_affiliation(&RuleContext::new(&[org]), "scan", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-107");
    assert_eq!(r[0].severity, super::Severity::Medium);
    assert!(r[0].description.contains("Globex Pty Ltd"));

    // Two INDEPENDENT breach sources naming the same employer → High.
    let mut org2 = Entity::new(EntityKind::Organisation, "Globex Pty Ltd", 0.50, "scan");
    org2.tag("breach");
    org2.add_evidence(Evidence::new("oathnet", "rec"));
    org2.add_evidence(Evidence::new("dehashed", "rec"));
    let r2 = super::rules::rule_au_107_breach_employer_affiliation(
        &RuleContext::new(&[org2]),
        "scan",
        0,
    );
    assert_eq!(r2[0].severity, super::Severity::High);

    // A registry Organisation (no `breach` tag) does NOT fire AU-107.
    let mut reg = Entity::new(EntityKind::Organisation, "Acme Ltd", 0.65, "scan");
    reg.tag("abr");
    assert!(
        super::rules::rule_au_107_breach_employer_affiliation(&RuleContext::new(&[reg]), "scan", 0)
            .is_empty(),
        "a registry org is not a breach-stated employer"
    );
}

#[test]
fn au108_reports_breach_cross_platform_footprint() {
    let mk = |val: &str| {
        let mut e = Entity::new(EntityKind::Username, val, 0.55, "scan");
        e.tag("breach");
        e
    };
    let r = super::rules::rule_au_108_breach_social_footprint(
        &RuleContext::new(&[mk("twitter:alice"), mk("telegram:alice_b")]),
        "scan",
        0,
    );
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-108");
    assert!(r[0].description.contains("twitter") && r[0].description.contains("telegram"));

    // A single platform never fires.
    assert!(
        super::rules::rule_au_108_breach_social_footprint(
            &RuleContext::new(&[mk("twitter:alice")]),
            "scan",
            0
        )
        .is_empty(),
        "one platform is not a cross-platform footprint"
    );
    // Two handles on the SAME platform don't inflate to a footprint.
    assert!(
        super::rules::rule_au_108_breach_social_footprint(
            &RuleContext::new(&[mk("twitter:alice"), mk("twitter:bob")]),
            "scan",
            0
        )
        .is_empty(),
        "two handles on one platform are still one platform"
    );
    // A non-allow-list prefix (an epieos `google:<id>`) is ignored, so it can't
    // combine with a single real platform to reach the ≥2 gate.
    assert!(
        super::rules::rule_au_108_breach_social_footprint(
            &RuleContext::new(&[mk("google:123456"), mk("twitter:alice")]),
            "scan",
            0
        )
        .is_empty(),
        "a non-social prefix must not count toward the footprint"
    );
}

// ─── best_au_location_estimate (single-signal headline geolocation) ──────────

#[test]
fn best_location_uses_a_single_confirmed_coordinate() {
    use super::best_au_location_estimate;
    // One person-anchored AU coordinate (geocode source makes it person-anchored).
    let mut coord = Entity::new(EntityKind::Coordinates, "-27.4698,153.0251", 0.7, "s");
    coord.add_evidence(Evidence::new("geocode", "Brisbane fix"));
    let est = best_au_location_estimate(&[coord]).expect("a single AU coord yields a fix");
    assert_eq!(est.basis, "confirmed coordinate");
    assert_eq!(est.state, Some("QLD"));
    assert_eq!(est.locality.as_deref(), Some("Brisbane"));
    assert!(est.radius_km <= 2.0);
}

#[test]
fn best_location_falls_back_to_name_matched_address_postcode() {
    use super::best_au_location_estimate;
    let mut addr = Entity::new(EntityKind::Address, "Spring Hill QLD 4000", 0.7, "s");
    addr.tag("exact-name-match");
    let est = best_au_location_estimate(&[addr]).expect("postcode 4000 resolves");
    assert_eq!(est.basis, "name-matched address (postcode grain)");
    assert_eq!(est.state, Some("QLD"));
    assert!((est.radius_km - 8.0).abs() < 1e-9, "postcode grain");
}

#[test]
fn best_location_uses_a_breach_postcode_when_nothing_finer() {
    use super::best_au_location_estimate;
    let mut p = Entity::new(EntityKind::Person, "Jo Citizen", 0.6, "s");
    p.add_evidence(Evidence::new("oathnet_pro", "breach").with_attr("postcode", "4000"));
    let est = best_au_location_estimate(&[p]).expect("breach postcode resolves");
    assert_eq!(est.basis, "breach/register postcode");
    assert_eq!(est.state, Some("QLD"));
}

#[test]
fn best_location_prefers_a_coordinate_over_an_address() {
    use super::best_au_location_estimate;
    // A Brisbane coordinate AND a Perth name-matched address: the finer coordinate
    // wins (precedence), so the headline is the coordinate, not the postcode.
    let mut coord = Entity::new(EntityKind::Coordinates, "-27.4698,153.0251", 0.7, "s");
    coord.add_evidence(Evidence::new("geocode", "Brisbane fix"));
    let mut addr = Entity::new(EntityKind::Address, "Perth WA 6000", 0.7, "s");
    addr.tag("exact-name-match");
    let est = best_au_location_estimate(&[coord, addr]).expect("should succeed");
    assert_eq!(est.basis, "confirmed coordinate");
    assert_eq!(est.state, Some("QLD"));
}

#[test]
fn best_location_is_none_without_any_location_signal() {
    use super::best_au_location_estimate;
    let e = Entity::new(EntityKind::Email, "x@y.com", 0.8, "s");
    assert!(best_au_location_estimate(&[e]).is_none());
}

#[test]
fn best_location_does_not_misread_a_coordinate_value_as_a_postcode() {
    use super::best_au_location_estimate;
    // A coordinate from a non-anchoring source (so NOT person-anchored) whose
    // longitude digits ("…151.2093") contain a postcode-shaped token ("2093").
    // It must yield no fix — coordinates are excluded from the postcode rung, so
    // the digits of a lat/lon are never misread as a residential postcode.
    let coord = Entity::new(EntityKind::Coordinates, "-33.8688,151.2093", 0.8, "s");
    assert!(best_au_location_estimate(&[coord]).is_none());
}

#[test]
fn best_location_uses_a_landline_area_code_region_when_nothing_finer() {
    use super::best_au_location_estimate;
    // A subject known only by a Queensland geographic landline (`07…`) — no
    // coordinate, address or postcode. The coarsest rung resolves the area code to
    // its ACMA region centroid (Brisbane), a region-grain fix.
    let phone = Entity::new(EntityKind::Phone, "+61 7 3739 4511", 0.7, "s");
    let est = best_au_location_estimate(&[phone]).expect("a QLD landline yields a region fix");
    assert_eq!(est.basis, "landline area-code region");
    assert_eq!(est.state, Some("QLD"));
    assert!(
        est.radius_km >= 600.0,
        "a region fix carries an honestly large radius, got {}",
        est.radius_km
    );
    assert!(
        est.confidence > 0.0 && est.confidence <= 0.35,
        "region grain is a weak, capped fix, got {}",
        est.confidence
    );
}

#[test]
fn best_location_ignores_a_mobile_number_with_no_region() {
    use super::best_au_location_estimate;
    // A mobile (`04…`) is fully portable and carries NO geographic area code, so it
    // must not yield a location fix — only geographic fixed lines do.
    let mobile = Entity::new(EntityKind::Phone, "+61 412 345 678", 0.8, "s");
    assert!(best_au_location_estimate(&[mobile]).is_none());
}

#[test]
fn best_location_prefers_any_finer_signal_over_a_landline_region() {
    use super::best_au_location_estimate;
    // A Brisbane coordinate AND a NSW (`02…`) landline: the coordinate (rung 2) must
    // win over the region rung, so a precise fix is never masked by a coarse one.
    let mut coord = Entity::new(EntityKind::Coordinates, "-27.4698,153.0251", 0.7, "s");
    coord.add_evidence(Evidence::new("geocode", "Brisbane fix"));
    let phone = Entity::new(EntityKind::Phone, "+61 2 9876 5432", 0.9, "s");
    let est = best_au_location_estimate(&[coord, phone]).expect("should succeed");
    assert_eq!(est.basis, "confirmed coordinate");
    assert_eq!(est.state, Some("QLD"));
}

#[test]
fn best_location_excludes_a_platform_infra_tagged_landline() {
    use super::best_au_location_estimate;
    // A landline scraped from a third-party page (a business footer, say) is tagged
    // platform-infra — not subject-owned, so it must not anchor the subject.
    let mut phone = Entity::new(EntityKind::Phone, "+61 7 3739 4511", 0.7, "s");
    phone.tag("platform-infra");
    assert!(best_au_location_estimate(&[phone]).is_none());
}

#[test]
fn best_location_uses_a_breach_login_ip_city_when_nothing_finer() {
    use super::best_au_location_estimate;
    // A subject located only by their breach login IP (geolocation-lead → ip_geo
    // Brisbane) still gets a city-grain headline fix — the common breach-victim
    // case with no GPS, address or postcode.
    let mut ip = Entity::new(EntityKind::IpAddress, "1.132.97.84", 0.6, "s");
    ip.tag("geolocation-lead");
    let mut coord = Entity::new(EntityKind::Coordinates, "-27.4683,153.0322", 0.6, "s");
    coord.add_evidence(Evidence::new("ip_geo", "g").with_attr("ip", "1.132.97.84"));

    let est = best_au_location_estimate(&[ip, coord]).expect("a login-IP city fix");
    assert_eq!(est.basis, "breach login-IP city");
    assert_eq!(est.state, Some("QLD"));
    assert!(est.confidence <= 0.50, "city/IP grain is capped low");
    assert!(est.radius_km <= 25.0 + 1e-9, "fixed-line city grain");
}

#[test]
fn best_location_prefers_a_postcode_over_a_breach_login_ip() {
    use super::best_au_location_estimate;
    // A name-matched postcode (suburb grain) outranks a coarser login-IP city.
    let mut addr = Entity::new(EntityKind::Address, "Spring Hill QLD 4000", 0.7, "s");
    addr.tag("exact-name-match");
    let mut ip = Entity::new(EntityKind::IpAddress, "1.132.97.84", 0.6, "s");
    ip.tag("geolocation-lead");
    let mut coord = Entity::new(EntityKind::Coordinates, "-27.4683,153.0322", 0.6, "s");
    coord.add_evidence(Evidence::new("ip_geo", "g").with_attr("ip", "1.132.97.84"));

    let est = best_au_location_estimate(&[addr, ip, coord]).expect("should succeed");
    assert_eq!(
        est.basis, "name-matched address (postcode grain)",
        "a postcode is finer than an IP city"
    );
}

#[test]
fn location_corroboration_counts_independent_classes() {
    use super::au_location_corroboration;
    // Two INDEPENDENT methods (electoral roll + unclaimed-money directory) place
    // the subject's circle at the same postcode — corroboration, not a lone guess.
    let mut a = Entity::new(EntityKind::Person, "A Person", 0.6, "s");
    a.add_evidence(Evidence::new("au_electoral", "roll").with_attr("postcode", "4000"));
    let mut b = Entity::new(EntityKind::Person, "B Person", 0.6, "s");
    b.add_evidence(Evidence::new("qld_unclaimed", "register").with_attr("postcode", "4000"));

    let c = au_location_corroboration(&[a, b]).expect("two AU postcode signals");
    assert_eq!(
        c.independent_classes, 2,
        "electoral + directory are independent"
    );
    assert_eq!(c.signal_count, 2);
    assert_eq!(c.state, "QLD");
    assert!(
        c.confidence > 0.65 && c.confidence < 0.75,
        "2 independent classes ≈ 0.70, got {}",
        c.confidence
    );
}

#[test]
fn location_corroboration_same_source_class_is_single_source() {
    use super::au_location_corroboration;
    // Two rows from the SAME breach source (one method) are NOT independent
    // corroboration, even at the same postcode — independence counts CLASSES.
    let mut a = Entity::new(EntityKind::Person, "A Person", 0.6, "s");
    a.add_evidence(Evidence::new("oathnet_pro", "breach").with_attr("postcode", "4000"));
    let mut b = Entity::new(EntityKind::Person, "B Person", 0.6, "s");
    b.add_evidence(Evidence::new("oathnet_pro", "breach").with_attr("postcode", "4000"));

    let c = au_location_corroboration(&[a, b]).expect("should succeed");
    assert_eq!(c.independent_classes, 1, "one breach source = one method");
    assert!(
        c.confidence < 0.5,
        "single-source stays low, got {}",
        c.confidence
    );
}

#[test]
fn location_corroboration_prefers_the_better_corroborated_locality() {
    use super::au_location_corroboration;
    // Two independent classes agree on Brisbane (4000); a lone Perth (6000) signal
    // ~3600 km away. The better-corroborated locality must win.
    let mut a = Entity::new(EntityKind::Person, "A Person", 0.6, "s");
    a.add_evidence(Evidence::new("au_electoral", "roll").with_attr("postcode", "4000"));
    let mut b = Entity::new(EntityKind::Person, "B Person", 0.6, "s");
    b.add_evidence(Evidence::new("qld_unclaimed", "register").with_attr("postcode", "4000"));
    let mut perth = Entity::new(EntityKind::Person, "C Person", 0.6, "s");
    perth.add_evidence(Evidence::new("au_people", "directory").with_attr("postcode", "6000"));

    let c = au_location_corroboration(&[a, b, perth]).expect("should succeed");
    assert_eq!(
        c.state, "QLD",
        "the 2-class Brisbane cluster beats the lone Perth signal"
    );
    assert_eq!(c.independent_classes, 2);
}

#[test]
fn location_corroboration_none_without_any_au_signal() {
    use super::au_location_corroboration;
    let e = Entity::new(EntityKind::Email, "x@y.com", 0.8, "s");
    assert!(au_location_corroboration(&[e]).is_none());
}

#[test]
fn location_corroboration_admits_person_breach_login_ip() {
    use super::au_location_corroboration;
    // A breach login IP (tagged geolocation-lead) geolocated to Brisbane — the
    // person's own connection — is a coarse but real person-location signal.
    let mut ip = Entity::new(EntityKind::IpAddress, "1.132.97.84", 0.6, "s");
    ip.tag("geolocation-lead");
    let mut coord = Entity::new(EntityKind::Coordinates, "-27.4683,153.0322", 0.6, "s");
    coord.add_evidence(
        Evidence::new("ip_geo", "IP geolocation for 1.132.97.84").with_attr("ip", "1.132.97.84"),
    );
    let c = au_location_corroboration(&[ip, coord]).expect("a person login-IP geo is a signal");
    assert_eq!(c.state, "QLD");
    assert!(c.class_names.contains(&"network-ip"));
}

#[test]
fn location_corroboration_breach_ip_corroborates_a_postcode() {
    use super::au_location_corroboration;
    // An electoral-roll postcode (Brisbane 4000) AND the person's breach login IP
    // (also Brisbane) are two INDEPENDENT methods converging on one locality.
    let mut person = Entity::new(EntityKind::Person, "A Person", 0.6, "s");
    person.add_evidence(Evidence::new("au_electoral", "roll").with_attr("postcode", "4000"));
    let mut ip = Entity::new(EntityKind::IpAddress, "1.132.97.84", 0.6, "s");
    ip.tag("geolocation-lead");
    let mut coord = Entity::new(EntityKind::Coordinates, "-27.4683,153.0322", 0.6, "s");
    coord.add_evidence(Evidence::new("ip_geo", "g").with_attr("ip", "1.132.97.84"));

    let c = au_location_corroboration(&[person, ip, coord]).expect("should succeed");
    assert_eq!(c.independent_classes, 2, "electoral + network-ip");
    assert!(c.class_names.contains(&"electoral") && c.class_names.contains(&"network-ip"));
    assert!(c.confidence > 0.65);
}

#[test]
fn location_corroboration_rejects_a_datacenter_ip_geo() {
    use super::au_location_corroboration;
    // A hosting/datacenter IP geo is the server's location, never the person's —
    // it must not be admitted even when tagged a geolocation-lead.
    let mut ip = Entity::new(EntityKind::IpAddress, "8.8.8.8", 0.6, "s");
    ip.tag("geolocation-lead");
    let mut coord = Entity::new(EntityKind::Coordinates, "-27.4683,153.0322", 0.6, "s");
    coord.tag("hosting");
    coord.add_evidence(Evidence::new("ip_geo", "g").with_attr("ip", "8.8.8.8"));
    assert!(
        au_location_corroboration(&[ip, coord]).is_none(),
        "a datacenter IP geo is not a person fix"
    );
}

#[test]
fn location_corroboration_ignores_ip_geo_without_a_login_lead() {
    use super::au_location_corroboration;
    // An ip_geo coordinate whose IP is NOT a person breach login lead (e.g. a
    // resolved infrastructure IP) is not a person-location signal.
    let mut coord = Entity::new(EntityKind::Coordinates, "-27.4683,153.0322", 0.6, "s");
    coord.add_evidence(Evidence::new("ip_geo", "g").with_attr("ip", "203.0.113.7"));
    assert!(au_location_corroboration(&[coord]).is_none());
}

#[test]
fn au099_reverse_geocodes_coordinate_to_locality() {
    // A Brisbane fix → "Brisbane, QLD" with a small distance.
    let mut coord = Entity::new(EntityKind::Coordinates, "-27.4705,153.0260", 0.7, "s");
    coord.add_evidence(Evidence::new("exif_geo", "photo GPS")); // person-anchored, not infra
    let r =
        super::rules::rule_au_099_coordinate_reverse_geocode(&RuleContext::new(&[coord]), "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-099");
    assert_eq!(r[0].severity, super::Severity::Medium);
    assert!(r[0].description.contains("Brisbane"));
    assert!(r[0].description.contains("QLD"));
    assert!(r[0].description.contains("reverse geocode"));
}

#[test]
fn au099_ignores_foreign_and_weak_coordinates() {
    // A New York coordinate is not in Australia → no locality.
    let ny = Entity::new(EntityKind::Coordinates, "40.7128,-74.0060", 0.8, "s");
    // A weak (candidate) AU coordinate is below the 0.50 confidence gate.
    let weak = Entity::new(EntityKind::Coordinates, "-27.4705,153.0260", 0.40, "s");
    assert!(
        super::rules::rule_au_099_coordinate_reverse_geocode(
            &RuleContext::new(&[ny, weak]),
            "s",
            0
        )
        .is_empty()
    );
}

#[test]
fn au046_resolves_an_alias_to_platform_exposed_identifiers() {
    // The alias confirmed across two platform families (npm=code, reddit=forum),
    // plus an email its npm account exposed → AU-046 links handle to identity.
    let mut handle = Entity::new(EntityKind::Username, "kylo4kylo", 0.6, "scan");
    for s in ["npm_author", "reddit_user"] {
        handle.add_evidence(Evidence::new(s, "confirmed account"));
    }
    let mut email = Entity::new(EntityKind::Email, "k@example.com", 0.7, "scan");
    email.add_evidence(Evidence::new("npm_author", "maintainer email"));

    let hits = super::rules::rule_au_046_cross_platform_identity_resolution(
        &RuleContext::new(&[handle.clone(), email.clone()]),
        "scan",
        0,
    );
    assert_eq!(hits.len(), 1, "alias + platform-exposed email must resolve");
    assert_eq!(hits[0].rule_id, "AU-046");
    assert_eq!(hits[0].severity, super::Severity::High);
    // The correlation links the alias AND the resolved identifier.
    assert!(hits[0].entity_uids.contains(&handle.uid));
    assert!(hits[0].entity_uids.contains(&email.uid));

    // Single-family handle (only npm) does NOT resolve — needs ≥2 platforms.
    let mut one = Entity::new(EntityKind::Username, "solo", 0.6, "scan");
    one.add_evidence(Evidence::new("npm_author", "x"));
    assert!(
        super::rules::rule_au_046_cross_platform_identity_resolution(
            &RuleContext::new(&[one, email]),
            "scan",
            0
        )
        .is_empty(),
        "one platform family is not cross-platform resolution"
    );
}

#[test]
fn au045_046_reject_junk_and_role_handles_as_identity_anchors() {
    // Regression for a live person-scan: `from` (a bare function word) and `dns`
    // (a 3-char acronym) were mis-extracted as usernames and, "confirmed" across
    // two source families, fired AU-045 "confirmed identity". They are parser
    // artifacts, not aliases — the handle-quality gate must drop them.
    let junk = |val: &str| {
        let mut u = Entity::new(EntityKind::Username, val, 0.6, "scan");
        for s in ["github_user", "reddit_user"] {
            u.add_evidence(Evidence::new(s, "confirmed"));
        }
        u
    };
    // Covers both the length path (`dns`, `www` are < 4 chars) and the
    // non-identity-token path (`from`, `http` are 4 chars but never handles).
    for bad in ["from", "dns", "www", "http"] {
        assert!(
            super::rules::rule_au_045_multi_service_identity(
                &RuleContext::new(&[junk(bad)]),
                "scan",
                0
            )
            .is_empty(),
            "AU-045 must not promote junk handle '{bad}' to a confirmed identity"
        );
    }

    // A role mailbox confirmed across families is an org desk, not the subject.
    let mut role = Entity::new(EntityKind::Email, "abuse@acme.com", 0.7, "scan");
    for s in ["github_user", "hibp"] {
        role.add_evidence(Evidence::new(s, "found"));
    }
    assert!(
        super::rules::rule_au_045_multi_service_identity(&RuleContext::new(&[role]), "scan", 0)
            .is_empty(),
        "AU-045 must not promote a role mailbox to a confirmed identity"
    );

    // Control: a distinctive handle across the SAME two families still fires —
    // the gate removes junk, not genuine cross-family confirmation.
    let mut good = Entity::new(EntityKind::Username, "kylo4kylo", 0.6, "scan");
    for s in ["github_user", "reddit_user"] {
        good.add_evidence(Evidence::new(s, "confirmed"));
    }
    assert_eq!(
        super::rules::rule_au_045_multi_service_identity(&RuleContext::new(&[good]), "scan", 0)
            .len(),
        1,
        "a distinctive handle across two families must still fire AU-045"
    );

    // AU-046: the same junk handle must not be selected as a resolvable alias.
    let mut email = Entity::new(EntityKind::Email, "k@example.com", 0.7, "scan");
    email.add_evidence(Evidence::new("github_user", "maintainer email"));
    let mut junk_alias = Entity::new(EntityKind::Username, "from", 0.6, "scan");
    for s in ["github_user", "reddit_user"] {
        junk_alias.add_evidence(Evidence::new(s, "confirmed account"));
    }
    assert!(
        super::rules::rule_au_046_cross_platform_identity_resolution(
            &RuleContext::new(&[junk_alias, email.clone()]),
            "scan",
            0,
        )
        .is_empty(),
        "AU-046 must not resolve a junk handle to identifiers"
    );

    // Control: a distinctive alias across two platform families still resolves.
    let mut real_alias = Entity::new(EntityKind::Username, "kylo4kylo", 0.6, "scan");
    for s in ["github_user", "reddit_user"] {
        real_alias.add_evidence(Evidence::new(s, "confirmed account"));
    }
    let hits = super::rules::rule_au_046_cross_platform_identity_resolution(
        &RuleContext::new(&[real_alias, email]),
        "scan",
        0,
    );
    assert_eq!(
        hits.len(),
        1,
        "a distinctive alias must still resolve via AU-046"
    );
    assert_eq!(hits[0].rule_id, "AU-046");
}

#[test]
fn au046_resolves_only_the_alias_own_account_identifiers() {
    // AU-046 used to fuse EVERY platform-sourced Email/Person in the whole scan
    // into every alias, even a stranger from a different platform account or a
    // role mailbox. It must resolve only identifiers the alias's OWN account(s)
    // published — those sharing a concrete corroborating source with the alias.
    let mut alias = Entity::new(EntityKind::Username, "kylo4kylo", 0.6, "scan");
    for s in ["github_user", "reddit_user"] {
        alias.add_evidence(Evidence::new(s, "confirmed account"));
    }
    // The alias's OWN github account published this email → shares github_user.
    let mut own = Entity::new(EntityKind::Email, "kylo@real.example", 0.7, "scan");
    own.add_evidence(Evidence::new("github_user", "profile email"));
    // A co-author's email from a DIFFERENT platform account the alias does not
    // share (gitlab, code family) → must NOT be fused into the alias's identity.
    let mut stranger = Entity::new(EntityKind::Email, "coauthor@other.example", 0.7, "scan");
    stranger.add_evidence(Evidence::new("gitlab_user", "co-maintainer email"));
    // A role mailbox published even by the alias's own account is a support/registrar
    // desk, never the person's real-world identifier.
    let mut role = Entity::new(EntityKind::Email, "noreply@github.com", 0.7, "scan");
    role.add_evidence(Evidence::new("github_user", "profile email"));

    let hits = super::rules::rule_au_046_cross_platform_identity_resolution(
        &RuleContext::new(&[alias.clone(), own.clone(), stranger.clone(), role.clone()]),
        "scan",
        0,
    );
    assert_eq!(hits.len(), 1, "the alias resolves via its own account");
    assert!(
        hits[0].entity_uids.contains(&own.uid),
        "the alias's own-account email must resolve"
    );
    assert!(
        !hits[0].entity_uids.contains(&stranger.uid),
        "a stranger from an unshared platform account must not be fused"
    );
    assert!(
        !hits[0].entity_uids.contains(&role.uid),
        "a role mailbox must not be treated as a real-world identifier"
    );
    assert!(
        hits[0].description.contains("1 real-world identifier"),
        "only the one own-account identifier is counted: {}",
        hits[0].description
    );
}

#[test]
fn au047_links_identities_by_a_reused_unique_secret_only() {
    // The account-linking rule, and its precision gate. A salted hash carried against
    // two emails links them (same controller); an UNSALTED digest must NOT —
    // md5("123456") is shared by millions and would manufacture false identities.
    let cred = |hash: &str, emails: &[&str]| {
        let mut c = Entity::new(EntityKind::Credential, hash, 0.6, "scan");
        for em in emails {
            c.add_evidence(Evidence::new("import:dossier", "breach entry").with_attr("email", *em));
        }
        c
    };
    let a = Entity::new(EntityKind::Email, "burner1@proton.me", 0.6, "scan");
    let b = Entity::new(EntityKind::Email, "real.name@gmail.com", 0.6, "scan");

    // Salted bcrypt hash seen against both identities → Critical link.
    let bcrypt = cred("$2a$10$id3HAw6TcOjKvPH/RK7MS.abcdef", &[&a.value, &b.value]);
    let hits = super::rules::rule_au_047_reused_secret_identity(
        &RuleContext::new(&[bcrypt.clone(), a.clone(), b.clone()]),
        "scan",
        0,
    );
    assert_eq!(
        hits.len(),
        1,
        "salted hash across 2 identities must link them"
    );
    assert_eq!(hits[0].rule_id, "AU-047");
    assert_eq!(hits[0].severity, super::Severity::Critical);
    assert!(hits[0].entity_uids.contains(&bcrypt.uid));
    assert!(hits[0].entity_uids.contains(&a.uid) && hits[0].entity_uids.contains(&b.uid));

    // PRECISION GATE: an unsalted hex digest across the same two identities must
    // NOT fire — it could be a common password shared by unrelated people.
    let unsalted = cred(
        "00346d91dd87c74089f3bfa88e13de8101000000dcb6",
        &[&a.value, &b.value],
    );
    assert!(
        super::rules::rule_au_047_reused_secret_identity(
            &RuleContext::new(&[unsalted, a.clone(), b.clone()]),
            "scan",
            0
        )
        .is_empty(),
        "an unsalted digest must NOT link people (weak-password collision risk)"
    );

    // A unique secret seen against only ONE identity is not a link.
    let single = cred("$2b$12$onlyoneidentityhasthisxx", &[&a.value]);
    assert!(
        super::rules::rule_au_047_reused_secret_identity(
            &RuleContext::new(&[single, a]),
            "scan",
            0
        )
        .is_empty(),
        "one identity is not a cross-account link"
    );
}

#[test]
fn au047_discloses_when_the_identifier_list_is_truncated() {
    // The description enumerates at most 6 implicated identifiers, but a
    // secret genuinely reused across MANY accounts must say so — not silently
    // cut the list with no indication, the same "(+N more)" convention AU-048/
    // AU-076/AU-106 all share via join_capped.
    let emails: Vec<String> = (0..9).map(|i| format!("acct{i}@breach-corp.io")).collect();
    let email_refs: Vec<&str> = emails.iter().map(String::as_str).collect();
    let mut cred = Entity::new(
        EntityKind::Credential,
        "$2a$10$manyAccountsShareThisOneHashXYZ",
        0.6,
        "scan",
    );
    for em in &email_refs {
        cred.add_evidence(Evidence::new("import:dossier", "breach entry").with_attr("email", *em));
    }
    let hits =
        super::rules::rule_au_047_reused_secret_identity(&RuleContext::new(&[cred]), "scan", 0);
    assert_eq!(hits.len(), 1);
    assert!(
        hits[0]
            .description
            .contains("9 otherwise-separate accounts"),
        "the true total must still be stated: {}",
        hits[0].description
    );
    assert!(
        hits[0].description.contains("(+3 more)"),
        "the enumerated (top-6) identifier list must disclose the 3 it omitted: {}",
        hits[0].description
    );
}

#[test]
fn au047_links_on_reused_plaintext_password_and_session_token() {
    // Password reuse, session/cookie tokens and raw credentials are all valid
    // cross-correlation join-keys. AU-047 must link on a reused HIGH-ENTROPY
    // plaintext password (High — slight coincidence risk) and a reused
    // session/cookie token (Critical — random by construction), while still
    // refusing a common/weak password (no false identities).
    let cred = |value: &str, tags: &[&str], emails: &[&str]| {
        let mut c = Entity::new(EntityKind::Credential, value, 0.6, "scan");
        for t in tags {
            c.tag(*t);
        }
        for em in emails {
            c.add_evidence(Evidence::new("import:dossier", "breach entry").with_attr("email", *em));
        }
        c
    };
    let a = Entity::new(EntityKind::Email, "burner1@proton.me", 0.6, "scan");
    let b = Entity::new(EntityKind::Email, "real.name@gmail.com", 0.6, "scan");

    // Reused high-entropy plaintext password → High link.
    let pw = cred(
        "Tr0ub4dor&3xK9!q",
        &["plaintext-credential"],
        &[&a.value, &b.value],
    );
    let hits = super::rules::rule_au_047_reused_secret_identity(
        &RuleContext::new(&[pw, a.clone(), b.clone()]),
        "scan",
        0,
    );
    assert_eq!(hits.len(), 1, "reused strong password must link accounts");
    assert_eq!(hits[0].severity, super::Severity::High);
    assert!(hits[0].description.contains("password"));

    // Reused session/cookie token → Critical link.
    let tok = cred(
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        &["session-token"],
        &[&a.value, &b.value],
    );
    let hits = super::rules::rule_au_047_reused_secret_identity(
        &RuleContext::new(&[tok, a.clone(), b.clone()]),
        "scan",
        0,
    );
    assert_eq!(hits.len(), 1, "reused session token must link accounts");
    assert_eq!(hits[0].severity, super::Severity::Critical);
    assert!(hits[0].description.contains("session/cookie token"));

    // PRECISION: a reused COMMON password must NOT link (millions share it).
    let weak = cred(
        "password123",
        &["plaintext-credential"],
        &[&a.value, &b.value],
    );
    assert!(
        super::rules::rule_au_047_reused_secret_identity(
            &RuleContext::new(&[weak, a.clone(), b.clone()]),
            "scan",
            0
        )
        .is_empty(),
        "a common password must not manufacture an identity link"
    );

    // PRECISION: a bare hex digest WITHOUT session-token provenance stays
    // unlinkable (it may be an unsalted hash of a common password).
    let bare_hex = cred(
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        &[], // no session-token tag
        &[&a.value, &b.value],
    );
    assert!(
        super::rules::rule_au_047_reused_secret_identity(
            &RuleContext::new(&[bare_hex, a, b]),
            "scan",
            0
        )
        .is_empty(),
        "an untagged hex digest must not link (unsalted-hash collision risk)"
    );
}
