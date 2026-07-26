use super::*;

#[test]
fn accepts_only_ip() {
    let m = CriminalIp;
    assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
    assert!(!m.accepts(&Target::new(TargetKind::Domain, "x")));
}
#[test]
fn cost_is_key_gated() {
    assert!(matches!(CriminalIp.cost(), ModuleCost::KeyGated));
}

// ── build_entities (pure extraction) ───────────────────────────────

fn report(json: &str) -> Resp {
    serde_json::from_str(json).expect("fixture is valid Resp JSON")
}
fn ip_target(ip: &str) -> Target {
    Target::new(TargetKind::IpAddress, ip)
}
fn of_kind(ents: &[Entity], kind: EntityKind) -> Option<&Entity> {
    ents.iter().find(|e| e.kind == kind)
}

#[test]
fn risk_is_high_only_for_top_bands() {
    for band in ["Critical", "Dangerous", "High"] {
        assert!(risk_is_high(band), "{band} should be high risk");
    }
    // Lower bands, the empty string, and a case-mismatch must not qualify.
    for band in ["Low", "Moderate", "Safe", "", "high"] {
        assert!(!risk_is_high(band), "{band} should not be high risk");
    }
}

#[test]
fn full_report_yields_subject_org_and_asn() {
    let body = report(
        r#"{
            "status": 200,
            "score": { "inbound": "Critical", "outbound": "Low" },
            "issues": { "is_vpn": true, "is_scanner": true, "is_proxy": false },
            "port": { "count": 7 },
            "vulnerability": { "count": 3 },
            "whois": { "data": [
                { "as_no": 15169, "as_name": "GOOGLE",
                  "org_name": "Google LLC", "org_country_code": "us" }
            ] }
        }"#,
    );
    let ents = build_entities(&body, &ip_target("8.8.8.8"), "s");
    assert_eq!(ents.len(), 3);

    let subject = of_kind(&ents, EntityKind::IpAddress).expect("subject IP entity");
    assert!(subject.has_tag("criminal_ip"));
    assert!(subject.has_tag("high-risk-inbound"));
    assert!(
        !subject.has_tag("high-risk-outbound"),
        "Low outbound is not high-risk"
    );
    assert!(subject.has_tag("vpn") && subject.has_tag("scanner"));
    assert!(!subject.has_tag("proxy"), "false flags must not tag");
    assert!(
        subject.has_tag("country:US"),
        "country code is uppercased into the tag"
    );

    let ev = &subject.evidence[0];
    let attr = |k: &str| ev.attributes.get(k).map(String::as_str);
    assert_eq!(attr("inbound_risk"), Some("Critical"));
    assert_eq!(attr("outbound_risk"), Some("Low"));
    assert_eq!(attr("asn"), Some("15169"));
    assert_eq!(attr("as_name"), Some("GOOGLE"));
    assert_eq!(attr("org"), Some("Google LLC"));
    assert_eq!(attr("country"), Some("us"));
    assert_eq!(attr("open_port_count"), Some("7"));
    assert_eq!(attr("vuln_count"), Some("3"));
    assert_eq!(attr("is_vpn"), Some("true"));
    assert_eq!(attr("is_scanner"), Some("true"));
    assert!(attr("is_proxy").is_none(), "false flags emit no attr");

    assert_eq!(
        of_kind(&ents, EntityKind::Organisation).expect("should succeed").value,
        "Google LLC"
    );
    assert_eq!(of_kind(&ents, EntityKind::Asn).expect("should succeed").value, "AS15169");
}

#[test]
fn empty_report_still_yields_only_the_subject() {
    let ents = build_entities(&report(r#"{"status":200}"#), &ip_target("1.2.3.4"), "s");
    assert_eq!(ents.len(), 1);
    let subject = &ents[0];
    assert_eq!(subject.kind, EntityKind::IpAddress);
    assert!(subject.has_tag("criminal_ip"));
    assert!(!subject.has_tag("high-risk-inbound"));
    // Only the summary evidence — no risk/issue attributes.
    assert!(subject.evidence[0].attributes.is_empty());
}

#[test]
fn blank_org_skips_organisation_but_asn_survives() {
    let body = report(r#"{ "status": 200, "whois": { "data": [ { "as_no": 64500, "org_name": "  " } ] } }"#);
    let ents = build_entities(&body, &ip_target("9.9.9.9"), "s");
    assert!(
        of_kind(&ents, EntityKind::Organisation).is_none(),
        "a blank org name must not produce an Organisation pivot"
    );
    assert_eq!(of_kind(&ents, EntityKind::Asn).expect("should succeed").value, "AS64500");
}

#[test]
fn org_without_asn_yields_organisation_only() {
    let body = report(r#"{ "status": 200, "whois": { "data": [ { "org_name": "Acme Networks" } ] } }"#);
    let ents = build_entities(&body, &ip_target("9.9.9.9"), "s");
    assert_eq!(
        of_kind(&ents, EntityKind::Organisation).expect("should succeed").value,
        "Acme Networks"
    );
    assert!(of_kind(&ents, EntityKind::Asn).is_none());
}

#[test]
fn blank_country_code_adds_no_tag_or_attr() {
    let body = report(r#"{ "status": 200, "whois": { "data": [ { "org_country_code": "" } ] } }"#);
    let subject = build_entities(&body, &ip_target("9.9.9.9"), "s").remove(0);
    assert!(
        !subject.tags.iter().any(|t| t.starts_with("country:")),
        "a blank country code adds no country tag"
    );
    assert!(!subject.evidence[0].attributes.contains_key("country"));
}

#[test]
fn outbound_high_risk_tagged_independently_of_inbound() {
    let body = report(r#"{ "status": 200, "score": { "outbound": "Dangerous" } }"#);
    let subject = build_entities(&body, &ip_target("1.2.3.4"), "s").remove(0);
    assert!(subject.has_tag("high-risk-outbound"));
    assert!(!subject.has_tag("high-risk-inbound"));
}

#[test]
fn whois_geolocation_yields_coordinates_and_address() {
    let body = report(
        r#"{
            "status": 200,
            "whois": { "data": [
                { "as_no": 4766, "org_name": "KT Corp", "org_country_code": "kr",
                  "city": "Seoul", "region": "Seoul", "latitude": 37.5665, "longitude": 126.978 }
            ] }
        }"#,
    );
    let ents = build_entities(&body, &ip_target("1.2.3.4"), "s");

    let coord = of_kind(&ents, EntityKind::Coordinates).expect("valid lat/lon → Coordinates");
    // Entity::new normalises Coordinates to 6-decimal lat,lon.
    assert_eq!(coord.value, "37.566500,126.978000");
    assert!(coord.has_tag("criminal_ip") && coord.has_tag("geoint"));

    let addr = of_kind(&ents, EntityKind::Address).expect("city/region/country → Address");
    // country code uppercased; the compose_address join drops no present part here.
    assert_eq!(addr.value, "Seoul, Seoul, KR");
    assert!(addr.has_tag("geoint"));
}

#[test]
fn null_island_whois_coords_are_rejected_but_city_still_maps() {
    // The API's `(0,0)` placeholder must never become an equatorial fix; a
    // present city still yields an Address (with no region → two-part join).
    let body = report(
        r#"{
            "status": 200,
            "whois": { "data": [
                { "org_country_code": "us", "city": "Ashburn", "latitude": 0.0, "longitude": 0.0 }
            ] }
        }"#,
    );
    let ents = build_entities(&body, &ip_target("1.2.3.4"), "s");
    assert!(
        of_kind(&ents, EntityKind::Coordinates).is_none(),
        "null-island (0,0) must be rejected by is_valid_coords"
    );
    assert_eq!(
        of_kind(&ents, EntityKind::Address).expect("should succeed").value,
        "Ashburn, US"
    );
}

#[test]
fn nonblank_filters_empty_and_whitespace_only() {
    assert_eq!(nonblank(Some("  AS13335 ")), Some("AS13335"));
    assert_eq!(nonblank(Some("x")), Some("x"));
    assert_eq!(nonblank(Some("")), None);
    assert_eq!(nonblank(Some("   ")), None);
    assert_eq!(nonblank(None), None);
}
