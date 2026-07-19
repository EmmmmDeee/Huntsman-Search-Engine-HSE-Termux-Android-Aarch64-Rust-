use super::*;

// ── Tests carried from paid-only shodan.rs ───────────────────────

#[test]
fn accepts_only_ip() {
    let m = Shodan;
    assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
    assert!(!m.accepts(&Target::new(TargetKind::Domain, "x")));
}

#[test]
fn cost_is_free() {
    assert!(matches!(Shodan.cost(), ModuleCost::Free));
}

// ── Tests carried from shodan_internetdb.rs ──────────────────────

#[test]
fn accepts_only_ip_not_domain() {
    let m = Shodan;
    assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
    assert!(!m.accepts(&Target::new(TargetKind::Domain, "x.com")));
}

// ── Merged-module tests ──────────────────────────────────────────

#[test]
fn priority_is_105() {
    assert_eq!(Shodan.priority(), 105);
}

#[test]
fn timeout_is_10s() {
    assert_eq!(Shodan.max_timeout_ms(), 10_000);
}

#[test]
fn name_is_shodan() {
    assert_eq!(Shodan.name(), "shodan");
}

#[test]
fn description_mentions_free_and_paid() {
    let desc = Shodan.description();
    assert!(desc.contains("free") || desc.contains("Free") || desc.contains("InternetDB"));
    assert!(desc.contains("paid") || desc.contains("Paid") || desc.contains("keyed"));
}

#[test]
fn target_entity_builds_ip_entity() {
    let e = target_entity("8.8.8.8", "scan-1");
    assert_eq!(e.kind, EntityKind::IpAddress);
    assert_eq!(e.value, "8.8.8.8");
    assert!((e.confidence - 0.90).abs() < 1e-9);
}

fn host(json: &str) -> HostResp {
    serde_json::from_str(json).expect("fixture is valid HostResp JSON")
}
fn of_kind(ents: &[Entity], kind: EntityKind) -> Vec<&Entity> {
    ents.iter().filter(|e| e.kind == kind).collect()
}

#[test]
fn real_host_coordinates_are_preferred_over_the_country_centroid() {
    // Shodan carries a precise per-host fix; the module must emit exactly that
    // ONE Coordinates (not addr-derived) and never also plant the coarse
    // country centroid alongside it.
    let body = host(
        r#"{"ports":[443],"country_name":"Australia","latitude":-27.4679,"longitude":153.0281,"city":"Brisbane"}"#,
    );
    let ents = build_paid_entities("1.2.3.4", body, "s");
    let coords = of_kind(&ents, EntityKind::Coordinates);
    assert_eq!(coords.len(), 1, "exactly one coordinate, the real host fix");
    assert_eq!(coords[0].value, "-27.467900,153.028100");
    assert!(coords[0].has_tag("geoint"));
    assert!(
        !coords[0].has_tag("addr-derived"),
        "a real fix is not a country-centroid approximation"
    );
    // City sharpens the address below country granularity.
    assert_eq!(
        of_kind(&ents, EntityKind::Address)[0].value,
        "Brisbane, Australia"
    );
}

#[test]
fn null_island_host_coords_are_rejected_not_emitted_as_a_real_fix() {
    // The `(0,0)` placeholder must be rejected by is_valid_coords — it must
    // never surface as a real per-host Coordinates fix. (The country centroid
    // is a separate, coarser fallback keyed on tabulated city names, so a bare
    // country string like "Australia" yields no centroid either — the point
    // here is only that the bogus (0,0) never leaks through.)
    let body = host(r#"{"ports":[80],"country_name":"Australia","latitude":0.0,"longitude":0.0}"#);
    let ents = build_paid_entities("1.2.3.4", body, "s");
    let real_fix = ents.iter().any(|e| {
        e.kind == EntityKind::Coordinates
            && e.evidence
                .iter()
                .any(|ev| ev.summary.contains("host coordinates"))
    });
    assert!(
        !real_fix,
        "a (0,0) host fix must be rejected, never emitted as a real coordinate"
    );
    // The country still yields its Address (location context survives).
    assert_eq!(
        of_kind(&ents, EntityKind::Address)[0].value,
        "Australia",
        "country Address still emits when no city is present"
    );
}

#[test]
fn registrable_domains_become_domain_pivots() {
    let body =
        host(r#"{"ports":[443],"hostnames":["dns.google"],"domains":["google.com","dns.google"]}"#);
    let ents = build_paid_entities("8.8.8.8", body, "s");
    let domains: Vec<&str> = of_kind(&ents, EntityKind::Domain)
        .iter()
        .map(|e| e.value.as_str())
        .collect();
    assert!(domains.contains(&"google.com"), "apex domain surfaces");
    assert!(domains.contains(&"dns.google"), "PTR hostname surfaces");
}

#[test]
fn paid_host_resp_deserializes_the_new_geo_and_domain_fields() {
    let body: HostResp = serde_json::from_str(
        r#"{"latitude":-27.5,"longitude":153.0,"city":"Brisbane","domains":["example.com"]}"#,
    )
    .unwrap();
    assert_eq!(body.latitude, Some(-27.5));
    assert_eq!(body.longitude, Some(153.0));
    assert_eq!(body.city.as_deref(), Some("Brisbane"));
    assert_eq!(body.domains, ["example.com"]);
    // Absent → defaults, no deserialize failure.
    let bare: HostResp = serde_json::from_str(r#"{"ports":[80]}"#).unwrap();
    assert!(bare.latitude.is_none() && bare.domains.is_empty());
}

#[test]
fn paid_host_resp_deserializes_the_tags_array() {
    // The paid host record carries the same `tags` classification array
    // (compromised/cloud/…) the free InternetDB path already surfaces —
    // HostResp must capture it, not silently drop it.
    let body: HostResp =
        serde_json::from_str(r#"{"ports":[443],"tags":["compromised","cloud","self-signed"]}"#)
            .unwrap();
    assert_eq!(body.tags, ["compromised", "cloud", "self-signed"]);
    // Absent `tags` defaults to empty (no deserialize failure).
    let bare: HostResp = serde_json::from_str(r#"{"ports":[80]}"#).unwrap();
    assert!(bare.tags.is_empty());
}
