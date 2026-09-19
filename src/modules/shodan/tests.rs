use super::*;
use crate::core::confidence;

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
    assert!((e.confidence - confidence::VERY_HIGH_PLUS).abs() < 1e-9);
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
fn real_fix_coordinates_carry_the_originating_ip_for_login_ip_recognition() {
    // Pass 31: the correlator's shared `person_login_ip_coords` (used by
    // `best_au_location_estimate` and `au_location_corroboration`) only
    // recognises a Coordinates fix as tied to a subject's breach/stealer
    // login IP when its evidence carries an `ip` attribute equal to that
    // IP — the same property `ipinfo`/`ip_whois_geo`/`ipquery`/`ip_geo`
    // already pin.
    let body = host(
        r#"{"ports":[443],"country_name":"Australia","latitude":-27.4679,"longitude":153.0281,"city":"Brisbane"}"#,
    );
    let ents = build_paid_entities("1.2.3.4", body, "s");
    let coords = of_kind(&ents, EntityKind::Coordinates);
    assert_eq!(
        coords[0].evidence[0]
            .attributes
            .get("ip")
            .map(String::as_str),
        Some("1.2.3.4"),
        "Coordinates evidence must carry the originating IP so \
         person_login_ip_coords can recognise this as a login-IP fix"
    );
}

#[test]
fn country_centroid_fallback_coordinates_carry_the_originating_ip_too() {
    // Same property as the real-fix test above, for the OTHER Coordinates
    // call site: the country-centroid fallback used when Shodan carries no
    // precise per-host lat/lon. "Brisbane" as `country_name` is an odd
    // fixture for a "country" field, but it's what actually resolves
    // through `city_coords` (a CITY table, not a country table) to
    // exercise this fallback branch at all — no bare country name is
    // tabulated, so this is the only way to reach it with a real fixture.
    let body = host(r#"{"ports":[443],"country_name":"Brisbane"}"#);
    let ents = build_paid_entities("1.2.3.4", body, "s");
    let coords = of_kind(&ents, EntityKind::Coordinates);
    assert_eq!(coords.len(), 1, "the fallback must have fired: {coords:?}");
    assert!(coords[0].has_tag("addr-derived"));
    assert_eq!(
        coords[0].evidence[0]
            .attributes
            .get("ip")
            .map(String::as_str),
        Some("1.2.3.4"),
        "Coordinates evidence must carry the originating IP so \
         person_login_ip_coords can recognise this as a login-IP fix"
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
    .expect("should succeed");
    assert_eq!(body.latitude, Some(-27.5));
    assert_eq!(body.longitude, Some(153.0));
    assert_eq!(body.city.as_deref(), Some("Brisbane"));
    assert_eq!(body.domains, ["example.com"]);
    // Absent → defaults, no deserialize failure.
    let bare: HostResp = serde_json::from_str(r#"{"ports":[80]}"#).expect("should succeed");
    assert!(bare.latitude.is_none() && bare.domains.is_empty());
}

#[test]
fn paid_host_resp_deserializes_the_tags_array() {
    // The paid host record carries the same `tags` classification array
    // (compromised/cloud/…) the free InternetDB path already surfaces —
    // HostResp must capture it, not silently drop it.
    let body: HostResp =
        serde_json::from_str(r#"{"ports":[443],"tags":["compromised","cloud","self-signed"]}"#)
            .expect("should succeed");
    assert_eq!(body.tags, ["compromised", "cloud", "self-signed"]);
    // Absent `tags` defaults to empty (no deserialize failure).
    let bare: HostResp = serde_json::from_str(r#"{"ports":[80]}"#).expect("should succeed");
    assert!(bare.tags.is_empty());
}

#[tokio::test]
async fn internetdb_failures_are_the_modules_error_and_only_a_404_is_the_clean_negative() {
    // Backlog #39. The keyless InternetDB path swallowed every transport
    // failure, throttle (429), outage (5xx) and unreadable body with a debug
    // line, so the scan recorded "no open ports, no CVEs" for the address. A
    // 404 is InternetDB's documented "No information available" — the one
    // genuine clean negative. Real request path against a loopback server.
    use crate::util::http::test_server::{Canned, serve};
    let base = serve(vec![
        Canned::json(500, r#"{"detail":"Internal Server Error"}"#),
        Canned::json(429, r#"{"detail":"Rate limit exceeded"}"#),
        Canned::text(200, "<html>interstitial</html>"),
        Canned::json(404, r#"{"detail":"No information available"}"#),
        Canned::json(
            200,
            r#"{"cpes":[],"hostnames":["one.one.one.one"],"ip":"1.1.1.1","ports":[53,443],"tags":[],"vulns":[]}"#,
        ),
    ])
    .await;
    let (bus, _rx) = tokio::sync::broadcast::channel(1);
    let ctx = ModuleContext {
        scan_id: "s".into(),
        bus,
        http: reqwest::Client::new(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
    };

    let mut result = ModuleResult::new();
    let err = Shodan
        .query_internetdb(&base, "1.1.1.1", &ctx, &mut result)
        .await
        .expect_err("a 5xx is an outage, not 'no ports, no CVEs'");
    assert!(err.to_string().contains("500"), "{err}");
    let err = Shodan
        .query_internetdb(&base, "1.1.1.1", &ctx, &mut result)
        .await
        .expect_err("a 429 is a throttle, not a clean host");
    assert!(err.to_string().contains("429"), "{err}");
    let err = Shodan
        .query_internetdb(&base, "1.1.1.1", &ctx, &mut result)
        .await
        .expect_err("an unreadable 200 body is a failed lookup");
    assert!(!err.to_string().is_empty());
    assert!(result.is_empty(), "no failure may leave entities behind");

    Shodan
        .query_internetdb(&base, "1.1.1.1", &ctx, &mut result)
        .await
        .expect("404 is InternetDB's documented 'no information available'");
    assert!(result.is_empty(), "the clean negative adds nothing");

    Shodan
        .query_internetdb(&base, "1.1.1.1", &ctx, &mut result)
        .await
        .expect("a genuine answer parses");
    let ip = result
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::IpAddress)
        .expect("the address entity carries the port summary");
    assert!(ip.has_tag("shodan-internetdb"));
    assert!(
        result
            .entities
            .iter()
            .any(|e| e.kind == EntityKind::Domain && e.value == "one.one.one.one"),
        "the PTR hostname becomes a Domain pivot"
    );
}

/// REQ-IPGEO-001. Both of this module's coordinate paths, because only one of
/// them was wrong and a test that exercised the other would pass vacuously.
///
/// On the real-fix path the module already sat below its own fix (0.55 under
/// 0.60). On the country-centroid FALLBACK it did not: 0.55 against a centroid
/// deliberately graded down to 0.45 — and with no city in the body the Address
/// is literally the same country string the centroid was looked up from, so
/// the two are the same datum at two different confidences.
#[test]
fn the_address_never_outranks_the_fix_it_was_composed_from() {
    // The centroid fixtures put a tabulated CITY in `country_name` for the same
    // reason `country_centroid_fallback_coordinates_carry_the_originating_ip_too`
    // does: `city_coords` is a city table, no bare country name resolves, and
    // this is the only way to reach that branch with a real fixture at all.
    let cases = [
        (
            "real per-host fix",
            r#"{"ports":[443],"country_name":"Australia","latitude":-27.4679,"longitude":153.0281,"city":"Brisbane"}"#,
        ),
        (
            "country-centroid fallback, city present",
            r#"{"ports":[443],"country_name":"Brisbane","city":"Ipswich"}"#,
        ),
        (
            "country-centroid fallback, country alone",
            r#"{"ports":[443],"country_name":"Brisbane"}"#,
        ),
    ];
    let mut inverted = Vec::new();
    for (why, json) in cases {
        let ents = build_paid_entities("1.2.3.4", host(json), "s");
        let coords = of_kind(&ents, EntityKind::Coordinates);
        let addrs = of_kind(&ents, EntityKind::Address);
        // A vacuous pass is the failure mode this test exists to avoid.
        if coords.is_empty() || addrs.is_empty() {
            inverted.push(format!(
                "{why}: no Coordinates/Address pair emitted ({} coords, {} addrs)",
                coords.len(),
                addrs.len()
            ));
            continue;
        }
        if addrs[0].confidence > coords[0].confidence {
            inverted.push(format!(
                "{why}: Address {:.2} > Coordinates {:.2}",
                addrs[0].confidence, coords[0].confidence
            ));
        }
    }
    assert!(
        inverted.is_empty(),
        "an Address is coarser than the fix it was composed from:\n  {}",
        inverted.join("\n  ")
    );
}
