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
fn real_host_coordinates_are_preferred_over_the_address_derived_centroid() {
    // Shodan carries a precise per-host fix; the module must emit exactly that
    // ONE Coordinates (not addr-derived) and never also plant the coarse
    // centroid alongside it.
    //
    // The "never also plant" half of this was vacuous until REQ-SHODAN-002: the
    // fallback geocoded `country` alone against a city gazetteer, so it could
    // not have fired on this fixture whatever the suppression did. It can now —
    // "Brisbane, Australia" resolves — so the assertion is load-bearing.
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
        "a real fix is not a city-centroid approximation"
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
fn address_derived_fallback_coordinates_carry_the_originating_ip_too() {
    // Same property as the real-fix test above, for the OTHER Coordinates call
    // site: the fallback used when Shodan carries no precise per-host lat/lon.
    //
    // This fixture used to read `{"country_name":"Brisbane"}`, under the comment
    // "no bare country name is tabulated, so this is the only way to reach it
    // with a real fixture". That was true, and it was the defect: the module
    // geocoded `country` alone against a gazetteer of cities, so the branch was
    // unreachable from any response Shodan can actually send, and the test had
    // to feed it one that cannot exist. The module now geocodes the COMPOSED
    // address, so an ordinary record reaches the branch (REQ-SHODAN-002).
    let body = host(r#"{"ports":[443],"city":"Brisbane","country_name":"Australia"}"#);
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
    // never surface as a real per-host Coordinates fix. (The address-derived
    // centroid is a separate, coarser fallback keyed on tabulated city names,
    // and this fixture carries no city, so the bare country "Australia" yields
    // no centroid either — the point here is only that the bogus (0,0) never
    // leaks through.)
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
    // Every fixture here is a response shape Shodan can actually send.
    //
    // Two of them used to put a tabulated CITY in `country_name`
    // (`{"country_name":"Brisbane","city":"Ipswich"}`, `{"country_name":"Brisbane"}`)
    // under the comment "this is the only way to reach that branch with a real
    // fixture at all" — true at the time, because the module geocoded `country`
    // alone against a city gazetteer and no country name is tabulated. The
    // workaround belonged in the module, not the fixture (REQ-SHODAN-002).
    //
    // The third old case, a country with no city, is gone from this sweep on
    // purpose: it emits no fix at all, so "the Address never outranks its fix"
    // is vacuously true there and this test's own emptiness guard rightly
    // rejects it. That case is pinned by
    // `a_country_only_record_still_earns_no_coordinate` instead.
    let cases = [
        (
            "real per-host fix",
            r#"{"ports":[443],"country_name":"Australia","latitude":-27.4679,"longitude":153.0281,"city":"Brisbane"}"#,
        ),
        (
            "address-derived fallback, AU city",
            r#"{"ports":[443],"country_name":"Australia","city":"Brisbane"}"#,
        ),
        (
            // Non-AU too: the gazetteer's foreign-place gate must not block a
            // composed overseas address from reaching its own tabulated row.
            "address-derived fallback, non-AU city",
            r#"{"ports":[443],"country_name":"United Kingdom","city":"Manchester"}"#,
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

// ── REQ-SHODAN-002: the fallback geocode reads the composed address ──────────

#[test]
fn a_city_bearing_record_without_a_host_fix_still_earns_a_coordinate() {
    // Shodan's paid record carries `city` + `country_name` but no lat/lon — a
    // real and common shape. The module composes "Brisbane, Australia" for the
    // Address; the fallback geocode must read THAT, not the bare country.
    //
    // It previously read `country` alone. `util::city_coords` is a gazetteer of
    // CITIES — not one of its rows is a country — so the lookup resolved to
    // nothing for every country Shodan can report, and this leg never fired.
    let body = host(r#"{"city":"Brisbane","country_name":"Australia"}"#);
    let ents = build_paid_entities("1.2.3.4", body, "s");
    let coords = of_kind(&ents, EntityKind::Coordinates);
    assert_eq!(
        coords.len(),
        1,
        "a record naming a tabulated city must yield exactly one centroid, got {:?}",
        coords.iter().map(|e| &e.value).collect::<Vec<_>>()
    );
    assert!(coords[0].has_tag("addr-derived"));
    assert!(coords[0].has_tag("geoint"));
    assert!(coords[0].has_tag("shodan"));
    // Brisbane, not a national centroid: the grain the gazetteer actually has.
    let (lat, lon) = crate::util::city_coords::city_coords("Brisbane, Australia")
        .expect("fixture city must be tabulated — otherwise this test is vacuous");
    // The module formats to 4 dp and `Entity::new` then normalises to 6, so
    // compare through the same normalisation rather than the raw format.
    assert_eq!(
        coords[0].value,
        crate::core::entity::normalise(&EntityKind::Coordinates, &format!("{lat:.4},{lon:.4}"))
    );
    // The evidence names the string that was geocoded, not "country".
    assert!(
        coords[0].evidence[0]
            .summary
            .contains("Brisbane, Australia"),
        "evidence must name the geocoded string, got {:?}",
        coords[0].evidence[0].summary
    );
    // The Address is unchanged, and REQ-IPGEO-001's cap — built for this path
    // and never able to run while the path was dead — now engages: the Address
    // cannot outrank the centroid it was composed from.
    let addrs = of_kind(&ents, EntityKind::Address);
    assert_eq!(addrs[0].value, "Brisbane, Australia");
    assert!(
        (addrs[0].confidence - confidence::LOW_MEDIUM).abs() < 1e-9,
        "Address must cap to the centroid's rung, got {}",
        addrs[0].confidence
    );
}

#[test]
fn a_country_only_record_still_earns_no_coordinate() {
    // The control that proves the fix did not broaden into fabrication. With no
    // city, the composed value IS the bare country — which the gazetteer still
    // cannot answer — so no coordinate is minted, exactly as before. A country
    // centroid would be ~1000 km of false precision.
    let body = host(r#"{"country_name":"Germany"}"#);
    let ents = build_paid_entities("1.2.3.4", body, "s");
    assert!(
        of_kind(&ents, EntityKind::Coordinates).is_empty(),
        "a bare country must never mint a coordinate"
    );
    let addrs = of_kind(&ents, EntityKind::Address);
    assert_eq!(addrs[0].value, "Germany", "the country Address still emits");
    assert!(
        (addrs[0].confidence - confidence::MEDIUM_HIGH).abs() < 1e-9,
        "with no centroid to cap against, the Address keeps its own rung"
    );
}

#[test]
fn a_cdn_edge_ip_earns_no_geo_even_with_a_tabulated_city() {
    // Control: the `geo_trusted` gate is checked once and covers the fallback
    // too, so making the fallback live cannot leak a datacentre location onto
    // an anycast edge.
    let untrusted = "104.16.0.1";
    assert!(
        crate::core::validation::untrusted_ip_geo_reason(untrusted).is_some(),
        "fixture IP must be classified untrusted — otherwise this test is vacuous"
    );
    let body = host(r#"{"city":"Brisbane","country_name":"Australia"}"#);
    let ents = build_paid_entities(untrusted, body, "s");
    assert!(of_kind(&ents, EntityKind::Coordinates).is_empty());
    assert!(of_kind(&ents, EntityKind::Address).is_empty());
}

#[test]
fn a_uk_host_in_a_homonym_city_is_never_placed_in_australia() {
    // The country is not decoration on the address label — `city_coords` reads
    // it to gate AU rows against overseas ones. `Newcastle` is tabulated as the
    // NSW city, so a Shodan record naming Newcastle in the UNITED KINGDOM must
    // not be geocoded to Australia: 17,000 km wrong, stamped `geoint`, and fed
    // to the geo correlator as a location fix.
    //
    // Geocoding `city` alone would do exactly that. Composing it with the
    // country trips the gazetteer's foreign-place gate, which is why the
    // fallback must geocode the composed string and not one field of it.
    assert!(
        crate::util::city_coords::city_coords("Newcastle").is_some(),
        "fixture city must be tabulated on its own — otherwise this test is vacuous"
    );
    let body = host(r#"{"city":"Newcastle","country_name":"United Kingdom"}"#);
    let ents = build_paid_entities("1.2.3.4", body, "s");
    for c in of_kind(&ents, EntityKind::Coordinates) {
        let (lat, lon) =
            crate::util::geohash::parse_coords(&c.value).expect("a Coordinates entity must parse");
        assert!(
            !crate::util::geo::is_in_australia(lat, lon),
            "a host Shodan places in the United Kingdom was geocoded to {} — \
             the country was dropped before the lookup",
            c.value
        );
    }
}
