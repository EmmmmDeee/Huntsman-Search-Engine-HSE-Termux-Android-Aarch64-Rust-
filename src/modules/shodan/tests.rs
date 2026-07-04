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

/// A paid host-lookup error (e.g. a 401/403/429 on the shared `oss` key) must
/// NOT discard the free InternetDB data already gathered — `process` runs the
/// free path first and routes the paid outcome through `finalize`, which keeps
/// the result. Regression guard for the `?`-on-paid-before-free bug: the free
/// InternetDB fallback used to be skipped whenever the paid path errored.
#[test]
fn paid_error_retains_free_internetdb_results() {
    let mut result = ModuleResult::new();
    result.push(Entity::new(EntityKind::IpAddress, "8.8.8.8", 0.92, "scan"));
    let out = finalize(
        Err(crate::core::error::Error::module(
            "shodan",
            "429 rate limited",
        )),
        result,
    )
    .expect("a paid-path error must not fail the module when free data exists");
    assert_eq!(
        out.len(),
        1,
        "InternetDB data must survive a paid-path error"
    );
    assert_eq!(out.entities[0].value, "8.8.8.8");
}

/// The paid Shodan host response carries the host's PRECISE latitude/longitude
/// and city (e.g. 38.0088,-122.1175 "Mountain View"). Those must be surfaced —
/// a precise `Coordinates` entity at the real lat/lon, not just the country
/// centroid — so the paid key delivers city-level geolocation, its key value
/// over the free InternetDB path.
#[test]
fn geo_entities_emit_precise_coordinates_when_present() {
    let body: HostResp = serde_json::from_value(serde_json::json!({
        "latitude": 38.0088,
        "longitude": -122.1175,
        "city": "Mountain View",
        "region_code": "CA",
        "country_name": "United States",
        "country_code": "US",
    }))
    .unwrap();

    let ents = geo_entities(&body, "8.8.8.8", "scan");
    let coord = ents
        .iter()
        .find(|e| e.kind == EntityKind::Coordinates)
        .expect("a coordinates entity must be emitted");
    // Parse rather than string-compare: `Entity::new` canonicalises the coord
    // string (e.g. to 6 decimals). The point is that it is the PRECISE host
    // fix, not the coarse country centroid.
    let (lat, lon) =
        crate::util::geohash::parse_coords(&coord.value).expect("coordinates must parse");
    assert!(
        (lat - 38.0088).abs() < 1e-3 && (lon - (-122.1175)).abs() < 1e-3,
        "must be the precise host lat/lon, got: {}",
        coord.value
    );
    let addr = ents
        .iter()
        .find(|e| e.kind == EntityKind::Address)
        .expect("an address entity must be emitted");
    assert!(
        addr.value.contains("Mountain View"),
        "address must be qualified with the city, got: {}",
        addr.value
    );
}
