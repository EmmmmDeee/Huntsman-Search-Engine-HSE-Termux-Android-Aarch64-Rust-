use super::Photon;
use super::build::{build_forward, build_reverse, join_unique};
use super::types::{Feature, PhotonResp, Props};
use crate::core::{
    entity::EntityKind,
    module::Module,
    scan::{Target, TargetKind},
};

fn props(json: &str) -> Props {
    serde_json::from_str(json).expect("should succeed")
}

// ── Module surface ──────────────────────────────────────────────────
#[test]
fn accepts_address_and_coordinates() {
    let m = Photon;
    assert!(m.accepts(&Target::new(TargetKind::Address, "Sydney")));
    assert!(m.accepts(&Target::new(TargetKind::Coordinates, "-33.8,151.2")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
}

#[test]
fn module_metadata() {
    assert_eq!(Photon.name(), "photon");
    assert_eq!(Photon.priority(), 20);
    assert_eq!(Photon.max_timeout_ms(), 4_000);
}

#[test]
fn parse_forward_response() {
    let raw = r#"{"features":[{"geometry":{"type":"Point","coordinates":[151.2093,-33.8688]},
        "properties":{"name":"Sydney","country":"Australia","countrycode":"AU","type":"city"}}]}"#;
    let r: PhotonResp = serde_json::from_str(raw).expect("should succeed");
    let coords = &r.features[0]
        .geometry
        .as_ref()
        .expect("should succeed")
        .coordinates;
    assert!((coords[0] - 151.2093).abs() < 0.001);
}

// ── Forward: Coordinates with name + OSM classification ─────────────
#[test]
fn build_forward_emits_coordinates_with_name_and_osm() {
    let feature: Feature = serde_json::from_str(
        r#"{"geometry":{"coordinates":[151.2153,-33.8568]},
            "properties":{"name":"Sydney Opera House","countrycode":"au","type":"house",
                          "osm_key":"amenity","osm_value":"theatre"}}"#,
    )
    .expect("should succeed");
    let e = build_forward("opera house sydney", &feature, false, "s").expect("should succeed");
    assert_eq!(e.kind, EntityKind::Coordinates);
    assert_eq!(e.value, "-33.856800,151.215300");
    assert!(e.has_tag("geocoded") && e.has_tag("country:AU"));
    assert!(e.has_tag("osm:theatre")); // the recovered classification
    let ev = &e.evidence[0];
    assert_eq!(
        ev.attributes.get("place_name").map(String::as_str),
        Some("Sydney Opera House")
    );
    assert_eq!(
        ev.attributes.get("osm_key").map(String::as_str),
        Some("amenity")
    );
    assert_eq!(
        ev.attributes.get("osm_value").map(String::as_str),
        Some("theatre")
    );
    assert_eq!(
        ev.attributes.get("input_address").map(String::as_str),
        Some("opera house sydney")
    );
}

#[test]
fn build_forward_without_geometry_is_none() {
    let feature: Feature =
        serde_json::from_str(r#"{"properties":{"name":"X"}}"#).expect("should succeed");
    assert!(build_forward("x", &feature, false, "s").is_none());
    let no_coords: Feature =
        serde_json::from_str(r#"{"geometry":{"coordinates":[1.0]}}"#).expect("should succeed");
    assert!(build_forward("x", &no_coords, false, "s").is_none());
}

#[test]
fn build_forward_prefers_the_authoritative_country_code_over_the_crude_box() {
    // Regression: build_forward used to call tag_au_state unconditionally, so
    // a coordinate falling in the offline bounding box's known false-positive
    // band (Rote Island/West Timor, Indonesia) got a self-contradicting
    // country:ID + country:AU + au-state:WA on the same entity, and sat at a
    // flat confidence::MEDIUM_PLUS regardless of the confirmed foreign country.
    let feature: Feature = serde_json::from_str(
        r#"{"geometry":{"coordinates":[123.0,-10.9]},
            "properties":{"name":"Rote","countrycode":"id"}}"#,
    )
    .expect("should succeed");
    let e = build_forward("rote island", &feature, false, "s").expect("should succeed");
    assert!(e.has_tag("country:ID"));
    assert!(
        !e.has_tag("country:AU"),
        "must not contradict the real country"
    );
    assert!(!e.has_tag("au-state:WA"), "must not misattribute to WA");
    assert!(e.has_tag("off-region"));
    assert!(e.has_tag("candidate"));
    assert!(
        (e.confidence - crate::core::confidence::LOW).abs() < 1e-9,
        "an off-region country code must demote confidence: {}",
        e.confidence
    );
}

#[test]
fn build_forward_rejects_out_of_range_and_null_island() {
    // A malformed geometry must not become a Coordinates entity (it would be
    // a high-confidence false fix). Longitude is `coordinates[0]`.
    let oob: Feature = serde_json::from_str(r#"{"geometry":{"coordinates":[999.0,500.0]}}"#)
        .expect("should succeed");
    assert!(build_forward("x", &oob, false, "s").is_none());
    let null_island: Feature =
        serde_json::from_str(r#"{"geometry":{"coordinates":[0.0,0.0]}}"#).expect("should succeed");
    assert!(build_forward("x", &null_island, false, "s").is_none());
}

// ── Reverse: Address with name folded in + OSM classification ────────
#[test]
fn build_reverse_is_the_address_not_the_landmark_and_dedupes_against_city() {
    // POI: the landmark name is evidence (place_name / nearest_feature), not
    // part of the address; the street leads the value (REQ-GEO-010).
    let p = props(
        r#"{"name":"Sydney Opera House","street":"Bennelong Point","city":"Sydney",
            "state":"NSW","country":"Australia","countrycode":"AU","postcode":"2000",
            "osm_key":"tourism","osm_value":"attraction"}"#,
    );
    let e = build_reverse(-33.8568, 151.2153, &p, None, "s").expect("should succeed");
    assert_eq!(e.kind, EntityKind::Address);
    assert_eq!(e.value, "Bennelong Point, Sydney, NSW, 2000, Australia");
    assert!(
        e.has_tag("reverse-geocoded")
            && e.has_tag("nearest-address")
            && e.has_tag("country:AU")
            && e.has_tag("osm:attraction")
    );
    let ev = &e.evidence[0];
    assert_eq!(
        ev.attributes.get("place_name").map(String::as_str),
        Some("Sydney Opera House")
    );
    assert_eq!(
        ev.attributes.get("nearest_feature").map(String::as_str),
        Some("Sydney Opera House")
    );
    assert_eq!(
        ev.attributes.get("postcode").map(String::as_str),
        Some("2000")
    );

    // A place feature's name IS its locality; one equal to the city collapses.
    let city = props(
        r#"{"name":"Sydney","city":"Sydney","country":"Australia","osm_key":"place","osm_value":"city"}"#,
    );
    let ce = build_reverse(-33.8, 151.2, &city, None, "s").expect("should succeed");
    assert_eq!(ce.value, "Sydney, Australia");

    // A road feature's name is the street when Photon gives no `street`.
    let road = props(
        r#"{"name":"George Street","city":"Sydney","country":"Australia","osm_key":"highway","osm_value":"primary"}"#,
    );
    let re = build_reverse(-33.87, 151.2, &road, None, "s").expect("should succeed");
    assert_eq!(re.value, "George Street, Sydney, Australia");
}

/// REQ-GEO-010: scan 7258fc07's "Nina Armando, King Street Cycleway, Sydney, …"
/// led with a clothes shop, which the address parser then read as the city.
#[test]
fn build_reverse_value_never_carries_the_poi_name() {
    let p = props(
        r#"{"name":"Nina Armando","street":"King Street Cycleway","city":"Sydney","state":"New South Wales","postcode":"2000","country":"Australia","countrycode":"AU","osm_key":"shop","osm_value":"clothes"}"#,
    );
    let e = build_reverse(-33.8688, 151.2093, &p, None, "s").expect("resolves");
    assert!(!e.value.contains("Nina Armando"));
    assert_eq!(
        e.value,
        "King Street Cycleway, Sydney, New South Wales, 2000, Australia"
    );
    assert_eq!(
        e.evidence[0]
            .attributes
            .get("place_name")
            .map(String::as_str),
        Some("Nina Armando")
    );
    assert_ne!(
        crate::util::geohash::parse_address(&e.value)
            .city
            .as_deref(),
        Some("Nina Armando")
    );
}

#[test]
fn build_reverse_prefers_the_authoritative_country_code_over_the_crude_box() {
    // Regression: same self-contradicting-tags/flat-confidence bug as
    // build_forward, on the reverse leg.
    let p = props(r#"{"name":"Rote","city":"Rote Ndao","country":"Indonesia","countrycode":"id"}"#);
    let e = build_reverse(-10.9, 123.0, &p, None, "s").expect("should succeed");
    assert!(e.has_tag("country:ID"));
    assert!(
        !e.has_tag("country:AU"),
        "must not contradict the real country"
    );
    assert!(!e.has_tag("au-state:WA"), "must not misattribute to WA");
    assert!(e.has_tag("off-region"));
    assert!(e.has_tag("candidate"));
    assert!(
        (e.confidence - crate::core::confidence::LOW).abs() < 1e-9,
        "an off-region country code must demote confidence: {}",
        e.confidence
    );
}

#[test]
fn build_reverse_too_few_parts_is_none() {
    assert!(build_reverse(0.0, 0.0, &props(r#"{"country":"Australia"}"#), None, "s").is_none());
    assert!(build_reverse(0.0, 0.0, &props("{}"), None, "s").is_none());
}

#[test]
fn join_unique_drops_case_insensitive_dupes_keeping_order() {
    // `name` == `city` ("Sydney") collapses to one; None parts skipped; first
    // spelling/casing wins for a case-insensitive duplicate.
    let parts = [
        Some("Sydney"),
        None,
        Some("sydney"), // dup of "Sydney" (case-insensitive) → dropped
        Some("NSW"),
        Some("Australia"),
    ];
    assert_eq!(
        join_unique(&parts),
        vec![
            "Sydney".to_string(),
            "NSW".to_string(),
            "Australia".to_string()
        ]
    );
}

#[test]
fn join_unique_all_none_is_empty() {
    let parts: [Option<&str>; 3] = [None, None, None];
    assert!(join_unique(&parts).is_empty());
}

#[test]
fn join_unique_preserves_first_casing() {
    // The earlier-seen casing is the one retained.
    let parts = [Some("PARIS"), Some("paris")];
    assert_eq!(join_unique(&parts), vec!["PARIS".to_string()]);
}

/// REQ-GEOLABEL-006: Photon's nearest address is inferred, exactly as
/// `geocode`'s reverse leg marks its record.
#[test]
fn build_reverse_evidence_is_inferred() {
    let p = props(
        r#"{"name":"Nina Armando","street":"King Street Cycleway","city":"Sydney","state":"New South Wales","postcode":"2000","country":"Australia","countrycode":"AU","osm_key":"shop","osm_value":"clothes"}"#,
    );
    let e = build_reverse(-33.8688, 151.2093, &p, None, "s").expect("resolves");
    assert!(
        e.evidence.iter().all(|ev| ev.is_inferred),
        "{:?}",
        e.evidence
    );
}

/// REQ-GEOLABEL-002: the reverse leg records the returned feature's own
/// position (GeoJSON `[lon, lat]`) and the house number and road separately,
/// so the place label can tell how far the nearest address is from the point.
#[test]
fn build_reverse_records_the_matched_feature_position_and_parts() {
    let feature: Feature = serde_json::from_str(
        r#"{"geometry":{"coordinates":[151.2099,-33.8676123]},
            "properties":{"street":"Martin Place","housenumber":"25","city":"Sydney",
                          "countrycode":"AU","osm_key":"building"}}"#,
    )
    .expect("feature");
    let props = feature.properties.as_ref().expect("props");
    let e = build_reverse(-33.8676, 151.2099, props, feature.position(), "s").expect("resolves");
    let a = &e.evidence[0].attributes;
    let get = |k: &str| a.get(k).map(String::as_str);
    assert_eq!(get("matched_lat"), Some("-33.867612"));
    assert_eq!(get("matched_lon"), Some("151.209900"));
    assert_eq!(get("house_number"), Some("25"));
    assert_eq!(get("road"), Some("Martin Place"));
    // No geometry, no recorded position.
    let e = build_reverse(-33.8676, 151.2099, props, None, "s").expect("resolves");
    assert!(!e.evidence[0].attributes.contains_key("matched_lat"));
}
