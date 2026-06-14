use super::Photon;
use super::build::{build_forward, build_reverse};
use super::types::{Feature, PhotonResp, Props};
use crate::core::{
    entity::EntityKind,
    module::Module,
    scan::{Target, TargetKind},
};

fn props(json: &str) -> Props {
    serde_json::from_str(json).unwrap()
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
    let r: PhotonResp = serde_json::from_str(raw).unwrap();
    let coords = &r.features[0].geometry.as_ref().unwrap().coordinates;
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
    .unwrap();
    let e = build_forward("opera house sydney", &feature, "s").unwrap();
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
    let feature: Feature = serde_json::from_str(r#"{"properties":{"name":"X"}}"#).unwrap();
    assert!(build_forward("x", &feature, "s").is_none());
    let no_coords: Feature = serde_json::from_str(r#"{"geometry":{"coordinates":[1.0]}}"#).unwrap();
    assert!(build_forward("x", &no_coords, "s").is_none());
}

#[test]
fn build_forward_rejects_out_of_range_and_null_island() {
    // A malformed geometry must not become a Coordinates entity (it would be
    // a high-confidence false fix). Longitude is `coordinates[0]`.
    let oob: Feature =
        serde_json::from_str(r#"{"geometry":{"coordinates":[999.0,500.0]}}"#).unwrap();
    assert!(build_forward("x", &oob, "s").is_none());
    let null_island: Feature =
        serde_json::from_str(r#"{"geometry":{"coordinates":[0.0,0.0]}}"#).unwrap();
    assert!(build_forward("x", &null_island, "s").is_none());
}

// ── Reverse: Address with name folded in + OSM classification ────────
#[test]
fn build_reverse_uses_name_and_dedupes_against_city() {
    // POI: the name is the most-specific component and must lead the display.
    let p = props(
        r#"{"name":"Sydney Opera House","street":"Bennelong Point","city":"Sydney",
            "state":"NSW","country":"Australia","countrycode":"AU","postcode":"2000",
            "osm_key":"tourism","osm_value":"attraction"}"#,
    );
    let e = build_reverse(-33.8568, 151.2153, &p, "s").unwrap();
    assert_eq!(e.kind, EntityKind::Address);
    assert_eq!(
        e.value,
        "Sydney Opera House, Bennelong Point, Sydney, NSW, Australia"
    );
    assert!(
        e.has_tag("reverse-geocoded") && e.has_tag("country:AU") && e.has_tag("osm:attraction")
    );
    let ev = &e.evidence[0];
    assert_eq!(
        ev.attributes.get("place_name").map(String::as_str),
        Some("Sydney Opera House")
    );
    assert_eq!(
        ev.attributes.get("postcode").map(String::as_str),
        Some("2000")
    );

    // A city whose name == city collapses to one occurrence.
    let city = props(r#"{"name":"Sydney","city":"Sydney","country":"Australia"}"#);
    let ce = build_reverse(-33.8, 151.2, &city, "s").unwrap();
    assert_eq!(ce.value, "Sydney, Australia");
}

#[test]
fn build_reverse_too_few_parts_is_none() {
    assert!(build_reverse(0.0, 0.0, &props(r#"{"country":"Australia"}"#), "s").is_none());
    assert!(build_reverse(0.0, 0.0, &props("{}"), "s").is_none());
}
