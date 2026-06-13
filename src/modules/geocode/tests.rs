use super::*;
use crate::util::geo::parse_coords;

// -- acceptance tests (from forward_geocode) -------------------------

#[test]
fn accepts_address() {
    let m = Geocode;
    assert!(m.accepts(&Target::new(TargetKind::Address, "Brisbane")));
}

#[test]
fn rejects_domain_and_email() {
    let m = Geocode;
    assert!(!m.accepts(&Target::new(TargetKind::Domain, "example.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
}

// -- acceptance tests (from reverse_geocode) --------------------------

#[test]
fn accepts_coordinates() {
    let m = Geocode;
    assert!(m.accepts(&Target::new(TargetKind::Coordinates, "0,0")));
}

#[test]
fn rejects_ip_address() {
    let m = Geocode;
    assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
}

// -- parse_coords tests (from reverse_geocode) ------------------------

#[test]
fn parse_coords_valid() {
    let (lat, lon) = parse_coords("-33.8688,151.2093").unwrap();
    assert!((lat - (-33.8688)).abs() < 1e-4);
    assert!((lon - 151.2093).abs() < 1e-4);
}

#[test]
fn parse_coords_with_spaces() {
    let (lat, lon) = parse_coords(" 40.7128 , -74.0060 ").unwrap();
    assert!((lat - 40.7128).abs() < 1e-4);
    assert!((lon - (-74.0060)).abs() < 1e-4);
}

#[test]
fn parse_coords_invalid() {
    assert!(parse_coords("not-coords").is_err());
    assert!(parse_coords("").is_err());
}

// -- module metadata --------------------------------------------------

#[test]
fn module_metadata() {
    let m = Geocode;
    assert_eq!(m.name(), "geocode");
    assert_eq!(m.priority(), 21);
    assert_eq!(m.max_timeout_ms(), 8_000);
}

// -- AU-relevance shaping of reverse geocode --------------------------

fn resp(json: serde_json::Value) -> NominatimResp {
    serde_json::from_value(json).unwrap()
}

#[test]
fn forward_geocode_shapes_confidence_by_au_relevance() {
    // An AU result is a strong on-region anchor; a foreign one is a demoted
    // candidate that won't be expanded or counted as confirmed.
    let au = build_forward_entity(-27.4766, 153.0166, "-27.476600,153.016600", "scan");
    assert!((au.confidence - 0.70).abs() < 1e-9);
    assert!(au.has_tag("au-relevant"));
    assert!(au.has_tag("au-state:QLD")); // Brisbane
    assert!(au.has_tag("geocoded"));
    assert!(!au.has_tag("candidate"));

    let foreign = build_forward_entity(51.5074, -0.1278, "51.507400,-0.127800", "scan");
    assert!((foreign.confidence - 0.40).abs() < 1e-9);
    assert!(foreign.has_tag("off-region"));
    assert!(foreign.has_tag("candidate"));
    assert!(!foreign.has_tag("au-relevant"));
}

#[test]
fn reverse_in_australia_by_country_code_is_a_strong_anchor() {
    let data = resp(serde_json::json!({
        "display_name": "Brisbane City, QLD, Australia",
        "address": { "city": "Brisbane", "state": "Queensland", "country_code": "au" }
    }));
    let e = build_reverse_entity(-27.4766, 153.0166, &data, "scan");
    assert!((e.confidence - 0.78).abs() < 1e-9);
    assert!(e.has_tag("au-relevant"));
    assert!(e.has_tag("country:AU"));
    assert!(e.has_tag("au-state:QLD"));
    assert!(!e.has_tag("candidate"));
}

#[test]
fn reverse_off_region_by_country_code_is_a_candidate() {
    let data = resp(serde_json::json!({
        "display_name": "Manhattan, New York, USA",
        "address": { "city": "New York", "country_code": "us" }
    }));
    let e = build_reverse_entity(40.7128, -74.0060, &data, "scan");
    assert!((e.confidence - 0.40).abs() < 1e-9);
    assert!(e.has_tag("candidate"));
    assert!(e.has_tag("country:US"));
    assert!(!e.has_tag("au-relevant"));
}

#[test]
fn reverse_without_country_code_falls_back_to_the_bounding_box() {
    // No country code: an AU coordinate is still recognised on-region via
    // the offline bounding box, while a foreign one stays Unknown (neutral).
    let bare = resp(serde_json::json!({ "display_name": "somewhere" }));
    let au = build_reverse_entity(-33.8688, 151.2093, &bare, "scan");
    assert!((au.confidence - 0.78).abs() < 1e-9);
    assert!(au.has_tag("au-relevant"));

    let foreign = build_reverse_entity(48.8566, 2.3522, &bare, "scan");
    assert!((foreign.confidence - 0.55).abs() < 1e-9);
    assert!(!foreign.has_tag("au-relevant"));
    assert!(!foreign.has_tag("candidate"));
}
