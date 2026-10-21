use super::*;
use crate::test_support::OneResponse;

/// A faithful Nominatim place (public OpenStreetMap data for a well-known landmark); the forward
/// search returns an array of these, the reverse search one object.
const PLACE: &str = r#"{
    "place_id": 322358946,
    "licence": "Data © OpenStreetMap contributors, ODbL 1.0.",
    "osm_type": "way", "osm_id": 23733659,
    "lat": "37.4224858", "lon": "-122.0855846",
    "category": "building", "type": "commercial",
    "place_rank": 30, "importance": 6.277943083843774e-05,
    "addresstype": "building", "name": "Google Building 41",
    "display_name": "Google Building 41, 1600, Amphitheatre Parkway, Mountain View, Santa Clara County, California, 94043, United States",
    "address": {"building": "Google Building 41", "house_number": "1600", "road": "Amphitheatre Parkway", "city": "Mountain View", "county": "Santa Clara County", "state": "California", "ISO3166-2-lvl4": "US-CA", "postcode": "94043", "country": "United States", "country_code": "us"},
    "boundingbox": ["37.4221124", "37.4228508", "-122.0859868", "-122.0851511"]
}"#;

fn forward_body() -> String {
    format!("[{PLACE}]")
}

#[test]
fn the_search_url_carries_the_query_once_with_address_details() {
    assert_eq!(
        search_url("1600 Amphitheatre Parkway"),
        "https://nominatim.openstreetmap.org/search?q=1600%20Amphitheatre%20Parkway&format=jsonv2&addressdetails=1&limit=10"
    );
}

#[test]
fn the_reverse_url_carries_the_point() {
    assert_eq!(
        reverse_url(37.4224858, -122.0855846),
        "https://nominatim.openstreetmap.org/reverse?lat=37.4224858&lon=-122.0855846&format=jsonv2&addressdetails=1"
    );
}

#[test]
fn a_forward_match_yields_a_coordinates_point_and_an_address() {
    let report = forward(
        &OneResponse::json(200, &forward_body()),
        "Google Building 41",
        "scan-geo",
        1,
    )
    .expect("forward");
    assert!(report.outcome.kind.is_accepted(), "{:?}", report.outcome);

    let coordinates = report
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Coordinates)
        .expect("a coordinates entity");
    assert_eq!(coordinates.value, "37.422486,-122.085585");
    assert!((coordinates.confidence - GEOCODE_CONFIDENCE).abs() < f64::EPSILON);

    let address = report
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Address)
        .expect("an address entity");
    // The full written address is preserved verbatim as the raw value and as evidence.
    assert!(
        address.raw_value.contains("Amphitheatre Parkway"),
        "{}",
        address.raw_value
    );
    assert_eq!(
        address.evidence[0]
            .attributes
            .get("display_name")
            .map(String::as_str),
        Some(
            "Google Building 41, 1600, Amphitheatre Parkway, Mountain View, Santa Clara County, California, 94043, United States"
        )
    );
}

#[test]
fn every_address_component_is_kept_as_evidence() {
    let report = forward(
        &OneResponse::json(200, &forward_body()),
        "Google Building 41",
        "scan-geo",
        1,
    )
    .expect("forward");
    let coordinates = report
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Coordinates)
        .expect("a coordinates entity");
    let attrs = &coordinates.evidence[0].attributes;
    // The separate components Nominatim returned, each preserved under its own key.
    for (key, value) in [
        ("address_road", "Amphitheatre Parkway"),
        ("address_city", "Mountain View"),
        ("address_state", "California"),
        ("address_postcode", "94043"),
        ("address_country", "United States"),
        ("address_country_code", "us"),
    ] {
        assert_eq!(
            attrs.get(key).map(String::as_str),
            Some(value),
            "missing {key}"
        );
    }
    assert_eq!(attrs.get("osm_id").map(String::as_str), Some("23733659"));
    assert_eq!(attrs.get("mode").map(String::as_str), Some("forward"));
}

#[test]
fn a_reverse_match_yields_the_address_at_the_point() {
    let report = reverse(
        &OneResponse::json(200, PLACE),
        37.4224858,
        -122.0855846,
        "scan-geo",
        1,
    )
    .expect("reverse");
    assert!(report.outcome.kind.is_accepted());
    let address = report
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Address)
        .expect("an address entity");
    assert!(
        address.raw_value.contains("Mountain View"),
        "{}",
        address.raw_value
    );
    let attrs = &address.evidence[0].attributes;
    assert_eq!(attrs.get("mode").map(String::as_str), Some("reverse"));
    assert_eq!(
        attrs.get("coordinates").map(String::as_str),
        Some("37.422486,-122.085585")
    );
}

#[test]
fn an_empty_forward_result_is_a_clean_negative() {
    let report =
        forward(&OneResponse::json(200, "[]"), "zzzznowhere", "scan-geo", 1).expect("forward");
    assert!(report.entities.is_empty());
    assert_eq!(report.outcome.kind, SourceOutcomeKind::ValidZero);
}

#[test]
fn a_reverse_error_body_is_a_clean_negative_not_a_failure() {
    let report = reverse(
        &OneResponse::json(200, r#"{"error":"Unable to geocode"}"#),
        0.0,
        0.0,
        "scan-geo",
        1,
    )
    .expect("reverse");
    assert!(report.entities.is_empty());
    assert_eq!(report.outcome.kind, SourceOutcomeKind::ValidZero);
}

#[test]
fn a_refusal_is_not_read_as_a_zero() {
    let report = forward(
        &OneResponse::json(429, "rate limited"),
        "anything",
        "scan-geo",
        1,
    )
    .expect("forward");
    assert!(report.entities.is_empty());
    assert!(!report.outcome.kind.is_accepted(), "{:?}", report.outcome);
}

#[test]
fn a_body_that_is_not_json_is_drift_not_a_zero() {
    let report = forward(
        &OneResponse::json(200, "<html>not json</html>"),
        "anything",
        "scan-geo",
        1,
    )
    .expect("forward");
    assert!(report.entities.is_empty());
    assert_eq!(report.outcome.kind, SourceOutcomeKind::ParserDrift);
}
