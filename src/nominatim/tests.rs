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
        reverse_url(37.422_485_8, -122.085_584_6),
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
        37.422_485_8,
        -122.085_584_6,
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
fn a_rate_limit_is_classified_not_read_as_a_zero() {
    // Exercised through the pure interpreter, not `forward`: a 429 fed through the network
    // path would trip the process-shared per-host pacing breaker for Nominatim's host and
    // suppress every sibling test that runs after it. The breaker's own rate-limit behaviour
    // is covered in `fetch`'s tests; here we only check the source reads the refusal, not a
    // zero. A `truncated` body or a 4xx/5xx is the same branch of `refusal`.
    let response = Response {
        status: 429,
        headers: vec![("content-type".into(), "text/plain".into())],
        body: b"rate limited".to_vec(),
        truncated: false,
    };
    let report = interpret_forward(&response, "anything", "scan-geo", 1);
    assert!(report.entities.is_empty());
    assert!(!report.outcome.kind.is_accepted(), "{:?}", report.outcome);
    assert_eq!(report.outcome.kind, SourceOutcomeKind::RateLimited);
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

#[test]
fn forward_preserves_every_raw_provider_field_and_observation_time() {
    let mut place: serde_json::Value = serde_json::from_str(PLACE).expect("valid fixture");
    place["unexpected_nested"] = serde_json::json!({"flags": [true, null, 3], "label": "retained"});
    let body = serde_json::to_string(&vec![place]).expect("forward fixture");
    let observed_at = 1_700_000_123_u64;

    let report = forward(
        &OneResponse::json(200, &body),
        "Google Building 41",
        "scan-raw",
        observed_at,
    )
    .expect("forward");
    assert!(report.outcome.kind.is_accepted());
    for entity in &report.entities {
        let evidence = &entity.evidence[0];
        assert_eq!(evidence.provenance.source, SOURCE);
        assert_eq!(evidence.provenance.recorded_at_unix, observed_at);
        assert_eq!(
            evidence
                .attributes
                .get("nominatim_raw_response_json")
                .map(String::as_str),
            Some(body.as_str())
        );
        assert_eq!(
            evidence
                .attributes
                .get("nominatim_candidate_index")
                .map(String::as_str),
            Some("0")
        );
        let raw: serde_json::Value = serde_json::from_str(
            evidence
                .attributes
                .get("nominatim_raw_response_json")
                .unwrap(),
        )
        .expect("raw JSON");
        assert_eq!(raw[0]["place_id"], 322_358_946);
        assert_eq!(
            raw[0]["licence"],
            "Data © OpenStreetMap contributors, ODbL 1.0."
        );
        assert_eq!(raw[0]["unexpected_nested"]["flags"][0], true);
        assert_eq!(
            raw[0]["unexpected_nested"]["flags"][1],
            serde_json::Value::Null
        );
    }
}

#[test]
fn candidates_keep_their_own_source_index_without_reassigning_fields() {
    let first: serde_json::Value = serde_json::from_str(PLACE).expect("fixture");
    let mut second = first.clone();
    second["lat"] = serde_json::json!("40.0");
    second["lon"] = serde_json::json!("-120.0");
    second["place_id"] = serde_json::json!(17);
    second["display_name"] = serde_json::json!("Alternate Place, California");
    let body = serde_json::to_string(&vec![first, second]).expect("body");
    let report = forward(
        &OneResponse::json(200, &body),
        "multi-candidate",
        "scan-multi",
        91,
    )
    .expect("forward");
    let coordinates: Vec<_> = report
        .entities
        .iter()
        .filter(|entity| entity.kind == EntityKind::Coordinates)
        .collect();
    assert_eq!(coordinates.len(), 2);
    for (index, expected_place_id) in [("0", 322_358_946), ("1", 17)] {
        let entry = coordinates
            .iter()
            .find(|entity| {
                entity.evidence[0]
                    .attributes
                    .get("nominatim_candidate_index")
                    .map(String::as_str)
                    == Some(index)
            })
            .expect("candidate coordinates");
        let attributes = &entry.evidence[0].attributes;
        assert_eq!(
            attributes
                .get("nominatim_raw_response_json")
                .map(String::as_str),
            Some(body.as_str())
        );
        let raw: serde_json::Value =
            serde_json::from_str(attributes.get("nominatim_raw_response_json").unwrap())
                .expect("raw body");
        let candidate = index.parse::<usize>().unwrap();
        assert_eq!(raw[candidate]["place_id"], expected_place_id);
        assert_eq!(entry.evidence[0].provenance.recorded_at_unix, 91);
        if index == "1" {
            assert_eq!(entry.value, "40,-120");
            assert_eq!(
                raw[candidate]["display_name"],
                "Alternate Place, California"
            );
        } else {
            assert_eq!(entry.value, "37.422486,-122.085585");
        }
    }
}

#[test]
fn reverse_preserves_exact_response_and_original_provider_fields() {
    let report = reverse(
        &OneResponse::json(200, PLACE),
        37.422_485_8,
        -122.085_584_6,
        "scan-reverse-raw",
        456,
    )
    .expect("reverse");
    assert_eq!(report.entities.len(), 2);
    for entity in &report.entities {
        let e = &entity.evidence[0];
        assert_eq!(e.provenance.recorded_at_unix, 456);
        assert_eq!(
            e.attributes
                .get("nominatim_raw_response_json")
                .map(String::as_str),
            Some(PLACE)
        );
        assert_eq!(
            e.attributes
                .get("nominatim_candidate_index")
                .map(String::as_str),
            Some("0")
        );
    }
}

#[test]
fn oversized_provider_payload_is_rejected_not_partially_provenanced() {
    let body = format!("[{{\"padding\":\"{}\"}}]", "x".repeat(MAX_PROVENANCE_BYTES));
    let report = interpret_forward(
        &Response {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: body.into_bytes(),
            truncated: false,
        },
        "oversized",
        "scan-too-large",
        123,
    );
    assert!(report.entities.is_empty());
    assert_eq!(report.outcome.kind, SourceOutcomeKind::ParserDrift);
}
