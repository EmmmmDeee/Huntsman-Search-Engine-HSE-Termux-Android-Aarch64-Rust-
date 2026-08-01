use super::*;
use crate::core::confidence;
use crate::util::geo::au_state_for_coords;

/// A minimal geocoding hit (name + coords + country code); enrichment fields
/// default to absent. Mirrors the shape the live API returns.
fn res(name: &str, lat: f64, lon: f64, cc: &str) -> GeoResult {
    GeoResult {
        name: name.to_string(),
        latitude: lat,
        longitude: lon,
        country_code: Some(cc.to_string()),
        ..Default::default()
    }
}

// ── trait metadata ──────────────────────────────────────────────────────────

#[test]
fn accepts_address_only() {
    let m = OpenMeteoGeo;
    assert!(m.accepts(&Target::new(TargetKind::Address, "Golden, CO")));
    assert!(!m.accepts(&Target::new(TargetKind::Coordinates, "1.0,2.0")));
    assert!(!m.accepts(&Target::new(TargetKind::Domain, "example.com")));
}

#[test]
fn metadata_sane() {
    let m = OpenMeteoGeo;
    assert_eq!(m.name(), "open_meteo_geo");
    assert!(!m.description().is_empty());
    assert!(matches!(m.cost(), crate::core::module::ModuleCost::Free));
    assert!(matches!(m.category(), ModuleCategory::Geo));
    assert!(m.max_timeout_ms() > crate::MODULE_TIMEOUT_MS);
    assert!(m.produces().contains(&EntityKind::Coordinates));
    // Geo category supplies a valid default ATT&CK Reconnaissance technique.
    assert!(!m.attack_techniques().is_empty());
}

// ── regional weighting ────────────────────────────────────────────────────────

#[test]
fn au_first_hit_is_anchored_and_state_tagged() {
    // Sydney — inside the AU bounding box.
    let (lat, lon) = (-33.8688, 151.2093);
    let ents = build_entities(&[res("Sydney", lat, lon, "AU")], "Sydney", "s");
    assert_eq!(ents.len(), 1);
    let e = &ents[0];
    assert_eq!(e.kind, EntityKind::Coordinates);
    assert!((e.confidence - confidence::HIGH_PLUS).abs() < 1e-9, "AU anchor → HIGH_PLUS");
    assert!(e.has_tag("geocoded") && e.has_tag("au-relevant"));
    assert!(!e.has_tag("candidate"), "an AU anchor is not a candidate");
    if let Some(state) = au_state_for_coords(lat, lon) {
        assert!(e.has_tag(&format!("au-state:{state}")), "expected au-state:{state}");
    }
}

#[test]
fn off_region_first_hit_is_low_candidate() {
    // Golden, CO — outside AU.
    let ents = build_entities(&[res("Golden", 39.75554, -105.2211, "US")], "Golden, CO", "s");
    assert_eq!(ents.len(), 1);
    let e = &ents[0];
    assert!((e.confidence - confidence::LOW).abs() < 1e-9, "off-region → LOW");
    assert!(e.has_tag("geocoded") && e.has_tag("off-region") && e.has_tag("candidate"));
    assert!(!e.has_tag("au-relevant"));
}

#[test]
fn alternates_after_the_first_are_candidates() {
    // Two "Golden" hits (CO then IL) — the first anchors (still off-region here),
    // both are candidates; each is a distinct coordinate.
    let ents = build_entities(
        &[
            res("Golden", 39.75554, -105.2211, "US"),
            res("Golden", 40.10921, -91.01764, "US"),
        ],
        "Golden",
        "s",
    );
    assert_eq!(ents.len(), 2);
    assert!(ents.iter().all(|e| e.has_tag("candidate")));
    assert_ne!(ents[0].value, ents[1].value, "distinct coordinates retained");
}

#[test]
fn au_alternate_is_candidate_even_though_in_region() {
    // First hit off-region (anchor slot, but not AU → candidate); second hit in
    // AU but, as a non-first alternate, still a candidate.
    let ents = build_entities(
        &[
            res("Perth", 56.3950, -3.4308, "GB"), // Perth, Scotland
            res("Perth", -31.9523, 115.8613, "AU"), // Perth, Western Australia
        ],
        "Perth",
        "s",
    );
    assert_eq!(ents.len(), 2);
    let au = ents.iter().find(|e| e.has_tag("au-relevant")).expect("AU alternate present");
    assert!(au.has_tag("candidate"), "an alternate is a candidate even in-region");
    assert!((au.confidence - confidence::LOW).abs() < 1e-9);
}

// ── enrichment ────────────────────────────────────────────────────────────────

#[test]
fn enrichment_attributes_are_emitted_when_present() {
    let r = GeoResult {
        name: "Paris".to_string(),
        latitude: 48.85341,
        longitude: 2.3488,
        elevation: Some(42.0),
        feature_code: Some("PPLC".to_string()),
        country: Some("France".to_string()),
        country_code: Some("fr".to_string()),
        admin1: Some("Île-de-France".to_string()),
        admin2: Some("Paris".to_string()),
        timezone: Some("Europe/Paris".to_string()),
        population: Some(2_138_551),
        postcodes: vec!["75001".to_string(), "75002".to_string()],
    };
    let ents = build_entities(&[r], "Paris", "s");
    let ev = &ents[0].evidence[0];
    let attr = |k: &str| ev.attributes.get(k).map(String::as_str);
    assert_eq!(attr("place_name"), Some("Paris"));
    assert_eq!(attr("country"), Some("France"));
    assert_eq!(attr("country_code"), Some("FR"), "country code upper-cased");
    assert_eq!(attr("admin1"), Some("Île-de-France"));
    assert_eq!(attr("timezone"), Some("Europe/Paris"));
    assert_eq!(attr("population"), Some("2138551"));
    assert_eq!(attr("feature_code"), Some("PPLC"));
    assert_eq!(attr("place_class"), Some("national capital"));
    assert_eq!(attr("elevation_m"), Some("42"));
    assert_eq!(attr("postcodes"), Some("75001, 75002"));
}

#[test]
fn zero_population_and_missing_fields_are_omitted() {
    let r = GeoResult {
        name: "Nowhere".to_string(),
        latitude: 10.0,
        longitude: 10.0,
        population: Some(0),
        ..Default::default()
    };
    let ents = build_entities(&[r], "Nowhere", "s");
    let ev = &ents[0].evidence[0];
    assert!(!ev.attributes.contains_key("population"), "zero population omitted");
    assert!(!ev.attributes.contains_key("timezone"), "absent timezone omitted");
    assert!(!ev.attributes.contains_key("feature_code"));
}

// ── pure helpers & guards ─────────────────────────────────────────────────────

#[test]
fn place_class_maps_known_codes_only() {
    assert_eq!(place_class("PPLC"), Some("national capital"));
    assert_eq!(place_class("PPLA2"), Some("second-order administrative capital"));
    assert_eq!(place_class("PPL"), Some("populated place"));
    assert_eq!(place_class("MT"), None, "non-populated-place code → None");
}

#[test]
fn invalid_coordinates_are_skipped() {
    // Latitude out of range → not a usable coordinate.
    let ents = build_entities(&[res("Bogus", 999.0, 999.0, "US")], "Bogus", "s");
    assert!(ents.is_empty());
}

#[test]
fn empty_results_yield_nothing() {
    assert!(build_entities(&[], "anywhere", "s").is_empty());
}
