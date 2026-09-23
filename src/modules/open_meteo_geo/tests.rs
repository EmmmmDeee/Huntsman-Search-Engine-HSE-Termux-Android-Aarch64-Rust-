use super::*;
use crate::core::confidence;
use crate::util::geo::au_state_for_coords;

/// A minimal geocoding hit (name + coords + country code); enrichment fields
/// default to absent. Mirrors the shape the live API returns.
fn res(name: &str, lat: f64, lon: f64, cc: &str) -> GeoResult {
    GeoResult {
        name: name.to_string(),
        latitude: Some(lat),
        longitude: Some(lon),
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
        latitude: Some(48.85341),
        longitude: Some(2.3488),
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
        latitude: Some(10.0),
        longitude: Some(10.0),
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
fn first_valid_hit_anchors_even_when_earlier_results_are_invalid() {
    // Regression: a leading invalid-coord result must NOT consume the anchor slot
    // and demote the first *valid* in-AU hit to a LOW candidate. The anchor is
    // keyed on the first EMITTED hit, not the raw index.
    let ents = build_entities(
        &[
            res("Bogus", 999.0, 999.0, "AU"),        // invalid coords → skipped
            res("Sydney", -33.8688, 151.2093, "AU"), // first VALID hit, in AU
        ],
        "Sydney",
        "s",
    );
    assert_eq!(ents.len(), 1);
    assert!(
        (ents[0].confidence - confidence::HIGH_PLUS).abs() < 1e-9,
        "first valid hit must anchor at HIGH_PLUS despite a skipped invalid result"
    );
    assert!(ents[0].has_tag("au-relevant") && !ents[0].has_tag("candidate"));
}

#[test]
fn emits_at_most_result_limit_valid_hits() {
    // The cap counts EMITTED valid hits, not raw results.
    let many: Vec<GeoResult> = (0..(RESULT_LIMIT + 3))
        .map(|k| res("Dup", 10.0 + k as f64, 20.0, "US"))
        .collect();
    let ents = build_entities(&many, "Dup", "s");
    assert_eq!(ents.len(), RESULT_LIMIT);
}

#[test]
fn empty_results_yield_nothing() {
    assert!(build_entities(&[], "anywhere", "s").is_empty());
}


// ── REQ-OPENMETEO-001: a missing coordinate component is not zero ───────────

/// REQ-OPENMETEO-001. `GeoResult` carries a struct-wide `#[serde(default)]` —
/// there for the optional enrichment fields, all of which are already `Option`
/// — and it also catches the two BARE `f64` coordinates. A hit that omits
/// `latitude` therefore deserializes to `0.0` instead of failing, and `0.0`
/// beside a real longitude passes `is_valid_coords` (correctly: the equator is
/// a real place, REQ-GEOGATE-001). The result is a `Coordinates` entity at a
/// latitude the provider never sent.
///
/// The fixture goes through `serde_json`, not the struct literal helper,
/// because the defect IS the deserialization step — a hand-built `GeoResult`
/// cannot reach it.
#[test]
fn a_hit_missing_latitude_is_not_placed_on_the_equator() {
    let resp: GeoResponse = serde_json::from_str(
        r#"{"results":[{"name":"Nowhere","longitude":151.2093,"country_code":"AU"}]}"#,
    )
    .expect("the enrichment defaults must still let the body parse");
    let out = build_entities(&resp.results, "Nowhere", "t");
    let coords: Vec<&str> = out.iter().map(|e| e.value.as_str()).collect();
    assert!(
        coords.is_empty(),
        "REQ-OPENMETEO-001: a hit with NO latitude produced {coords:?} — the \
         missing component was defaulted to 0.0 and shipped as a position on \
         the equator."
    );
}

/// REQ-OPENMETEO-001, the other direction — and the reason the fix cannot be
/// "reject a zero component". An EXPLICIT `"latitude":0.0` is the provider
/// asserting a value, and the equator is a real place: Pontianak, Nanyuki and
/// the Sulawesi equator monument all sit on it. Rejecting it would re-introduce
/// exactly the cross-shaped rejection REQ-GEOGATE-001 removed from the
/// coarse-provider gate.
#[test]
fn an_explicit_zero_latitude_is_a_real_equatorial_fix_and_is_kept() {
    let resp: GeoResponse = serde_json::from_str(
        r#"{"results":[{"name":"Pontianak","latitude":0.0,"longitude":109.3333,"country_code":"ID"}]}"#,
    )
    .expect("parse");
    let out = build_entities(&resp.results, "Pontianak", "t");
    assert_eq!(
        out.len(),
        1,
        "REQ-OPENMETEO-001/REQ-GEOGATE-001: an explicit latitude of 0.0 beside \
         a real longitude is the EQUATOR, not a missing field. Dropping it is \
         the cross-shaped rejection REQ-GEOGATE-001 exists to prevent."
    );
    assert_eq!(out[0].value, "0.000000,109.333300");
}

/// REQ-OPENMETEO-001. A row skipped for a missing component must not consume
/// `RESULT_LIMIT` budget — the cap counts EMITTED hits, as the loop's own
/// comment says, so a bad row must not push a good one out of the results.
#[test]
fn a_row_skipped_for_a_missing_component_does_not_consume_the_cap() {
    let body = format!(
        r#"{{"results":[{}]}}"#,
        [
            r#"{"name":"NoLat","longitude":151.0,"country_code":"AU"}"#,
            r#"{"name":"X","latitude":-27.4766,"longitude":153.0166,"country_code":"AU"}"#,
            r#"{"name":"X","latitude":-33.8688,"longitude":151.2093,"country_code":"AU"}"#,
            r#"{"name":"X","latitude":-37.8136,"longitude":144.9631,"country_code":"AU"}"#,
        ]
        .join(",")
    );
    let resp: GeoResponse = serde_json::from_str(&body).expect("parse");
    let out = build_entities(&resp.results, "x", "t");
    assert_eq!(
        out.len(),
        RESULT_LIMIT,
        "the skipped row consumed cap budget: {} emitted, expected {RESULT_LIMIT}",
        out.len()
    );
    // Vacuity guard: the three that survived must be the three REAL ones, in
    // order — not the skipped row silently emitting something.
    let names: Vec<&str> = out
        .iter()
        .map(|e| e.value.as_str())
        .collect();
    assert!(
        names.iter().all(|v| !v.starts_with("0.000000")),
        "a fabricated equatorial coordinate reached the output: {names:?}"
    );
}

/// REQ-OPENMETEO-002: GeoNames' fuzzy search answered "Sydney, Australia" with
/// the headland "Sydney Heads" (feature code MT) near Isaac, Queensland,
/// ~1,400 km from Sydney, and it became the anchor. A hit whose name is not a
/// whole-word phrase of the query is not a geocode of it: skipped without
/// taking the anchor slot, so the real match behind it anchors.
#[test]
fn a_fuzzy_neighbour_of_the_query_is_not_its_geocode() {
    let heads = GeoResult {
        feature_code: Some("MT".to_string()),
        ..res("Sydney Heads", -21.95, 148.68, "AU")
    };
    let sydney = res("Sydney", -33.8688, 151.2093, "AU");
    let ents = build_entities(&[heads, sydney], "Sydney, Australia", "s");
    assert_eq!(ents.len(), 1, "{ents:?}");
    assert_eq!(ents[0].value, "-33.868800,151.209300");
    assert!(!ents[0].has_tag("candidate"), "the real match anchors");

    let heads_alone = GeoResult {
        feature_code: Some("MT".to_string()),
        ..res("Sydney Heads", -21.95, 148.68, "AU")
    };
    assert!(build_entities(&[heads_alone], "Sydney, Australia", "s").is_empty());

    // Case, punctuation and diacritics do not make a match a fragment.
    let hanoi = res("Hà Nội", 21.0245, 105.8412, "VN");
    assert_eq!(build_entities(&[hanoi], "ha noi, vietnam", "s").len(), 1);
}
