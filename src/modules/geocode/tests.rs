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
    // No boundingbox → the prior flat baseline confidence is preserved.
    let au = build_forward_entity(-27.4766, 153.0166, "-27.476600,153.016600", None, "scan");
    assert!((au.confidence - 0.70).abs() < 1e-9);
    assert!(au.has_tag("au-relevant"));
    assert!(au.has_tag("au-state:QLD")); // Brisbane
    assert!(au.has_tag("geocoded"));
    assert!(!au.has_tag("candidate"));

    let foreign = build_forward_entity(51.5074, -0.1278, "51.507400,-0.127800", None, "scan");
    assert!((foreign.confidence - 0.40).abs() < 1e-9);
    assert!(foreign.has_tag("off-region"));
    assert!(foreign.has_tag("candidate"));
    assert!(!foreign.has_tag("au-relevant"));
}

/// A precise (small-boundingbox) AU match must outrank a coarse (city-sized)
/// one: higher confidence and a finer `geo-precision:*` class, so a building-
/// level pin is not treated the same as a whole-city centroid. This is the
/// accuracy fix — a coarse match must not masquerade as a precise one.
#[test]
fn forward_geocode_confidence_scales_with_match_precision() {
    // Brisbane (QLD). A ~30 m building bbox vs a ~40 km city bbox.
    let precise = build_forward_entity(
        -27.4766,
        153.0166,
        "-27.476600,153.016600",
        Some(0.03),
        "scan",
    );
    let coarse = build_forward_entity(
        -27.4700,
        153.0200,
        "-27.470000,153.020000",
        Some(20.0),
        "scan",
    );

    assert!(
        precise.confidence > coarse.confidence,
        "a building-level match ({}) must beat a city-level one ({})",
        precise.confidence,
        coarse.confidence
    );
    assert!(
        precise.confidence > 0.70,
        "a precise AU pin exceeds the flat baseline, got {}",
        precise.confidence
    );
    assert!(precise.has_tag("geo-precision:building"));
    assert!(coarse.has_tag("geo-precision:locality"));
    // Both are still on-region AU anchors.
    assert!(precise.has_tag("au-relevant") && coarse.has_tag("au-relevant"));
}

/// The bbox uncertainty radius is half the corner-to-corner diagonal: a tight
/// building box is sub-100 m; a city box is tens of km. Pure computation.
#[test]
fn bbox_precision_radius_reflects_match_extent() {
    let sv = |v: &[f64]| v.iter().map(ToString::to_string).collect::<Vec<_>>();
    // ~ a few metres of latitude/longitude around a point → well under 100 m.
    let tight = bbox_precision_radius_km(&sv(&[-27.4767, -27.4765, 153.0165, 153.0167])).unwrap();
    assert!(tight < 0.1, "tight box radius {tight} km should be < 100 m");
    // ~ 0.4° box (~40+ km) → tens of km.
    let wide = bbox_precision_radius_km(&sv(&[-27.7, -27.3, 152.8, 153.2])).unwrap();
    assert!(
        wide > 15.0,
        "wide box radius {wide} km should be tens of km"
    );
    // Malformed boxes yield None.
    assert!(bbox_precision_radius_km(&sv(&[-27.0, 153.0])).is_none());
    assert!(bbox_precision_radius_km(&["x".into(), "y".into(), "z".into(), "w".into()]).is_none());
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

fn addr(json: serde_json::Value) -> NominatimAddr {
    serde_json::from_value(json).unwrap()
}

#[test]
fn au_relevance_country_code_au_is_in_australia_regardless_of_coords() {
    let a = addr(serde_json::json!({ "country_code": "AU" }));
    assert_eq!(au_relevance(0.0, 0.0, Some(&a)), AuRelevance::InAustralia);
}

#[test]
fn au_relevance_other_country_code_is_off_region() {
    let a = addr(serde_json::json!({ "country_code": "us" }));
    assert_eq!(
        au_relevance(-27.47, 153.02, Some(&a)),
        AuRelevance::OffRegion
    );
}

#[test]
fn au_relevance_no_country_code_falls_back_to_bounding_box() {
    assert_eq!(
        au_relevance(-27.4766, 153.0166, None),
        AuRelevance::InAustralia
    );
    let a = addr(serde_json::json!({ "city": "Nowhere" }));
    assert_eq!(
        au_relevance(-27.4766, 153.0166, Some(&a)),
        AuRelevance::InAustralia
    );
}

#[test]
fn au_relevance_no_country_code_outside_box_is_unknown() {
    assert_eq!(au_relevance(48.8566, 2.3522, None), AuRelevance::Unknown);
}
