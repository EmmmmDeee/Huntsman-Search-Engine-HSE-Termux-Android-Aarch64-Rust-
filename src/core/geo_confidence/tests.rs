//! Acceptance tests for geolocation confidence and uncertainty.

use super::*;
use crate::core::claim::SourceLineage;

fn fix(lat: f64, lon: f64, r: f64, m: GeoMethod) -> GeoFix {
    GeoFix::new(lat, lon, r, m, SourceLineage::provider("p")).expect("valid coordinate")
}

// Sydney CBD and Melbourne CBD — ~713 km apart, a real separation no
// uncertainty at city grain can bridge.
const SYD: (f64, f64) = (-33.8688, 151.2093);
const MEL: (f64, f64) = (-37.8136, 144.9631);

#[test]
fn a_radius_is_never_finer_than_its_method_can_support() {
    // An IP fix claiming 100 m of precision is raised to the method's floor.
    let f = fix(SYD.0, SYD.1, 0.1, GeoMethod::IpInference);
    assert!(
        (f.radius_km - GeoMethod::IpInference.floor_km()).abs() < 1e-9,
        "IP geolocation cannot claim street-level precision: {}",
        f.radius_km
    );
    // An instrument fix may legitimately be tight.
    let g = fix(SYD.0, SYD.1, 0.05, GeoMethod::Instrument);
    assert!(g.radius_km <= 0.05 + 1e-9);
    // A non-finite radius falls back to the floor rather than poisoning maths.
    let h = fix(SYD.0, SYD.1, f64::NAN, GeoMethod::City);
    assert!((h.radius_km - GeoMethod::City.floor_km()).abs() < 1e-9);
}

#[test]
fn an_invalid_coordinate_is_refused_not_clamped() {
    // Silently relocating a subject to the nearest valid point would be a
    // fabricated observation.
    for (lat, lon) in [
        (91.0, 0.0),
        (-91.0, 0.0),
        (0.0, 181.0),
        (0.0, -181.0),
        (f64::NAN, 0.0),
        (0.0, f64::INFINITY),
    ] {
        assert!(
            GeoFix::new(lat, lon, 1.0, GeoMethod::City, SourceLineage::provider("p")).is_none(),
            "({lat}, {lon}) must be refused"
        );
    }
    assert!(
        GeoFix::new(
            90.0,
            180.0,
            1.0,
            GeoMethod::City,
            SourceLineage::provider("p")
        )
        .is_some(),
        "the extremes themselves are valid"
    );
}

#[test]
fn two_agreeing_city_fixes_corroborate_the_city_not_a_street() {
    let a = fix(SYD.0, SYD.1, 25.0, GeoMethod::City);
    let b = fix(SYD.0 + 0.01, SYD.1 + 0.01, 25.0, GeoMethod::City);
    match a.intersect(&b) {
        GeoCombination::Narrowed(n) => {
            assert!(
                n.radius_km >= GeoMethod::City.floor_km() - 1e-9,
                "agreement must not synthesise resolution neither source had: {}",
                n.radius_km
            );
        }
        GeoCombination::Conflict { .. } => panic!("nearby city fixes overlap"),
    }
}

#[test]
fn a_tighter_fix_narrows_an_overlapping_coarse_one() {
    let coarse = fix(SYD.0, SYD.1, 50.0, GeoMethod::IpInference);
    let tight = fix(SYD.0 + 0.02, SYD.1 + 0.02, 0.25, GeoMethod::Address);
    match coarse.intersect(&tight) {
        GeoCombination::Narrowed(n) => {
            assert_eq!(n.method, GeoMethod::Address);
            assert!((n.radius_km - 0.25).abs() < 1e-9);
            assert!(
                (n.lat - tight.lat).abs() < 1e-9,
                "the result is the tighter fix's centre, never a midpoint"
            );
        }
        GeoCombination::Conflict { .. } => panic!("the address sits inside the IP disc"),
    }
}

#[test]
fn disjoint_fixes_conflict_and_are_never_averaged() {
    let syd = fix(SYD.0, SYD.1, 25.0, GeoMethod::City);
    let mel = fix(MEL.0, MEL.1, 25.0, GeoMethod::City);
    match syd.intersect(&mel) {
        GeoCombination::Conflict {
            left,
            right,
            separation_km,
        } => {
            assert!(
                (700.0..730.0).contains(&separation_km),
                "Sydney-Melbourne is ~713 km, got {separation_km}"
            );
            // BOTH are preserved; nothing collapsed to a point in between.
            assert_eq!(left.lat, syd.lat);
            assert_eq!(right.lat, mel.lat);
            let midpoint_lat = (syd.lat + mel.lat) / 2.0;
            assert_ne!(left.lat, midpoint_lat);
            assert_ne!(right.lat, midpoint_lat);
        }
        GeoCombination::Narrowed(n) => {
            panic!("two cities 700 km apart must not narrow to {n:?}")
        }
    }
}

#[test]
fn an_associated_location_is_distinguished_from_the_subjects_own() {
    // A VPN egress or a registry service address is a real place that need not
    // be the subject's place, and the rendering must say so.
    assert!(GeoMethod::Instrument.locates_subject_directly());
    assert!(GeoMethod::RadioSurvey.locates_subject_directly());
    for m in [
        GeoMethod::IpInference,
        GeoMethod::Country,
        GeoMethod::City,
        GeoMethod::Address,
        GeoMethod::Locality,
    ] {
        assert!(
            !m.locates_subject_directly(),
            "{m:?} locates something associated with the subject, not the subject"
        );
    }
    let f = fix(SYD.0, SYD.1, 50.0, GeoMethod::IpInference);
    assert!(
        f.describe().contains("associated-location"),
        "{}",
        f.describe()
    );
    assert!(
        f.describe().contains('±'),
        "the uncertainty is always shown"
    );
}

#[test]
fn separation_is_symmetric_and_zero_for_the_same_point() {
    let a = fix(SYD.0, SYD.1, 1.0, GeoMethod::Address);
    let b = fix(MEL.0, MEL.1, 1.0, GeoMethod::Address);
    assert!((a.separation_km(&b) - b.separation_km(&a)).abs() < 1e-9);
    assert!(a.separation_km(&a) < 1e-9);
}

#[test]
fn a_country_fix_never_masquerades_as_a_precise_one() {
    let c = fix(-25.0, 133.0, 0.0, GeoMethod::Country);
    assert!(
        c.radius_km >= 500.0,
        "a country is not a point: {}",
        c.radius_km
    );
    // And it cannot be narrowed below its floor by an overlapping city fix
    // whose own floor is coarser than street level.
    let city = fix(SYD.0, SYD.1, 25.0, GeoMethod::City);
    if let GeoCombination::Narrowed(n) = c.intersect(&city) {
        assert!(n.radius_km >= GeoMethod::City.floor_km() - 1e-9);
    }
}
