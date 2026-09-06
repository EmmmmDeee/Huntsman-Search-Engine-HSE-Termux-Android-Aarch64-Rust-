use super::{Feature, FeatureCollection, Geometry, Props, SRC, WifiDb, build_result};
use crate::core::{
    entity::EntityKind,
    module::Module,
    scan::{Target, TargetKind},
};

fn feature(mac: &str, lon: f64, lat: f64, ssid: &str) -> Feature {
    Feature {
        geometry: Some(Geometry {
            coordinates: Some(vec![lon, lat]),
        }),
        properties: Some(Props {
            mac: Some(mac.into()),
            ssid: Some(ssid.into()),
            manuf: Some("Cisco-Linksys, LLC".into()),
            chan: Some("6".into()),
            radio: Some("802.11g".into()),
            auth: Some("Open".into()),
            encry: Some("None".into()),
            fa: Some("2017-09-17 00:41:45".into()),
            la: Some("2018-08-05 01:14:38".into()),
            lat: Some(format!("{lat}")),
            lon: Some(format!("{lon}")),
        }),
    }
}

#[test]
fn accepts_mac_only() {
    let m = WifiDb;
    assert!(m.accepts(&Target::new(TargetKind::MacAddress, "00:13:10:69:EF:11")));
    assert!(!m.accepts(&Target::new(TargetKind::Domain, "y.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Coordinates, "1.0,2.0")));
}

#[test]
fn module_name_is_stable() {
    assert_eq!(WifiDb.name(), "wifidb");
    assert_eq!(WifiDb.name(), SRC);
}

#[test]
fn geojson_coordinates_are_lon_lat_and_yield_one_fix() {
    // Real observed values: coordinates=[-111.9469417, 33.5961517] = [lon, lat].
    let fc = FeatureCollection {
        features: vec![feature(
            "00:13:10:69:EF:11",
            -111.9469417,
            33.5961517,
            "cryptic24g",
        )],
    };
    let r = build_result(&fc, "00:13:10:69:EF:11", "scan-1");
    assert_eq!(r.entities.len(), 1);
    let e = &r.entities[0];
    assert_eq!(e.kind, EntityKind::Coordinates);
    // lat first in HSE's Coordinates value, from coordinates[1].
    assert_eq!(e.value, "33.596152,-111.946942");
    assert!(e.has_tag(SRC));
    assert!(e.has_tag("bssid-located"));
    assert_eq!(
        e.evidence[0].attributes.get("ssid").map(String::as_str),
        Some("cryptic24g")
    );
    assert_eq!(
        e.evidence[0]
            .attributes
            .get("first_seen")
            .map(String::as_str),
        Some("2017-09-17 00:41:45")
    );
}

#[test]
fn invalid_coordinates_are_rejected() {
    // Null Island — rejected by the shared validator.
    let fc = FeatureCollection {
        features: vec![feature("00:13:10:69:EF:11", 0.0, 0.0, "x")],
    };
    let r = build_result(&fc, "00:13:10:69:EF:11", "s");
    assert_eq!(r.entities.len(), 0);
}

#[test]
fn a_different_bssid_feature_is_not_emitted_as_our_location() {
    let fc = FeatureCollection {
        features: vec![feature("AA:BB:CC:DD:EE:FF", -111.9, 33.5, "other")],
    };
    let r = build_result(&fc, "00:13:10:69:EF:11", "s");
    assert_eq!(r.entities.len(), 0);
}

#[test]
fn feature_without_a_mac_is_not_located() {
    // A feature that does not positively report the queried BSSID cannot be
    // tied to this AP, so it is skipped even with valid coordinates.
    let mut f = feature("00:13:10:69:EF:11", -111.9469417, 33.5961517, "cryptic24g");
    if let Some(p) = f.properties.as_mut() {
        p.mac = None;
    }
    let fc = FeatureCollection { features: vec![f] };
    let r = build_result(&fc, "00:13:10:69:EF:11", "s");
    assert_eq!(r.entities.len(), 0);

    // Same when the whole properties block is absent.
    let bare = Feature {
        geometry: Some(Geometry {
            coordinates: Some(vec![-111.9469417, 33.5961517]),
        }),
        properties: None,
    };
    let fc2 = FeatureCollection {
        features: vec![bare],
    };
    assert_eq!(
        build_result(&fc2, "00:13:10:69:EF:11", "s").entities.len(),
        0
    );
}

#[test]
fn empty_feature_collection_is_a_clean_negative() {
    let fc = FeatureCollection { features: vec![] };
    let r = build_result(&fc, "00:13:10:69:EF:11", "s");
    assert_eq!(r.entities.len(), 0);
}

#[test]
fn falls_back_to_string_lat_lon_when_geometry_missing() {
    let mut f = feature("00:13:10:69:EF:11", -111.9469417, 33.5961517, "cryptic24g");
    f.geometry = None; // force the properties.lat/lon fallback
    let fc = FeatureCollection { features: vec![f] };
    let r = build_result(&fc, "00:13:10:69:EF:11", "s");
    assert_eq!(r.entities.len(), 1);
    assert_eq!(r.entities[0].value, "33.596152,-111.946942");
}

#[test]
fn skips_invalid_matching_feature_then_emits_one_fix_for_first_valid() {
    // Three matching features for the queried BSSID, in order:
    //   1. Null Island (invalid) -> skipped via `continue`, NOT `break`
    //   2. valid feature A        -> the one representative fix emitted
    //   3. valid feature B        -> dropped by the trailing `break`
    let fc = FeatureCollection {
        features: vec![
            feature("00:13:10:69:EF:11", 0.0, 0.0, "null-island"),
            feature("00:13:10:69:EF:11", -111.9469417, 33.5961517, "A"),
            feature("00:13:10:69:EF:11", -112.5, 34.5, "B"),
        ],
    };
    let r = build_result(&fc, "00:13:10:69:EF:11", "s");
    // continue-past-invalid reached A; break dropped B => exactly one entity.
    assert_eq!(r.entities.len(), 1);
    assert_eq!(r.entities[0].value, "33.596152,-111.946942");
}
