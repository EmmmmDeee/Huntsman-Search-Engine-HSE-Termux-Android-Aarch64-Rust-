use crate::core::{confidence, entity::EntityKind, scan::Target, scan::TargetKind};

use super::{
    DeviceSensors,
    wifi::{parse_conn, wifi_band},
};

/// The canonical `termux-location` parse bound to THIS module's evidence-source
/// tag — the binding these tests exercise. Test scaffolding, so it lives here
/// rather than as a production forwarder no production code calls.
fn parse_fix(
    stdout: &[u8],
    scan_id: &str,
) -> crate::core::error::Result<crate::core::module::ModuleResult> {
    crate::modules::device_fix::parse_fix(stdout, scan_id, super::SRC)
}
use crate::core::module::Module;

#[test]
fn is_passive() {
    assert!(DeviceSensors.is_passive());
}

#[test]
fn accepts_only_local_physical_seeds() {
    assert!(DeviceSensors.accepts(&Target::new(TargetKind::Coordinates, "-27.47,153.02")));
    assert!(DeviceSensors.accepts(&Target::new(TargetKind::MacAddress, "aa:bb:cc:dd:ee:ff")));
    assert!(!DeviceSensors.accepts(&Target::new(TargetKind::FullName, "Jane Doe")));
    assert!(!DeviceSensors.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    assert!(!DeviceSensors.accepts(&Target::new(TargetKind::Domain, "x.com")));
    assert!(!DeviceSensors.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
    assert!(!DeviceSensors.accepts(&Target::new(TargetKind::Username, "user")));
}

#[test]
fn module_name_and_priority() {
    assert_eq!(DeviceSensors.name(), "device_sensors");
    assert_eq!(DeviceSensors.priority(), 70);
}

#[test]
fn max_timeout_is_20s() {
    assert_eq!(DeviceSensors.max_timeout_ms(), 20_000);
}

#[test]
fn parses_connected_state() {
    let json = br#"{"bssid":"aa:bb:cc:dd:ee:ff","ssid":"MyNet","ip":"192.168.1.42",
        "frequency_mhz":2412,"rssi":-45,"link_speed_mbps":866,
        "supplicant_state":"COMPLETED"}"#;
    let r = parse_conn(json, "test").expect("valid sensor JSON parses");
    assert_eq!(r.entities.len(), 2);
}

#[test]
fn parses_disconnected_state() {
    let json = br#"{"bssid":"02:00:00:00:00:00","ssid":"<unknown ssid>","ip":"0.0.0.0",
        "supplicant_state":"DISCONNECTED"}"#;
    let r = parse_conn(json, "test").expect("valid sensor JSON parses");
    assert_eq!(r.entities.len(), 0);
}

#[test]
fn wifi_filters_all_zero_mac() {
    let json = br#"{"bssid":"00:00:00:00:00:00","ssid":"Test","ip":"10.0.0.1"}"#;
    let r = parse_conn(json, "test").expect("valid sensor JSON parses");
    assert_eq!(r.entities.len(), 1);
    assert_eq!(r.entities[0].kind, EntityKind::IpAddress);
}

#[test]
fn wifi_band_classification() {
    assert_eq!(wifi_band(Some(2412)), Some("2.4GHz"));
    assert_eq!(wifi_band(Some(5180)), Some("5GHz"));
    assert_eq!(wifi_band(Some(5955)), Some("6GHz"));
    assert_eq!(wifi_band(Some(0)), None);
    assert_eq!(wifi_band(None), None);
    assert_eq!(wifi_band(Some(1234)), None);
}

#[test]
fn connected_bssid_is_geolocatable_and_banded() {
    let json = br#"{"bssid":"aa:bb:cc:dd:ee:ff","ssid":"MyNet","ip":"192.168.1.42",
        "frequency_mhz":5180,"supplicant_state":"COMPLETED"}"#;
    let r = parse_conn(json, "test").expect("valid sensor JSON parses");
    let mac = r
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::MacAddress)
        .expect("BSSID entity");
    assert!(mac.has_tag("geolocatable"));
    assert!(mac.has_tag("band:5GHz"));
    assert_eq!(
        mac.evidence[0]
            .attributes
            .get("band")
            .expect("should succeed"),
        "5GHz"
    );
}

#[test]
fn wifi_ssid_in_evidence() {
    let json = br#"{"bssid":"aa:bb:cc:dd:ee:ff","ssid":"CafeNet","ip":"192.168.0.5",
        "frequency_mhz":5180,"rssi":-60,"link_speed_mbps":400,
        "supplicant_state":"COMPLETED"}"#;
    let r = parse_conn(json, "test").expect("valid sensor JSON parses");
    let mac_ev = &r.entities[0].evidence[0];
    assert_eq!(
        mac_ev.attributes.get("ssid").expect("should succeed"),
        "CafeNet"
    );
    assert_eq!(
        mac_ev
            .attributes
            .get("frequency_mhz")
            .expect("should succeed"),
        "5180"
    );
}

#[test]
fn wifi_evidence_source_is_device_sensors() {
    let json = br#"{"bssid":"aa:bb:cc:dd:ee:ff","ssid":"Net","ip":"10.0.0.1"}"#;
    let r = parse_conn(json, "test").expect("valid sensor JSON parses");
    assert_eq!(r.entities[0].evidence[0].source, "device_sensors");
    assert_eq!(r.entities[1].evidence[0].source, "device_sensors");
}

#[test]
fn network_fix_gets_lower_confidence() {
    let json = br#"{"latitude":-27.4698,"longitude":153.0251,"accuracy":12.5,
        "provider":"network"}"#;
    let r = parse_fix(json, "test").expect("valid sensor JSON parses");
    assert_eq!(r.entities.len(), 1);
    assert!((r.entities[0].confidence - confidence::HIGH).abs() < 1e-6);
}

#[test]
fn gps_fix_gets_higher_confidence() {
    let json = br#"{"latitude":-27.4698,"longitude":153.0251,"accuracy":2.0,
        "provider":"gps"}"#;
    let r = parse_fix(json, "test").expect("valid sensor JSON parses");
    assert!((r.entities[0].confidence - confidence::VERY_HIGH_PLUS).abs() < 1e-6);
}

#[test]
fn coordinate_value_is_fixed_precision() {
    let json = br#"{"latitude":-27.469824123,"longitude":153.025198765,
        "provider":"network"}"#;
    let r = parse_fix(json, "test").expect("valid sensor JSON parses");
    assert_eq!(r.entities[0].value, "-27.469824,153.025199");
}

#[test]
fn entity_tags_and_kind() {
    let json = br#"{"latitude":51.5074,"longitude":-0.1278,"provider":"network"}"#;
    let r = parse_fix(json, "scan-gps").expect("valid sensor JSON parses");
    let e = &r.entities[0];
    assert_eq!(e.kind, EntityKind::Coordinates);
    assert!(e.has_tag("geoint"));
    assert!(e.has_tag("provider:network"));
    assert_eq!(e.scan_id, "scan-gps");
}

#[test]
fn gps_provider_tag() {
    let json = br#"{"latitude":-27.4698,"longitude":153.0251,"provider":"gps"}"#;
    let r = parse_fix(json, "test").expect("valid sensor JSON parses");
    assert!(r.entities[0].has_tag("provider:gps"));
    assert!(r.entities[0].has_tag("device-sensor"));
}

#[test]
fn null_island_rejected() {
    let json = br#"{"latitude":0.0,"longitude":0.0,"provider":"gps"}"#;
    assert_eq!(
        parse_fix(json, "test")
            .expect("valid sensor JSON parses")
            .entities
            .len(),
        0
    );
}

#[test]
fn out_of_range_coords_rejected() {
    for json in [
        &br#"{"latitude":91.0,"longitude":10.0}"#[..],
        &br#"{"latitude":-90.1,"longitude":10.0}"#[..],
        &br#"{"latitude":10.0,"longitude":181.0}"#[..],
        &br#"{"latitude":10.0,"longitude":-180.5}"#[..],
    ] {
        assert_eq!(
            parse_fix(json, "test")
                .expect("valid sensor JSON parses")
                .entities
                .len(),
            0,
            "out-of-range fix must be rejected: {}",
            String::from_utf8_lossy(json)
        );
    }
}

#[test]
fn boundary_coords_accepted() {
    let json = br#"{"latitude":90.0,"longitude":180.0,"provider":"gps"}"#;
    assert_eq!(
        parse_fix(json, "test")
            .expect("valid sensor JSON parses")
            .entities
            .len(),
        1
    );
}

#[test]
fn accuracy_scales_confidence_below_provider_ceiling() {
    let tight = br#"{"latitude":-27.47,"longitude":153.02,"accuracy":5.0,"provider":"gps"}"#;
    let wide = br#"{"latitude":-27.47,"longitude":153.02,"accuracy":3000.0,"provider":"gps"}"#;
    let ct = parse_fix(tight, "t")
        .expect("valid sensor JSON parses")
        .entities[0]
        .confidence;
    let cw = parse_fix(wide, "t")
        .expect("valid sensor JSON parses")
        .entities[0]
        .confidence;
    assert!(
        (ct - confidence::VERY_HIGH_PLUS).abs() < 1e-6,
        "tight gps fix keeps ceiling: {ct}"
    );
    assert!(cw < ct, "wide fix ({cw}) must score below tight ({ct})");
    assert!(cw >= 0.30, "confidence floored: {cw}");
}

#[test]
fn accuracy_tag_emitted() {
    let json = br#"{"latitude":-27.47,"longitude":153.02,"accuracy":42.0,"provider":"gps"}"#;
    let r = parse_fix(json, "test").expect("valid sensor JSON parses");
    assert!(r.entities[0].has_tag("accuracy:42m"));
}

#[test]
fn evidence_attributes_populated() {
    let json = br#"{"latitude":37.7749,"longitude":-122.4194,"altitude":15.5,
        "accuracy":8.2,"speed":1.5,"bearing":90.0,"provider":"gps"}"#;
    let r = parse_fix(json, "test").expect("valid sensor JSON parses");
    let ev = &r.entities[0].evidence[0];
    assert_eq!(ev.source, "device_sensors");
    assert_eq!(
        ev.attributes.get("latitude").expect("should succeed"),
        "37.7749"
    );
    assert_eq!(
        ev.attributes.get("longitude").expect("should succeed"),
        "-122.4194"
    );
    assert_eq!(
        ev.attributes.get("altitude").expect("should succeed"),
        "15.5"
    );
    assert_eq!(
        ev.attributes.get("accuracy_m").expect("should succeed"),
        "8.2"
    );
    assert_eq!(ev.attributes.get("speed").expect("should succeed"), "1.5");
    assert_eq!(ev.attributes.get("bearing").expect("should succeed"), "90");
    assert_eq!(
        ev.attributes.get("provider").expect("should succeed"),
        "gps"
    );
}

/// A field the OS did not supply must be *absent* from the evidence, not
/// recorded as `0`. Zero is a legitimate reading for every one of these —
/// sea level, stationary, due north — so defaulting an unknown to zero would
/// publish an assumption as an observation. The always-present fields and the
/// `provider` fallback still hold.
#[test]
fn missing_optional_fields_are_omitted_not_zeroed() {
    let json = br#"{"latitude":10.0,"longitude":20.0}"#;
    let r = parse_fix(json, "test").expect("valid sensor JSON parses");
    assert_eq!(r.entities.len(), 1);
    let ev = &r.entities[0].evidence[0];
    assert_eq!(
        ev.attributes.get("provider").expect("should succeed"),
        "network"
    );
    assert_eq!(ev.attributes.get("latitude").expect("should succeed"), "10");
    assert_eq!(
        ev.attributes.get("longitude").expect("should succeed"),
        "20"
    );
    for absent in ["altitude", "accuracy_m", "speed", "bearing"] {
        assert!(
            !ev.attributes.contains_key(absent),
            "{absent} was not supplied by the OS and must be omitted, not defaulted to 0"
        );
    }
    assert!((r.entities[0].confidence - confidence::HIGH).abs() < 1e-6);
}

/// The complement of the test above: a genuine zero reading that the OS *did*
/// supply must still be recorded, so omission unambiguously means "unknown".
#[test]
fn supplied_zero_readings_are_recorded() {
    let json = br#"{"latitude":10.0,"longitude":20.0,"altitude":0.0,"speed":0.0,"bearing":0.0}"#;
    let r = parse_fix(json, "test").expect("valid sensor JSON parses");
    assert_eq!(r.entities.len(), 1);
    let ev = &r.entities[0].evidence[0];
    assert_eq!(ev.attributes.get("altitude").expect("should succeed"), "0");
    assert_eq!(ev.attributes.get("speed").expect("should succeed"), "0");
    assert_eq!(ev.attributes.get("bearing").expect("should succeed"), "0");
    assert!(
        !ev.attributes.contains_key("accuracy_m"),
        "accuracy was not supplied and must stay absent"
    );
}

/// Unparseable tool output is a malfunction, not "no fix". Reporting it as an
/// empty result would make a broken termux-location indistinguishable from a
/// device that genuinely has no signal.
#[test]
fn malformed_json_is_an_error() {
    assert!(parse_fix(b"not json at all", "test").is_err());
}

/// `{}` is well-formed JSON but lacks the required lat/lon, so it fails to
/// parse as a `Fix` — still a malfunction, not a clean negative.
#[test]
fn empty_object_is_an_error() {
    assert!(parse_fix(b"{}", "test").is_err());
}

/// The complement of both: a tool that exits 0 and prints nothing has answered
/// "nothing to report", which stays a clean empty Ok. Together these make an
/// empty result unambiguously mean "no fix observed".
#[test]
fn blank_output_is_an_empty_ok() {
    for blank in [&b""[..], b"   ", b"\n\t "] {
        assert!(
            parse_fix(blank, "test")
                .expect("blank output is an empty answer, not an error")
                .entities
                .is_empty()
        );
        assert!(
            parse_conn(blank, "test")
                .expect("blank output is an empty answer, not an error")
                .entities
                .is_empty()
        );
    }
}

#[test]
fn negative_coordinates_handled() {
    let json = br#"{"latitude":-33.8688,"longitude":151.2093,"provider":"network"}"#;
    let r = parse_fix(json, "test").expect("valid sensor JSON parses");
    assert_eq!(r.entities[0].value, "-33.868800,151.209300");
}

// The `fix_confidence` ladder and `is_valid_fix` are now defined and tested in
// `crate::modules::device_fix`; these tests cover this module's `parse_fix`
// wrapper and its Wi-Fi/connection parsing.
