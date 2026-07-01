use super::*;
use crate::core::scan::TargetKind;

// ── Module trait tests ──────────────────────────────────────────────

#[test]
fn is_passive() {
    assert!(WifiIntel.is_passive());
}

#[test]
fn accepts_only_local_physical_seeds() {
    assert!(WifiIntel.accepts(&Target::new(TargetKind::Coordinates, "-27.47,153.02")));
    assert!(WifiIntel.accepts(&Target::new(TargetKind::MacAddress, "aa:bb:cc:dd:ee:ff")));
    assert!(!WifiIntel.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    assert!(!WifiIntel.accepts(&Target::new(TargetKind::Domain, "x.com")));
    assert!(!WifiIntel.accepts(&Target::new(TargetKind::FullName, "Jane Doe")));
}

#[test]
fn cost_is_key_gated() {
    assert!(matches!(WifiIntel.cost(), ModuleCost::KeyGated));
}

#[test]
fn module_name_and_priority() {
    assert_eq!(WifiIntel.name(), "wifi_intel");
    assert_eq!(WifiIntel.priority(), 65);
}

#[test]
fn description_is_set() {
    assert_eq!(
        WifiIntel.description(),
        "WiFi AP survey and BSSID geolocation via Termux + WiGLE"
    );
}

#[test]
fn max_timeout_is_20s() {
    assert_eq!(WifiIntel.max_timeout_ms(), 20_000);
}

// ── AP parsing ─────────────────────────────────────

#[test]
fn parses_sample_payload() {
    let json = br#"[
        {"bssid":"aa:bb:cc:dd:ee:ff","ssid":"MyNet","frequency":2412,"rssi":-45,"timestamp":1},
        {"bssid":"11:22:33:44:55:66","ssid":null,"frequency":5180,"rssi":-72,"timestamp":2}
    ]"#;
    let r = parse_aps(json, "test");
    assert_eq!(r.entities.len(), 2);
    assert_eq!(r.entities[0].kind, EntityKind::MacAddress);
    assert_eq!(r.entities[0].value, "aa:bb:cc:dd:ee:ff");
}

#[test]
fn malformed_json_no_ops() {
    let r = parse_aps(b"not json", "test");
    assert_eq!(r.entities.len(), 0);
}

#[test]
fn parses_three_aps_with_all_fields() {
    let json = br#"[
        {"bssid":"aa:bb:cc:dd:ee:ff","ssid":"HomeNet","frequency":2437,"rssi":-42,"timestamp":100},
        {"bssid":"11:22:33:44:55:66","ssid":"Office5G","frequency":5745,"rssi":-68,"timestamp":200},
        {"bssid":"de:ad:be:ef:ca:fe","ssid":"CafeWifi","frequency":2462,"rssi":-55,"timestamp":300}
    ]"#;
    let r = parse_aps(json, "scan-001");
    assert_eq!(r.entities.len(), 3);

    // Verify first AP entity
    let ap0 = &r.entities[0];
    assert_eq!(ap0.kind, EntityKind::MacAddress);
    assert_eq!(ap0.value, "aa:bb:cc:dd:ee:ff");
    assert!((ap0.confidence - 0.95).abs() < 1e-6);
    assert!(ap0.has_tag(crate::core::tags::WIFI_AP));
    assert_eq!(ap0.scan_id, "scan-001");

    // Verify evidence attributes on first AP
    let ev0 = &ap0.evidence[0];
    assert_eq!(ev0.source, SOURCE);
    assert_eq!(ev0.attributes.get("ssid").unwrap(), "HomeNet");
    assert_eq!(ev0.attributes.get("bssid").unwrap(), "aa:bb:cc:dd:ee:ff");
    assert_eq!(ev0.attributes.get("frequency_mhz").unwrap(), "2437");
    assert_eq!(ev0.attributes.get("rssi_dbm").unwrap(), "-42");
    assert_eq!(ev0.attributes.get("timestamp").unwrap(), "100");

    // Verify third AP (5 GHz band)
    let ap2 = &r.entities[2];
    assert_eq!(ap2.value, "de:ad:be:ef:ca:fe");
    assert_eq!(
        ap2.evidence[0].attributes.get("frequency_mhz").unwrap(),
        "2462"
    );
}

#[test]
fn hidden_ssid_shows_placeholder() {
    let json =
        br#"[{"bssid":"ff:ff:ff:ff:ff:ff","ssid":null,"frequency":2412,"rssi":-80,"timestamp":0}]"#;
    let r = parse_aps(json, "test");
    assert_eq!(r.entities.len(), 1);
    let ev = &r.entities[0].evidence[0];
    assert_eq!(ev.attributes.get("ssid").unwrap(), "<hidden>");
    assert!(ev.summary.contains("<hidden>"));
}

#[test]
fn missing_optional_fields_default_to_zero() {
    let json = br#"[{"bssid":"ab:cd:ef:01:23:45"}]"#;
    let r = parse_aps(json, "test");
    assert_eq!(r.entities.len(), 1);
    let ev = &r.entities[0].evidence[0];
    assert_eq!(ev.attributes.get("frequency_mhz").unwrap(), "0");
    assert_eq!(ev.attributes.get("rssi_dbm").unwrap(), "0");
    assert_eq!(ev.attributes.get("timestamp").unwrap(), "0");
}

#[test]
fn empty_json_array_no_ops() {
    let r = parse_aps(b"[]", "test");
    assert_eq!(r.entities.len(), 0);
}

// ── WiGLE DetailResp deserialization (from bssid_locate) ────────────

#[test]
fn detail_resp_deserializes() {
    let json = r#"{
        "success": true,
        "results": [{
            "trilat": -27.4766,
            "trilong": 153.0166,
            "ssid": "TestNet",
            "city": "Brisbane",
            "region": "Queensland",
            "country": "AU",
            "postalcode": "4000",
            "lastupdt": "2024-12-01",
            "encryption": "wpa2"
        }]
    }"#;
    let r: types::DetailResp = serde_json::from_str(json).unwrap();
    assert_eq!(r.success, Some(true));
    assert_eq!(r.results.len(), 1);
    let net = &r.results[0];
    assert!((net.trilat.unwrap() - (-27.4766)).abs() < 0.001);
    assert_eq!(net.city.as_deref(), Some("Brisbane"));
}

#[test]
fn detail_resp_handles_empty() {
    let json = r#"{"success": true, "results": []}"#;
    let r: types::DetailResp = serde_json::from_str(json).unwrap();
    assert!(r.results.is_empty());
}

#[test]
fn detail_resp_handles_failure() {
    let json = r#"{"success": false}"#;
    let r: types::DetailResp = serde_json::from_str(json).unwrap();
    assert_eq!(r.success, Some(false));
}
