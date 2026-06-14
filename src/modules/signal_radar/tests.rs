use super::*;

use crate::core::entity::EntityKind;

// ── wifi parser ────────────────────────────────────────────────────────────

#[test]
fn wifi_parse_valid_aps() {
    let json = br#"[
        {"bssid":"AA:BB:CC:DD:EE:FF","ssid":"TestNet","rssi":-45,"frequency":2437,"channel_width":"20","timestamp":1000},
        {"bssid":"11:22:33:44:55:66","ssid":"WeakAP","rssi":-80,"frequency":5180,"channel_width":"40","timestamp":2000}
    ]"#;
    let result = wifi::parse_scan(json, "test-scan");
    assert_eq!(result.len(), 2);

    let ap1 = &result.entities[0];
    assert_eq!(ap1.kind, EntityKind::MacAddress);
    assert_eq!(ap1.value, "aa:bb:cc:dd:ee:ff");
    // rssi -45 >= -50 → confidence 0.90
    assert!(
        (ap1.confidence - 0.90).abs() < 0.01,
        "confidence={}",
        ap1.confidence
    );
    assert!(ap1.has_tag("band:2.4GHz"), "expected 2.4GHz band tag");

    let ap2 = &result.entities[1];
    // rssi -80 → confidence 0.60
    assert!(
        (ap2.confidence - 0.60).abs() < 0.01,
        "confidence={}",
        ap2.confidence
    );
    assert!(ap2.has_tag("band:5GHz"), "expected 5GHz band tag");
}

#[test]
fn wifi_skip_placeholder_bssids() {
    let json = br#"[
        {"bssid":"00:00:00:00:00:00","ssid":"Bad1","rssi":-40,"frequency":2437},
        {"bssid":"02:00:00:00:00:00","ssid":"Bad2","rssi":-40,"frequency":2437},
        {"bssid":"","ssid":"Bad3","rssi":-40,"frequency":2437},
        {"bssid":"AA:BB:CC:DD:EE:FF","ssid":"Good","rssi":-40,"frequency":2437}
    ]"#;
    let result = wifi::parse_scan(json, "test-scan");
    assert_eq!(result.len(), 1);
}

#[test]
fn wifi_parse_empty_array() {
    let result = wifi::parse_scan(b"[]", "test-scan");
    assert!(result.is_empty());
}

#[test]
fn wifi_parse_invalid_json() {
    let result = wifi::parse_scan(b"not json", "test-scan");
    assert!(result.is_empty());
}

// ── wifi_band helper ──────────────────────────────────────────────────────

#[test]
fn wifi_band_classification() {
    assert_eq!(wifi::wifi_band(Some(2412)), Some("band:2.4GHz"));
    assert_eq!(wifi::wifi_band(Some(5180)), Some("band:5GHz"));
    assert_eq!(wifi::wifi_band(Some(6000)), Some("band:6GHz"));
    assert_eq!(wifi::wifi_band(Some(3000)), None);
    assert_eq!(wifi::wifi_band(None), None);
}

// ── rssi_confidence helper ─────────────────────────────────────────────────

#[test]
fn rssi_confidence_tiers() {
    assert!((wifi::rssi_confidence(Some(-40)) - 0.90).abs() < 0.01);
    assert!((wifi::rssi_confidence(Some(-65)) - 0.75).abs() < 0.01);
    assert!((wifi::rssi_confidence(Some(-80)) - 0.60).abs() < 0.01);
    assert!((wifi::rssi_confidence(Some(-90)) - 0.45).abs() < 0.01);
    assert!((wifi::rssi_confidence(None) - 0.45).abs() < 0.01);
}

// ── bluetooth parser ───────────────────────────────────────────────────────

#[test]
fn bluetooth_parse_valid_devices() {
    let json = br#"[
        {"address":"AA:BB:CC:DD:EE:01","name":"Headphones","type":"classic","bondState":"bonded"},
        {"address":"AA:BB:CC:DD:EE:02","name":"Speaker","type":"le","bondState":"none"}
    ]"#;
    let result = bluetooth::parse_bt_json(json, "test-scan");
    assert_eq!(result.len(), 2);

    let d1 = &result.entities[0];
    assert_eq!(d1.kind, EntityKind::MacAddress);
    assert_eq!(d1.value, "aa:bb:cc:dd:ee:01");
    assert!((d1.confidence - 0.80).abs() < 0.01);
    assert!(d1.has_tag("bluetooth"));
    assert!(d1.has_tag("bt-classic"));
    assert!(d1.has_tag("bond:bonded"));
}

#[test]
fn bluetooth_skip_placeholder_address() {
    let json = br#"[
        {"address":"00:00:00:00:00:00","name":"Bad"},
        {"address":"","name":"Empty"},
        {"address":"AA:BB:CC:DD:EE:FF","name":"Good"}
    ]"#;
    let result = bluetooth::parse_bt_json(json, "test-scan");
    assert_eq!(result.len(), 1);
}

#[test]
fn bluetooth_hcitool_parse() {
    let text = b"Scanning ...\n\t11:22:33:44:55:66\tMouse\n\t77:88:99:AA:BB:CC\tKeyboard\n";
    let result = bluetooth::parse_hcitool(text, "test-scan");
    assert_eq!(result.len(), 2);
    // hcitool addresses are passed through as-is; normalisation may lower-case
    assert_eq!(
        result.entities[0].value.to_ascii_lowercase(),
        "11:22:33:44:55:66"
    );
    assert!(result.entities[0].has_tag("bt-classic"));
}

// ── cell parser ────────────────────────────────────────────────────────────

#[test]
fn cell_parse_valid_towers() {
    let json = br#"[
        {"type":"LTE","registered":true,"dbm":-80,"cid":12345,"lac":null,"tac":678,"mcc":"505","mnc":"01"},
        {"type":"GSM","registered":false,"dbm":-95,"cid":999,"lac":100,"tac":null,"mcc":505,"mnc":3}
    ]"#;
    let result = cell::parse_cells(json, "test-scan");
    assert_eq!(result.len(), 2);

    let t1 = &result.entities[0];
    assert_eq!(t1.kind, EntityKind::DeviceId);
    assert_eq!(t1.value, "505-01-678-12345");
    assert!((t1.confidence - 0.75).abs() < 0.01);
    assert!(t1.has_tag("cell-tower"));
    assert!(t1.has_tag("lte"));
    assert!(t1.has_tag("registered"));

    let t2 = &result.entities[1];
    assert_eq!(t2.value, "505-3-100-999");
    assert!(t2.has_tag("gsm"));
}

#[test]
fn cell_skip_incomplete_towers() {
    let json = br#"[
        {"type":"LTE","cid":0,"mcc":"505","mnc":"01"},
        {"type":"LTE","cid":1234,"mcc":"","mnc":"01"},
        {"type":"LTE","cid":null,"mcc":"505","mnc":"01"}
    ]"#;
    let result = cell::parse_cells(json, "test-scan");
    assert!(result.is_empty());
}

// ── 5G NR cell parser ─────────────────────────────────────────────────────

#[test]
fn cell_parse_nr_tower_with_arfcn_and_ssband() {
    let json = br#"[
        {"type":"NR","registered":true,"nrArfcn":627264,"ssBand":"n78","csiRsrp":-88,
         "cid":55001,"tac":9000,"mcc":"234","mnc":"20"}
    ]"#;
    let result = cell::parse_cells(json, "test-scan");
    assert_eq!(result.len(), 1);

    let e = &result.entities[0];
    assert_eq!(e.kind, EntityKind::DeviceId);
    assert_eq!(e.value, "234-20-9000-55001");
    assert!(e.has_tag("cell-tower"), "missing cell-tower tag");
    assert!(e.has_tag("nr"), "missing nr tag");
    assert!(e.has_tag("5g-nr"), "missing 5g-nr tag");
    assert!(e.has_tag("registered"), "missing registered tag");

    let ev = &e.evidence[0];
    assert_eq!(
        ev.attributes.get("nr_arfcn").map(String::as_str),
        Some("627264"),
        "nr_arfcn attribute missing or wrong"
    );
    assert_eq!(
        ev.attributes.get("ss_band").map(String::as_str),
        Some("n78"),
        "ss_band attribute missing or wrong"
    );
    // dbm absent → falls back to csiRsrp
    assert_eq!(
        ev.attributes.get("dbm").map(String::as_str),
        Some("-88"),
        "dbm should equal csiRsrp"
    );
}

#[test]
fn cell_parse_nr_tower_dbm_preferred_over_csi_rsrp() {
    let json = br#"[
        {"type":"NR","dbm":-70,"csiRsrp":-99,"nrArfcn":123456,"ssBand":"n41",
         "cid":1,"tac":1,"mcc":"001","mnc":"01"}
    ]"#;
    let result = cell::parse_cells(json, "test-scan");
    assert_eq!(result.len(), 1);
    let ev = &result.entities[0].evidence[0];
    assert_eq!(
        ev.attributes.get("dbm").map(String::as_str),
        Some("-70"),
        "dbm field should be preferred over csiRsrp"
    );
}

#[test]
fn cell_parse_nr_without_optional_nr_fields() {
    // NR entry with no nrArfcn / ssBand — should still parse, just omit those attrs.
    let json = br#"[
        {"type":"NR","csiRsrp":-90,"cid":2,"tac":2,"mcc":"310","mnc":"260"}
    ]"#;
    let result = cell::parse_cells(json, "test-scan");
    assert_eq!(result.len(), 1);
    let e = &result.entities[0];
    assert!(e.has_tag("5g-nr"));
    let ev = &e.evidence[0];
    assert!(
        !ev.attributes.contains_key("nr_arfcn"),
        "nr_arfcn should be absent"
    );
    assert!(
        !ev.attributes.contains_key("ss_band"),
        "ss_band should be absent"
    );
}

// ── NFC parser ────────────────────────────────────────────────────────────

#[test]
fn nfc_parse_valid_tags() {
    let json = br#"[{"id":"04:AB:CD:EF"},{"id":"A1:B2:C3:D4"}]"#;
    let result = nfc::parse_tags(json, "test-scan");
    assert_eq!(result.len(), 2);

    let t = &result.entities[0];
    assert_eq!(t.kind, EntityKind::DeviceId);
    assert_eq!(t.value, "04:AB:CD:EF");
    assert!((t.confidence - 0.75).abs() < 0.01);
    assert!(t.has_tag("nfc"), "missing nfc tag");
    assert!(t.has_tag("nfc-tag"), "missing nfc-tag tag");
}

#[test]
fn nfc_skip_empty_id() {
    let json = br#"[{"id":""},{"id":"AA:BB:CC:DD"}]"#;
    let result = nfc::parse_tags(json, "test-scan");
    assert_eq!(result.len(), 1);
}

#[test]
fn nfc_parse_empty_array() {
    let result = nfc::parse_tags(b"[]", "test-scan");
    assert!(result.is_empty());
}

#[test]
fn nfc_parse_invalid_json() {
    let result = nfc::parse_tags(b"not json", "test-scan");
    assert!(result.is_empty());
}

// ── ARP parser ─────────────────────────────────────────────────────────────

#[test]
fn arp_parse_valid_entries() {
    let content = "IP address       HW type  Flags  HW address         Mask  Device\n\
                   192.168.1.1      0x1      0x2    AA:BB:CC:DD:EE:FF  *     wlan0\n\
                   192.168.1.50     0x1      0x2    11:22:33:44:55:66  *     wlan0\n";

    let result = lan::parse_arp(content, "test-scan");
    // 2 IPs + 2 MACs = 4 entities
    assert_eq!(result.len(), 4);

    let ips: Vec<_> = result
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::IpAddress)
        .collect();
    assert_eq!(ips.len(), 2);
    // IP ordering: each ARP row emits IP then MAC; IPs come first
    assert!(
        ips.iter().any(|e| e.value == "192.168.1.1"),
        "missing 192.168.1.1"
    );
    assert!((ips[0].confidence - 0.85).abs() < 0.01);
    assert!(ips[0].has_tag("lan-host"));

    let macs: Vec<_> = result
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::MacAddress)
        .collect();
    assert_eq!(macs.len(), 2);
    assert!(macs[0].has_tag("arp-neighbor"));
    assert!(macs[0].has_tag("lan"));
}

#[test]
fn arp_skip_incomplete_entries() {
    // flags 0x0 = incomplete, 0x4 = proxy, 00:00:00:00:00:00 = placeholder
    let content = "IP address       HW type  Flags  HW address         Mask  Device\n\
                   10.0.0.1         0x1      0x0    AA:BB:CC:DD:EE:FF  *     eth0\n\
                   10.0.0.2         0x1      0x4    AA:BB:CC:DD:EE:FF  *     eth0\n\
                   10.0.0.3         0x1      0x2    00:00:00:00:00:00  *     eth0\n";
    let result = lan::parse_arp(content, "test-scan");
    assert!(result.is_empty());
}

#[test]
fn arp_parse_empty() {
    let content = "IP address       HW type  Flags  HW address         Mask  Device\n";
    let result = lan::parse_arp(content, "test-scan");
    assert!(result.is_empty());
}
