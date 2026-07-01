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
    assert!(t1.has_tag(crate::core::tags::CELL_TOWER));
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
