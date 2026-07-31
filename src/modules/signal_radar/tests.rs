use super::*;

use crate::core::{confidence, entity::EntityKind};

// ── wifi parser ────────────────────────────────────────────────────────────

#[test]
fn wifi_parse_valid_aps() {
    let json = br#"[
        {"bssid":"AA:BB:CC:DD:EE:FF","ssid":"TestNet","rssi":-45,"frequency":2437,"channel_width":"20","timestamp":1000},
        {"bssid":"11:22:33:44:55:66","ssid":"WeakAP","rssi":-80,"frequency":5180,"channel_width":"40","timestamp":2000}
    ]"#;
    let result = wifi::parse_scan(json, "test-scan").expect("valid AP JSON parses");
    // 2 APs, each with a non-empty SSID → 2 MacAddress entities + 2 Ssid
    // entities (one Ssid pushed right after its AP's MacAddress entity).
    assert_eq!(result.len(), 4);

    let ap1 = &result.entities[0];
    assert_eq!(ap1.kind, EntityKind::MacAddress);
    assert_eq!(ap1.value, "aa:bb:cc:dd:ee:ff");
    // rssi -45 >= -50 → confidence confidence::VERY_HIGH_PLUS
    assert!(
        (ap1.confidence - confidence::VERY_HIGH_PLUS).abs() < 0.01,
        "confidence={}",
        ap1.confidence
    );
    assert!(ap1.has_tag("band:2.4GHz"), "expected 2.4GHz band tag");

    let ssid1 = &result.entities[1];
    assert_eq!(ssid1.kind, EntityKind::Ssid);
    assert_eq!(ssid1.value, "TestNet");
    assert!(
        (ssid1.confidence - confidence::MEDIUM_HIGH).abs() < 0.01,
        "confidence={}",
        ssid1.confidence
    );
    assert!(ssid1.has_tag(crate::core::tags::WIFI_AP));
    assert!(ssid1.has_tag("device-sensor"));

    let ap2 = &result.entities[2];
    assert_eq!(ap2.kind, EntityKind::MacAddress);
    // rssi -80 → confidence confidence::MEDIUM_PLUS
    assert!(
        (ap2.confidence - confidence::MEDIUM_PLUS).abs() < 0.01,
        "confidence={}",
        ap2.confidence
    );
    assert!(ap2.has_tag("band:5GHz"), "expected 5GHz band tag");

    let ssid2 = &result.entities[3];
    assert_eq!(ssid2.kind, EntityKind::Ssid);
    assert_eq!(ssid2.value, "WeakAP");
}

#[test]
fn wifi_skip_placeholder_bssids() {
    let json = br#"[
        {"bssid":"00:00:00:00:00:00","ssid":"Bad1","rssi":-40,"frequency":2437},
        {"bssid":"02:00:00:00:00:00","ssid":"Bad2","rssi":-40,"frequency":2437},
        {"bssid":"","ssid":"Bad3","rssi":-40,"frequency":2437},
        {"bssid":"AA:BB:CC:DD:EE:FF","ssid":"Good","rssi":-40,"frequency":2437}
    ]"#;
    let result = wifi::parse_scan(json, "test-scan").expect("valid AP JSON parses");
    // Only the last AP survives the placeholder/empty-BSSID filter, and its
    // non-empty SSID ("Good") mints a second, Ssid entity alongside its
    // MacAddress entity.
    assert_eq!(result.len(), 2);
    assert_eq!(result.entities[0].kind, EntityKind::MacAddress);
    assert_eq!(result.entities[1].kind, EntityKind::Ssid);
    assert_eq!(result.entities[1].value, "Good");
}

#[test]
fn wifi_parse_empty_array() {
    let result = wifi::parse_scan(b"[]", "test-scan").expect("an empty array parses");
    assert!(result.is_empty());
}

/// Unparseable tool output is a malfunction, not an empty answer: reporting it
/// as zero access points would make a broken termux-api indistinguishable from
/// "no Wi-Fi in range".
#[test]
fn wifi_parse_invalid_json_is_an_error() {
    assert!(wifi::parse_scan(b"not json", "test-scan").is_err());
}

/// Blank output is the complement: a tool that exits 0 and prints nothing has
/// answered "nothing to report", which stays a clean empty Ok.
#[test]
fn wifi_parse_blank_output_is_an_empty_ok() {
    for blank in [&b""[..], b"  \n"] {
        assert!(
            wifi::parse_scan(blank, "test-scan")
                .expect("blank output is an empty answer, not an error")
                .is_empty()
        );
    }
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
    assert!((wifi::rssi_confidence(Some(-40)) - confidence::VERY_HIGH_PLUS).abs() < 0.01);
    assert!((wifi::rssi_confidence(Some(-65)) - confidence::VERY_HIGH).abs() < 0.01);
    assert!((wifi::rssi_confidence(Some(-80)) - confidence::MEDIUM_PLUS).abs() < 0.01);
    assert!((wifi::rssi_confidence(Some(-90)) - confidence::LOW_MEDIUM).abs() < 0.01);
    assert!((wifi::rssi_confidence(None) - confidence::LOW_MEDIUM).abs() < 0.01);
}

// ── bluetooth parser ───────────────────────────────────────────────────────

#[test]
fn bluetooth_parse_valid_devices() {
    let json = br#"[
        {"address":"AA:BB:CC:DD:EE:01","name":"Headphones","type":"classic","bondState":"bonded"},
        {"address":"AA:BB:CC:DD:EE:02","name":"Speaker","type":"le","bondState":"none"}
    ]"#;
    let result = bluetooth::parse_bt_json(json, "test-scan").expect("valid BT JSON parses");
    assert_eq!(result.len(), 2);

    let d1 = &result.entities[0];
    assert_eq!(d1.kind, EntityKind::MacAddress);
    assert_eq!(d1.value, "aa:bb:cc:dd:ee:01");
    assert!((d1.confidence - confidence::HIGH_PLUSPLUS).abs() < 0.01);
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
    let result = bluetooth::parse_bt_json(json, "test-scan").expect("valid BT JSON parses");
    assert_eq!(result.len(), 1);
}

// ── cell parser ────────────────────────────────────────────────────────────

#[test]
fn cell_parse_valid_towers() {
    let json = br#"[
        {"type":"LTE","registered":true,"dbm":-80,"cid":12345,"lac":null,"tac":678,"mcc":"505","mnc":"01"},
        {"type":"GSM","registered":false,"dbm":-95,"cid":999,"lac":100,"tac":null,"mcc":505,"mnc":3}
    ]"#;
    let result = cell::parse_cells(json, "test-scan").expect("valid cell JSON parses");
    assert_eq!(result.len(), 2);

    let t1 = &result.entities[0];
    assert_eq!(t1.kind, EntityKind::DeviceId);
    assert_eq!(t1.value, "505-01-678-12345");
    assert!((t1.confidence - confidence::VERY_HIGH).abs() < 0.01);
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
    let result = cell::parse_cells(json, "test-scan").expect("valid cell JSON parses");
    assert!(result.is_empty());
}

// ── scan_cell (redundant signalstrength call) ──────────────────────────────

#[tokio::test]
async fn scan_cell_does_not_spawn_the_discarded_signalstrength_tool() {
    use crate::util::termux::{clear_unavailable_for_test, is_marked_unavailable_for_test};

    // Known state regardless of what earlier tests in this process did.
    clear_unavailable_for_test("termux-telephony-cellinfo");
    clear_unavailable_for_test("termux-telephony-signalstrength");

    let _ = scan_cell("test-scan").await;

    // Off-device (this sandbox), the real tool fails to spawn (ENOENT),
    // which caches it unavailable — proves the harness genuinely exercised
    // termux_cmd rather than short-circuiting before ever calling it.
    assert!(
        is_marked_unavailable_for_test("termux-telephony-cellinfo"),
        "cellinfo must actually be invoked by scan_cell"
    );
    // signalstrength's result was always discarded (`_sigstrength`), so it
    // must never be spawned at all now. This fails against the pre-fix code,
    // which called (and threw away) it on every scan.
    assert!(
        !is_marked_unavailable_for_test("termux-telephony-signalstrength"),
        "signalstrength must not be spawned when its result is unused"
    );
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
    assert!((ips[0].confidence - confidence::HIGH_PLUSPLUS_PLUS).abs() < 0.01);
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
