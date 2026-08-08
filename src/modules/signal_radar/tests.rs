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

    let macs: Vec<_> = result
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::MacAddress)
        .collect();
    assert_eq!(macs.len(), 2);

    let d1 = macs[0];
    assert_eq!(d1.value, "aa:bb:cc:dd:ee:01");
    assert!((d1.confidence - confidence::HIGH_PLUSPLUS).abs() < 0.01);
    assert!(d1.has_tag("bluetooth"));
    assert!(d1.has_tag("bt-classic"));
    assert!(d1.has_tag("bond:bonded"));

    // The friendly name is emitted alongside the address, exactly as the Wi-Fi
    // sensor emits an SSID beside its BSSID. A Bluetooth broadcast name is an
    // independently searchable identifier and routinely carries a person's name.
    let names: Vec<&str> = result
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::Ssid)
        .map(|e| e.value.as_str())
        .collect();
    assert!(
        names.contains(&"headphones") || names.contains(&"Headphones"),
        "the device name must be emitted as its own entity, got {names:?}"
    );
}

/// The placeholder guard must delegate to `is_placeholder_bssid`, not re-derive
/// a partial copy of it.
///
/// `02:00:00:00:00:00` is the load-bearing case and is why this test exists:
/// it is `BluetoothAdapter.DEFAULT_MAC_ADDRESS`, the constant AOSP returns from
/// `getAddress()` to any app without the signature-level `LOCAL_MAC_ADDRESS`
/// permission — which Termux can never hold. It is therefore the single most
/// likely bogus address to arrive on THIS sensor, and the hand-rolled guard
/// that used to live here (`is_empty() || == "00:00:00:00:00:00"`) was the one
/// copy that missed it.
#[test]
fn bluetooth_skip_placeholder_address() {
    let json = br#"[
        {"address":"00:00:00:00:00:00"},
        {"address":"02:00:00:00:00:00"},
        {"address":""},
        {"address":"AA:BB:CC:DD:EE:FF"}
    ]"#;
    let result = bluetooth::parse_bt_json(json, "test-scan").expect("valid BT JSON parses");
    let macs: Vec<&str> = result
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::MacAddress)
        .map(|e| e.value.as_str())
        .collect();
    assert_eq!(
        macs,
        vec!["aa:bb:cc:dd:ee:ff"],
        "every placeholder sentinel must be dropped, including Android's \
         anonymised 02:00:00:00:00:00"
    );
}

/// A value that is not a complete address must never be minted as a
/// `MacAddress`. `classify_mac` reads only a hex PREFIX, so without a
/// full-address gate a friendly name whose first six hex-ish characters spell
/// one — "Facade" — becomes a confidently vendor-attributed hardware entity.
#[test]
fn bluetooth_never_mints_a_mac_from_a_non_address() {
    let json = br#"[
        {"address":"Facade","name":"Facade"},
        {"address":"not-a-mac","name":"Junk"}
    ]"#;
    let result = bluetooth::parse_bt_json(json, "test-scan").expect("valid BT JSON parses");
    assert!(
        result
            .entities
            .iter()
            .all(|e| e.kind != EntityKind::MacAddress),
        "a non-address must not become a MacAddress: {:?}",
        result
            .entities
            .iter()
            .map(|e| (&e.value, &e.kind))
            .collect::<Vec<_>>()
    );
    // The name is still a real observation and is kept.
    assert!(
        result.entities.iter().any(|e| e.kind == EntityKind::Ssid),
        "the observed name must survive even without an address"
    );
}

/// The shipping third-party tool answers its first invocation with a JSON
/// OBJECT acknowledging the scan, not an array. That is a working tool
/// behaving as designed — an empty `Ok`, never the `unparseable` hard error
/// that counts in `modules_errored` and feeds the circuit breaker.
#[test]
fn bluetooth_scan_acknowledgement_is_not_a_malfunction() {
    let json = br#"{"message":"scanning bluetooth devices, please type termux-bluetooth-scaninfo again to stop the scanning and print the results"}"#;
    let result = bluetooth::parse_bt_json(json, "test-scan")
        .expect("a scan acknowledgement is a successful, device-free answer");
    assert!(result.entities.is_empty());
}

/// The same tool's result form reports a device NAME with no address at all.
/// It must yield the name (the only identifier it ever produces) and must not
/// invent an address for it.
#[test]
fn bluetooth_name_only_form_yields_a_name_and_no_address() {
    let json = br#"{"device":"Matthew's iPhone"}"#;
    let result = bluetooth::parse_bt_json(json, "test-scan").expect("the name-only form parses");
    assert_eq!(result.entities.len(), 1);
    let e = &result.entities[0];
    assert_eq!(e.kind, EntityKind::Ssid);
    assert!(e.has_tag("bluetooth"));
    assert!(
        e.value.to_lowercase().contains("iphone"),
        "the broadcast name must be preserved, got {:?}",
        e.value
    );
}

/// Genuinely broken output is still a hard error — the contract this module
/// shares with every other Termux sensor. Without this, the fixes above could
/// have been made by simply swallowing all parse failures.
#[test]
fn bluetooth_unparseable_output_is_still_an_error() {
    assert!(
        bluetooth::parse_bt_json(b"this is not json at all", "test-scan").is_err(),
        "a real malfunction must not be reported as an empty observation"
    );
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
    clear_unavailable_for_test(crate::modules::termux_sensor::Sensor::CellInfo.tool());
    clear_unavailable_for_test("termux-telephony-signalstrength");

    let _ = scan_cell("test-scan").await;

    // Off-device (this sandbox), the real tool fails to spawn (ENOENT),
    // which caches it unavailable — proves the harness genuinely exercised
    // termux_cmd rather than short-circuiting before ever calling it.
    assert!(
        is_marked_unavailable_for_test(crate::modules::termux_sensor::Sensor::CellInfo.tool()),
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

// ── port_sweep (concurrent ip×port cross product) ──────────────────────────

#[tokio::test]
async fn port_sweep_finds_every_open_port_and_sorts_the_result() {
    // Two REAL ephemeral listeners (open ports) plus one certainly-closed
    // port, all against the same host — mirrors `portscan::tests`'s
    // real-listener pattern. Proves the concurrent ip×port cross product
    // (JoinSet + Semaphore) correctly gathers BOTH hits without dropping or
    // corrupting either, that the closed port is excluded, and that the
    // output is sorted rather than reflecting completion order: the input
    // `ports` list is deliberately given in an order that does not match the
    // sorted expectation.
    let l1 = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("should bind");
    let l2 = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("should bind");
    let p1 = l1.local_addr().expect("should succeed").port();
    let p2 = l2.local_addr().expect("should succeed").port();
    // A port distinct from both listeners, almost certainly closed.
    let closed = p1.max(p2).wrapping_add(1).max(1);

    let ips = vec!["127.0.0.1".to_string()];
    // Deliberately NOT in sorted order, so a pass here can't be explained by
    // the sweep merely preserving input order.
    let (hi, lo) = if p1 > p2 { (p1, p2) } else { (p2, p1) };
    let ports = [hi, closed, lo];
    let open = lan::port_sweep(&ips, &ports).await;

    let mut expected = vec![format!("127.0.0.1:{p1}"), format!("127.0.0.1:{p2}")];
    expected.sort_unstable();
    assert_eq!(
        open, expected,
        "both listening ports found (closed port absent), sorted for determinism"
    );
}

#[tokio::test]
async fn port_sweep_reports_nothing_for_an_all_closed_sweep() {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("should bind");
    let listening = l.local_addr().expect("should succeed").port();
    // Neither swept port is the listener's — both should read closed.
    let ports = [listening.wrapping_add(1).max(1), listening.wrapping_add(2)];
    let open = lan::port_sweep(&["127.0.0.1".to_string()], &ports).await;
    assert!(
        open.is_empty(),
        "no port in the sweep list is open: {open:?}"
    );
}
