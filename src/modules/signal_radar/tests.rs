use super::*;

use crate::core::{
    confidence,
    entity::EntityKind,
    rf::{AddressKind, RadioKind, RfSighting, RfSource},
};

/// A fixed reading time for the parser tests — the parsers take the epoch as
/// an argument precisely so nothing here depends on the clock.
const TEST_EPOCH: i64 = 1_758_500_000;

// ── wifi parser ────────────────────────────────────────────────────────────

#[test]
fn wifi_parse_valid_aps() {
    let json = br#"[
        {"bssid":"AA:BB:CC:DD:EE:FF","ssid":"TestNet","rssi":-45,"frequency":2437,"channel_width":"20","timestamp":1000},
        {"bssid":"11:22:33:44:55:66","ssid":"WeakAP","rssi":-80,"frequency":5180,"channel_width":"40","timestamp":2000}
    ]"#;
    let result =
        wifi::parse_scan(json, "test-scan", Some(TEST_EPOCH)).expect("valid AP JSON parses");
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
    // HSE BLE Radar enrichment: the specific channel (2437 MHz → ch 6 via
    // bleradar_core::wifi_frequency_to_channel) and a coarse RSSI proximity band
    // (-45 dBm ≥ -50 → immediate via bleradar_core::proximity_label).
    assert!(ap1.has_tag("channel:6"), "2437 MHz → channel 6");
    assert!(
        ap1.has_tag("proximity:immediate"),
        "rssi -45 → immediate band"
    );

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
    // 5180 MHz → channel 36; rssi -80 dBm sits at the mid/far boundary
    // (≥ -80 → mid) — the BLE Radar's coarse band, never a fabricated distance.
    assert!(ap2.has_tag("channel:36"), "5180 MHz → channel 36");
    assert!(ap2.has_tag("proximity:mid"), "rssi -80 → mid band");

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
    let result =
        wifi::parse_scan(json, "test-scan", Some(TEST_EPOCH)).expect("valid AP JSON parses");
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
    let result =
        wifi::parse_scan(b"[]", "test-scan", Some(TEST_EPOCH)).expect("an empty array parses");
    assert!(result.is_empty());
}

/// Unparseable tool output is a malfunction, not an empty answer: reporting it
/// as zero access points would make a broken termux-api indistinguishable from
/// "no Wi-Fi in range".
#[test]
fn wifi_parse_invalid_json_is_an_error() {
    assert!(wifi::parse_scan(b"not json", "test-scan", Some(TEST_EPOCH)).is_err());
}

/// Blank output is the complement: a tool that exits 0 and prints nothing has
/// answered "nothing to report", which stays a clean empty Ok.
#[test]
fn wifi_parse_blank_output_is_an_empty_ok() {
    for blank in [&b""[..], b"  \n"] {
        assert!(
            wifi::parse_scan(blank, "test-scan", Some(TEST_EPOCH))
                .expect("blank output is an empty answer, not an error")
                .is_empty()
        );
    }
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

#[test]
fn rssi_confidence_implausible_positive_reading_degrades_to_worst_tier() {
    // Regression: `rssi` is deserialised directly from untrusted
    // termux-wifi-scaninfo JSON. Wi-Fi RSSI in dBm is never positive in
    // practice, but the old `Some(r) if r >= -50 => VERY_HIGH_PLUS` had no
    // upper bound — a driver bug or corrupted scan line reporting a
    // positive value (e.g. a raw percentage in place of dBm) scored the
    // SAME best-possible confidence as a genuine, very-strong -40 dBm
    // reading. Same "malformed input must never score better than a real
    // worst-case reading" shape already fixed for
    // util::geo::confidence_for_accuracy_m and device_fix::fix_confidence.
    for bad in [1, 5, 100, 9999, i64::MAX] {
        let c = wifi::rssi_confidence(Some(bad));
        assert!(
            (c - confidence::LOW_MEDIUM).abs() < 0.01,
            "implausible positive RSSI {bad} must score the worst tier, got {c}"
        );
        assert!(
            c < confidence::VERY_HIGH_PLUS,
            "implausible positive RSSI {bad} must never reach the ceiling: {c}"
        );
        // Compared against a concrete valid weak-but-real reading, not the
        // bare ceiling constant: under the old bug an implausible positive
        // RSSI landed on EXACTLY the ceiling (the unbounded first arm), so
        // comparing against the ceiling constant itself would tie vacuously
        // and never catch it. Comparing two `rssi_confidence` calls keeps
        // this a true metamorphic test (same function, two inputs).
        confidence::assert_metamorphic_no_gain(
            wifi::rssi_confidence(Some(-90)),
            c,
            "signal_radar::wifi::rssi_confidence: implausible positive RSSI vs a valid weak-but-real reading",
        );
    }
}

// ── bluetooth parser ───────────────────────────────────────────────────────

#[test]
fn bluetooth_parse_valid_devices() {
    let json = br#"[
        {"address":"AA:BB:CC:DD:EE:01","name":"Headphones","type":"classic","bondState":"bonded"},
        {"address":"AA:BB:CC:DD:EE:02","name":"Speaker","type":"le","bondState":"none"}
    ]"#;
    let result = bluetooth::parse_bt_json(json, "test-scan", Some(TEST_EPOCH))
        .expect("valid BT JSON parses");
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
    let result = bluetooth::parse_bt_json(json, "test-scan", Some(TEST_EPOCH))
        .expect("valid BT JSON parses");
    assert_eq!(result.len(), 1);
}

// ── cell parser ────────────────────────────────────────────────────────────

#[test]
fn cell_parse_valid_towers() {
    let json = br#"[
        {"type":"LTE","registered":true,"dbm":-80,"cid":12345,"lac":null,"tac":678,"mcc":"505","mnc":"01"},
        {"type":"GSM","registered":false,"dbm":-95,"cid":999,"lac":100,"tac":null,"mcc":505,"mnc":3}
    ]"#;
    let result =
        cell::parse_cells(json, "test-scan", Some(TEST_EPOCH)).expect("valid cell JSON parses");
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
    let result =
        cell::parse_cells(json, "test-scan", Some(TEST_EPOCH)).expect("valid cell JSON parses");
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

#[test]
fn wifi_absent_readings_are_omitted_never_zero_or_hidden() {
    // Backlog #16 (the sibling of device_sensors/wifi.rs): a scan line with
    // only a BSSID must not gain `rssi_dbm=0`, `frequency_mhz=0`,
    // `timestamp=0` or a `<hidden>` network name.
    let json = br#"[{"bssid":"AA:BB:CC:DD:EE:FF"}]"#;
    let r = super::wifi::parse_scan(json, "s", Some(TEST_EPOCH)).expect("parses");
    let mac = r
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::MacAddress)
        .expect("the BSSID entity");
    let attrs = &mac.evidence[0].attributes;
    for key in [
        "rssi_dbm",
        "frequency_mhz",
        "timestamp",
        "ssid",
        "channel",
        "proximity",
        "channel_width",
    ] {
        assert!(!attrs.contains_key(key), "{key} must be absent: {attrs:?}");
    }
    assert_eq!(
        attrs.get("bssid").map(String::as_str),
        Some("AA:BB:CC:DD:EE:FF")
    );
    assert_eq!(mac.evidence[0].summary, "Wi-Fi AP scan (SSID not reported)");
    assert!(
        r.entities.iter().all(|e| e.kind != EntityKind::Ssid),
        "no Ssid entity without a reported name"
    );
}

#[test]
fn cell_absent_dbm_is_omitted_never_zero() {
    let json =
        br#"[{"type":"LTE","registered":true,"cid":12345,"tac":678,"mcc":"505","mnc":"01"}]"#;
    let r = super::cell::parse_cells(json, "s", Some(TEST_EPOCH)).expect("parses");
    let e = r
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::DeviceId)
        .expect("the tower");
    assert!(
        !e.evidence[0].attributes.contains_key("dbm"),
        "{:?}",
        e.evidence[0].attributes
    );
}

// ── REQ-RADAR-001: every reading is also a sighting ──────────────────────────

/// Each Wi-Fi reading yields one sighting beside its entity: the same BSSID
/// (canonical), the SSID where reported, the level as measured, the read time.
#[test]
fn wifi_readings_become_sightings_with_signal_name_and_time() {
    let json = br#"[
        {"bssid":"AA:BB:CC:DD:EE:FF","ssid":"TestNet","rssi":-45,"frequency":2437},
        {"bssid":"11:22:33:44:55:66","rssi":-80,"frequency":5180}
    ]"#;
    let r = wifi::parse_scan(json, "test-scan", Some(TEST_EPOCH)).expect("parses");
    assert_eq!(r.sightings.len(), 2, "one sighting per AP, hidden or not");
    let s = &r.sightings[0];
    assert_eq!(s.network_id, "aa:bb:cc:dd:ee:ff");
    assert_eq!(s.radio, RadioKind::Wifi);
    assert_eq!(s.source, RfSource::WifiRadar);
    assert!(s.source.is_local_sensor());
    assert_eq!(s.name.as_deref(), Some("TestNet"));
    assert_eq!(s.signal_dbm, Some(-45.0));
    assert_eq!(s.observed_epoch, Some(TEST_EPOCH));
    assert!(
        !s.has_usable_position(),
        "the parser knows no position; the sweep stamps it"
    );
    let hidden = &r.sightings[1];
    assert_eq!(hidden.name, None, "an unreported SSID stays absent");
    assert_eq!(hidden.signal_dbm, Some(-80.0));
}

/// `le` is BLE; `classic`/`dual`/unknown are recorded as classic with the
/// tool's own type kept verbatim, and a missing or blank name stays absent.
#[test]
fn bluetooth_readings_classify_the_radio_and_keep_the_type_verbatim() {
    let json = br#"[
        {"address":"AA:BB:CC:DD:EE:01","name":"Headphones","type":"classic","bondState":"bonded"},
        {"address":"AA:BB:CC:DD:EE:02","name":"Speaker","type":"le","bondState":"none"},
        {"address":"AA:BB:CC:DD:EE:03","type":"dual"},
        {"address":"AA:BB:CC:DD:EE:04","name":"  "}
    ]"#;
    let r = bluetooth::parse_bt_json(json, "test-scan", Some(TEST_EPOCH)).expect("parses");
    assert_eq!(r.sightings.len(), 4);
    let by_id = |id: &str| r.sightings.iter().find(|s| s.network_id == id).expect(id);
    let classic = by_id("aa:bb:cc:dd:ee:01");
    assert_eq!(classic.radio, RadioKind::BtClassic);
    assert_eq!(classic.source, RfSource::BluetoothRadar);
    assert_eq!(classic.name.as_deref(), Some("Headphones"));
    assert_eq!(classic.raw_type.as_deref(), Some("classic"));
    let le = by_id("aa:bb:cc:dd:ee:02");
    assert_eq!(le.radio, RadioKind::Ble);
    assert_eq!(le.raw_type.as_deref(), Some("le"));
    let dual = by_id("aa:bb:cc:dd:ee:03");
    assert_eq!(
        dual.radio,
        RadioKind::BtClassic,
        "found over BR/EDR discovery"
    );
    assert_eq!(
        dual.raw_type.as_deref(),
        Some("dual"),
        "the tool's own word survives for re-derivation"
    );
    assert_eq!(dual.name, None);
    let blank_name = by_id("aa:bb:cc:dd:ee:04");
    assert_eq!(blank_name.name, None, "a blank name is no name");
    assert_eq!(blank_name.raw_type, None);
    assert!(
        r.sightings
            .iter()
            .all(|s| s.observed_epoch == Some(TEST_EPOCH))
    );
}

/// A tower sighting carries the engine's own tower id (so it joins the
/// `DeviceId` entity), the level only when the radio gave a real one, and the
/// technology string verbatim.
#[test]
fn cell_readings_become_sightings_keyed_by_the_engine_tower_id() {
    let json = br#"[
        {"type":"LTE","registered":true,"dbm":-80,"cid":12345,"lac":null,"tac":678,"mcc":"505","mnc":"01"},
        {"type":"GSM","registered":false,"dbm":2147483647,"cid":999,"lac":100,"tac":null,"mcc":505,"mnc":3}
    ]"#;
    let r = cell::parse_cells(json, "test-scan", Some(TEST_EPOCH)).expect("parses");
    assert_eq!(r.sightings.len(), 2);
    let lte = &r.sightings[0];
    assert_eq!(lte.network_id, "505-01-678-12345");
    assert_eq!(
        lte.network_id, r.entities[0].value,
        "the sighting keys on the DeviceId the entity carries"
    );
    assert_eq!(lte.radio, RadioKind::Cellular);
    assert_eq!(lte.source, RfSource::CellRadar);
    assert_eq!(lte.signal_dbm, Some(-80.0));
    assert_eq!(lte.raw_type.as_deref(), Some("LTE"));
    assert_eq!(lte.address_kind(), AddressKind::NotAnAddress);
    let gsm = &r.sightings[1];
    assert_eq!(
        gsm.signal_dbm, None,
        "the Integer.MAX_VALUE sentinel is not a level"
    );
}

/// The sweep's fix is stamped onto every sighting the other radios made — and
/// only onto those with no position of their own.
#[test]
fn the_sweeps_fix_positions_every_sighting_that_has_none_of_its_own() {
    let fix = Fix {
        latitude: -27.4705,
        longitude: 153.026,
        altitude: None,
        accuracy: Some(8.0),
        speed: None,
        bearing: None,
        provider: Some("gps".into()),
    };
    let mut sightings = vec![
        RfSighting::new("aa:bb:cc:dd:ee:ff", RadioKind::Wifi, RfSource::WifiRadar),
        RfSighting::new("505-01-678-12345", RadioKind::Cellular, RfSource::CellRadar),
    ];
    let mut own = RfSighting::new(
        "aa:bb:cc:dd:ee:01",
        RadioKind::Ble,
        RfSource::BluetoothRadar,
    );
    own.latitude = Some(51.5074);
    own.longitude = Some(-0.1278);
    own.accuracy_m = Some(12.0);
    sightings.push(own);

    stamp_sweep_position(&mut sightings, Some(&fix));

    assert_eq!(
        (
            sightings[0].latitude,
            sightings[0].longitude,
            sightings[0].accuracy_m
        ),
        (Some(-27.4705), Some(153.026), Some(8.0))
    );
    assert_eq!(
        (sightings[1].latitude, sightings[1].longitude),
        (Some(-27.4705), Some(153.026)),
        "a tower sighting is positioned too"
    );
    assert_eq!(
        (
            sightings[2].latitude,
            sightings[2].longitude,
            sightings[2].accuracy_m
        ),
        (Some(51.5074), Some(-0.1278), Some(12.0)),
        "a reading's own position is never overwritten"
    );
}

/// No fix in the sweep: nothing is invented. A sighting stays position-less
/// rather than being placed at a stale or null position.
#[test]
fn without_a_fix_no_sighting_is_positioned() {
    let mut sightings = vec![RfSighting::new(
        "aa:bb:cc:dd:ee:ff",
        RadioKind::Wifi,
        RfSource::WifiRadar,
    )];
    stamp_sweep_position(&mut sightings, None);
    assert!(!sightings[0].has_usable_position());
    assert_eq!(sightings[0].accuracy_m, None);
}

/// `combine_sensors` keeps every radio's sightings, not only their entities —
/// merging sub-results with `extend` is exactly how they used to be lost.
#[test]
fn combine_sensors_keeps_every_radios_sightings() {
    let wifi = wifi::parse_scan(
        br#"[{"bssid":"AA:BB:CC:DD:EE:FF","rssi":-45}]"#,
        "s",
        Some(TEST_EPOCH),
    )
    .expect("parses");
    let bt = bluetooth::parse_bt_json(
        br#"[{"address":"AA:BB:CC:DD:EE:02","type":"le"}]"#,
        "s",
        Some(TEST_EPOCH),
    )
    .expect("parses");
    let combined = combine_sensors([
        Ok(wifi),
        Ok(bt),
        Ok(ModuleResult::new()),
        Ok(ModuleResult::new()),
        Ok(ModuleResult::new()),
    ])
    .expect("nothing failed");
    assert_eq!(combined.sightings.len(), 2);
    assert_eq!(combined.entities.len(), 2);
}
