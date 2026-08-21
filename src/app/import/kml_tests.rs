// Tests for the WiGLE KML wardriving importer.
//
// The fixtures reproduce the two properties of a real capture-device export
// that a naive parser gets wrong — no newlines anywhere, and `<description>`
// fields run together with no separator — because a prettified fixture would
// pass against a line-splitting parser that cannot read the real thing. BSSIDs
// and SSIDs here are invented.
//
// Plain `//` rather than `//!`: this file is `include!`d into a `mod tests`
// block (the repo convention that keeps `tests/architecture.rs`'s orphan-file
// check able to see it), and an inner doc comment is not valid there.

use super::*;
use crate::app::import::{ImportFormat, detect_import_format};

/// A two-placemark export in the exact single-line, separator-free shape the
/// device writes. `00:1a:2b:…` is a hardware BSSID; `02:…` is
/// locally-administered (the `x2` low bit of the first octet), i.e. a rotating
/// privacy address that must not be called trackable.
const WIGLE_KML: &str = concat!(
    r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>"#,
    r#"<kml xmlns="http://www.opengis.net/kml/2.2"><Document><name>WiGLE_Upload-20260821</name>"#,
    r#"<Placemark><name>Sunset &amp; Vine</name><open>1</open>"#,
    r#"<description>Network ID: 00:1A:2B:3C:4D:5EEncryption: WPA2Time: 2026-08-21T16:38:38.000-07:00Signal: -82.0Accuracy: 3.37Type: WIFI</description>"#,
    r#"<styleUrl>#highConfidence</styleUrl>"#,
    r#"<Point><coordinates>153.08647156,-26.81446838</coordinates></Point></Placemark>"#,
    r#"<Placemark><name>(no SSID)</name>"#,
    r#"<description>Network ID: 02:AA:BB:CC:DD:EEEncryption: WPA3Time: 2026-08-21T16:39:00.000-07:00Signal: -60.0Accuracy: 5.0Type: WIFI</description>"#,
    r#"<Point><coordinates>153.09000000,-26.82000000</coordinates></Point></Placemark>"#,
    r#"</Document></kml>"#,
);

fn parse() -> (Vec<Entity>, ImportStats) {
    parse_kml(WIGLE_KML, "s")
}

#[test]
fn a_kml_export_is_detected_and_not_swallowed_by_the_txt_catch_all() {
    // The regression this whole module exists for: a KML opens `<?xml`, which
    // the HTML test does not match, so it used to fall through every heuristic
    // to `OathnetTxt` and yield nothing from a wardriving survey.
    assert_eq!(
        detect_import_format("survey.kml", WIGLE_KML),
        ImportFormat::Kml
    );
    // Detection is by content, never by extension.
    assert_eq!(detect_import_format("", WIGLE_KML), ImportFormat::Kml);
    assert_eq!(
        detect_import_format("misnamed.txt", WIGLE_KML),
        ImportFormat::Kml
    );
}

#[test]
fn description_fields_split_on_labels_not_on_whitespace_or_colons() {
    // The crux of the format: no separators, and the first value is a MAC with
    // five colons of its own. Splitting on `:` or on whitespace mangles both.
    let f = description_fields(
        "Network ID: 00:1A:2B:3C:4D:5EEncryption: WPA2Time: 2026-08-21T16:38:38.000-07:00Signal: -82.0Accuracy: 3.37Type: WIFI",
    );
    let get = |k: &str| f.iter().find(|(l, _)| *l == k).map(|(_, v)| v.as_str());
    assert_eq!(get("Network ID"), Some("00:1A:2B:3C:4D:5E"));
    assert_eq!(get("Encryption"), Some("WPA2"));
    assert_eq!(get("Time"), Some("2026-08-21T16:38:38.000-07:00"));
    assert_eq!(get("Signal"), Some("-82.0"));
    assert_eq!(get("Accuracy"), Some("3.37"));
    assert_eq!(get("Type"), Some("WIFI"));
}

#[test]
fn coordinates_are_swapped_from_kml_lon_lat_to_engine_lat_lon() {
    // KML writes lon,lat; the engine stores lat,lon. A transposed pair is still
    // a valid coordinate, so this mistake yields a plausible location in the
    // wrong hemisphere rather than an error — hence an explicit test.
    let (lat, lon) = parse_coordinates("153.08647156,-26.81446838").expect("valid pair");
    assert!(
        (lat - -26.814_468_38).abs() < 1e-9,
        "latitude must come from the SECOND KML field, got {lat}"
    );
    assert!((lon - 153.086_471_56).abs() < 1e-9);

    let (ents, _) = parse();
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Coordinates && e.value == "-26.814468,153.086472"),
        "coordinates must be stored lat,lon at the engine's 6dp convention, got {:?}",
        ents.iter()
            .filter(|e| e.kind == EntityKind::Coordinates)
            .map(|e| e.value.clone())
            .collect::<Vec<_>>()
    );
}

#[test]
fn out_of_range_and_null_island_coordinates_are_rejected() {
    assert!(
        parse_coordinates("0,0").is_none(),
        "a GPS-less fix is not a location"
    );
    assert!(parse_coordinates("181.0,10.0").is_none());
    assert!(parse_coordinates("10.0,91.0").is_none());
    assert!(parse_coordinates("not,numbers").is_none());
    assert!(
        parse_coordinates("153.0").is_none(),
        "a lone value is not a pair"
    );
}

#[test]
fn a_bssid_becomes_a_mac_entity_with_the_radars_own_oui_tags() {
    let (ents, stats) = parse();
    let mac = ents
        .iter()
        .find(|e| e.kind == EntityKind::MacAddress && e.value == "00:1a:2b:3c:4d:5e")
        .expect("hardware BSSID must be emitted, lowercased");

    // Lowercasing is identity, not cosmetics: WiGLE writes BSSIDs uppercase and
    // every other MAC producer writes them lowercase, so without folding, one
    // access point would be two unrelated graph nodes.
    assert!(mac.tags.iter().any(|t| t == "bssid"));
    assert!(mac.tags.iter().any(|t| t == "geolocatable"));
    assert_eq!(stats.bssids, 2);
}

#[test]
fn a_locally_administered_bssid_is_randomized_not_trackable() {
    // `02:…` has the locally-administered bit set — a rotating privacy address.
    // Calling it trackable would pin a device that deliberately is not fixed.
    let (ents, _) = parse();
    let mac = ents
        .iter()
        .find(|e| e.kind == EntityKind::MacAddress && e.value == "02:aa:bb:cc:dd:ee")
        .expect("locally-administered BSSID is still a real observation");
    assert!(
        !mac.tags.iter().any(|t| t == "trackable"),
        "a locally-administered BSSID must never be tagged trackable, got {:?}",
        mac.tags
    );
}

#[test]
fn the_no_ssid_placeholder_never_becomes_a_network_name() {
    let (ents, stats) = parse();
    assert!(
        !ents
            .iter()
            .any(|e| e.kind == EntityKind::Ssid && e.value.contains("no SSID")),
        "WiGLE's hidden-network placeholder is not a network name"
    );
    // Exactly one real SSID in the fixture; the second placemark is hidden.
    assert_eq!(stats.ssids, 1);
}

#[test]
fn an_ssid_is_xml_entity_decoded() {
    let (ents, _) = parse();
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Ssid && e.value == "Sunset & Vine"),
        "`&amp;` in a network name must be decoded, not stored literally"
    );
}

#[test]
fn a_non_wifi_record_yields_no_bssid() {
    // A `Type: GSM` record's `Network ID` is a cell identifier, not a MAC, and
    // must not be attributed to a hardware vendor.
    let gsm = concat!(
        r#"<kml><Placemark><name>Telco</name>"#,
        r#"<description>Network ID: 505_1_12345_678Encryption: NoneTime: 2026-08-21T16:38:38.000-07:00Signal: -95.0Accuracy: 20.0Type: GSM</description>"#,
        r#"<Point><coordinates>153.0,-26.8</coordinates></Point></Placemark></kml>"#,
    );
    let (ents, stats) = parse_kml(gsm, "s");
    assert_eq!(stats.bssids, 0);
    assert!(!ents.iter().any(|e| e.kind == EntityKind::MacAddress));
    // The observation itself is still geolocated — the tower's position is real.
    assert_eq!(stats.coordinates, 1);
}

#[test]
fn bluetooth_observations_are_kept_not_discarded() {
    // Regression: gating MAC emission on `Type: WIFI` threw away every
    // Bluetooth/BLE record — 31% of a real capture — even though their Network
    // IDs are genuine, OUI-classifiable MACs and are precisely what the BLE
    // radar analyses. The device name is preserved as evidence.
    let bt = concat!(
        r#"<kml><Placemark><name>Pixel Buds</name>"#,
        r#"<description>Network ID: 00:1A:2B:99:88:77Encryption: MiscTime: 2026-08-21T16:38:38.000-07:00Signal: -70.0Accuracy: 4.0Type: BLEAttributes</description>"#,
        r#"<Point><coordinates>153.0,-26.8</coordinates></Point></Placemark></kml>"#,
    );
    let (ents, stats) = parse_kml(bt, "s");
    let mac = ents
        .iter()
        .find(|e| e.kind == EntityKind::MacAddress && e.value == "00:1a:2b:99:88:77")
        .expect("a BLE device MAC is a real observation and must be kept");
    assert_eq!(stats.bssids, 1);
    assert!(mac.tags.iter().any(|t| t == "bluetooth"));
    assert!(
        !mac.tags.iter().any(|t| t == "wifi-ap"),
        "a BLE device is not a Wi-Fi access point, got {:?}",
        mac.tags
    );

    // A Bluetooth `<name>` is a device name, not a network name — not
    // searchable in WiGLE, so it must not become an Ssid and spend geo budget.
    assert_eq!(stats.ssids, 0);
    assert!(!ents.iter().any(|e| e.kind == EntityKind::Ssid));
    assert!(
        mac.evidence
            .iter()
            .any(|ev| ev.attributes.get("name").is_some_and(|v| v == "Pixel Buds")),
        "the device name must survive as evidence"
    );
}

#[test]
fn radio_kind_matches_the_apps_real_type_spellings() {
    // The app writes `BLEAttributes` / `BTAttributes`, not bare `BLE` / `BT`;
    // an equality test against the short forms classified every Bluetooth
    // record as Unknown and dropped its tags.
    assert_eq!(radio_kind("WIFI"), RadioKind::Wifi);
    assert_eq!(radio_kind("BLEAttributes"), RadioKind::Bluetooth);
    assert_eq!(radio_kind("BTAttributes"), RadioKind::Bluetooth);
    assert_eq!(radio_kind("LTE"), RadioKind::Cellular);
    assert_eq!(radio_kind("GSM"), RadioKind::Cellular);
    assert_eq!(radio_kind(""), RadioKind::Unknown);
}

#[test]
fn normalize_bssid_rejects_anything_that_is_not_a_mac() {
    assert_eq!(
        normalize_bssid("00:1A:2B:3C:4D:5E").as_deref(),
        Some("00:1a:2b:3c:4d:5e")
    );
    assert!(normalize_bssid("505_1_12345_678").is_none());
    assert!(normalize_bssid("00:1A:2B:3C:4D").is_none(), "five octets");
    assert!(normalize_bssid("00:1A:2B:3C:4D:5E:6F").is_none(), "seven");
    assert!(normalize_bssid("ZZ:1A:2B:3C:4D:5E").is_none(), "non-hex");
    assert!(normalize_bssid("").is_none());
}

#[test]
fn repeat_sightings_of_one_network_collapse_to_one_node() {
    // A wardrive records the same AP many times as the operator moves. Identity
    // is the value, so the graph must not grow a node per sighting.
    let repeated = WIGLE_KML.replace(
        "</Document>",
        &WIGLE_KML[WIGLE_KML.find("<Placemark>").unwrap()..WIGLE_KML.find("</Document>").unwrap()],
    );
    let (ents, _) = parse_kml(&repeated, "s");
    let macs: Vec<_> = ents
        .iter()
        .filter(|e| e.kind == EntityKind::MacAddress && e.value == "00:1a:2b:3c:4d:5e")
        .collect();
    assert_eq!(macs.len(), 1, "one AP seen twice is still one AP");
}

#[test]
fn parsing_is_deterministic() {
    let a = parse_kml(WIGLE_KML, "s").0;
    let b = parse_kml(WIGLE_KML, "s").0;
    let key = |v: &[Entity]| {
        v.iter()
            .map(|e| format!("{}:{}", e.kind, e.value))
            .collect::<Vec<_>>()
    };
    assert_eq!(key(&a), key(&b), "the same file must yield the same graph");
}

#[test]
fn a_truncated_or_empty_document_fails_closed() {
    // No closing tags, no placemarks, and outright garbage must all yield an
    // empty result rather than a partial value or a panic.
    assert!(parse_kml("", "s").0.is_empty());
    assert!(
        parse_kml("<kml><Document></Document></kml>", "s")
            .0
            .is_empty()
    );
    // A truncated record must not yield a half-read value. The `<name>` here is
    // complete and its SSID is legitimately recoverable; it is the unterminated
    // `<description>` that must contribute nothing rather than a partial MAC.
    let (ents, stats) = parse_kml(
        "<kml><Placemark><name>x</name><description>Network ID: 00:1A",
        "s",
    );
    assert_eq!(
        stats.bssids, 0,
        "an unterminated description yields no BSSID"
    );
    assert_eq!(stats.coordinates, 0, "no Point, no location");
    assert!(!ents.iter().any(|e| e.kind == EntityKind::MacAddress));
}

#[test]
fn a_malformed_placemark_cannot_bleed_into_the_next() {
    // Each placemark is bounded at its own closing tag, so an unterminated
    // `<description>` cannot capture the following record's fields.
    let bleed = concat!(
        r#"<kml><Placemark><name>A</name><description>Network ID: 00:1A:2B:3C:4D:5EType: WIFI</Placemark>"#,
        r#"<Placemark><name>B</name>"#,
        r#"<description>Network ID: 00:99:88:77:66:55Type: WIFI</description>"#,
        r#"<Point><coordinates>153.0,-26.8</coordinates></Point></Placemark></kml>"#,
    );
    let (ents, _) = parse_kml(bleed, "s");
    // The first record's description never closes, so it contributes no MAC;
    // the second is intact and must still parse.
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::MacAddress && e.value == "00:99:88:77:66:55"),
        "a well-formed record after a malformed one must still parse"
    );
    assert!(
        !ents
            .iter()
            .any(|e| e.kind == EntityKind::MacAddress && e.value == "00:1a:2b:3c:4d:5e"),
        "an unterminated description must fail closed, not read past its record"
    );
}
