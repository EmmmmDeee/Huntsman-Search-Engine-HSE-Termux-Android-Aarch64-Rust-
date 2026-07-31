use super::CellIntel;
use super::helpers::{
    accuracy_to_confidence, build_tower_device, json_to_str, mcc_to_centroid, parse_cells_survey,
};
use crate::core::module::Module;
use crate::core::scan::{Target, TargetKind};
use crate::core::{confidence, entity::EntityKind};

// ---- Module trait tests ----

#[test]
fn is_passive() {
    assert!(CellIntel.is_passive());
}

#[test]
fn accepts_only_local_physical_seeds() {
    assert!(CellIntel.accepts(&Target::new(TargetKind::Coordinates, "-27.47,153.02")));
    assert!(CellIntel.accepts(&Target::new(TargetKind::MacAddress, "aa:bb:cc:dd:ee:ff")));
    assert!(!CellIntel.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    assert!(!CellIntel.accepts(&Target::new(TargetKind::FullName, "Jane Doe")));
    assert!(!CellIntel.accepts(&Target::new(TargetKind::Domain, "x.com")));
}

#[test]
fn module_name_and_priority() {
    assert_eq!(CellIntel.name(), "cell_intel");
    assert_eq!(CellIntel.priority(), 64);
}

#[test]
fn module_description() {
    assert_eq!(
        CellIntel.description(),
        "Cell-tower survey & geolocation — sweeps nearby towers via Termux and geolocates them against OpenCelliD"
    );
}

#[test]
fn module_max_timeout() {
    assert_eq!(CellIntel.max_timeout_ms(), 15_000);
}

// ---- Survey (DeviceId) tests (from cell_survey) ----

#[test]
fn parses_mcc_as_string_or_number() {
    let json = br#"[
        {"type":"lte","registered":true,"cid":12345,"tac":54321,
         "mcc":"505","mnc":"01","dbm":-75,"asu":30,"level":4,"pci":100},
        {"type":"gsm","registered":true,"cid":99,"lac":42,
         "mcc":505,"mnc":1,"dbm":-90,"asu":10,"level":2}
    ]"#;
    let r = parse_cells_survey(json, "test").unwrap();
    assert_eq!(r.entities.len(), 2);
    assert_eq!(r.entities[0].value, "505-01-54321-12345");
    assert_eq!(r.entities[1].value, "505-1-42-99");
}

#[test]
fn skips_cells_without_mcc_or_cid() {
    let json = br#"[{"type":"lte","registered":true}]"#;
    let r = parse_cells_survey(json, "test").unwrap();
    assert_eq!(r.entities.len(), 0);
}

/// A malfunctioning tool must never be reported as "no towers in range".
/// Non-blank output that will not parse is a real `ModuleError`; this is the
/// guard for that contract, and it lives on the same `helpers::parse_cells`
/// the live `process()` path uses — so reverting the fix in `process()` is not
/// possible without failing here.
#[test]
fn malformed_output_surfaces_an_error_not_an_empty_survey() {
    let err = parse_cells_survey(b"{", "test").expect_err("unparseable output must be an error");
    let msg = err.to_string();
    assert!(
        msg.contains("telephony-cellinfo"),
        "error must name the tool whose output failed to parse, got: {msg}"
    );
}

/// Blank output is the honest empty answer, not a malfunction: `termux_cmd`
/// returns `Some(stdout)` for any zero-exit run, so a Termux:API stub that
/// exits 0 printing nothing must not hard-fail on the primary target platform.
#[test]
fn blank_output_is_an_empty_survey_not_an_error() {
    for blank in [b"".as_slice(), b"   ".as_slice(), b"\n\t\n".as_slice()] {
        let r = parse_cells_survey(blank, "test")
            .unwrap_or_else(|e| panic!("blank output must not error, got: {e}"));
        assert_eq!(r.entities.len(), 0);
    }
}

#[test]
fn entity_tags_include_cell_tower_and_radio_type() {
    let json = br#"[
        {"type":"lte","registered":true,"cid":5678,"tac":1234,
         "mcc":"310","mnc":"260","dbm":-85,"asu":25,"level":3,"pci":42}
    ]"#;
    let r = parse_cells_survey(json, "scan-x").unwrap();
    assert_eq!(r.entities.len(), 1);
    let e = &r.entities[0];
    assert_eq!(e.kind, EntityKind::DeviceId);
    assert_eq!(e.value, "310-260-1234-5678");
    assert!((e.confidence - confidence::HIGH_PLUSPLUS).abs() < 1e-6);
    assert!(e.has_tag(crate::core::tags::CELL_TOWER));
    assert!(e.has_tag("radio:lte"));
    assert_eq!(e.scan_id, "scan-x");
}

#[test]
fn evidence_attributes_populated() {
    let json = br#"[
        {"type":"gsm","registered":false,"cid":100,"lac":200,
         "mcc":"505","mnc":"01","dbm":-95,"asu":8,"level":1,"pci":0}
    ]"#;
    let r = parse_cells_survey(json, "test").unwrap();
    let ev = &r.entities[0].evidence[0];
    assert_eq!(ev.source, "cell_intel");
    assert_eq!(ev.attributes.get("type").expect("should succeed"), "gsm");
    assert_eq!(ev.attributes.get("mcc").expect("should succeed"), "505");
    assert_eq!(ev.attributes.get("mnc").expect("should succeed"), "01");
    assert_eq!(ev.attributes.get("lac_tac").expect("should succeed"), "200");
    assert_eq!(ev.attributes.get("cid").expect("should succeed"), "100");
    assert_eq!(ev.attributes.get("dbm").expect("should succeed"), "-95");
    assert_eq!(ev.attributes.get("asu").expect("should succeed"), "8");
    assert_eq!(ev.attributes.get("level").expect("should succeed"), "1");
    assert_eq!(
        ev.attributes.get("registered").expect("should succeed"),
        "false"
    );
}

#[test]
fn lac_falls_back_to_tac_for_lte() {
    let json = br#"[{"type":"lte","cid":999,"tac":555,"mcc":"310","mnc":"410"}]"#;
    let r = parse_cells_survey(json, "test").unwrap();
    assert_eq!(r.entities[0].value, "310-410-555-999");
}

#[test]
fn lac_preferred_over_tac_when_both_present() {
    let json = br#"[{"type":"gsm","cid":1,"lac":10,"tac":20,"mcc":"505","mnc":"01"}]"#;
    let r = parse_cells_survey(json, "test").unwrap();
    assert_eq!(r.entities[0].value, "505-01-10-1");
}

#[test]
fn skips_cell_with_zero_cid() {
    let json = br#"[{"type":"lte","cid":0,"tac":123,"mcc":"310","mnc":"260"}]"#;
    let r = parse_cells_survey(json, "test").unwrap();
    assert_eq!(r.entities.len(), 0);
}

#[test]
fn empty_json_array() {
    let r = parse_cells_survey(b"[]", "test").unwrap();
    assert_eq!(r.entities.len(), 0);
}

#[test]
fn missing_type_defaults_to_unknown() {
    let json = br#"[{"cid":42,"lac":7,"mcc":"001","mnc":"01"}]"#;
    let r = parse_cells_survey(json, "test").unwrap();
    assert_eq!(r.entities.len(), 1);
    assert!(r.entities[0].has_tag("radio:unknown"));
    assert!(r.entities[0].evidence[0].summary.contains("unknown"));
}

// ---- json_to_str tests (from both modules) ----

#[test]
fn json_to_str_handles_all_variants() {
    use std::borrow::Cow;

    // String value
    let s = Some(serde_json::Value::String("505".into()));
    assert_eq!(json_to_str(&s), Cow::Borrowed("505"));

    // Number value
    let n = Some(serde_json::json!(310));
    assert_eq!(json_to_str(&n).as_ref(), "310");

    // Null value
    let null = Some(serde_json::Value::Null);
    assert_eq!(json_to_str(&null), Cow::Borrowed(""));

    // None
    assert_eq!(json_to_str(&None), Cow::Borrowed(""));
}

// ---- Geolocation helper tests (from cell_locate) ----

#[test]
fn accuracy_to_confidence_tiers() {
    assert!((accuracy_to_confidence(50) - confidence::HIGH_PLUSPLUS_PLUS).abs() < 1e-6);
    assert!((accuracy_to_confidence(300) - confidence::VERY_HIGH).abs() < 1e-6);
    assert!((accuracy_to_confidence(1000) - confidence::HIGH).abs() < 1e-6);
    assert!((accuracy_to_confidence(5000) - confidence::MEDIUM).abs() < 1e-6);
    assert!((accuracy_to_confidence(50000) - 0.35).abs() < 1e-6);
}

#[test]
fn mcc_us_maps_to_us_centroid() {
    let (lat, lon, cc) = mcc_to_centroid("310").expect("should succeed");
    assert!((lat - 39.8283).abs() < 0.01);
    assert!((lon - (-98.5795)).abs() < 0.01);
    assert_eq!(cc, "US");
}

#[test]
fn mcc_au_maps_to_au_centroid() {
    let (lat, lon, cc) = mcc_to_centroid("505").expect("should succeed");
    assert!((lat - (-25.2744)).abs() < 0.01);
    assert_eq!(cc, "AU");
    assert!(lon > 100.0);
}

#[test]
fn unknown_mcc_returns_none() {
    assert!(mcc_to_centroid("999").is_none());
}

// ---- TowerKey / build_tower_device tests ----

use super::types::{Cell, TowerKey};

fn cell_from_json(json: &str) -> Cell {
    serde_json::from_str(json).expect("should succeed")
}

#[test]
fn from_cell_returns_none_without_mcc() {
    let cell = cell_from_json(r#"{"type":"lte","cid":12345,"mnc":"01","lac":42}"#);
    assert!(TowerKey::from_cell(&cell).is_none(), "no MCC -> skip");
}

#[test]
fn from_cell_returns_none_for_zero_or_missing_cid() {
    let zero = cell_from_json(r#"{"type":"lte","mcc":"505","mnc":"01","cid":0,"lac":42}"#);
    assert!(TowerKey::from_cell(&zero).is_none(), "cid==0 -> skip");
    let missing = cell_from_json(r#"{"type":"lte","mcc":"505","mnc":"01","lac":42}"#);
    assert!(TowerKey::from_cell(&missing).is_none(), "no cid -> skip");
}

#[test]
fn from_cell_lac_falls_back_to_tac() {
    let cell = cell_from_json(r#"{"type":"lte","mcc":"505","mnc":"01","cid":12345,"tac":54321}"#);
    let key = TowerKey::from_cell(&cell).expect("should succeed");
    assert_eq!(key.lac, 54321);
    assert_eq!(key.tower_id, "505-01-54321-12345");
}

#[test]
fn from_cell_prefers_lac_over_tac_and_defaults_missing_type() {
    let cell = cell_from_json(r#"{"mcc":"505","mnc":"01","cid":99,"lac":42,"tac":54321}"#);
    let key = TowerKey::from_cell(&cell).expect("should succeed");
    assert_eq!(key.lac, 42, "lac wins over tac");
    assert_eq!(key.ctype, "unknown", "missing type defaults to unknown");
}

#[test]
fn is_geolocatable_requires_mnc_and_nonzero_lac() {
    let ok = cell_from_json(r#"{"type":"lte","mcc":"505","mnc":"01","cid":1,"lac":42}"#);
    assert!(
        TowerKey::from_cell(&ok)
            .expect("should succeed")
            .is_geolocatable()
    );
    let no_mnc = cell_from_json(r#"{"type":"lte","mcc":"505","cid":1,"lac":42}"#);
    assert!(
        !TowerKey::from_cell(&no_mnc)
            .expect("should succeed")
            .is_geolocatable()
    );
    let no_lac = cell_from_json(r#"{"type":"lte","mcc":"505","mnc":"01","cid":1}"#);
    assert!(
        !TowerKey::from_cell(&no_lac)
            .expect("should succeed")
            .is_geolocatable()
    );
}

#[test]
fn radio_code_maps_air_interfaces_with_gsm_default() {
    let cases = [
        ("lte", "LTE"),
        ("gsm", "GSM"),
        ("umts", "UMTS"),
        ("wcdma", "UMTS"),
        ("nr", "NR"),
        ("5g", "NR"),
        ("cdma", "CDMA"),
        ("LTE", "LTE"),
        ("wifi", "GSM"),
    ];
    for (ctype, expected) in cases {
        let json = format!(r#"{{"type":"{ctype}","mcc":"505","mnc":"01","cid":1,"lac":42}}"#);
        let cell = cell_from_json(&json);
        let key = TowerKey::from_cell(&cell).expect("should succeed");
        assert_eq!(key.radio_code(), expected, "radio_code for {ctype}");
    }
}

#[test]
fn build_tower_device_carries_radio_tags_and_evidence_attrs() {
    let cell = cell_from_json(
        r#"{"type":"lte","registered":true,"cid":12345,"tac":54321,
            "mcc":"505","mnc":"01","dbm":-75,"asu":30,"level":4,"pci":100}"#,
    );
    let key = TowerKey::from_cell(&cell).expect("should succeed");
    let e = build_tower_device(&cell, &key, "scan-1");
    assert_eq!(e.kind, EntityKind::DeviceId);
    assert_eq!(e.value, "505-01-54321-12345");
    assert!(e.has_tag(crate::core::tags::CELL_TOWER));
    assert!(e.has_tag("radio:lte"));
    let attrs = &e.evidence[0].attributes;
    assert_eq!(attrs.get("type").map(String::as_str), Some("lte"));
    assert_eq!(attrs.get("mcc").map(String::as_str), Some("505"));
    assert_eq!(attrs.get("mnc").map(String::as_str), Some("01"));
    assert_eq!(attrs.get("lac_tac").map(String::as_str), Some("54321"));
    assert_eq!(attrs.get("cid").map(String::as_str), Some("12345"));
    assert_eq!(attrs.get("pci").map(String::as_str), Some("100"));
    assert_eq!(attrs.get("dbm").map(String::as_str), Some("-75"));
    assert_eq!(attrs.get("registered").map(String::as_str), Some("true"));
}

#[test]
fn build_tower_device_defaults_absent_signal_fields_to_zero() {
    let cell = cell_from_json(r#"{"type":"gsm","mcc":"505","mnc":"1","cid":99,"lac":42}"#);
    let key = TowerKey::from_cell(&cell).expect("should succeed");
    let e = build_tower_device(&cell, &key, "s");
    let attrs = &e.evidence[0].attributes;
    assert_eq!(attrs.get("pci").map(String::as_str), Some("0"));
    assert_eq!(attrs.get("dbm").map(String::as_str), Some("0"));
    assert_eq!(attrs.get("asu").map(String::as_str), Some("0"));
    assert_eq!(attrs.get("level").map(String::as_str), Some("0"));
    assert_eq!(attrs.get("registered").map(String::as_str), Some("false"));
}

// ---- OpenCellidResp bad-key error shape ----

use super::types::OpenCellidResp;

#[test]
fn opencellid_resp_captures_the_real_live_confirmed_bad_key_error_shape() {
    // Live-confirmed 2026-07-15: a garbage key against the real
    // `cell/get` endpoint (the same one `query_opencellid` calls) returns
    // HTTP 200 with exactly this body — no HTTP-level 401/403/429 at all.
    // `query_opencellid`'s `data.error.is_some()` check is what tells this
    // apart from a genuine "couldn't geolocate this tower" negative.
    let raw = r#"{"error":"API Key not known: garbage00000invalid","code":2}"#;
    let resp: OpenCellidResp = serde_json::from_str(raw).expect("should succeed");
    assert_eq!(
        resp.error.as_deref(),
        Some("API Key not known: garbage00000invalid")
    );
    assert_eq!(resp.lat, None, "the error shape carries no geo fields");
    assert_eq!(
        resp.status, None,
        "distinct from the status:\"error\" shape"
    );
}

#[test]
fn opencellid_resp_status_error_is_distinct_from_the_body_error_field() {
    // The pre-existing "no fix available" negative (a real key, genuinely no
    // data) uses `status`, never `error` — the two fields must not be
    // conflated, or a real key would wrongly report itself exhausted on
    // every ordinary miss.
    let raw = r#"{"status":"error"}"#;
    let resp: OpenCellidResp = serde_json::from_str(raw).expect("should succeed");
    assert_eq!(resp.status.as_deref(), Some("error"));
    assert_eq!(resp.error, None);
}
