use super::{AreaResp, KEY_REJECTED_MSG, OpenCellId, accuracy_to_confidence};
use crate::core::{
    confidence,
    module::{Module, ModuleCost},
    scan::{Target, TargetKind},
};

#[test]
fn module_metadata() {
    assert_eq!(OpenCellId.name(), "opencellid");
    assert_eq!(OpenCellId.priority(), 70);
    assert_eq!(OpenCellId.max_timeout_ms(), 10_000);
    assert_eq!(OpenCellId.cache_ttl_secs(), 86_400);
    assert!(matches!(OpenCellId.cost(), ModuleCost::KeyGated));
}

#[test]
fn accepts_coordinates_and_device_id() {
    let m = OpenCellId;
    assert!(m.accepts(&Target::new(TargetKind::Coordinates, "-27.47,153.02")));
    assert!(m.accepts(&Target::new(TargetKind::DeviceId, "505-1-12345-67890")));
    assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
    assert!(!m.accepts(&Target::new(TargetKind::MacAddress, "aa:bb:cc:dd:ee:ff")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Domain, "example.com")));
}

#[test]
fn attack_techniques_are_geo_and_open_db_but_not_dns() {
    let t = OpenCellId.attack_techniques();
    assert!(t.contains(&"T1591.001"), "must include physical location");
    assert!(
        t.contains(&"T1596"),
        "must include open technical databases"
    );
    // It queries a cell-tower geolocation database, not DNS — so it must NOT
    // claim DNS/Passive DNS (T1596.001). There is no cell-database sub-technique,
    // so the honest mapping stops at the T1596 parent.
    assert!(
        !t.contains(&"T1596.001"),
        "OpenCelliD makes no DNS query; T1596.001 would be a mis-attribution"
    );
}

#[test]
fn parse_full_area_response() {
    let raw = r#"{
        "count": 2,
        "cells": [
            {
                "radio": "LTE",
                "mcc": 505,
                "net": 1,
                "area": 12345,
                "cell": 67890,
                "lon": 153.016600,
                "lat": -27.476600,
                "range": 500,
                "averageSignal": -75,
                "samples": 42
            },
            {
                "radio": "GSM",
                "mcc": 505,
                "net": 3,
                "area": 9900,
                "cell": 11111,
                "lon": 153.020000,
                "lat": -27.480000,
                "range": 2000
            }
        ]
    }"#;
    let resp: AreaResp = serde_json::from_str(raw).expect("should succeed");
    assert_eq!(resp.cells.len(), 2);

    let c0 = &resp.cells[0];
    assert_eq!(c0.mcc, Some(505));
    assert_eq!(c0.mnc, Some(1));
    assert_eq!(c0.lac, Some(12345));
    assert_eq!(c0.cid, Some(67890));
    assert_eq!(c0.radio.as_deref(), Some("LTE"));
    assert!((c0.lat.expect("should succeed") - (-27.476600_f64)).abs() < 1e-6);
    assert!((c0.lon.expect("should succeed") - 153.016600_f64).abs() < 1e-6);
    assert_eq!(c0.range, Some(500));
    assert_eq!(c0.average_signal, Some(-75));
    assert_eq!(c0.samples, Some(42));

    let c1 = &resp.cells[1];
    assert_eq!(c1.radio.as_deref(), Some("GSM"));
    assert_eq!(c1.mnc, Some(3));
}

#[test]
fn parse_empty_cells_array() {
    let raw = r#"{"count": 0, "cells": []}"#;
    let resp: AreaResp = serde_json::from_str(raw).expect("should succeed");
    assert_eq!(resp.cells.len(), 0);
}

#[test]
fn parse_missing_cells_key_defaults_empty() {
    let raw = r#"{}"#;
    let resp: AreaResp = serde_json::from_str(raw).expect("should succeed");
    assert_eq!(resp.cells.len(), 0);
}

#[test]
fn confidence_bands_match_cell_intel_scale() {
    // Boundaries at each tier edge.
    assert!((accuracy_to_confidence(0) - confidence::HIGH_PLUSPLUS_PLUS).abs() < 1e-9);
    assert!((accuracy_to_confidence(100) - confidence::HIGH_PLUSPLUS_PLUS).abs() < 1e-9);
    assert!((accuracy_to_confidence(101) - confidence::VERY_HIGH).abs() < 1e-9);
    assert!((accuracy_to_confidence(500) - confidence::VERY_HIGH).abs() < 1e-9);
    assert!((accuracy_to_confidence(501) - confidence::HIGH).abs() < 1e-9);
    assert!((accuracy_to_confidence(2000) - confidence::HIGH).abs() < 1e-9);
    assert!((accuracy_to_confidence(2001) - confidence::MEDIUM).abs() < 1e-9);
    assert!((accuracy_to_confidence(10000) - confidence::MEDIUM).abs() < 1e-9);
    assert!((accuracy_to_confidence(10001) - 0.35).abs() < 1e-9);
}

#[test]
fn cell_entry_optional_fields_default_to_none() {
    let raw = r#"{"mcc": 505, "net": 1, "area": 100, "cell": 200}"#;
    let c: super::CellEntry = serde_json::from_str(raw).expect("should succeed");
    assert_eq!(c.radio, None);
    assert_eq!(c.lat, None);
    assert_eq!(c.lon, None);
    assert_eq!(c.range, None);
    assert_eq!(c.average_signal, None);
    assert_eq!(c.samples, None);
    assert_eq!(c.error, None);
}

#[test]
fn cell_entry_captures_the_real_live_confirmed_bad_key_error_shape() {
    // Live-confirmed 2026-07-15: a garbage key against the real `cell/get`
    // endpoint returns HTTP 200 with exactly this body — no HTTP-level
    // 401/403/429 at all, so `error` is the only signal a bad key ever
    // leaves. Every geo/tower field is absent, same as a genuine "not
    // found" — `process_tower`'s `error.is_some()` check is what tells the
    // two apart and reports the key to the pool.
    let raw = r#"{"error":"API Key not known: garbage00000invalid","code":2}"#;
    let c: super::CellEntry = serde_json::from_str(raw).expect("should succeed");
    assert_eq!(
        c.error.as_deref(),
        Some("API Key not known: garbage00000invalid")
    );
    assert_eq!(c.mcc, None, "the error shape carries no tower fields");
}

#[test]
fn area_resp_captures_the_real_live_confirmed_bad_key_error_shape() {
    // Same live-confirmed shape as `cell/get`, for `cell/getInArea` — no
    // "cells" key at all on an error response.
    let raw = r#"{"error":"API Key not known: garbage00000invalid","code":2}"#;
    let resp: AreaResp = serde_json::from_str(raw).expect("should succeed");
    assert_eq!(
        resp.error.as_deref(),
        Some("API Key not known: garbage00000invalid")
    );
    assert_eq!(resp.cells.len(), 0);
}

// The live-confirmed bad-key shape: OpenCelliD answers a plain HTTP 200 whose
// entire body is an error object, with no `cells` key at all. `CellEntry::error`
// documents this and exists to DETECT it — but the detection only matters
// because the module now returns a typed error on it instead of an empty
// success. Before that, a rejected key was still indistinguishable from "no
// towers here" as far as the scan was concerned, which is precisely what the
// doc says the field was added to prevent.
#[test]
fn a_two_hundred_with_an_error_body_is_parsed_as_a_key_failure() {
    let body = r#"{"error":"API Key not known: abc123","code":2}"#;
    let parsed: AreaResp = serde_json::from_str(body).expect("the bad-key shape must deserialize");
    assert_eq!(
        parsed.error.as_deref(),
        Some("API Key not known: abc123"),
        "the error field is what distinguishes a rejected key from an empty area"
    );
    assert!(
        parsed.cells.is_empty(),
        "the bad-key body carries no cells key at all"
    );
}

// The converse, so the check above cannot start firing on healthy responses: a
// genuine empty area is a 200 with `cells: []` and NO error field. Reporting a
// key failure here would turn every genuinely-empty bounding box into a module
// error and burn a working key.
#[test]
fn a_genuinely_empty_area_is_not_mistaken_for_a_key_failure() {
    let parsed: AreaResp = serde_json::from_str(r#"{"cells":[]}"#).expect("should deserialize");
    assert!(
        parsed.error.is_none(),
        "no error field on a healthy response"
    );
    assert!(parsed.cells.is_empty());
}

// ── The key must never reach an error surface ───────────────────────────────
//
// OpenCelliD echoes the rejected key back inside its own error message. An
// earlier revision of this module interpolated that message into the returned
// error, which would have written the key into the verbose log, the SSE stream
// and the dossier — a credential leak introduced by the very change that made
// these paths return an error instead of an empty success.
//
// The guard is structural: `KEY_REJECTED_MSG` is a `const`, so no
// provider-controlled bytes can pass through it. This test pins the hazard it
// exists to prevent, so the constant cannot quietly become a `format!` again.
#[test]
fn the_key_rejection_error_never_echoes_the_providers_message() {
    // The documented bad-key shape, with a recognisable stand-in for the key.
    let body = r#"{"error":"API Key not known: SUPERSECRETKEY123","code":2}"#;
    let parsed: AreaResp = serde_json::from_str(body).expect("bad-key shape must deserialize");
    let provider_msg = parsed
        .error
        .as_deref()
        .expect("error field must be present");

    // First establish that the hazard is real: the provider genuinely hands
    // back the key. If OpenCelliD ever stops doing this, the assertion below
    // still holds and this one documents why the constant exists.
    assert!(
        provider_msg.contains("SUPERSECRETKEY123"),
        "the provider echoes the key back — that is the hazard: {provider_msg}"
    );

    // What the module actually surfaces carries none of it.
    assert!(
        !KEY_REJECTED_MSG.contains("SUPERSECRETKEY123"),
        "the returned error must not carry the key"
    );
    assert!(
        !KEY_REJECTED_MSG.contains(provider_msg),
        "the returned error must not echo the provider's message verbatim"
    );
    assert!(
        KEY_REJECTED_MSG.contains("rejected the API key"),
        "it must still say what went wrong, so the operator can act on it"
    );
}
