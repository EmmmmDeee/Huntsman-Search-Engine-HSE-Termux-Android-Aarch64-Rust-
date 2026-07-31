use super::{AreaResp, OpenCellId, accuracy_to_confidence};
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

// ── `fetch_cell` failure contract ─────────────────────────────────────────────
//
// These pin the four cases `fetch_cell` changed from "empty success" to `Err`.
// Each was a way for a dead network, a broken response, or a rejected key to be
// reported as zero towers — which on this module is indistinguishable from the
// genuine and entirely expected "no towers here" answer (the T2.115 class).
//
// `fetch_cell` takes its URL as a parameter, so unlike the hardcoded-host
// modules this contract can be pinned directly and hermetically, on loopback.

use super::{CellEntry, fetch_cell};
use crate::core::module::ModuleContext;

fn test_ctx() -> ModuleContext {
    let (bus, _rx) = tokio::sync::broadcast::channel(8);
    ModuleContext {
        scan_id: "test".into(),
        bus,
        http: reqwest::Client::new(),
        keys: Default::default(),
        cancel: Default::default(),
    }
}

/// Serve one request with the given status and body, then close.
async fn serve_once(status: u16, reason: &'static str, body: &'static str) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("should succeed");
    let addr = listener.local_addr().expect("should succeed");
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.expect("should succeed");
        let mut buf = vec![0u8; 2048];
        let _ = sock.read(&mut buf).await;
        let head = format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let _ = sock.write_all(head.as_bytes()).await;
        let _ = sock.write_all(body.as_bytes()).await;
        let _ = sock.flush().await;
    });
    format!("http://{addr}/")
}

/// The 5xx/non-2xx tests above record a breaker failure for the shared
/// "127.0.0.1" host; reset it so they can't nudge an unrelated later test
/// toward FAILURE_THRESHOLD.
fn reset_breaker() {
    crate::util::circuit_breaker::record_success("127.0.0.1");
}

#[tokio::test]
async fn fetch_cell_returns_the_decoded_body_on_a_healthy_response() {
    reset_breaker();
    let url = serve_once(200, "OK", r#"{"cells":[{"mcc":505,"net":1}]}"#).await;
    let got: Option<AreaResp> = fetch_cell(&test_ctx(), "k", &url)
        .await
        .expect("a healthy response must decode");
    assert_eq!(got.expect("present").cells.len(), 1);
    reset_breaker();
}

#[tokio::test]
async fn fetch_cell_surfaces_a_body_level_bad_key_as_err_not_zero_towers() {
    reset_breaker();
    // The live-confirmed bad-key shape: HTTP 200, key failure only in the body.
    // Previously `note_keyed_error` + empty success — the pool learned the key
    // was dead while the scan recorded a clean "no towers here".
    let url = serve_once(
        200,
        "OK",
        r#"{"error":"API Key not known: garbage00000invalid","code":2}"#,
    )
    .await;
    let got: crate::core::error::Result<Option<AreaResp>> =
        fetch_cell(&test_ctx(), "garbage00000invalid", &url).await;
    assert!(
        got.is_err(),
        "a rejected key must not be reported as zero towers, got {:?}",
        got.map(|o| o.map(|r| r.cells.len()))
    );
    reset_breaker();
}

#[tokio::test]
async fn fetch_cell_surfaces_an_unparseable_body_as_err_not_zero_towers() {
    reset_breaker();
    let url = serve_once(200, "OK", "<html>not json at all</html>").await;
    let got: crate::core::error::Result<Option<CellEntry>> =
        fetch_cell(&test_ctx(), "k", &url).await;
    assert!(
        got.is_err(),
        "a malfunctioning endpoint must not be reported as zero towers"
    );
    reset_breaker();
}

#[tokio::test]
async fn fetch_cell_surfaces_a_5xx_as_err_not_zero_towers() {
    reset_breaker();
    let url = serve_once(500, "Internal Server Error", "{}").await;
    let got: crate::core::error::Result<Option<CellEntry>> =
        fetch_cell(&test_ctx(), "k", &url).await;
    assert!(
        got.is_err(),
        "an upstream outage must not be reported as zero towers"
    );
    reset_breaker();
}

#[tokio::test]
async fn fetch_cell_surfaces_a_transport_failure_as_err_not_zero_towers() {
    reset_breaker();
    // Bind and drop, so the port is closed and the connection is refused.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("should succeed");
    let addr = listener.local_addr().expect("should succeed");
    drop(listener);
    let got: crate::core::error::Result<Option<CellEntry>> =
        fetch_cell(&test_ctx(), "k", &format!("http://{addr}/")).await;
    assert!(
        got.is_err(),
        "an unreachable network must not be reported as zero towers"
    );
    reset_breaker();
}

#[tokio::test]
async fn fetch_cell_maps_404_to_a_clean_miss_not_an_error() {
    reset_breaker();
    // The one non-2xx that is a real answer rather than a malfunction: the cell
    // is genuinely not in the database.
    let url = serve_once(404, "Not Found", "{}").await;
    let got: Option<CellEntry> = fetch_cell(&test_ctx(), "k", &url)
        .await
        .expect("404 is a clean miss, not an error");
    assert!(got.is_none());
    reset_breaker();
}
