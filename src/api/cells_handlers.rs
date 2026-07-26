//! `GET/POST /api/v1/cells/*` — web-UI equivalent of `hse cells
//! status|import|clear`.
//!
//! Before this module, populating, refreshing, or inspecting the local
//! OpenCelliD cell-tower database (which `signal_radar`/`cell_intel` read
//! for every scan, and Live Signal Radar activates from the browser) was
//! 100% CLI-only — a browser-only Termux operator had no way to fix a
//! stale or empty cell DB. `status` is read-only, non-secret aggregate
//! geodata (tower counts, MCC breakdown, last-import metadata) and is
//! intentionally left ungated, the same call this project already made for
//! `settings_toggles_get`. `import`/`clear` mutate local state (a network
//! download + potentially large DB write, or an irreversible truncate), so
//! both require a loopback peer — the same policy `update/trigger` already
//! applies to a mutating, non-secret action.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    Json,
    extract::{ConnectInfo, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;
use serde_json::json;

use crate::api::{AppState, CellsImportPhase};
use crate::app::cells::{
    clear_cells_db, mcc_for_country, opencellid_download_url, opencellid_filename,
};
use crate::util::cell_db;

use super::handlers::bad_request;

/// Builds the `last_import` JSON block, including the same `is_stale`
/// freshness signal `hse doctor` already prints (`cell_db::is_stale`) — until
/// this was added, a browser-only Termux operator had no way to learn their
/// local OpenCelliD dataset had gone stale (`STALE_THRESHOLD_DAYS`) without
/// running the CLI's `doctor` subcommand.
fn last_import_json(rec: &cell_db::ImportRecord, now: i64) -> serde_json::Value {
    let stale = cell_db::is_stale(rec.imported_at, now);
    let age_days = now.saturating_sub(rec.imported_at).max(0) / 86_400;
    json!({
        "imported_at": rec.imported_at,
        "mcc": rec.mcc,
        "source_file": rec.source_file,
        "row_count": rec.row_count,
        "duration_ms": rec.duration_ms,
        "age_days": age_days,
        "is_stale": stale,
        "stale_threshold_days": cell_db::STALE_THRESHOLD_DAYS,
    })
}

/// `GET /api/v1/cells/status` — DB stats (total towers, MCC breakdown, last
/// import) plus whether an import triggered via `POST /cells/import` is
/// currently running or last failed. Ungated: aggregate tower counts and a
/// local cache-file path carry none of the "which paid services are
/// configured" sensitivity `settings_keys_get`/`keys_status` gate.
pub async fn cells_status(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    let (phase_str, phase_error) = match s
        .cells_import
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
    {
        CellsImportPhase::Idle => ("idle", None),
        CellsImportPhase::Running => ("running", None),
        CellsImportPhase::Error(msg) => ("error", Some(msg)),
    };

    let path = cell_db::cell_db_path().display().to_string();

    // The reads — `open_ro` plus `count_by_mcc`'s full-table GROUP BY over a
    // world-scale tower DB — are blocking SQLite work that must not run on the
    // ~2-worker async reactor (this is the SPA's status-poll target). Offload the
    // whole read set to the blocking pool in one task, mirroring the offloading
    // discipline every sibling handler already follows.
    let db = tokio::task::spawn_blocking(|| {
        let conn = cell_db::open_ro().ok()?;
        let total = cell_db::total_count(&conn).unwrap_or(0);
        let by_mcc: Vec<serde_json::Value> = cell_db::count_by_mcc(&conn)
            .unwrap_or_default()
            .into_iter()
            .take(10)
            .map(|(mcc, count)| json!({ "mcc": mcc, "count": count }))
            .collect();
        let now = crate::core::entity::unix_now() as i64;
        let last_import = cell_db::last_import(&conn)
            .ok()
            .flatten()
            .map(|rec| last_import_json(&rec, now));
        Some((total, by_mcc, last_import))
    })
    .await
    .ok()
    .flatten();

    // Absent DB (or a failed blocking join) → the same "not present" shape.
    let Some((total, by_mcc, last_import)) = db else {
        return Json(json!({
            "present": false,
            "total": 0,
            "path": path,
            "by_mcc": [],
            "last_import": null,
            "import_phase": phase_str,
            "import_error": phase_error,
        }))
        .into_response();
    };

    Json(json!({
        "present": true,
        "total": total,
        "path": path,
        "by_mcc": by_mcc,
        "last_import": last_import,
        "import_phase": phase_str,
        "import_error": phase_error,
    }))
    .into_response()
}

#[derive(Deserialize)]
pub struct CellsImportRequest {
    /// Country code ("AU"), "world", or a raw MCC integer string — same
    /// acceptance as `hse cells import --country`.
    pub country: String,
}

fn reject_non_loopback(peer: &SocketAddr) -> Option<axum::response::Response> {
    if peer.ip().is_loopback() {
        None
    } else {
        Some(
            (
                StatusCode::FORBIDDEN,
                Json(json!({ "error": "cell DB import is loopback-only" })),
            )
                .into_response(),
        )
    }
}

/// Atomically check no import is already running and, if so, claim it —
/// same check-and-claim-under-one-lock shape as `update_handlers::
/// try_start_update`, so two near-simultaneous triggers can't both start a
/// download+import racing each other against the same SQLite file.
fn try_start_import(cells_import: &std::sync::Mutex<CellsImportPhase>) -> bool {
    let mut phase = cells_import
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if *phase == CellsImportPhase::Running {
        return false;
    }
    *phase = CellsImportPhase::Running;
    true
}

/// `POST /api/v1/cells/import` — server-side download-by-country-code
/// equivalent of `hse cells import --country`. Loopback-only. Returns 202
/// immediately; a detached task drives the download+import, and the SPA
/// polls `GET /cells/status`'s `import_phase` the same way it already polls
/// `update/status`. Requires `HUNTSMAN_OPENCELLID_KEY` to already be set
/// (via the Settings page's key editor, or the environment) — there is no
/// per-request key override, unlike the CLI's `--key` flag, since the web
/// path always uses the operator's configured key.
pub async fn cells_import(
    State(s): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(req): Json<CellsImportRequest>,
) -> impl IntoResponse {
    if let Some(rejection) = reject_non_loopback(&peer) {
        return rejection;
    }
    let country = req.country.trim().to_string();
    if country.is_empty() {
        return bad_request("country must not be empty");
    }
    let Ok(api_key) = std::env::var("HUNTSMAN_OPENCELLID_KEY") else {
        return bad_request(
            "no OpenCelliD API key configured — set HUNTSMAN_OPENCELLID_KEY via Settings first",
        );
    };
    if !try_start_import(&s.cells_import) {
        return StatusCode::CONFLICT.into_response();
    }

    let cells_import_state = Arc::clone(&s.cells_import);
    tokio::spawn(async move {
        let mcc = mcc_for_country(&country);
        let filename = opencellid_filename(&country, mcc);
        let url = opencellid_download_url(&filename, &api_key);
        let result = crate::app::cells::download_and_import(&url, &filename, mcc).await;
        let mut phase = cells_import_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *phase = match result {
            Ok(()) => CellsImportPhase::Idle,
            // Defense-in-depth: this error is served verbatim by the ungated
            // `GET /cells/status` `import_error` field, so a key that reached it
            // through any path (the download URL carries `token=<key>`) is masked
            // before it can be read by a LAN peer under a non-loopback bind. The
            // primary fix strips the URL at the source (see app::cells
            // `.without_url()`); this guarantees the invariant at the sink.
            Err(e) => {
                CellsImportPhase::Error(crate::util::http::redact_credentials(&e.to_string()))
            }
        };
    });

    (StatusCode::ACCEPTED, Json(json!({ "status": "started" }))).into_response()
}

#[derive(Deserialize)]
pub struct CellsClearRequest {
    /// Must be `true` — the explicit-consent equivalent of `hse cells
    /// clear`'s interactive "type 'yes' to confirm" prompt, which has no
    /// stdin to prompt over HTTP.
    #[serde(default)]
    pub confirm: bool,
}

/// `POST /api/v1/cells/clear` — truncates the cell-tower DB. Loopback-only
/// and requires `{"confirm": true}` in the body; an irreversible delete
/// must never be one accidental click (or an unauthenticated cross-origin
/// POST) away.
pub async fn cells_clear(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(req): Json<CellsClearRequest>,
) -> impl IntoResponse {
    if let Some(rejection) = reject_non_loopback(&peer) {
        return rejection;
    }
    if !req.confirm {
        return bad_request("set confirm: true to clear the cell tower database");
    }
    match clear_cells_db() {
        Ok(()) => Json(json!({ "cleared": true })).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt as _;

    #[test]
    fn reject_non_loopback_allows_loopback_and_refuses_lan() {
        let loopback: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let lan: SocketAddr = "192.168.1.50:40000".parse().unwrap();
        assert!(reject_non_loopback(&loopback).is_none());
        assert!(reject_non_loopback(&lan).is_some());
    }

    #[test]
    fn try_start_import_claims_atomically_and_refuses_a_concurrent_second_call() {
        let m = std::sync::Mutex::new(CellsImportPhase::Idle);
        assert!(try_start_import(&m), "first caller must win the claim");
        assert!(
            !try_start_import(&m),
            "a second call while Running must be refused, not race a duplicate import"
        );
    }

    #[test]
    fn last_import_json_flags_a_recent_import_as_fresh() {
        let rec = cell_db::ImportRecord {
            imported_at: 1_000_000,
            mcc: Some(505),
            source_file: "OCID_cells_mcc505.csv.gz".to_string(),
            row_count: 42,
            duration_ms: 10,
        };
        // One day later — well under STALE_THRESHOLD_DAYS.
        let json = last_import_json(&rec, 1_000_000 + 86_400);
        assert_eq!(json["is_stale"], false);
        assert_eq!(json["age_days"], 1);
    }

    #[test]
    fn last_import_json_flags_an_old_import_as_stale() {
        let rec = cell_db::ImportRecord {
            imported_at: 0,
            mcc: None,
            source_file: "OCID_cells_full.csv.gz".to_string(),
            row_count: 1,
            duration_ms: 1,
        };
        // 200 days later — past the 180-day threshold.
        let now = i64::from(cell_db::STALE_THRESHOLD_DAYS) * 86_400 + 20 * 86_400;
        let json = last_import_json(&rec, now);
        assert_eq!(json["is_stale"], true);
        assert_eq!(json["age_days"], 200);
        assert_eq!(json["stale_threshold_days"], cell_db::STALE_THRESHOLD_DAYS);
    }

    #[test]
    fn try_start_import_allows_a_new_import_after_the_previous_one_finished() {
        let m = std::sync::Mutex::new(CellsImportPhase::Error("boom".to_string()));
        assert!(
            try_start_import(&m),
            "a prior Error phase must not permanently block future imports"
        );
    }

    fn cells_router() -> axum::Router {
        use crate::core::live::LiveScanner;
        use std::collections::HashMap;

        let store: Arc<dyn crate::core::StoragePort> =
            Arc::new(crate::storage::Store::open(":memory:").unwrap());
        let (bus, _rx) = tokio::sync::broadcast::channel(16);
        let engine = Arc::new(crate::core::engine::ScanEngine::new(
            Vec::new(),
            Arc::clone(&store),
            bus.clone(),
        ));
        let live = LiveScanner::new(
            Arc::clone(&engine),
            bus.clone(),
            reqwest::Client::new(),
            Default::default(),
        );
        let state = Arc::new(AppState {
            store,
            engine,
            bus,
            live,
            http: reqwest::Client::new(),
            allow_key_write: false,
            cancellations: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            scan_semaphore: Arc::new(tokio::sync::Semaphore::new(
                super::super::MAX_CONCURRENT_SCANS,
            )),
            update_info: Arc::new(std::sync::Mutex::new(crate::api::UpdateInfo::default())),
            cells_import: Arc::new(std::sync::Mutex::new(CellsImportPhase::default())),
        });
        axum::Router::new()
            .route("/api/v1/cells/status", axum::routing::get(cells_status))
            .route("/api/v1/cells/import", axum::routing::post(cells_import))
            .route("/api/v1/cells/clear", axum::routing::post(cells_clear))
            .with_state(state)
    }

    fn req_with_peer(method: &str, uri: &str, body: &str, peer: SocketAddr) -> Request<Body> {
        let mut r = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        r.extensions_mut().insert(axum::extract::ConnectInfo(peer));
        r
    }

    #[tokio::test]
    async fn cells_status_has_the_expected_shape_on_an_absent_or_empty_db() {
        let app = cells_router();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/cells/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let bytes = axum::body::to_bytes(resp.into_body(), 1_000_000)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(json.get("total").is_some());
        assert!(json.get("path").is_some());
        assert!(json.get("by_mcc").is_some());
        assert_eq!(json["import_phase"], "idle");
    }

    #[tokio::test]
    async fn cells_import_refuses_a_non_loopback_peer() {
        let app = cells_router();
        let lan: SocketAddr = "192.168.1.50:40000".parse().unwrap();
        let req = req_with_peer("POST", "/api/v1/cells/import", r#"{"country":"AU"}"#, lan);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), 403);
    }

    #[tokio::test]
    async fn cells_import_rejects_an_empty_country() {
        let app = cells_router();
        let loopback: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        // No HUNTSMAN_OPENCELLID_KEY needed to reach this check — empty
        // country is rejected before the key is even resolved.
        let req = req_with_peer(
            "POST",
            "/api/v1/cells/import",
            r#"{"country":"  "}"#,
            loopback,
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), 400);
    }

    #[tokio::test]
    async fn cells_clear_refuses_a_non_loopback_peer() {
        let app = cells_router();
        let lan: SocketAddr = "192.168.1.50:40000".parse().unwrap();
        let req = req_with_peer("POST", "/api/v1/cells/clear", r#"{"confirm":true}"#, lan);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), 403);
    }

    #[tokio::test]
    async fn cells_clear_requires_explicit_confirm() {
        let app = cells_router();
        let loopback: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let req = req_with_peer(
            "POST",
            "/api/v1/cells/clear",
            r#"{"confirm":false}"#,
            loopback,
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), 400);
    }

    #[tokio::test]
    async fn cells_clear_succeeds_with_confirm_true() {
        let app = cells_router();
        let loopback: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let req = req_with_peer(
            "POST",
            "/api/v1/cells/clear",
            r#"{"confirm":true}"#,
            loopback,
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), 200);
    }
}
