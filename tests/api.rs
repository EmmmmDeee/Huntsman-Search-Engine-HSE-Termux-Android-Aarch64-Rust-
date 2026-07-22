//! API handler integration tests — exercises every HTTP endpoint
//! through axum's test utilities with a real SQLite store.

mod common;

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use http::Request;
use serde_json::Value;
use tower::ServiceExt;

use huntsman_search_engine::{
    api::{AppState, routes::router},
    core::{
        engine::ScanEngine,
        entity::{Entity, EntityKind},
        error::Result,
        live::LiveScanner,
        module::{Module, ModuleContext, ModuleResult},
        relation::{Relation, RelationKind},
        scan::{Scan, Target, TargetKind},
    },
    storage::Store,
};

// ── Synthetic module (mirrors tests/smoke.rs) ─────────────────────────────

/// Echoes the seed back as an entity of the same kind.
struct SyntheticModule;

#[async_trait]
impl Module for SyntheticModule {
    fn name(&self) -> &'static str {
        "synthetic"
    }
    fn priority(&self) -> u8 {
        100
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Email)
    }
    fn description(&self) -> &'static str {
        "test-only echo module"
    }
    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut r = ModuleResult::new();
        let mut e = Entity::new(EntityKind::Email, &target.value, 0.95, &ctx.scan_id);
        e.tag("synthetic");
        r.push(e);
        Ok(r)
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────

/// Return a fresh temp-db path, removing any leftover files from prior runs.
fn tmp_db(suffix: &str) -> String {
    common::tmp_db("api", suffix)
}

/// Build a complete axum `Router` backed by a fresh SQLite store.
/// Each test gets its own database via the `suffix` parameter.
fn test_app(suffix: &str) -> axum::Router {
    let path = tmp_db(suffix);
    let store = Arc::new(Store::open(&path).unwrap());
    let (bus, _rx) = tokio::sync::broadcast::channel(256);
    let modules: Vec<Arc<dyn Module>> = vec![Arc::new(SyntheticModule)];
    let engine = Arc::new(ScanEngine::new(
        modules,
        Arc::clone(&store) as Arc<dyn huntsman_search_engine::core::StoragePort>,
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
            huntsman_search_engine::api::MAX_CONCURRENT_SCANS,
        )),
        update_info: Arc::new(std::sync::Mutex::new(
            huntsman_search_engine::api::UpdateInfo::default(),
        )),
        cells_import: Arc::new(std::sync::Mutex::new(
            huntsman_search_engine::api::CellsImportPhase::default(),
        )),
    });
    router(state, "127.0.0.1:8080")
}

/// Like [`test_app`] but also hands back the shared store so a test can seed
/// entities directly (synchronous, FTS-indexed in the same transaction as the
/// write) without depending on an async scan completing.
fn test_app_with_store(suffix: &str) -> (axum::Router, Arc<Store>) {
    let path = tmp_db(suffix);
    let store = Arc::new(Store::open(&path).unwrap());
    let (bus, _rx) = tokio::sync::broadcast::channel(256);
    let modules: Vec<Arc<dyn Module>> = vec![Arc::new(SyntheticModule)];
    let engine = Arc::new(ScanEngine::new(
        modules,
        Arc::clone(&store) as Arc<dyn huntsman_search_engine::core::StoragePort>,
        bus.clone(),
    ));
    let live = LiveScanner::new(
        Arc::clone(&engine),
        bus.clone(),
        reqwest::Client::new(),
        Default::default(),
    );
    let state = Arc::new(AppState {
        store: Arc::clone(&store) as Arc<dyn huntsman_search_engine::core::StoragePort>,
        engine,
        bus,
        live,
        http: reqwest::Client::new(),
        allow_key_write: false,
        cancellations: Arc::new(parking_lot::Mutex::new(HashMap::new())),
        scan_semaphore: Arc::new(tokio::sync::Semaphore::new(
            huntsman_search_engine::api::MAX_CONCURRENT_SCANS,
        )),
        update_info: Arc::new(std::sync::Mutex::new(
            huntsman_search_engine::api::UpdateInfo::default(),
        )),
        cells_import: Arc::new(std::sync::Mutex::new(
            huntsman_search_engine::api::CellsImportPhase::default(),
        )),
    });
    (router(state, "127.0.0.1:8080"), store)
}

/// Like [`test_app`] but also hands back the shared `Arc<AppState>` so a test
/// can manipulate state the HTTP surface doesn't expose directly (e.g.
/// seeding `cancellations` to simulate an in-flight scan deterministically,
/// without racing a real spawned scan's completion).
fn test_app_with_state(suffix: &str) -> (axum::Router, Arc<AppState>) {
    let path = tmp_db(suffix);
    let store = Arc::new(Store::open(&path).unwrap());
    let (bus, _rx) = tokio::sync::broadcast::channel(256);
    let modules: Vec<Arc<dyn Module>> = vec![Arc::new(SyntheticModule)];
    let engine = Arc::new(ScanEngine::new(
        modules,
        Arc::clone(&store) as Arc<dyn huntsman_search_engine::core::StoragePort>,
        bus.clone(),
    ));
    let live = LiveScanner::new(
        Arc::clone(&engine),
        bus.clone(),
        reqwest::Client::new(),
        Default::default(),
    );
    let state = Arc::new(AppState {
        store: Arc::clone(&store) as Arc<dyn huntsman_search_engine::core::StoragePort>,
        engine,
        bus,
        live,
        http: reqwest::Client::new(),
        allow_key_write: false,
        cancellations: Arc::new(parking_lot::Mutex::new(HashMap::new())),
        scan_semaphore: Arc::new(tokio::sync::Semaphore::new(
            huntsman_search_engine::api::MAX_CONCURRENT_SCANS,
        )),
        update_info: Arc::new(std::sync::Mutex::new(
            huntsman_search_engine::api::UpdateInfo::default(),
        )),
        cells_import: Arc::new(std::sync::Mutex::new(
            huntsman_search_engine::api::CellsImportPhase::default(),
        )),
    });
    (router(Arc::clone(&state), "127.0.0.1:8080"), state)
}

/// Parse a response body into a `serde_json::Value`.
async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 1_000_000)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// Shorthand: build a GET request.
fn get(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}

/// Shorthand: build a POST request with a JSON body. Carries the `X-HSE-CSRF`
/// header the API's CSRF guard requires on every mutating request (the SPA
/// injects it transparently; tests/clients send it explicitly).
fn post_json(uri: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-hse-csrf", "1")
        .body(Body::from(body.to_string()))
        .unwrap()
}

/// Shorthand: build a DELETE request (with the required CSRF header).
fn delete(uri: &str) -> Request<Body> {
    Request::builder()
        .method("DELETE")
        .uri(uri)
        .header("x-hse-csrf", "1")
        .body(Body::empty())
        .unwrap()
}

/// Poll `GET /scans/{id}` until the spawned scan's background task has left
/// `Running`/`Pending` (bounded — panics after 5s so a real regression fails
/// fast rather than hanging). `spawn_scan`'s task is merely queued, not run,
/// by the time the `202 Accepted` response returns, so any test that needs
/// the scan to have actually finished (e.g. before deleting it, now that
/// `scan_delete` refuses an in-flight scan) must wait for this rather than
/// assuming completion.
async fn wait_for_scan_to_finish(app: &axum::Router, scan_id: &str) {
    for _ in 0..500 {
        let resp = app
            .clone()
            .oneshot(get(&format!("/api/v1/scans/{scan_id}")))
            .await
            .unwrap();
        let json = body_json(resp).await;
        match json["status"].as_str() {
            Some("running" | "pending") => {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            _ => return,
        }
    }
    panic!("scan {scan_id} did not finish within 5s");
}

/// Create a scan via POST and return `(app_clone, scan_id)`.
/// The returned `app_clone` shares the same `Arc<AppState>` so subsequent
/// requests see the scan that was just created.
async fn create_scan(suffix: &str) -> (axum::Router, String) {
    let app = test_app(suffix);
    let body = r#"{"kind":"email","value":"test@contoso.com","options":{}}"#;
    let resp = app
        .clone()
        .oneshot(post_json("/api/v1/scans", body))
        .await
        .unwrap();
    assert_eq!(resp.status(), 202);
    let json = body_json(resp).await;
    let scan_id = json["scan_id"].as_str().unwrap().to_string();
    (app, scan_id)
}

// ── 1. Health ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn health_returns_ok() {
    let app = test_app("health");
    let resp = app.oneshot(get("/api/v1/health")).await.unwrap();
    assert_eq!(resp.status(), 200);
    let json = body_json(resp).await;
    assert_eq!(json["status"], "ok");
    assert!(json.get("version").is_some(), "body must include 'version'");
}

#[tokio::test]
async fn responses_carry_security_headers() {
    // Defence-in-depth headers must ride on both API JSON and the SPA document.
    let app = test_app("sec-headers");
    for uri in ["/api/v1/health", "/"] {
        let resp = app.clone().oneshot(get(uri)).await.unwrap();
        let h = resp.headers();
        let hv = |name: &str| h.get(name).and_then(|v| v.to_str().ok()).unwrap_or("");
        let csp = hv("content-security-policy");
        assert!(
            csp.contains("default-src 'self'"),
            "{uri}: CSP default-src missing: {csp:?}"
        );
        assert!(
            csp.contains("connect-src 'self'"),
            "{uri}: CSP connect-src 'self' missing (data-exfil guard): {csp:?}"
        );
        assert!(
            csp.contains("frame-ancestors 'none'"),
            "{uri}: CSP frame-ancestors missing: {csp:?}"
        );
        assert_eq!(hv("x-content-type-options"), "nosniff", "{uri}: nosniff");
        assert_eq!(hv("x-frame-options"), "DENY", "{uri}: X-Frame-Options");
        assert_eq!(
            hv("referrer-policy"),
            "no-referrer",
            "{uri}: Referrer-Policy"
        );
        // Phone defence-in-depth: the browser must deny the device's camera,
        // mic, and GPS to the console (which uses none of them).
        let pp = hv("permissions-policy");
        for feature in ["camera=()", "microphone=()", "geolocation=()"] {
            assert!(
                pp.contains(feature),
                "{uri}: Permissions-Policy must deny {feature}: {pp:?}"
            );
        }
    }
}

// ── 2. Version ────────────────────────────────────────────────────────────

#[tokio::test]
async fn version_returns_version() {
    let app = test_app("version");
    let resp = app.oneshot(get("/api/v1/version")).await.unwrap();
    assert_eq!(resp.status(), 200);
    let json = body_json(resp).await;
    assert!(json["version"].is_string());
    assert!(!json["version"].as_str().unwrap().is_empty());
}

// ── 3. Modules ────────────────────────────────────────────────────────────

#[tokio::test]
async fn modules_list_returns_array() {
    let app = test_app("modules");
    let resp = app.oneshot(get("/api/v1/modules")).await.unwrap();
    assert_eq!(resp.status(), 200);
    let json = body_json(resp).await;
    let modules = json["modules"]
        .as_array()
        .expect("modules must be an array");
    assert!(!modules.is_empty());
    assert!(
        json["count"].as_u64().unwrap() >= 1,
        "should have at least 1 module (the synthetic one)"
    );

    // The v1.1+ schema adds category + produces; assert they're present.
    let first = &modules[0];
    assert!(
        first.get("category").is_some(),
        "every module entry must have a category"
    );
    assert!(
        first.get("produces").is_some(),
        "every module entry must have a produces array"
    );
    assert!(
        first.get("accepts").is_some(),
        "every module entry must have an accepts array"
    );
}

#[tokio::test]
async fn modules_graph_endpoint_returns_kinds_and_edges() {
    // /api/v1/modules/graph — the dependency-graph view consumed by
    // the SPA's pivot-chain visualisation.
    let app = test_app("modules_graph");
    let resp = app.oneshot(get("/api/v1/modules/graph")).await.unwrap();
    assert_eq!(resp.status(), 200);
    let json = body_json(resp).await;

    let kinds = json["kinds"]
        .as_array()
        .expect("graph must include kinds array");
    assert!(!kinds.is_empty(), "kinds array must be non-empty");
    // First entry should expose richness, module_count, and modules.
    let first = &kinds[0];
    assert!(first.get("richness").is_some());
    assert!(first.get("module_count").is_some());
    assert!(first.get("modules").is_some());
    assert!(first.get("kind").is_some());

    let edges = json["edges"]
        .as_array()
        .expect("graph must include edges array");
    assert!(!edges.is_empty());
    assert!(edges[0].get("consumes").is_some());
    assert!(edges[0].get("produces").is_some());
    assert!(edges[0].get("category").is_some());

    let module_count = json["module_count"].as_u64().unwrap();
    assert!(module_count >= 1);
}

#[tokio::test]
async fn modules_health_endpoint_returns_shape_the_spa_panel_expects() {
    // /api/v1/modules/health (PROBLEM_TREE T2.7 / SOLUTION_TREE
    // SOL-HEALTH-SIGNAL) — per-module failure-streak data previously
    // reachable only from `hse doctor`, now surfaced for the SPA panel.
    // The underlying health state is a process-global shared across every
    // test in this binary, so this only pins the wire shape (an array plus
    // a matching count), not specific content.
    let app = test_app("modules_health");
    let resp = app.oneshot(get("/api/v1/modules/health")).await.unwrap();
    assert_eq!(resp.status(), 200);
    let json = body_json(resp).await;
    let modules = json["modules"]
        .as_array()
        .expect("modules must be an array");
    assert_eq!(
        json["count"].as_u64().unwrap(),
        modules.len() as u64,
        "count must match the modules array length"
    );
    if let Some(first) = modules.first() {
        assert!(first.get("name").is_some());
        assert!(first.get("consecutive_failures").is_some());
        assert!(first.get("last_success_at").is_some());
    }
}

#[tokio::test]
async fn scan_create_accepts_expansion_strategy_option() {
    // The CLI/API surface for ExpansionStrategy must round-trip through
    // the scan-create endpoint so the SPA can offer it as a setting.
    let app = test_app("scan_strategy");
    let body = r#"{
        "kind":"domain","value":"contoso.com",
        "options":{"expansion_strategy":"richest_first","depth":0}
    }"#;
    let resp = app.oneshot(post_json("/api/v1/scans", body)).await.unwrap();
    assert_eq!(resp.status(), 202);
}

#[tokio::test]
async fn scan_create_accepts_seeknow_scan_cap_option() {
    // The per-scan SeekNow budget override must round-trip through the
    // scan-create endpoint so an operator can spend more of the daily
    // quota on a single high-value scan.
    let app = test_app("scan_seeknow_cap");
    let body = r#"{
        "kind":"email","value":"target@contoso.com",
        "options":{"seeknow_scan_cap":80,"depth":0}
    }"#;
    let resp = app.oneshot(post_json("/api/v1/scans", body)).await.unwrap();
    assert_eq!(resp.status(), 202);
}

#[tokio::test]
async fn stats_endpoint_includes_seeknow_block() {
    // /api/v1/stats must surface the SeekNow budget snapshot so the
    // operator can see remaining quota at a glance from the UI.
    let app = test_app("stats_seeknow");
    let resp = app.oneshot(get("/api/v1/stats")).await.unwrap();
    assert_eq!(resp.status(), 200);
    let json = body_json(resp).await;
    let sn = json
        .get("seeknow")
        .expect("stats must include seeknow block");
    for field in [
        "scan_used",
        "scan_cap",
        "session_used",
        "session_cap",
        "quota_exhausted",
    ] {
        assert!(
            sn.get(field).is_some(),
            "seeknow block missing field {field}"
        );
    }
    // scan_cap is a positive integer (default 24 unless env-tuned).
    let cap = sn["scan_cap"].as_u64().unwrap();
    assert!(cap >= 16, "scan_cap dropped below 16 — quota under-used");
}

#[tokio::test]
async fn stats_endpoint_includes_wigle_sub_budgets() {
    // WiGLE has four observation-type budgets (geo / bssid / cell /
    // bluetooth). All four must surface on stats so operators can
    // see remaining quota per observation type.
    let app = test_app("stats_wigle");
    let resp = app.oneshot(get("/api/v1/stats")).await.unwrap();
    assert_eq!(resp.status(), 200);
    let json = body_json(resp).await;
    let wn = json.get("wigle").expect("stats must include wigle block");
    for sub in ["geo", "bssid", "cell", "bluetooth"] {
        let block = wn
            .get(sub)
            .unwrap_or_else(|| panic!("wigle block missing sub-budget {sub}"));
        for field in [
            "scan_used",
            "scan_cap",
            "session_used",
            "session_cap",
            "quota_exhausted",
        ] {
            assert!(
                block.get(field).is_some(),
                "wigle.{sub} missing field {field}"
            );
        }
        // Every sub-budget must have a positive cap.
        let cap = block["scan_cap"].as_u64().unwrap();
        assert!(cap >= 1, "wigle.{sub}.scan_cap must be ≥ 1 (got {cap})");
    }
    // Account block must also be present — fields may be null until
    // /profile/user is polled, but the keys must exist so the SPA can
    // render placeholders without `undefined` reads.
    let account = wn
        .get("account")
        .expect("wigle block must include account sub-object");
    for field in ["verified", "user", "last_polled_ts"] {
        assert!(
            account.get(field).is_some(),
            "wigle.account missing field {field}"
        );
    }
}

#[tokio::test]
async fn stats_endpoint_includes_oathnet_block() {
    // After the budget consolidation, oathnet exposes the same wire
    // shape as seeknow (both back-ended by util::budget::QuotaBudget).
    let app = test_app("stats_oathnet");
    let resp = app.oneshot(get("/api/v1/stats")).await.unwrap();
    assert_eq!(resp.status(), 200);
    let json = body_json(resp).await;
    let on = json
        .get("oathnet")
        .expect("stats must include oathnet block");
    for field in [
        "scan_used",
        "scan_cap",
        "session_used",
        "session_cap",
        "quota_exhausted",
    ] {
        assert!(
            on.get(field).is_some(),
            "oathnet block missing field {field}"
        );
    }
    // OathNet default scan cap is 4 (much tighter than SeekNow's 24).
    let cap = on["scan_cap"].as_u64().unwrap();
    assert!(cap >= 1, "oathnet scan_cap must be positive (got {cap})");
}

// ── 4. Scan create (valid) ────────────────────────────────────────────────

#[tokio::test]
async fn scan_create_accepts_valid_request() {
    let app = test_app("scan_create");
    let body = r#"{"kind":"email","value":"test@contoso.com","options":{}}"#;
    let resp = app.oneshot(post_json("/api/v1/scans", body)).await.unwrap();
    assert_eq!(resp.status(), 202);
    let json = body_json(resp).await;
    assert!(
        json.get("scan_id").is_some(),
        "response must contain scan_id"
    );
    assert!(!json["scan_id"].as_str().unwrap().is_empty());
}

// ── 5. Scan create (invalid target) ───────────────────────────────────────

#[tokio::test]
async fn scan_create_rejects_invalid_target() {
    let app = test_app("scan_bad");
    let body = r#"{"kind":"email","value":"not-an-email","options":{}}"#;
    let resp = app.oneshot(post_json("/api/v1/scans", body)).await.unwrap();
    assert_eq!(resp.status(), 400);
    let json = body_json(resp).await;
    assert!(json.get("error").is_some(), "response must contain error");
}

// ── 5b. Live Signal Radar (button activation) ─────────────────────────────

#[tokio::test]
async fn radar_sweep_activates_with_zero_input_by_default() {
    // The live-sensor radar is armed by default: a bare `POST /api/v1/radar` with
    // no body, no seed, no prior opt-in queues a sweep (the button press IS the
    // activation). What a sweep queues — sensors only, a non-target seed,
    // `allow_live_sensors` set — is covered by the
    // `radar_scan_spec_activates_only_the_live_sensors` unit test.
    let app = test_app("radar");
    let resp = app.oneshot(post_json("/api/v1/radar", "")).await.unwrap();
    assert_eq!(
        resp.status(),
        http::StatusCode::ACCEPTED,
        "the radar must activate on a single request with no prior setup"
    );
}

#[tokio::test]
async fn continuous_radar_activates_with_zero_input_by_default() {
    // The continuous, zero-input radar (`POST /api/v1/radar/live`) takes no body,
    // no target, no seed, no interval — a bare POST is the entire request — and
    // starts a live session by default (armed, no prior opt-in).
    let app = test_app("radar_live");
    let resp = app
        .oneshot(post_json("/api/v1/radar/live", ""))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        http::StatusCode::ACCEPTED,
        "the continuous radar must start on a single request with no prior setup"
    );
    let body = body_json(resp).await;
    assert_eq!(body["mode"], "radar");
    assert!(
        body["live_id"].is_string(),
        "a continuous radar returns a live_id to watch"
    );
}

#[tokio::test]
async fn autonomous_scan_requires_no_input() {
    // `POST /api/v1/scan/auto` takes NO body, NO seed — the platform selects its
    // own target by ranking what it already knows. On a fresh store it either
    // auto-selects from HUNTSMAN_DEFAULT_SEED (202) or, with an empty base and no
    // default, cleanly declines with a 422 + guidance — never a 500. Either way the
    // response is tagged the autonomous mode.
    let app = test_app("auto");
    let resp = app
        .oneshot(post_json("/api/v1/scan/auto", ""))
        .await
        .unwrap();
    let status = resp.status();
    assert!(
        status == http::StatusCode::ACCEPTED || status == http::StatusCode::UNPROCESSABLE_ENTITY,
        "autonomous scan must accept (202) or cleanly decline (422), got {status}"
    );
    let body = body_json(resp).await;
    assert_eq!(body["mode"], "autonomous");
    // When a seed is selected, the response carries the identity-cluster context
    // the identity-aware ranker resolves (>= 1 for the chosen individual).
    if status == http::StatusCode::ACCEPTED {
        let seed = &body["selected_seed"];
        assert!(
            seed["identity_cluster_size"]
                .as_u64()
                .is_some_and(|n| n >= 1),
            "an accepted autonomous seed reports its identity cluster size"
        );
        assert!(
            seed["identity_distinct_kinds"]
                .as_u64()
                .is_some_and(|n| n >= 1),
            "an accepted autonomous seed reports its identity's distinct kinds"
        );
    }
}

#[tokio::test]
async fn autonomous_plan_previews_the_queue_without_dispatching() {
    // `GET /api/v1/scan/auto/plan` is read-only: it returns the diversity-aware
    // investigation queue the platform would work down, dispatching nothing. On a
    // fresh store the base is empty, so the queue is empty — but the envelope is
    // always well-formed (mode + coverage counts + queue array), never a 500.
    let app = test_app("auto_plan");
    let resp = app
        .oneshot(get("/api/v1/scan/auto/plan?limit=5&diversity=0.5"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_json(resp).await;
    assert_eq!(body["mode"], "autonomous");
    assert!(
        body.get("queue").is_some_and(serde_json::Value::is_array),
        "plan carries a queue array"
    );
    for k in ["considered", "kinds_covered"] {
        assert!(
            body.get(k).is_some_and(serde_json::Value::is_u64),
            "plan carries a {k} count"
        );
    }
    assert!(
        body["queue"].as_array().is_some_and(|q| q.len() <= 5),
        "the limit param caps the queue length"
    );
}

#[tokio::test]
async fn autonomous_plan_considers_the_full_scan_history_not_just_the_newest_50() {
    // `scan_auto`/`scan_auto_plan`/`scan_auto_sweep`'s own doc comments promise the
    // candidate pool is ranked from "everything the platform has discovered" — but
    // a hardcoded `list_scans(50)` silently bounded the pool to the 50 MOST RECENT
    // scans, so an entity discovered in any older scan could never be selected, no
    // matter how high its leverage. Seed 55 scans, each with one distinct
    // cross-scan-candidate entity, and confirm every one is considered — not just
    // the newest 50.
    let (app, store) = test_app_with_store("autonomous-pool-bound");
    for i in 0..55u64 {
        let target = Target::new(TargetKind::Email, format!("history{i}@poolbound.io"));
        let mut scan = Scan::new(format!("hist-scan-{i:03}"), target.clone());
        // Distinct, ascending timestamps — scan 0 is the OLDEST and would be the
        // first one dropped by a `list_scans(50)`-style newest-first cap.
        scan.started_at = 1_700_000_000 + i;
        store.upsert_scan(&scan).unwrap();
        let e = Entity::new(EntityKind::Email, &target.value, 0.9, &scan.id);
        store.upsert_entities_batch(&[e]).unwrap();
    }
    let resp = app
        .oneshot(get("/api/v1/scan/auto/plan?limit=200"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let json = body_json(resp).await;
    assert_eq!(
        json["considered"].as_u64().unwrap(),
        55,
        "every scan's entity must be considered, not just the 50 most recent: {json}"
    );
}

#[tokio::test]
async fn autonomous_sweep_dispatches_without_input() {
    // `POST /api/v1/scan/auto/sweep` takes NO body, NO seed — the platform plans the
    // diversity-aware queue and dispatches its top `breadth` targets in one call. On
    // a fresh store with an empty base it cleanly declines (422 + guidance), never a
    // 500; either way the response is tagged the autonomous mode and is well-formed.
    let app = test_app("auto_sweep");
    let resp = app
        .oneshot(post_json("/api/v1/scan/auto/sweep?breadth=3", ""))
        .await
        .unwrap();
    let status = resp.status();
    assert!(
        status == http::StatusCode::ACCEPTED || status == http::StatusCode::UNPROCESSABLE_ENTITY,
        "autonomous sweep must accept (202) or cleanly decline (422), got {status}"
    );
    let body = body_json(resp).await;
    assert_eq!(body["mode"], "autonomous");
    if status == http::StatusCode::ACCEPTED {
        assert!(
            body.get("dispatched")
                .is_some_and(serde_json::Value::is_array),
            "an accepted sweep lists the scans it dispatched"
        );
        assert!(
            body["dispatched"].as_array().is_some_and(|d| d.len() <= 3),
            "the breadth param bounds how many scans are dispatched"
        );
    }
}

// ── 5c. Subject network synthesis ─────────────────────────────────────────

#[tokio::test]
async fn scan_network_synthesises_subject_graph() {
    // Unknown scan → 404, matching the other `/scans/{id}/...` sub-resources.
    let app = test_app("network_nf");
    let resp = app
        .oneshot(get("/api/v1/scans/nope/network"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    // A known scan → 200 with the synthesis envelope. The async engine may not
    // have produced entities yet, but the shape is always present and well-formed.
    let (app, sid) = create_scan("network_ok").await;
    let resp = app
        .oneshot(get(&format!("/api/v1/scans/{sid}/network")))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let net = body_json(resp).await;
    assert!(
        net.get("groups").is_some_and(serde_json::Value::is_array),
        "network carries a groups array"
    );
    for k in ["direct_count", "reachable_count", "edge_count"] {
        assert!(
            net.get(k).is_some_and(serde_json::Value::is_u64),
            "network carries a {k} count"
        );
    }
}

#[tokio::test]
async fn scan_identities_resolves_coreferences() {
    // Unknown scan → 404, like the other `/scans/{id}/...` sub-resources.
    let app = test_app("identities_nf");
    let resp = app
        .oneshot(get("/api/v1/scans/nope/identities"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    // A known scan → 200 with the co-reference envelope. The async engine may not
    // have produced entities yet, but the shape is always present and well-formed.
    let (app, sid) = create_scan("identities_ok").await;
    let resp = app
        .oneshot(get(&format!(
            "/api/v1/scans/{sid}/identities?min_score=0.6"
        )))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_json(resp).await;
    assert!(
        body.get("coreferences")
            .is_some_and(serde_json::Value::is_array),
        "carries a coreferences array"
    );
    assert!(
        body.get("count").is_some_and(serde_json::Value::is_u64),
        "carries a count"
    );
    assert_eq!(body["min_score"], 0.6, "echoes the requested threshold");
}

#[tokio::test]
async fn scan_location_returns_the_residency_fix_envelope() {
    // Unknown scan → 404, like the other `/scans/{id}/...` sub-resources.
    let app = test_app("location_nf");
    let resp = app
        .oneshot(get("/api/v1/scans/nope/location"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    // A known scan → 200 with the `best_location` envelope. With no AU location
    // signal the value is null, but the KEY is always present so the SPA's
    // renderLocation can branch on it deterministically (the lightweight twin of
    // the report.json field, so the headline location finding is reachable
    // without downloading every entity).
    let (app, sid) = create_scan("location_ok").await;
    let resp = app
        .oneshot(get(&format!("/api/v1/scans/{sid}/location")))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_json(resp).await;
    assert!(
        body.get("best_location").is_some(),
        "always carries a best_location key (null when no AU location signal)"
    );
}

// ── 5d. Proactive leads ───────────────────────────────────────────────────

#[tokio::test]
async fn scan_leads_returns_ranked_actions() {
    // Unknown scan → 404, matching the other `/scans/{id}/...` sub-resources.
    let app = test_app("leads_nf");
    let resp = app.oneshot(get("/api/v1/scans/nope/leads")).await.unwrap();
    assert_eq!(resp.status(), 404);

    // A known scan → 200 with a `leads` array (possibly empty until the engine
    // has produced connected, untapped entities).
    let (app, sid) = create_scan("leads_ok").await;
    let resp = app
        .oneshot(get(&format!("/api/v1/scans/{sid}/leads")))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_json(resp).await;
    assert!(
        body.get("leads").is_some_and(serde_json::Value::is_array),
        "leads response carries a leads array"
    );
}

// ── 6. Scan list ──────────────────────────────────────────────────────────

#[tokio::test]
async fn scan_list_returns_scans() {
    let (app, _scan_id) = create_scan("scan_list").await;
    let resp = app.oneshot(get("/api/v1/scans")).await.unwrap();
    assert_eq!(resp.status(), 200);
    let json = body_json(resp).await;
    let scans = json["scans"].as_array().expect("scans must be an array");
    assert!(!scans.is_empty(), "should contain the scan we just created");
}

// ── 7. Scan get ───────────────────────────────────────────────────────────

#[tokio::test]
async fn scan_get_returns_scan() {
    let (app, scan_id) = create_scan("scan_get").await;
    let resp = app
        .oneshot(get(&format!("/api/v1/scans/{scan_id}")))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let json = body_json(resp).await;
    assert_eq!(json["id"].as_str().unwrap(), scan_id);
}

// ── 8. Scan get (not found) ──────────────────────────────────────────────

#[tokio::test]
async fn scan_get_not_found() {
    let app = test_app("scan_nf");
    let resp = app.oneshot(get("/api/v1/scans/nonexistent")).await.unwrap();
    assert_eq!(resp.status(), 404);
}

// ── 9. Scan delete ────────────────────────────────────────────────────────

#[tokio::test]
async fn scan_delete_returns_ok() {
    let (app, scan_id) = create_scan("scan_del").await;
    wait_for_scan_to_finish(&app, &scan_id).await;
    // `wait_for_scan_to_finish` polls the persisted `status` field, which the
    // engine sets to `complete` slightly BEFORE the spawned task's own
    // `CancelRegistryGuard` drops (finalisation's post-`engine.run()`
    // diagnostics tail still runs first) — so `scan_delete`'s in-flight guard
    // can still legitimately see the id in `cancellations` for a moment after
    // `status` already reads `complete`. Retry like a real client would.
    let mut resp = None;
    for _ in 0..500 {
        let r = app
            .clone()
            .oneshot(delete(&format!("/api/v1/scans/{scan_id}")))
            .await
            .unwrap();
        if r.status() != 409 {
            resp = Some(r);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let resp = resp.expect("scan never left the in-flight registry within 5s");
    assert_eq!(resp.status(), 200);
    let json = body_json(resp).await;
    assert_eq!(json["deleted"].as_str().unwrap(), scan_id);
}

// ── 10. Scan delete (not found) ──────────────────────────────────────────

#[tokio::test]
async fn scan_delete_not_found() {
    let app = test_app("scan_del_nf");
    let resp = app
        .oneshot(delete("/api/v1/scans/nonexistent"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

// ── 10b. Scan delete refuses an in-flight scan (data-integrity guard) ────

/// Deleting a scan while its engine task is still alive used to race
/// `Store::delete_scan`'s cascade against the still-running scan's own
/// mid-flight `upsert_entities_batch`/`upsert_scan`/`upsert_correlation`
/// writes under the SAME scan_id — silently resurrecting a "deleted" scan
/// in a partially-rebuilt, potentially inconsistent state, with the client
/// already told 200 "deleted". `s.cancellations` holds an entry for exactly
/// as long as the scan's spawned task is alive (installed at `spawn_scan`,
/// removed by `CancelRegistryGuard`'s Drop when the task returns), so it's
/// the authoritative "is this still running" signal `scan_delete` now
/// checks first. Seeds `cancellations` directly rather than racing a real
/// spawned scan's completion, so this is deterministic.
#[tokio::test]
async fn scan_delete_refuses_an_in_flight_scan_then_succeeds_once_it_ends() {
    let (app, state) = test_app_with_state("scan_del_inflight");
    let scan = Scan::new(
        "inflight1",
        Target::new(TargetKind::Email, "test@contoso.com"),
    );
    state.store.upsert_scan(&scan).unwrap();
    state.cancellations.lock().insert(
        "inflight1".to_string(),
        huntsman_search_engine::core::cancel::CancelHandle::new(),
    );

    let resp = app
        .clone()
        .oneshot(delete("/api/v1/scans/inflight1"))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        409,
        "an in-flight scan must not be deletable out from under its own writer"
    );
    assert!(
        state.store.get_scan("inflight1").unwrap().is_some(),
        "the refused delete must not have touched the scan row"
    );

    // Simulate the scan's task ending (what `CancelRegistryGuard::drop` does).
    state.cancellations.lock().remove("inflight1");

    let resp = app
        .oneshot(delete("/api/v1/scans/inflight1"))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "once no longer in-flight, delete must succeed as normal"
    );
    assert!(state.store.get_scan("inflight1").unwrap().is_none());
}

// ── 11. Scan entities (empty initially) ──────────────────────────────────

#[tokio::test]
async fn scan_entities_empty_initially() {
    let (app, scan_id) = create_scan("scan_ent").await;
    let resp = app
        .oneshot(get(&format!("/api/v1/scans/{scan_id}/entities")))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let json = body_json(resp).await;
    assert!(json.get("entities").is_some());
    // The scan may or may not have completed by now; we verify the response
    // shape is correct and count is a non-negative integer.
    assert!(json["count"].as_u64().is_some());
}

// ── 12. Scan correlations (empty) ────────────────────────────────────────

#[tokio::test]
async fn scan_correlations_empty() {
    let (app, scan_id) = create_scan("scan_corr").await;
    let resp = app
        .oneshot(get(&format!("/api/v1/scans/{scan_id}/correlations")))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let json = body_json(resp).await;
    assert!(json.get("correlations").is_some());
    assert_eq!(json["count"].as_u64().unwrap(), 0);
}

#[tokio::test]
async fn scan_relations_endpoint_returns_list() {
    let (app, scan_id) = create_scan("scan_rel").await;
    let resp = app
        .oneshot(get(&format!("/api/v1/scans/{scan_id}/relations")))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let json = body_json(resp).await;
    assert!(
        json.get("relations").is_some(),
        "body must include 'relations'"
    );
    assert!(json["count"].as_u64().is_some());
}

// ── 13. API not found (JSON) ─────────────────────────────────────────────

#[tokio::test]
async fn api_not_found_returns_json() {
    let app = test_app("api_nf");
    let resp = app.oneshot(get("/api/v1/nonexistent")).await.unwrap();
    assert_eq!(resp.status(), 404);
    let json = body_json(resp).await;
    assert!(
        json.get("error").is_some(),
        "JSON body must include 'error' field"
    );
}

// ── 14. SPA fallback (HTML) ──────────────────────────────────────────────

#[tokio::test]
async fn spa_fallback_returns_html() {
    let app = test_app("spa");
    let resp = app.oneshot(get("/")).await.unwrap();
    assert_eq!(resp.status(), 200);
    let ct = resp
        .headers()
        .get("content-type")
        .expect("should have content-type header")
        .to_str()
        .unwrap()
        .to_string();
    // Read the body to confirm it contains HTML markup.
    let bytes = axum::body::to_bytes(resp.into_body(), 2_000_000)
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&bytes);
    assert!(
        ct.contains("text/html"),
        "content-type should contain text/html, got: {ct}"
    );
    assert!(body.contains("<html") || body.contains("<!DOCTYPE"));
}

// ── 14b. Favicon (SVG, not the SPA HTML) ─────────────────────────────────

#[tokio::test]
async fn favicon_returns_svg_not_html() {
    let app = test_app("favicon");
    let resp = app.oneshot(get("/favicon.ico")).await.unwrap();
    assert_eq!(resp.status(), 200);
    let ct = resp
        .headers()
        .get("content-type")
        .expect("favicon should have content-type")
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        ct.contains("image/svg+xml"),
        "favicon must be SVG, not the SPA fallback HTML — got: {ct}"
    );
    let bytes = axum::body::to_bytes(resp.into_body(), 100_000)
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&bytes);
    assert!(body.contains("<svg"), "favicon body should be an SVG");
    assert!(
        !body.contains("<!DOCTYPE"),
        "favicon must not return the SPA HTML document"
    );
}

#[tokio::test]
async fn dossier_upload_creates_a_complete_scan_with_entities() {
    // Wiring: a dossier file uploaded as a raw text body (the Termux/Chrome UI
    // path) must parse via the shared cli::import path and land as a normal,
    // viewable scan — entities included.
    let app = test_app("import");
    let dossier = "Entry #1:\n   \u{2022} username: isaacfrost\n   \u{2022} email: isaacfrost@gmail.com\n   \u{2022} name: Isaac Frost\n   \u{2022} country: GB\nEMAILS:\n  -> betocastillo097@gmail.com\n";
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/scans/import")
        .header("content-type", "text/plain")
        .header("x-hse-csrf", "1")
        .body(Body::from(dossier))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let json = body_json(resp).await;
    assert_eq!(json["status"], "complete");
    let sid = json["scan_id"].as_str().expect("scan_id").to_string();
    assert!(json["entity_count"].as_u64().unwrap() >= 3);

    // The imported scan is a first-class scan: its entities are retrievable.
    let resp = app
        .oneshot(get(&format!("/api/v1/scans/{sid}/entities")))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let ents = body_json(resp).await;
    let values: Vec<&str> = ents["entities"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["value"].as_str())
        .collect();
    assert!(values.contains(&"isaacfrost@gmail.com"));
    assert!(values.contains(&"Isaac Frost"));
}

#[tokio::test]
async fn stealer_log_upload_persists_paired_rows_retrievable_via_stealer_rows_endpoint() {
    // Wiring: a Stealerlogs-format upload must persist paired credential
    // rows (login+password+machine, kept together) retrievable via the
    // dedicated Stealer Logs Viewer endpoint — not just the flattened,
    // unpaired Email/Username/Credential entities the generic entities
    // endpoint already returns.
    let app = test_app("stealer-rows");
    let stealer = "Module: Stealerlogs\nVictims:\n  [1]\n    Log Id:\n      ea0621568ccd7fee2bd78e16f637727612aca78d4b3d1f6bf8175cf2ca8de831\n    Credentials:\n      [1]\n        Username:\n          jordanavery@gmail.com\n        Password:\n          Hunter2pass\n        Pwned At:\n          2026-05-20T21:00:00Z\n      [2]\n        Username:\n          javery\n        Password:\n          Hunter2pass\n        Pwned At:\n          2026-05-20T21:00:00Z\n    Domains:\n      [1]\n        acme-corp.com\n";
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/scans/import")
        .header("content-type", "text/plain")
        .header("x-hse-csrf", "1")
        .body(Body::from(stealer))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let json = body_json(resp).await;
    let sid = json["scan_id"].as_str().expect("scan_id").to_string();

    let resp = app
        .oneshot(get(&format!("/api/v1/scans/{sid}/stealer-rows")))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let out = body_json(resp).await;
    let rows = out["rows"].as_array().expect("rows array");
    assert_eq!(rows.len(), 2, "both credentials in the one victim block");
    assert!(
        rows.iter().any(|r| r["login"] == "jordanavery@gmail.com"
            && r["password"] == "Hunter2pass"
            && r["pwned_at"] == "2026-05-20T21:00:00Z"
            && r["log_id"] == "ea0621568ccd7fee2bd78e16f637727612aca78d4b3d1f6bf8175cf2ca8de831"),
        "login+password+pwned_at+log_id must survive paired in one row: {rows:?}"
    );
    assert!(
        rows.iter().any(|r| r["login"] == "javery"),
        "the second credential in the same victim block must also be a row: {rows:?}"
    );
}

#[tokio::test]
async fn dossier_upload_derives_and_persists_entity_relations() {
    // An imported scan must carry the same deterministic relation graph a live
    // scan would (structural/geo/DNS/WHOIS/name-lineage). This dossier yields a
    // URL and its host domain, which `derive_all` links — so the import path is
    // no longer relation-blind and the graph/GEXF views work on uploads.
    let app = test_app("import-rel");
    let dossier = "Entry #1:\n   \u{2022} email: ops@acme-corp.io\n   \u{2022} name: Ops Lead\n   \u{2022} domain: acme-corp.io\nhttp://acme-corp.io/login\n";
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/scans/import")
        .header("content-type", "text/plain")
        .header("x-hse-csrf", "1")
        .body(Body::from(dossier))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let json = body_json(resp).await;
    assert_eq!(json["status"], "complete");
    assert!(
        json["relation_count"]
            .as_u64()
            .expect("relation_count field")
            >= 1,
        "the URL→domain structural edge must be derived and persisted: {json}"
    );
}

#[tokio::test]
async fn dossier_upload_reports_relation_count_as_a_true_zero_within_the_enrichment_cap() {
    // A dossier with no relatable entities (one bare email, no shared
    // domain/URL to link) is well within `IMPORT_ENRICH_MAX_ENTITIES`, so
    // enrichment actually runs and the reported zero is a REAL zero — not the
    // size-skip zero the over-cap case below also reports as `0`.
    let app = test_app("import-real-zero");
    let dossier = "Entry #1\n\u{2022} email: solo@enrichcheck.io\n";
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/scans/import")
        .header("content-type", "text/plain")
        .header("x-hse-csrf", "1")
        .body(Body::from(dossier))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let json = body_json(resp).await;
    assert_eq!(
        json["enrichment_skipped"], false,
        "a dossier within the enrichment cap must not be flagged as skipped: {json}"
    );
}

#[tokio::test]
async fn dossier_upload_flags_enrichment_skipped_above_the_entity_cap() {
    // Above `IMPORT_ENRICH_MAX_ENTITIES` (5,000) the O(n²) relation/correlator
    // pass is skipped for device safety — every entity is still persisted, but
    // the response must say so rather than reporting the SAME `relation_count:
    // 0` / `correlation_count: 0` a genuinely relation-free small dossier
    // (the sibling test above) also reports.
    let app = test_app("import-enrich-cap");
    let mut dossier = String::with_capacity(500_000);
    for i in 0..5_100u32 {
        dossier.push_str(&format!(
            "Entry #{i}\n\u{2022} email: user{i}@enrichcap{i}.io\n"
        ));
    }
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/scans/import")
        .header("content-type", "text/plain")
        .header("x-hse-csrf", "1")
        .body(Body::from(dossier))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let json = body_json(resp).await;
    assert!(
        json["entity_count"].as_u64().unwrap() > 5_000,
        "fixture must exceed the enrichment cap: {json}"
    );
    assert_eq!(
        json["enrichment_skipped"], true,
        "an over-cap import must flag that enrichment was skipped, not silently \
         report a zero indistinguishable from a genuinely relation-free import: {json}"
    );
    assert_eq!(json["relation_count"], 0);
    assert_eq!(json["correlation_count"], 0);
}

#[tokio::test]
async fn dossier_upload_rejects_unrecognised_format() {
    let app = test_app("import-bad");
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/scans/import")
        .header("content-type", "text/plain")
        .header("x-hse-csrf", "1")
        .body(Body::from(
            "just some random prose with no dossier structure",
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn dossier_upload_accepts_body_larger_than_axum_default_limit() {
    // The import handler declares a 16 MB cap, but axum's *default* body limit is
    // 2 MB and is enforced before the handler runs — so without a per-route
    // override a legitimate multi-entry breach dossier between 2 and 16 MB was
    // rejected with a bare 413, and the handler's 16 MB check was dead code. The
    // `/scans/import` route raises the limit to scan_handlers::MAX_UPLOAD_BYTES;
    // this proves a >2 MB upload is buffered and parsed, not 413'd.
    let app = test_app("import-large");
    let mut dossier = String::with_capacity(2_300_000);
    dossier.push_str("Entry #1\n\u{2022} email: lead@frostcorp.io\n");
    let mut i = 2u32;
    while dossier.len() < 2_200_000 {
        // Each entry is a valid, distinct record so the parse does real work.
        dossier.push_str(&format!(
            "Entry #{i}\n\u{2022} email: user{i}@frostcorp.io\n"
        ));
        i += 1;
    }
    assert!(
        dossier.len() > 2 * 1024 * 1024,
        "fixture must exceed axum's 2 MB default to exercise the override"
    );

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/scans/import")
        .header("content-type", "text/plain")
        .header("x-hse-csrf", "1")
        .body(Body::from(dossier))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_ne!(
        resp.status(),
        http::StatusCode::PAYLOAD_TOO_LARGE,
        "a 2-16 MB dossier must not be rejected at axum's default 2 MB limit"
    );
    assert_eq!(
        resp.status(),
        200,
        "the large dossier should import cleanly"
    );
}

#[tokio::test]
async fn batch_endpoint_enforces_empty_and_size_limits() {
    // The batch cap is a DoS-relevant contract: an empty batch is a 400, and more
    // than 50 targets is rejected (so a client can't queue thousands of scans in
    // one request). A valid small batch is Accepted. These are explicit handler
    // checks; this pins them so a refactor can't silently drop the cap.
    let app = test_app("batch-limits");

    // Empty array → 400 "empty batch".
    let resp = app
        .clone()
        .oneshot(post_json("/api/v1/scans/batch", "[]"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "empty batch must be rejected");

    // 51 targets → 400 "batch too large (max 50)".
    let over: String = {
        let items: Vec<String> = (0..51)
            .map(|i| format!("{{\"kind\":\"email\",\"value\":\"u{i}@x.com\"}}"))
            .collect();
        format!("[{}]", items.join(","))
    };
    let resp = app
        .clone()
        .oneshot(post_json("/api/v1/scans/batch", &over))
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "a 51-target batch must exceed the cap");

    // Exactly at the cap (50) is Accepted (202).
    let at_cap: String = {
        let items: Vec<String> = (0..50)
            .map(|i| format!("{{\"kind\":\"email\",\"value\":\"v{i}@x.com\"}}"))
            .collect();
        format!("[{}]", items.join(","))
    };
    let resp = app
        .oneshot(post_json("/api/v1/scans/batch", &at_cap))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        http::StatusCode::ACCEPTED,
        "a 50-target batch (at the cap) must be accepted"
    );
}

#[tokio::test]
async fn search_endpoint_rejects_overlong_query() {
    // The 256-char query cap bounds work per request; it fires before any FTS
    // query, so no entities need seeding. A normal query is fine; a 300-char one
    // is a clean 400, not a 500 or an unbounded scan.
    let app = test_app("search-len");

    let ok = app
        .clone()
        .oneshot(get("/api/v1/search?q=alice"))
        .await
        .unwrap();
    assert_ne!(
        ok.status(),
        http::StatusCode::INTERNAL_SERVER_ERROR,
        "a normal query must never 500"
    );

    let long = "x".repeat(300);
    let resp = app
        .oneshot(get(&format!("/api/v1/search?q={long}")))
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "a >256-char query must be rejected 400");
}

#[tokio::test]
async fn manifest_is_valid_installable_pwa() {
    // Chrome-on-Android installability: the manifest must serve as JSON (not the
    // SPA fallback), parse, and declare standalone display so "Add to Home Screen"
    // launches the UI fullscreen.
    let app = test_app("manifest");
    let resp = app.oneshot(get("/manifest.webmanifest")).await.unwrap();
    assert_eq!(resp.status(), 200);
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        ct.contains("application/manifest+json"),
        "manifest must have the manifest content-type, got: {ct}"
    );
    let bytes = axum::body::to_bytes(resp.into_body(), 100_000)
        .await
        .unwrap();
    let m: serde_json::Value = serde_json::from_slice(&bytes).expect("manifest must be valid JSON");
    assert_eq!(m["display"], "standalone");
    assert_eq!(m["start_url"], "/");
    assert!(m["icons"].as_array().is_some_and(|a| !a.is_empty()));
}

// ── 15. Stats ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn stats_returns_counts() {
    let app = test_app("stats");
    let resp = app.oneshot(get("/api/v1/stats")).await.unwrap();
    assert_eq!(resp.status(), 200);
    let json = body_json(resp).await;
    assert!(
        json.get("scans_total").is_some(),
        "stats must include scans_total"
    );
    assert!(json.get("modules").is_some(), "stats must include modules");
    assert!(json.get("version").is_some(), "stats must include version");
}

#[tokio::test]
async fn scraper_health_reports_an_honest_empty_state_for_a_fresh_database() {
    // The SPA counterpart of `hse doctor`'s "Scraper health" section
    // (T2.7 / SOL-HEALTH-SIGNAL): a brand-new test database has dispatched no
    // modules at all, so this must report a genuine empty state — zero
    // tracked sources, zero drifted — never a fabricated result.
    let app = test_app("scraper_health_empty");
    let resp = app.oneshot(get("/api/v1/health/scrapers")).await.unwrap();
    assert_eq!(resp.status(), 200);
    let json = body_json(resp).await;
    assert_eq!(json["tracked"], 0);
    assert_eq!(json["events_checked"], 0);
    assert!(json["drifted"].as_array().unwrap().is_empty());
    assert!(
        json.get("drifted_threshold").is_some(),
        "must surface the drift threshold so the SPA panel can explain the bar"
    );
    // The silent zero-yield ("parse-rate") drift signal — same honest-empty
    // contract, never fabricated for a database with no history.
    assert!(json["yield_drifted"].as_array().unwrap().is_empty());
    assert!(
        json.get("yield_drift_threshold").is_some(),
        "must surface the yield-drift threshold so the SPA panel can explain the bar"
    );
}

// ── 16. Settings keys GET ─────────────────────────────────────────────────

#[tokio::test]
async fn settings_keys_get_lists_keys() {
    use std::net::SocketAddr;
    let app = test_app("keys_get");
    let loopback: SocketAddr = "127.0.0.1:9999".parse().unwrap();
    let mut req = get("/api/v1/settings/keys");
    req.extensions_mut()
        .insert(axum::extract::ConnectInfo(loopback));
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let json = body_json(resp).await;
    assert!(
        json.get("keys").is_some(),
        "response must contain keys array"
    );
    assert!(json["keys"].as_array().is_some());

    // Convex acquisition guidance: unset keys ranked highest-leverage first, each
    // with a tier and (usually) a free-signup hint. The web-UI operator gets the
    // same ranking `hse doctor` prints.
    let acq = json["acquisition"]
        .as_array()
        .expect("response must contain an acquisition array");
    assert!(
        !acq.is_empty(),
        "a fresh test app has unset keys, so acquisition must be non-empty"
    );
    // Ranking is Multiplier > Expansion > Terminal: the tier rank must be
    // non-increasing across the list (never a lower tier before a higher one).
    let rank = |t: &str| match t {
        "multiplier" => 2,
        "expansion" => 1,
        _ => 0,
    };
    let mut prev = i32::MAX;
    for e in acq {
        let tier = e["tier"].as_str().expect("each entry has a tier");
        assert!(e["name"].as_str().is_some(), "each entry has a name");
        let r = rank(tier);
        assert!(
            r <= prev,
            "acquisition must be ranked highest-leverage first (saw {tier} out of order)"
        );
        prev = r;
    }
}

#[tokio::test]
async fn settings_keys_get_refuses_non_loopback_peer() {
    // Which key services are configured (+ the on-disk env path) is the same
    // class of sensitive infra metadata `keys_status`/`keys_pool_get` already
    // gate loopback-only, and this route's own PUT sibling already refuses a
    // non-loopback peer — this GET must match, not leak silently under an
    // operator-chosen LAN bind.
    use std::net::SocketAddr;
    let app = test_app("keys_get_lan");
    let lan: SocketAddr = "192.168.1.50:40000".parse().unwrap();
    let mut req = get("/api/v1/settings/keys");
    req.extensions_mut().insert(axum::extract::ConnectInfo(lan));
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        403,
        "settings/keys GET must be loopback-only"
    );
}

// ── 17. Settings keys PUT (forbidden) ─────────────────────────────────────

#[tokio::test]
async fn settings_keys_put_forbidden_without_flag() {
    use std::net::SocketAddr;

    let app = test_app("keys_put");
    let body = r#"{"updates":{"HUNTSMAN_TEST":"val"},"deletes":[]}"#;

    // Inject `ConnectInfo` via request extensions so the extractor
    // succeeds in the test harness (no real TCP listener). The
    // `allow_key_write` flag is false, so the handler returns 403
    // before ever checking the peer address.
    let mut req = Request::builder()
        .method("PUT")
        .uri("/api/v1/settings/keys")
        .header("content-type", "application/json")
        .header("x-hse-csrf", "1")
        .body(Body::from(body))
        .unwrap();

    let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
    req.extensions_mut()
        .insert(axum::extract::ConnectInfo(addr));

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 403);
}

// ── Settings toggles (universal toggleability) ────────────────────────────

#[tokio::test]
async fn settings_toggles_get_lists_features_engines_and_modules() {
    let app = test_app("toggles_get");
    let resp = app.oneshot(get("/api/v1/settings/toggles")).await.unwrap();
    assert_eq!(resp.status(), 200);
    let json = body_json(resp).await;
    let groups = json["groups"].as_array().expect("groups array");
    let group = |name: &str| {
        groups
            .iter()
            .find(|g| g["group"].as_str() == Some(name))
            .unwrap_or_else(|| panic!("must expose a {name} group"))["toggles"]
            .as_array()
            .expect("toggles array")
    };
    let features = group("features");
    let engines = group("engines");
    let modules = group("modules");
    // Engine list is the real keyless-engine catalogue (independent of the test
    // engine's module set); modules reflect the engine the server was built with
    // (here the single synthetic stub) — proving the handler reads live state.
    assert!(
        engines.len() >= 10,
        "engine catalogue should list every keyless engine, got {}",
        engines.len()
    );
    assert!(
        modules.iter().any(|t| t["key"] == "module.synthetic"),
        "modules group must reflect the engine's registered modules"
    );
    assert!(
        features.iter().any(|t| t["key"] == "feature.regional"),
        "features group must expose the regional-search toggle"
    );
    // Every toggle carries a key/name/enabled triple with a recognised prefix.
    for g in groups {
        for t in g["toggles"].as_array().expect("toggles array") {
            assert!(t["enabled"].is_boolean(), "enabled is a bool");
            let key = t["key"].as_str().expect("key is a string");
            assert!(
                key.starts_with("engine.")
                    || key.starts_with("module.")
                    || key.starts_with("feature."),
                "unexpected toggle key prefix: {key}"
            );
        }
    }
    assert_eq!(
        json["count"].as_u64().unwrap_or(0),
        (features.len() + engines.len() + modules.len()) as u64,
        "count is the sum of all groups"
    );
}

#[tokio::test]
async fn settings_toggles_put_rejects_non_loopback_peer() {
    use std::net::SocketAddr;
    let app = test_app("toggles_put_lan");
    // A LAN peer must never be able to flip server-wide capability toggles.
    let mut req = Request::builder()
        .method("PUT")
        .uri("/api/v1/settings/toggles")
        .header("content-type", "application/json")
        .header("x-hse-csrf", "1")
        .body(Body::from(r#"{"key":"engine.google","enabled":false}"#))
        .unwrap();
    let addr: SocketAddr = "192.168.1.50:5555".parse().unwrap();
    req.extensions_mut()
        .insert(axum::extract::ConnectInfo(addr));
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 403, "toggle writes are loopback-only");
}

#[tokio::test]
async fn settings_toggles_put_rejects_unknown_key() {
    use std::net::SocketAddr;
    let app = test_app("toggles_put_unknown");
    // Loopback peer, but the key names no real capability — must 400 and (since
    // it never reaches `set_bool`) must not mutate the persisted settings.
    let mut req = Request::builder()
        .method("PUT")
        .uri("/api/v1/settings/toggles")
        .header("content-type", "application/json")
        .header("x-hse-csrf", "1")
        .body(Body::from(
            r#"{"key":"module.not_a_real_module","enabled":false}"#,
        ))
        .unwrap();
    let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
    req.extensions_mut()
        .insert(axum::extract::ConnectInfo(addr));
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 400, "an unknown toggle key is rejected");
}

// ── Scan rerun ──────────────────────────────────────────────────────────

#[tokio::test]
async fn scan_rerun_creates_new_scan() {
    let (app, scan_id) = create_scan("rerun").await;
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let resp = app
        .oneshot(post_json(&format!("/api/v1/scans/{scan_id}/rerun"), "{}"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 202);
    let json = body_json(resp).await;
    assert!(json["scan_id"].is_string());
    assert_eq!(json["source_scan_id"].as_str().unwrap(), scan_id);
}

#[tokio::test]
async fn scan_rerun_not_found() {
    let app = test_app("rerun_nf");
    let resp = app
        .oneshot(post_json("/api/v1/scans/nonexistent/rerun", "{}"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

// ── CSV export ──────────────────────────────────────────────────────────

#[tokio::test]
async fn scan_entities_csv_returns_csv_content_type() {
    let (app, scan_id) = create_scan("csv").await;
    let resp = app
        .oneshot(get(&format!("/api/v1/scans/{scan_id}/entities.csv")))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let ct = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(ct.contains("text/csv"), "expected text/csv, got {ct}");
    let bytes = axum::body::to_bytes(resp.into_body(), 1_000_000)
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&bytes);
    assert!(
        body.starts_with("kind,"),
        "CSV should start with header row"
    );
}

// ── GEXF export ─────────────────────────────────────────────────────────

#[tokio::test]
async fn scan_gexf_quarantines_candidate_nodes_by_default() {
    use huntsman_search_engine::core::tags::CANDIDATE;
    let (app, store) = test_app_with_store("gexf_candidate");
    let sid = "s-gexf-cand";
    store
        .upsert_scan(&Scan::new(
            sid,
            Target::new(TargetKind::FullName, "Jordan Avery"),
        ))
        .unwrap();
    // A confirmed subject entity plus a quarantined candidate breach-victim.
    let subject = Entity::new(EntityKind::Email, "subject@real.example", 0.9, sid);
    let mut candidate = Entity::new(EntityKind::Email, "stranger@breach.example", 0.5, sid);
    candidate.tag(CANDIDATE);
    store.upsert_entity(&subject).unwrap();
    store.upsert_entity(&candidate).unwrap();

    // Default: the quarantined candidate must NOT leak as a node — matching CSV,
    // report.json, and the CLI GEXF export.
    let resp = app
        .clone()
        .oneshot(get(&format!("/api/v1/scans/{sid}/graph.gexf")))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let bytes = axum::body::to_bytes(resp.into_body(), 5_000_000)
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&bytes);
    assert!(
        body.contains("subject@real.example"),
        "the confirmed subject node must be present: {body}"
    );
    assert!(
        !body.contains("stranger@breach.example"),
        "a quarantined candidate breach-victim must not leak into the graph export: {body}"
    );

    // Opt-in: `?include_candidates=1` returns the full set (parity with CSV).
    let resp2 = app
        .clone()
        .oneshot(get(&format!(
            "/api/v1/scans/{sid}/graph.gexf?include_candidates=1"
        )))
        .await
        .unwrap();
    assert_eq!(resp2.status(), 200);
    let bytes2 = axum::body::to_bytes(resp2.into_body(), 5_000_000)
        .await
        .unwrap();
    let body2 = String::from_utf8_lossy(&bytes2);
    assert!(
        body2.contains("stranger@breach.example"),
        "include_candidates=1 must return the candidate node: {body2}"
    );
}

// ── JSON report ─────────────────────────────────────────────────────────

#[tokio::test]
async fn scan_report_json_returns_full_report() {
    let (app, scan_id) = create_scan("report").await;
    let resp = app
        .oneshot(get(&format!("/api/v1/scans/{scan_id}/report.json")))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let ct = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(ct.contains("application/json"));
    let json = body_json(resp).await;
    assert!(json.get("scan").is_some());
    assert!(json.get("entities").is_some());
    assert!(json.get("correlations").is_some());
    assert!(json.get("exported_at").is_some());
}

#[tokio::test]
async fn scan_report_json_not_found() {
    let app = test_app("report_nf");
    let resp = app
        .oneshot(get("/api/v1/scans/nonexistent/report.json"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

// ── Events history ──────────────────────────────────────────────────────

#[tokio::test]
async fn scan_events_history_returns_list() {
    let (app, scan_id) = create_scan("evt_hist").await;
    let resp = app
        .oneshot(get(&format!("/api/v1/scans/{scan_id}/events.history")))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let json = body_json(resp).await;
    assert!(json["events"].is_array());
}

// ── Facets ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn scan_entities_facets_returns_facets() {
    let (app, scan_id) = create_scan("facets").await;
    let resp = app
        .oneshot(get(&format!("/api/v1/scans/{scan_id}/entities/facets")))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let json = body_json(resp).await;
    assert!(json["facets"].is_array());
}

#[tokio::test]
async fn scan_diamond_rolls_entities_up_by_vertex() {
    use huntsman_search_engine::core::tags::CANDIDATE;
    let (app, store) = test_app_with_store("diamond");
    let sid = "s-diamond";
    store
        .upsert_scan(&Scan::new(
            sid,
            Target::new(TargetKind::FullName, "Jordan Avery"),
        ))
        .unwrap();
    // One entity per Diamond vertex the kind-classifier produces, plus a
    // quarantined candidate that the endpoint must exclude by default.
    store
        .upsert_entity(&Entity::new(EntityKind::Person, "Jordan Avery", 0.9, sid))
        .unwrap();
    store
        .upsert_entity(&Entity::new(EntityKind::Domain, "jordan.example", 0.8, sid))
        .unwrap();
    store
        .upsert_entity(&Entity::new(EntityKind::Password, "leaked-hash", 0.7, sid))
        .unwrap();
    let mut cand = Entity::new(EntityKind::Email, "stranger@breach.example", 0.5, sid);
    cand.tag(CANDIDATE);
    store.upsert_entity(&cand).unwrap();

    let resp = app
        .oneshot(get(&format!("/api/v1/scans/{sid}/diamond")))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let json = body_json(resp).await;
    // The quarantined candidate is excluded by default → 3 across 3 vertices.
    assert_eq!(
        json["total"].as_u64(),
        Some(3),
        "candidate excluded by default: {json}"
    );
    let vertices = json["vertices"].as_array().unwrap();
    let vcount = |name: &str| -> u64 {
        vertices
            .iter()
            .find(|v| v["vertex"] == name)
            .and_then(|v| v["count"].as_u64())
            .unwrap_or(0)
    };
    assert_eq!(vcount("victim"), 1, "Person → victim: {json}");
    assert_eq!(
        vcount("infrastructure"),
        1,
        "Domain → infrastructure: {json}"
    );
    assert_eq!(vcount("capability"), 1, "Password → capability: {json}");
    // Adversary is a relational role — the kind classifier never emits it.
    assert_eq!(
        vcount("adversary"),
        0,
        "adversary is relational, not intrinsic: {json}"
    );
}

// ── Cancel nonexistent ──────────────────────────────────────────────────

#[tokio::test]
async fn scan_cancel_not_found() {
    let app = test_app("cancel_nf");
    let resp = app
        .oneshot(post_json("/api/v1/scans/nonexistent/cancel", "{}"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

// ── Live create with invalid target ─────────────────────────────────────

#[tokio::test]
async fn live_create_rejects_invalid_target() {
    let app = test_app("live_bad");
    let body = r#"{"kind":"email","value":"not-an-email","options":{},"live":{}}"#;
    let resp = app.oneshot(post_json("/api/v1/live", body)).await.unwrap();
    assert_eq!(resp.status(), 400);
    let json = body_json(resp).await;
    assert!(json["error"].as_str().unwrap().contains("invalid target"));
}

// ── Entities filter ─────────────────────────────────────────────────────

#[tokio::test]
async fn scan_entities_filter_returns_entities() {
    let (app, scan_id) = create_scan("filter").await;
    let resp = app
        .oneshot(get(&format!(
            "/api/v1/scans/{scan_id}/entities/filter?kind=email"
        )))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let json = body_json(resp).await;
    assert!(json["entities"].is_array());
}

#[tokio::test]
async fn scan_entities_filter_quarantines_candidate_entities_by_default() {
    // Regression: unlike `scan_entities`, `scan_entities_csv`, `report.json`, and
    // GEXF export, `/entities/filter` never applied the candidate quarantine — a
    // caller could route around the quarantine every sibling endpoint enforces
    // simply by adding a `kind`/`min_confidence`/`q` query param.
    use huntsman_search_engine::core::tags::CANDIDATE;
    let (app, store) = test_app_with_store("filter_candidate");
    let sid = "s-filter-cand";
    store
        .upsert_scan(&Scan::new(
            sid,
            Target::new(TargetKind::FullName, "Jordan Avery"),
        ))
        .unwrap();
    let subject = Entity::new(EntityKind::Email, "subject@real.example", 0.9, sid);
    let mut candidate = Entity::new(EntityKind::Email, "stranger@breach.example", 0.5, sid);
    candidate.tag(CANDIDATE);
    store.upsert_entity(&subject).unwrap();
    store.upsert_entity(&candidate).unwrap();

    // Default: the quarantined candidate must not leak through the filter route.
    let resp = app
        .clone()
        .oneshot(get(&format!(
            "/api/v1/scans/{sid}/entities/filter?kind=email"
        )))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let json = body_json(resp).await;
    let values: Vec<&str> = json["entities"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["value"].as_str())
        .collect();
    assert!(
        values.contains(&"subject@real.example"),
        "the confirmed subject entity must be present: {json}"
    );
    assert!(
        !values.contains(&"stranger@breach.example"),
        "a quarantined candidate breach-victim must not leak through /entities/filter: {json}"
    );

    // Opt-in: `?include_candidates=1` returns the full set (parity with the other
    // entity-listing endpoints).
    let resp2 = app
        .oneshot(get(&format!(
            "/api/v1/scans/{sid}/entities/filter?kind=email&include_candidates=1"
        )))
        .await
        .unwrap();
    assert_eq!(resp2.status(), 200);
    let json2 = body_json(resp2).await;
    let values2: Vec<&str> = json2["entities"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["value"].as_str())
        .collect();
    assert!(
        values2.contains(&"stranger@breach.example"),
        "include_candidates=1 must return the candidate entity: {json2}"
    );
}

// ── Live list (empty) ───────────────────────────────────────────────────

#[tokio::test]
async fn live_list_returns_empty_initially() {
    let app = test_app("live_list");
    let resp = app.oneshot(get("/api/v1/live")).await.unwrap();
    assert_eq!(resp.status(), 200);
    let json = body_json(resp).await;
    assert!(json["sessions"].is_array());
    assert_eq!(json["count"].as_u64().unwrap(), 0);
}

// ── Live get not found ──────────────────────────────────────────────────

#[tokio::test]
async fn live_get_not_found() {
    let app = test_app("live_get_nf");
    let resp = app.oneshot(get("/api/v1/live/nonexistent")).await.unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn live_create_list_get_stop_roundtrip() {
    let app = test_app("live_rt");
    // Empty module allowlist => the spawned iteration runs no modules (instant,
    // no network), so this exercises the create/list/get/stop API the Live
    // Monitor UI drives, deterministically.
    let body = r#"{"kind":"domain","value":"contoso.com","options":{"modules":[]},"live":{"interval_secs":3600}}"#;
    let resp = app
        .clone()
        .oneshot(post_json("/api/v1/live", body))
        .await
        .unwrap();
    // 202 Accepted: the session is registered and its loop spawned. With a
    // 3600s interval and no iteration cap it stays running after the first
    // (instant, module-less) iteration, so the list/get/stop below are stable.
    assert_eq!(resp.status(), 202);
    let created = body_json(resp).await;
    let id = created["live_id"].as_str().expect("live_id").to_string();
    assert_eq!(created["status"], "running");

    let resp = app.clone().oneshot(get("/api/v1/live")).await.unwrap();
    let list = body_json(resp).await;
    assert_eq!(list["count"].as_u64().unwrap(), 1);
    assert_eq!(list["sessions"][0]["id"].as_str().unwrap(), id);
    assert_eq!(list["sessions"][0]["target"]["value"], "contoso.com");

    let resp = app
        .clone()
        .oneshot(get(&format!("/api/v1/live/{id}")))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = app
        .oneshot(delete(&format!("/api/v1/live/{id}")))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(body_json(resp).await["status"], "stopping");
}

// ── Live stop not found ─────────────────────────────────────────────────

#[tokio::test]
async fn live_stop_not_found() {
    let app = test_app("live_stop_nf");
    let resp = app
        .oneshot(delete("/api/v1/live/nonexistent"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn sub_resource_endpoints_404_for_unknown_scan() {
    // Regression: every /scans/{id}/<sub> must 404 for an unknown scan —
    // consistent with GET /scans/{id} and report.json — instead of a
    // misleading empty 200 a client can't distinguish from "found nothing".
    let (app, sid) = create_scan("subres404").await;
    let bad = "nonexistent0000000000000000000000000000000000000000000000000000";

    for ep in [
        "entities",
        "entities/facets",
        "entities/filter?kind=email",
        "correlations",
        "relations",
        "stealer-rows",
        "entities.csv",
        "events.history",
        "graph.gexf",
    ] {
        let unknown = app
            .clone()
            .oneshot(get(&format!("/api/v1/scans/{bad}/{ep}")))
            .await
            .unwrap();
        assert_eq!(unknown.status(), 404, "unknown scan {ep} must 404");
    }

    // A real scan still serves each sub-resource (no success-path regression).
    for ep in [
        "entities",
        "entities/facets",
        "correlations",
        "relations",
        "stealer-rows",
        "entities.csv",
        "events.history",
        "graph.gexf",
    ] {
        let known = app
            .clone()
            .oneshot(get(&format!("/api/v1/scans/{sid}/{ep}")))
            .await
            .unwrap();
        assert_eq!(known.status(), 200, "known scan {ep} must 200");
    }
}

#[tokio::test]
async fn search_endpoint_returns_fts_indexed_entities() {
    let (app, store) = test_app_with_store("search");
    let scan = Scan::new(
        "s-search",
        Target::new(TargetKind::FullName, "Jordan Leigh Meyers"),
    );
    store.upsert_scan(&scan).unwrap();
    for v in ["jordoftw123", "Jordan Leigh Meyers", "unrelated_handle"] {
        let kind = if v.contains(' ') {
            EntityKind::Person
        } else {
            EntityKind::Username
        };
        store
            .upsert_entity(&Entity::new(kind, v, 0.9, "s-search"))
            .unwrap();
    }

    let vals = |json: &Value| -> Vec<String> {
        json["entities"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["value"].as_str().unwrap_or("").to_lowercase())
            .collect()
    };

    // Prefix-token FTS: "jordo" matches "jordoftw123".
    let resp = app
        .clone()
        .oneshot(get("/api/v1/search?q=jordo"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let v = vals(&body_json(resp).await);
    assert!(
        v.iter().any(|x| x.contains("jordoftw123")),
        "prefix hit, got {v:?}"
    );

    // Word-order-independent ranked MATCH (FTS, not a substring LIKE):
    // "meyers jordan" must still find "Jordan Leigh Meyers".
    let resp = app
        .oneshot(get("/api/v1/search?q=meyers%20jordan"))
        .await
        .unwrap();
    let v = vals(&body_json(resp).await);
    assert!(
        v.iter()
            .any(|x| x.contains("jordan") && x.contains("meyers")),
        "any-order hit, got {v:?}"
    );
}

// ── SPA contract tests ──────────────────────────────────────────────────────
//
// Guard the embedded single-page app against the regression classes a Rust
// suite can catch *without* a headless browser. A Chromium/Playwright harness
// is deliberately avoided — it would pull a Node + native-browser toolchain
// into a project that is rigorously pure-Rust / no-native-deps / Termux-minimal,
// and would be slow and flaky in CI. Instead these assert, against the document
// the real router actually serves:
//   1. every `/api/v1/<base>` the SPA calls resolves to a registered route, not
//      the `api_not_found` fallback (the `API.stats()`-style dead-endpoint bug
//      that shipped once and is recorded in the changelog);
//   2. every `/static/<file>` the SPA loads is served, non-empty, by the vendor
//      handler (a broken vendored-asset link → unstyled / broken UI);
//   3. the directive's required UI structural elements stay present.

/// GET `uri` through a clone of `app`, returning `(status, body-as-text)`.
async fn fetch_text(app: &axum::Router, uri: &str) -> (http::StatusCode, String) {
    let resp = app.clone().oneshot(get(uri)).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 2_000_000)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// Distinct path segment immediately following every occurrence of `prefix`,
/// taking characters while `keep` holds. Pure-std (no regex dev-dep) discovery
/// of which API / static paths the served SPA actually wires up.
fn segments_after(text: &str, prefix: &str, keep: impl Fn(char) -> bool) -> Vec<String> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(rel) = text[from..].find(prefix) {
        let start = from + rel + prefix.len();
        let seg: String = text[start..].chars().take_while(|c| keep(*c)).collect();
        if !seg.is_empty() {
            out.push(seg);
        }
        from = start; // advance past this prefix so the next find can't re-match it
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// Crawl every asset the served SPA shell depends on: its own `<link>` /
/// `<script src>` references, plus every `import … from '/static/js/…'` inside
/// each fetched JS module (transitively — `main.js` alone pulls in ~35 view
/// modules). The former monolithic `spa.html` held every view inline, so a
/// content check could just scan the one served document; now that it's split
/// across `src/web/js/`, the same checks need the concatenation of the shell
/// plus every module it transitively loads. Returns `(combined text, sorted
/// list of every `/static/…` path discovered)`.
async fn spa_bundle(app: &axum::Router) -> (String, Vec<String>) {
    fn path_char(c: char) -> bool {
        c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' || c == '/'
    }

    let (_, shell) = fetch_text(app, "/").await;
    let mut queue: Vec<String> = segments_after(&shell, "/static/", path_char)
        .into_iter()
        .map(|p| format!("/static/{p}"))
        .collect();
    let mut combined = shell.clone();
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut discovered: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut i = 0;
    while i < queue.len() {
        let path = queue[i].clone();
        i += 1;
        if !seen.insert(path.clone()) {
            continue;
        }
        discovered.insert(path.clone());
        let (status, body) = fetch_text(app, &path).await;
        if status != http::StatusCode::OK {
            continue;
        }
        combined.push('\n');
        combined.push_str(&body);
        if path.ends_with(".js") {
            for imp in segments_after(&body, "from '/static/", path_char) {
                let full = format!("/static/{imp}");
                if !seen.contains(&full) {
                    queue.push(full);
                }
            }
        }
    }
    (combined, discovered.into_iter().collect())
}

#[tokio::test]
async fn spa_served_with_required_ui_structure() {
    let app = test_app("spa-structure");
    let (status, _) = fetch_text(&app, "/").await;
    assert_eq!(status, http::StatusCode::OK);
    let (html, _) = spa_bundle(&app).await;
    assert!(
        html.len() > 10_000,
        "SPA bundle suspiciously small ({} bytes)",
        html.len()
    );
    // Directive UI checklist — this scaffolding must stay present.
    for marker in [
        "<html",             // a real HTML document
        "viewport",          // touch / mobile-optimised
        "#222",              // dark theme (navbar dark)
        "/static/d3.min.js", // interactive node graph (D3)
        "tablesorter",       // sortable data tables
        "#/dash",            // tabbed navigation (client-side hash routes)
        "#/scans",
        "#/newscan",
        "EventSource", // live event log (SSE)
    ] {
        assert!(
            html.contains(marker),
            "SPA missing required UI element: {marker:?}"
        );
    }
}

#[tokio::test]
async fn spa_references_only_registered_api_endpoints() {
    // Every `/api/v1/<base>` the SPA calls must resolve to a registered route,
    // never the `api_not_found` fallback. A new SPA endpoint with no probe here
    // fails loudly, forcing its route to be confirmed.
    let app = test_app("spa-endpoints");
    let (html, _) = spa_bundle(&app).await;

    let bases = segments_after(&html, "/api/v1/", |c| c.is_ascii_lowercase() || c == '_');
    assert!(
        !bases.is_empty(),
        "extracted no /api/v1 endpoints from the served SPA"
    );

    for base in &bases {
        // `/entities/{uid}` (cross-scan entity pivot) is resource-style: every
        // uid that isn't present returns the handler's own 404, so a parameter-
        // free probe can't distinguish "route registered" from "no such entity"
        // by status alone. Confirm the route is wired by checking the body is the
        // handler's `not found`, NOT the api fallback's `endpoint not found`.
        if base == "entities" {
            let (_, body) = fetch_text(&app, "/api/v1/entities/__nonexistent__").await;
            assert!(
                !body.contains("endpoint not found"),
                "SPA calls /api/v1/entities/{{uid}} but it hit the api fallback \
                 (route not registered): {body}"
            );
            continue;
        }
        // A representative, parameter-free URL for this endpoint family.
        let url = match base.as_str() {
            "health" => "/api/v1/health".to_string(),
            "version" => "/api/v1/version".to_string(),
            "keys" => "/api/v1/keys/pool".to_string(),
            "modules" => "/api/v1/modules".to_string(),
            "engines" => "/api/v1/engines/health".to_string(),
            "stats" => "/api/v1/stats".to_string(),
            "scans" => "/api/v1/scans".to_string(),
            "search" => "/api/v1/search?q=x".to_string(),
            "settings" => "/api/v1/settings/keys".to_string(),
            "selftest" => "/api/v1/selftest".to_string(),
            "logs" => "/api/v1/logs".to_string(),
            "live" => "/api/v1/live".to_string(),
            "update" => "/api/v1/update/status".to_string(),
            // Live Signal Radar — POST-only, so a bare GET returns 405 (Method
            // Not Allowed), not the fallback's 404; the assertion below only
            // requires "not 404", which confirms the route is registered.
            "radar" => "/api/v1/radar".to_string(),
            // Autonomous investigation (`POST /api/v1/scan/auto`) — POST-only, so a
            // bare GET returns 405, not the fallback 404; the assertion only needs
            // "not 404", confirming the route is registered.
            "scan" => "/api/v1/scan/auto".to_string(),
            // Forward-only scan-plan preview — parameter-driven; a bare value
            // exercises the registered route (returns 200, never the fallback 404).
            "plan" => "/api/v1/plan?value=example.com".to_string(),
            // Cell-tower DB status — ungated GET, safe to probe with no side effects.
            "cells" => "/api/v1/cells/status".to_string(),
            // Live capability probe — POST-only (a real network sweep per keyless
            // module), so a bare GET returns 405, not the fallback 404; the
            // assertion only needs "not 404", confirming the route is registered
            // WITHOUT firing the live network probe in the hermetic suite.
            "capabilities" => "/api/v1/capabilities/probe".to_string(),
            // System self-diagnosis bundle — loopback-gated and it also needs a
            // `ConnectInfo` peer, so a bare probe GET reaches the handler and
            // returns 403/500 (never the fallback 404), confirming the route is
            // registered.
            "debug" => "/api/v1/debug/bundle".to_string(),
            other => panic!(
                "SPA references /api/v1/{other} but this test has no probe for it — \
                 add one and confirm the route is registered in src/api/routes.rs"
            ),
        };
        let (status, _) = fetch_text(&app, &url).await;
        assert_ne!(
            status,
            http::StatusCode::NOT_FOUND,
            "SPA calls /api/v1/{base} but {url} returned 404 (route not registered)",
        );
    }
}

#[tokio::test]
async fn spa_references_only_served_static_assets() {
    // Every vendored `/static/<file>` the SPA links must be served (200,
    // non-empty) by the vendor handler — guards a broken-link regression.
    let app = test_app("spa-static");
    let (_, files) = spa_bundle(&app).await;
    assert!(
        files.len() >= 5,
        "expected the SPA to load several vendored/app assets, found {files:?}"
    );
    for f in &files {
        let (status, body) = fetch_text(&app, f).await;
        assert_eq!(
            status,
            http::StatusCode::OK,
            "asset {f} not served (broken link)"
        );
        assert!(!body.is_empty(), "asset {f} served empty");
    }
}

#[tokio::test]
async fn spa_api_client_calls_are_all_defined() {
    // Internal JS wiring guard: every `API.<name>` the SPA *calls* must also be
    // *defined* on the `const API = {…}` client object. A call to an undefined
    // method is a TypeError at click time — a dead button no Rust *route* test
    // catches (the route can exist while the JS helper is missing/misspelled).
    // Pure static scan of the served document; no JS engine, no browser.
    let app = test_app("spa-api-client");
    let (status, _) = fetch_text(&app, "/").await;
    assert_eq!(status, http::StatusCode::OK, "SPA `/` must serve 200");
    let (html, _) = spa_bundle(&app).await;

    // Identifiers written as `API.<name>` — this captures call sites
    // (`API.foo(`, `API.csvUrl(`) but NOT the object-literal definitions
    // (which are bare `foo:` / `async foo(`), so the two sets are independent.
    let called: std::collections::BTreeSet<String> =
        segments_after(&html, "API.", |c| c.is_ascii_alphanumeric() || c == '_')
            .into_iter()
            .collect();
    assert!(
        called.len() > 5,
        "expected several API.* call sites in the SPA, found {called:?}"
    );

    // Members of the `const API = { … }` object literal: a member is either
    // `name:` (arrow/value form) or `async name(` / `name(` (method form).
    // Scan from the `const API` line and STOP at the literal's closing `};`,
    // so members of any later object/function can't be mistaken for API
    // methods (which would mask a genuinely-undefined call). Iterating lines
    // (not a byte-sliced window) also avoids slicing through a multi-byte char
    // — the SPA contains non-ASCII (`…`, `→`, `⚠️`) that a raw offset could
    // split, panicking the test.
    let start = html.find("const API").expect("SPA must define `const API`");
    let mut defined: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for line in html[start..].lines().skip(1) {
        let t = line.trim_start();
        if t.starts_with("};") {
            break; // end of the API object literal
        }
        let cand = t.strip_prefix("async ").unwrap_or(t);
        if let Some(end) = cand.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
            let name = &cand[..end];
            let rest = cand[end..].trim_start();
            if !name.is_empty() && (rest.starts_with(':') || rest.starts_with('(')) {
                defined.insert(name.to_string());
            }
        }
    }
    assert!(
        defined.len() > 5,
        "expected to parse several API members, found {defined:?} — \
         object-literal scan boundary may be wrong"
    );

    let missing: Vec<&String> = called.iter().filter(|c| !defined.contains(*c)).collect();
    assert!(
        missing.is_empty(),
        "SPA calls API methods that are never defined on the API client \
         (dead buttons): {missing:?}",
    );
}

// ── Live event stream (SSE) contract ────────────────────────────────────────

#[tokio::test]
async fn scan_events_endpoint_is_server_sent_events() {
    // The live event stream is the project's realisation of the "live updates"
    // requirement: one-way server→browser push over SSE, not WebSockets (see
    // the rationale at `handlers::scan_events_sse`). Guard the wire contract the
    // browser's `EventSource` depends on — a 200 typed `text/event-stream`. The
    // body is an open keep-alive stream, so it is deliberately never read here.
    let (app, scan_id) = create_scan("sse-contract").await;
    let resp = app
        .oneshot(get(&format!("/api/v1/scans/{scan_id}/events")))
        .await
        .unwrap();
    assert_eq!(resp.status(), http::StatusCode::OK);
    let ct = resp
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.starts_with("text/event-stream"),
        "scan events must stream as SSE, got content-type {ct:?}"
    );
}

#[tokio::test]
async fn live_events_endpoint_is_server_sent_events() {
    // The live-session stream shares `scan_events_sse`'s plumbing via
    // `sse_event_stream` but routes on session ownership; guard its wire
    // contract independently so the two endpoints can't silently diverge.
    let app = test_app("live-sse-contract");
    let body = r#"{"kind":"domain","value":"contoso.com","options":{"modules":[]},"live":{"interval_secs":3600}}"#;
    let created = app
        .clone()
        .oneshot(post_json("/api/v1/live", body))
        .await
        .unwrap();
    assert_eq!(created.status(), 202);
    let live_id = body_json(created).await["live_id"]
        .as_str()
        .expect("live_id")
        .to_string();

    let resp = app
        .oneshot(get(&format!("/api/v1/live/{live_id}/events")))
        .await
        .unwrap();
    assert_eq!(resp.status(), http::StatusCode::OK);
    let ct = resp
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.starts_with("text/event-stream"),
        "live events must stream as SSE, got content-type {ct:?}"
    );
}

// ── HTTP response compression (mobile-bandwidth) ─────────────────────────────

/// GET with `Accept-Encoding: gzip`, as every browser sends.
fn get_gzip(uri: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header(http::header::ACCEPT_ENCODING, "gzip")
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn spa_is_gzip_compressed_for_a_gzip_capable_client() {
    // The ~118 KB SPA is the heaviest single asset on a fresh load; on a phone's
    // mobile link it must arrive gzip-compressed. Guard both that the encoding is
    // negotiated AND that the wire body is materially smaller than the source.
    let app = test_app("spa-gzip");
    let resp = app.oneshot(get_gzip("/")).await.unwrap();
    assert_eq!(resp.status(), 200);
    let enc = resp
        .headers()
        .get(http::header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(enc, "gzip", "SPA must be gzip-encoded for a gzip client");
    // A compressed response MUST advertise `Vary: Accept-Encoding` so a shared
    // cache never hands a gzipped body to a client that didn't negotiate it.
    let vary = resp
        .headers()
        .get_all(http::header::VARY)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect::<Vec<_>>()
        .join(",")
        .to_ascii_lowercase();
    assert!(
        vary.contains("accept-encoding"),
        "compressed response must Vary on Accept-Encoding, got {vary:?}"
    );
    let bytes = axum::body::to_bytes(resp.into_body(), 2_000_000)
        .await
        .unwrap();
    // The uncompressed SPA is ~212 KB; gzip should bring the wire body well
    // under half that. (Generous bound so a future SPA edit doesn't flake.)
    assert!(
        bytes.len() < 80_000,
        "gzipped SPA should be much smaller than the ~212 KB source, got {} bytes",
        bytes.len()
    );
}

#[tokio::test]
async fn sse_stream_is_never_compressed() {
    // CompressionLayer's default predicate must exclude `text/event-stream`:
    // buffering an open keep-alive SSE body to compress it would stall the live
    // event log. Even with `Accept-Encoding: gzip`, the stream must be identity.
    let (app, scan_id) = create_scan("sse-nogzip").await;
    let resp = app
        .oneshot(get_gzip(&format!("/api/v1/scans/{scan_id}/events")))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert!(
        resp.headers().get(http::header::CONTENT_ENCODING).is_none(),
        "SSE stream must not be compressed"
    );
    // Body is an open stream — deliberately not read.
}

// ── Scan diff endpoint ───────────────────────────────────────────────────────

#[tokio::test]
async fn scan_diff_endpoint_reports_added_removed_common() {
    let (app, store) = test_app_with_store("diff");
    // Scan A: keep@x.com + gone@x.com
    let a = Scan::new("s-a", Target::new(TargetKind::FullName, "Target A"));
    store.upsert_scan(&a).unwrap();
    for v in ["keep@x.com", "gone@x.com"] {
        store
            .upsert_entity(&Entity::new(EntityKind::Email, v, 0.8, "s-a"))
            .unwrap();
    }
    // Scan B: keep@x.com + new@x.com
    let b = Scan::new("s-b", Target::new(TargetKind::FullName, "Target B"));
    store.upsert_scan(&b).unwrap();
    for v in ["keep@x.com", "new@x.com"] {
        store
            .upsert_entity(&Entity::new(EntityKind::Email, v, 0.8, "s-b"))
            .unwrap();
    }

    let resp = app
        .oneshot(get("/api/v1/scans/s-a/diff/s-b"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let j = body_json(resp).await;
    assert_eq!(j["common"], 1, "keep@x.com is in both");
    assert_eq!(j["added"].as_array().unwrap().len(), 1);
    assert_eq!(j["removed"].as_array().unwrap().len(), 1);
    assert_eq!(j["added"][0]["value"], "new@x.com", "in B, not A");
    assert_eq!(j["removed"][0]["value"], "gone@x.com", "in A, not B");
}

#[tokio::test]
async fn scan_diff_404_for_unknown_scan() {
    let (app, _store) = test_app_with_store("diff-404");
    let resp = app
        .oneshot(get("/api/v1/scans/nope-a/diff/nope-b"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn keys_status_endpoint_returns_service_summary_shape() {
    // Reads the process-global key pool (env-dependent contents), so this
    // asserts the wire contract, not specific data: a `{ count, services[] }`
    // object with the two in sync. The per-service counting + value-free
    // guarantee are unit-tested in handlers::tests::summarize_pool_*.
    // The endpoint is loopback-only (per-service pool inventory is sensitive
    // infra metadata), so inject a loopback ConnectInfo like keys/pool does.
    use std::net::SocketAddr;
    let app = test_app("keys-status");
    let loopback: SocketAddr = "127.0.0.1:9999".parse().unwrap();
    let mut req = get("/api/v1/keys/status");
    req.extensions_mut()
        .insert(axum::extract::ConnectInfo(loopback));
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let j = body_json(resp).await;
    let services = j["services"].as_array().expect("services array");
    assert_eq!(j["count"].as_u64().unwrap() as usize, services.len());
}

#[tokio::test]
async fn keys_status_endpoint_refuses_non_loopback_peer() {
    // Per-service key-pool inventory (which services hold keys, how healthy)
    // must not leak to a LAN peer under an operator-chosen non-loopback bind —
    // the same guard keys/pool GET already enforces for this data class.
    use std::net::SocketAddr;
    let app = test_app("keys-status-lan");
    let lan: SocketAddr = "192.168.1.50:40000".parse().unwrap();
    let mut req = get("/api/v1/keys/status");
    req.extensions_mut().insert(axum::extract::ConnectInfo(lan));
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 403, "key-pool status must be loopback-only");
}

#[tokio::test]
async fn keys_patterns_endpoint_returns_detector_catalogue_shape() {
    // The key-shape detector catalogue powers the SPA "Key diagnostics" coverage
    // line. Previously this endpoint had zero test coverage. Wire contract:
    // `{ count, unique_services, patterns[] }` with count == patterns.len().
    let app = test_app("keys-patterns");
    let resp = app.oneshot(get("/api/v1/keys/patterns")).await.unwrap();
    assert_eq!(resp.status(), 200);
    let j = body_json(resp).await;
    let patterns = j["patterns"].as_array().expect("patterns array");
    assert_eq!(j["count"].as_u64().unwrap() as usize, patterns.len());
    assert!(
        j["unique_services"].as_u64().unwrap() >= 1,
        "the catalogue must cover at least one service"
    );
    assert!(
        !patterns.is_empty(),
        "the detector catalogue must be non-empty"
    );
}

#[tokio::test]
async fn selftest_endpoint_returns_structured_report() {
    // GET /api/v1/selftest runs the full module + feature suite on demand and
    // returns the structured report the Web UI renders.
    let app = test_app("selftest-ep");
    let resp = app.oneshot(get("/api/v1/selftest")).await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::OK);
    let j = body_json(resp).await;
    assert!(j["ok"].is_boolean(), "report has a boolean `ok`");
    assert!(j["elapsed_ms"].is_number(), "report has elapsed_ms");
    let checks = j["checks"].as_array().expect("checks array");
    assert!(
        checks.len() >= 5,
        "full suite runs (>=5 checks), got {}",
        checks.len()
    );
    // Each check is a {name, status, detail} triple with a known status.
    for c in checks {
        assert!(c["name"].is_string());
        let st = c["status"].as_str().unwrap_or("");
        assert!(
            matches!(st, "pass" | "warn" | "fail"),
            "unexpected status {st}"
        );
    }
}

#[tokio::test]
async fn logs_endpoint_serves_downloadable_text_attachment() {
    // GET /api/v1/logs streams the verbose debug-log ring buffer as a
    // downloadable text file (the Settings "Download debug log" button). The
    // endpoint is loopback-only (TRACE logs hold scan PII), so inject a loopback
    // peer via request extensions the way the key-pool test does.
    let app = test_app("logs-ep");
    let loopback: std::net::SocketAddr = "127.0.0.1:9999".parse().unwrap();
    let mut req = get("/api/v1/logs");
    req.extensions_mut()
        .insert(axum::extract::ConnectInfo(loopback));
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::OK);
    let ct = resp
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.starts_with("text/plain"),
        "logs are text/plain, got {ct}"
    );
    let cd = resp
        .headers()
        .get(http::header::CONTENT_DISPOSITION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        cd.contains("attachment") && cd.contains(".log"),
        "served as a .log attachment, got {cd:?}"
    );
    let bytes = axum::body::to_bytes(resp.into_body(), 5_000_000)
        .await
        .unwrap();
    assert!(
        String::from_utf8_lossy(&bytes).contains("Huntsman Search Engine"),
        "dump carries its header"
    );

    // A NON-loopback peer must be refused — the TRACE ring buffer holds scan PII
    // and must not stream to a LAN peer under a non-loopback bind.
    let app = test_app("logs-ep2");
    let lan: std::net::SocketAddr = "192.168.1.50:40000".parse().unwrap();
    let mut req = get("/api/v1/logs");
    req.extensions_mut().insert(axum::extract::ConnectInfo(lan));
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        http::StatusCode::FORBIDDEN,
        "debug logs must be loopback-only"
    );
}

#[tokio::test]
async fn keys_pool_get_is_masked_and_revoke_is_write_gated() {
    // The web key-pool surface: GET returns a masked, loopback-only view; revoke
    // is a write, so it's refused unless the server was started with key-write.
    // ConnectInfo is injected via request extensions (no real TCP listener).
    use std::net::SocketAddr;
    let loopback: SocketAddr = "127.0.0.1:9999".parse().unwrap();
    let app = test_app("keys-pool");

    let mut get = Request::builder()
        .uri("/api/v1/keys/pool")
        .body(Body::empty())
        .unwrap();
    get.extensions_mut()
        .insert(axum::extract::ConnectInfo(loopback));
    let resp = app.clone().oneshot(get).await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::OK);
    let body = body_json(resp).await;
    assert!(
        body.get("services").is_some(),
        "pool returns a services list"
    );

    // Revoke without --allow-key-write (test_app default) must be forbidden.
    let mut post = Request::builder()
        .method("POST")
        .uri("/api/v1/keys/pool/revoke")
        .header("content-type", "application/json")
        .header("x-hse-csrf", "1")
        .body(Body::from(r#"{"service":"shodan","id":"deadbeef"}"#))
        .unwrap();
    post.extensions_mut()
        .insert(axum::extract::ConnectInfo(loopback));
    let resp = app.oneshot(post).await.unwrap();
    assert_eq!(
        resp.status(),
        http::StatusCode::FORBIDDEN,
        "pool revoke must require --allow-key-write"
    );
}

#[tokio::test]
async fn keys_pool_add_is_write_gated() {
    // Adding a new pooled key is a write — refused without --allow-key-write
    // (test_app default), same policy as revoke/rotate. This is the web
    // equivalent of `hse keys add`, previously CLI-only.
    use std::net::SocketAddr;
    let loopback: SocketAddr = "127.0.0.1:9999".parse().unwrap();
    let app = test_app("keys-pool-add");
    let mut post = Request::builder()
        .method("POST")
        .uri("/api/v1/keys/pool/add")
        .header("content-type", "application/json")
        .header("x-hse-csrf", "1")
        .body(Body::from(r#"{"service":"shodan","key":"NEW-KEY-VALUE"}"#))
        .unwrap();
    post.extensions_mut()
        .insert(axum::extract::ConnectInfo(loopback));
    let resp = app.oneshot(post).await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn keys_pool_rotate_is_write_gated() {
    // Rotation is a write — refused without --allow-key-write (test_app default),
    // never a silent no-op.
    use std::net::SocketAddr;
    let loopback: SocketAddr = "127.0.0.1:9999".parse().unwrap();
    let app = test_app("keys-pool-rotate");
    let mut post = Request::builder()
        .method("POST")
        .uri("/api/v1/keys/pool/rotate")
        .header("content-type", "application/json")
        .header("x-hse-csrf", "1")
        .body(Body::from(
            r#"{"service":"shodan","id":"deadbeef","new":"NEW-VAL"}"#,
        ))
        .unwrap();
    post.extensions_mut()
        .insert(axum::extract::ConnectInfo(loopback));
    let resp = app.oneshot(post).await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn plan_preview_lists_engaged_modules_for_a_seed() {
    let app = test_app("plan");
    // A two-word name seed detects as a full name and engages real registry modules,
    // WITHOUT running a scan.
    let resp = app
        .clone()
        .oneshot(get("/api/v1/plan?value=Kyle%20Diegmann"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let json = body_json(resp).await;
    assert_eq!(json["kind"].as_str().unwrap(), "full_name");
    assert!(
        json["module_count"].as_u64().unwrap() > 0,
        "a name seed engages at least one module"
    );
    assert!(json["modules"].is_array());
    assert!(json["categories"].is_array());

    // An empty value is rejected cleanly, not a panic.
    let resp = app.oneshot(get("/api/v1/plan?value=")).await.unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn scan_profiles_lists_the_full_named_catalogue_including_skiptrace() {
    // The New Scan wizard's profile picker has no other source of truth for
    // the name/description list — this pins the wire shape it depends on,
    // and that `skiptrace` (the debtor-location profile, previously
    // unreachable from the browser at all) is actually present.
    let app = test_app("scan-profiles");
    let resp = app.oneshot(get("/api/v1/scan/profiles")).await.unwrap();
    assert_eq!(resp.status(), 200);
    let json = body_json(resp).await;
    let profiles = json["profiles"].as_array().expect("profiles array");
    assert_eq!(
        profiles.len(),
        6,
        "every core::profiles::list_profiles() entry must be present"
    );
    let names: Vec<&str> = profiles
        .iter()
        .map(|p| p["name"].as_str().unwrap())
        .collect();
    for expected in [
        "recommended",
        "passive",
        "footprint",
        "investigate",
        "fast",
        "skiptrace",
    ] {
        assert!(
            names.contains(&expected),
            "missing profile {expected} — got {names:?}"
        );
    }
    for p in profiles {
        assert!(
            p["description"].as_str().is_some_and(|d| !d.is_empty()),
            "every profile must carry a non-empty description for the picker's tooltip/help text"
        );
    }
}

#[tokio::test]
async fn scan_benchmark_returns_a_scorecard() {
    let (app, store) = test_app_with_store("benchmark");
    let scan = Scan::new(
        "s-bench",
        Target::new(TargetKind::FullName, "Subject Person"),
    );
    store.upsert_scan(&scan).unwrap();
    for v in ["a@example.com", "b@example.com"] {
        store
            .upsert_entity(&Entity::new(EntityKind::Email, v, 0.8, "s-bench"))
            .unwrap();
    }
    let resp = app
        .clone()
        .oneshot(get("/api/v1/scans/s-bench/benchmark"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let json = body_json(resp).await;
    assert_eq!(json["scan_id"].as_str().unwrap(), "s-bench");
    assert_eq!(
        json["scorecard"]["total_entities"].as_u64().unwrap(),
        2,
        "the scorecard reflects the seeded entities"
    );
    assert!(
        json["metrics"].is_object(),
        "the full metrics are embedded for traceability"
    );

    // Unknown scan -> 404.
    let resp = app
        .oneshot(get("/api/v1/scans/__nope__/benchmark"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn scan_pivots_reports_cut_vertices_and_bridges() {
    let (app, store) = test_app_with_store("pivots");
    let scan = Scan::new("s-piv", Target::new(TargetKind::FullName, "Subject Person"));
    store.upsert_scan(&scan).unwrap();

    // A path a—b—c—d: the interior nodes b and c are cut vertices, and all three
    // edges are bridges (single points of failure for connectivity).
    let a = Entity::new(EntityKind::Person, "Aa Person", 0.8, "s-piv");
    let b = Entity::new(EntityKind::Email, "b@example.com", 0.8, "s-piv");
    let c = Entity::new(EntityKind::Phone, "+15551230000", 0.8, "s-piv");
    let d = Entity::new(EntityKind::Domain, "d.example.com", 0.8, "s-piv");
    for e in [&a, &b, &c, &d] {
        store.upsert_entity(e).unwrap();
    }
    for (x, y) in [(&a, &b), (&b, &c), (&c, &d)] {
        store
            .upsert_relation(&Relation::new(
                x.uid.as_str(),
                y.uid.as_str(),
                RelationKind::AssociatedWith,
                0.7,
                "s-piv",
            ))
            .unwrap();
    }

    let resp = app
        .clone()
        .oneshot(get("/api/v1/scans/s-piv/pivots"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let json = body_json(resp).await;

    let pivots = json["pivots"].as_array().expect("pivots is a list");
    assert!(!pivots.is_empty(), "the path's interior nodes are pivots");
    assert!(
        pivots
            .iter()
            .any(|p| p["is_cut_vertex"].as_bool() == Some(true)),
        "at least one pivot is flagged a cut vertex (single point of failure)"
    );

    let bridges = json["bridges"].as_array().expect("bridges is a list");
    assert_eq!(bridges.len(), 3, "every edge on the path is a bridge");
    for br in bridges {
        assert!(br["from_uid"].is_string() && br["to_uid"].is_string());
    }

    // Unknown scan -> 404, matching the other sub-resources.
    let resp = app
        .oneshot(get("/api/v1/scans/__nope__/pivots"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn scan_gaps_reports_isolated_seeds_with_corrective_modules() {
    let (app, store) = test_app_with_store("gaps");
    let scan = Scan::new("s-gap", Target::new(TargetKind::FullName, "Subject Person"));
    store.upsert_scan(&scan).unwrap();

    // A linked pair (email—domain) plus an isolated phone (no relation).
    let a = Entity::new(EntityKind::Email, "a@example.test", 0.8, "s-gap");
    let b = Entity::new(EntityKind::Domain, "example.test", 0.8, "s-gap");
    let orphan = Entity::new(EntityKind::Phone, "+15551230000", 0.8, "s-gap");
    for e in [&a, &b, &orphan] {
        store.upsert_entity(e).unwrap();
    }
    store
        .upsert_relation(&Relation::new(
            a.uid.as_str(),
            b.uid.as_str(),
            RelationKind::BelongsToDomain,
            0.7,
            "s-gap",
        ))
        .unwrap();

    let resp = app
        .clone()
        .oneshot(get("/api/v1/scans/s-gap/gaps"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let json = body_json(resp).await;

    assert_eq!(json["total_seeds"].as_u64().unwrap(), 3);
    assert_eq!(json["linked_seeds"].as_u64().unwrap(), 2);
    assert_eq!(json["isolated_seeds"].as_u64().unwrap(), 1);
    let orphans = json["orphans"].as_array().expect("orphans is a list");
    assert_eq!(orphans.len(), 1, "the isolated phone is the only orphan");
    let o = &orphans[0];
    assert_eq!(o["kind"].as_str().unwrap(), "phone");
    assert_eq!(o["isolation"].as_str().unwrap(), "unexpanded");
    assert_eq!(o["reinjection_target"].as_str().unwrap(), "phone");
    assert!(
        !o["corrective_modules"].as_array().unwrap().is_empty(),
        "the orphan phone has registered modules that would query it"
    );

    // Unknown scan -> 404.
    let resp = app
        .oneshot(get("/api/v1/scans/__nope__/gaps"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

// ── Regression tests derived from real execution: 6 routes with zero prior ──
// coverage, detected by cross-referencing the live route table against the    ──
// test file. Each test verifies: 404 for unknown scan + 200 with the correct  ──
// JSON shape for a known scan, grounding the contract in real handler output.  ──

#[tokio::test]
async fn scan_audit_404_unknown_and_200_with_score_for_known() {
    let (app, sid) = create_scan("audit-cov").await;

    let resp = app
        .clone()
        .oneshot(get(&format!("/api/v1/scans/{sid}/audit")))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "audit must 200 for a known scan");
    let json = body_json(resp).await;
    // Audit report must have the canonical top-level keys.
    assert!(
        json["score"].is_number(),
        "audit must include a numeric score"
    );
    assert!(
        json["grade"].is_string(),
        "audit must include a grade string"
    );
    assert!(
        json["entity_total"].is_number(),
        "audit must include entity_total"
    );
    assert!(
        json["findings"].is_array(),
        "audit must include a findings array"
    );
    assert!(
        json["tiers"].is_object(),
        "audit must include a tiers object"
    );

    let resp = app
        .oneshot(get("/api/v1/scans/__nope__/audit"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "audit must 404 for an unknown scan");
}

#[tokio::test]
async fn scan_timeline_404_unknown_and_200_list_for_known() {
    let (app, sid) = create_scan("timeline-cov").await;

    let resp = app
        .clone()
        .oneshot(get(&format!("/api/v1/scans/{sid}/timeline")))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "timeline must 200 for a known scan");
    let json = body_json(resp).await;
    assert!(
        json["events"].is_array(),
        "timeline must return an 'events' array"
    );
    assert!(json["count"].is_number(), "timeline must include a count");

    let resp = app
        .oneshot(get("/api/v1/scans/__nope__/timeline"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "timeline must 404 for an unknown scan");
}

#[tokio::test]
async fn scan_communities_404_unknown_and_200_list_for_known() {
    let (app, sid) = create_scan("communities-cov").await;

    let resp = app
        .clone()
        .oneshot(get(&format!("/api/v1/scans/{sid}/communities")))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "communities must 200 for a known scan");
    let json = body_json(resp).await;
    assert!(
        json["communities"].is_array(),
        "communities must return a 'communities' array"
    );
    assert!(
        json["count"].is_number(),
        "communities must include a count"
    );

    let resp = app
        .oneshot(get("/api/v1/scans/__nope__/communities"))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        404,
        "communities must 404 for an unknown scan"
    );
}

#[tokio::test]
async fn scan_trust_404_unknown_and_200_list_for_known() {
    let (app, sid) = create_scan("trust-cov").await;

    let resp = app
        .clone()
        .oneshot(get(&format!("/api/v1/scans/{sid}/trust")))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "trust must 200 for a known scan");
    let json = body_json(resp).await;
    assert!(
        json["trust"].is_array(),
        "trust must return a 'trust' array"
    );
    assert!(json["count"].is_number(), "trust must include a count");

    let resp = app
        .oneshot(get("/api/v1/scans/__nope__/trust"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "trust must 404 for an unknown scan");
}

#[tokio::test]
async fn scan_duplicates_404_unknown_and_200_list_for_known() {
    let (app, sid) = create_scan("dupes-cov").await;

    let resp = app
        .clone()
        .oneshot(get(&format!("/api/v1/scans/{sid}/duplicates")))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "duplicates must 200 for a known scan");
    let json = body_json(resp).await;
    assert!(
        json["duplicates"].is_array(),
        "duplicates must return a 'duplicates' array"
    );
    assert!(json["count"].is_number(), "duplicates must include a count");

    let resp = app
        .oneshot(get("/api/v1/scans/__nope__/duplicates"))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        404,
        "duplicates must 404 for an unknown scan"
    );
}

#[tokio::test]
async fn scan_debug_bundle_404_unknown_and_text_attachment_for_known() {
    let (app, sid) = create_scan("debug-cov").await;

    let resp = app
        .clone()
        .oneshot(get(&format!("/api/v1/scans/{sid}/debug.txt")))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "debug.txt must 200 for a known scan");
    let ct = resp
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.starts_with("text/plain"),
        "debug.txt must be text/plain, got {ct:?}"
    );
    let cd = resp
        .headers()
        .get(http::header::CONTENT_DISPOSITION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        cd.contains("attachment") && cd.contains(".txt"),
        "debug.txt must carry a download Content-Disposition, got {cd:?}"
    );

    let resp = app
        .oneshot(get("/api/v1/scans/__nope__/debug.txt"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "debug.txt must 404 for an unknown scan");
}

// ── Security: DNS-rebind Host guard + scan-import CSRF ──────────────────────

#[tokio::test]
async fn dns_rebind_host_header_is_rejected() {
    let app = test_app("rebind");
    // A mismatched Host (the DNS-rebind attacker's domain) is refused with 403
    // before any handler — even though the socket peer is loopback.
    let req = Request::builder()
        .uri("/api/v1/health")
        .header("host", "evil.example.com")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 403, "a rebind Host must be rejected");

    // A loopback Host the user legitimately types is allowed through.
    let ok = Request::builder()
        .uri("/api/v1/health")
        .header("host", "localhost:8080")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(ok).await.unwrap();
    assert_eq!(resp.status(), 200, "a legitimate loopback Host passes");
}

#[tokio::test]
async fn scan_import_requires_csrf_header() {
    let app = test_app("csrf");
    let dossier = "Entry #1:\nEMAILS: a@b.com\n";
    // A text/plain POST WITHOUT the custom header is a CORS simple request — the
    // CSRF vector — and must be blocked with 403.
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/scans/import")
        .header("content-type", "text/plain")
        .body(Body::from(dossier))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        403,
        "import without X-HSE-CSRF must be blocked"
    );

    // WITH the header the request is no longer CSRF-blocked (it proceeds to parse).
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/scans/import")
        .header("content-type", "text/plain")
        .header("x-hse-csrf", "1")
        .header("x-hse-csrf", "1")
        .body(Body::from(dossier))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_ne!(
        resp.status(),
        403,
        "with X-HSE-CSRF the import is not CSRF-blocked"
    );
}

#[tokio::test]
async fn bodyless_mutating_post_requires_csrf_header() {
    // The vulnerability the CSRF middleware closes: a BODYLESS mutating POST is a
    // CORS simple request (no preflight), so a cross-site page could previously
    // drive /scan/auto, /radar, /update/trigger and the scan controls without the
    // header — only /scans/import checked. The guard now rejects ANY mutating
    // request lacking X-HSE-CSRF, before the handler runs (no side effect). Using
    // a cancel of a non-existent scan keeps the with-header case side-effect-free.
    let app = test_app("csrf_bodyless");
    let uri = "/api/v1/scans/does-not-exist/cancel";
    let no_hdr = Request::builder()
        .method("POST")
        .uri(uri)
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(no_hdr).await.unwrap();
    assert_eq!(
        resp.status(),
        403,
        "a bodyless mutating POST without X-HSE-CSRF must be blocked"
    );

    let with_hdr = Request::builder()
        .method("POST")
        .uri(uri)
        .header("x-hse-csrf", "1")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(with_hdr).await.unwrap();
    assert_ne!(
        resp.status(),
        403,
        "with X-HSE-CSRF the request reaches the handler (404 for the missing scan)"
    );
}

// ── System self-diagnosis debug bundle ──────────────────────────────────────

/// Build a GET request carrying a `ConnectInfo<SocketAddr>` peer, so the
/// loopback-gated handlers (logs, system debug bundle) see a client address
/// under `.oneshot()` — production supplies this via
/// `into_make_service_with_connect_info`.
fn get_with_peer(uri: &str, peer: &str) -> Request<Body> {
    let mut req = Request::builder().uri(uri).body(Body::empty()).unwrap();
    let addr: std::net::SocketAddr = peer.parse().expect("valid socket addr");
    req.extensions_mut()
        .insert(axum::extract::ConnectInfo(addr));
    req
}

#[tokio::test]
async fn system_debug_bundle_is_loopback_gated() {
    // The bundle embeds the TRACE log ring (scan targets / PII), so a
    // non-loopback peer must be refused — the same gate `/logs` carries.
    let app = test_app("sysdbg-gate");
    let resp = app
        .oneshot(get_with_peer("/api/v1/debug/bundle", "192.168.1.10:5555"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "non-loopback peer must be forbidden");
}

#[tokio::test]
async fn system_debug_bundle_returns_the_diagnostic_artifact_on_loopback() {
    let app = test_app("sysdbg-ok");
    let resp = app
        .oneshot(get_with_peer("/api/v1/debug/bundle", "127.0.0.1:5555"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(ct.starts_with("text/plain"), "content-type was {ct}");
    let cd = resp
        .headers()
        .get("content-disposition")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        cd.contains("attachment") && cd.contains("hse-system-debug-"),
        "download disposition was {cd}"
    );
    let bytes = axum::body::to_bytes(resp.into_body(), 50_000_000)
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&bytes);
    // The consolidated artifact carries every top-level section — one file, the
    // whole engine's diagnostic + validation state.
    for header in [
        "HUNTSMAN SYSTEM DEBUG BUNDLE",
        "── DETECTED ISSUES",
        "── ENVIRONMENT",
        "── UPDATE STATUS ──",
        "── DISABLED CAPABILITIES",
        "── VALIDATION (SELF-TEST) ──",
        "── MODULE HEALTH",
        "── SEARCH-ENGINE LIVENESS",
        "── SCRAPER HEALTH",
        "── PROVIDER QUOTAS",
        "── KEY POOL",
        "── STORAGE HEALTH",
        "── RECENT SCANS",
        "── RECENT LOGS",
        "── SOURCE FILES",
    ] {
        assert!(body.contains(header), "bundle missing section: {header}");
    }
}

#[tokio::test]
async fn radar_recurring_returns_devices_array() {
    // With an empty radar history the endpoint must still answer 200 with a
    // well-formed (empty) devices array — the cross-sweep persistent-device
    // review surface (AU-122/117's temporal counterpart, core::radar_track).
    let app = test_app("radar-recurring");
    let resp = app.oneshot(get("/api/v1/radar/recurring")).await.unwrap();
    assert_eq!(resp.status(), 200);
    let json = body_json(resp).await;
    assert!(
        json["devices"].as_array().is_some(),
        "response must carry a 'devices' array"
    );
}
