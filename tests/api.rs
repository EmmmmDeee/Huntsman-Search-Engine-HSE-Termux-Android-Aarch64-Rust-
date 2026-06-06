//! API handler integration tests — exercises every HTTP endpoint
//! through axum's test utilities with a real SQLite store.

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
    let mut p = std::env::temp_dir();
    p.push(format!("hse-api-{}-{}.db", std::process::id(), suffix));
    let s = p.to_string_lossy().into_owned();
    let _ = std::fs::remove_file(&s);
    let _ = std::fs::remove_file(format!("{s}-wal"));
    let _ = std::fs::remove_file(format!("{s}-shm"));
    s
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
        proxy_pool: Default::default(),
        scan_semaphore: Arc::new(tokio::sync::Semaphore::new(
            huntsman_search_engine::api::MAX_CONCURRENT_SCANS,
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
        proxy_pool: Default::default(),
        scan_semaphore: Arc::new(tokio::sync::Semaphore::new(
            huntsman_search_engine::api::MAX_CONCURRENT_SCANS,
        )),
    });
    (router(state, "127.0.0.1:8080"), store)
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

/// Shorthand: build a POST request with a JSON body.
fn post_json(uri: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

/// Shorthand: build a DELETE request.
fn delete(uri: &str) -> Request<Body> {
    Request::builder()
        .method("DELETE")
        .uri(uri)
        .body(Body::empty())
        .unwrap()
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
    for field in [
        "verified",
        "user",
        "daily_api_calls",
        "monthly_api_calls",
        "last_polled_ts",
    ] {
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
    let resp = app
        .oneshot(delete(&format!("/api/v1/scans/{scan_id}")))
        .await
        .unwrap();
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

// ── 16. Settings keys GET ─────────────────────────────────────────────────

#[tokio::test]
async fn settings_keys_get_lists_keys() {
    let app = test_app("keys_get");
    let resp = app.oneshot(get("/api/v1/settings/keys")).await.unwrap();
    assert_eq!(resp.status(), 200);
    let json = body_json(resp).await;
    assert!(
        json.get("keys").is_some(),
        "response must contain keys array"
    );
    assert!(json["keys"].as_array().is_some());
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

#[tokio::test]
async fn spa_served_with_required_ui_structure() {
    let app = test_app("spa-structure");
    let (status, html) = fetch_text(&app, "/").await;
    assert_eq!(status, http::StatusCode::OK);
    assert!(
        html.len() > 10_000,
        "SPA document suspiciously small ({} bytes)",
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
    let (_, html) = fetch_text(&app, "/").await;

    let bases = segments_after(&html, "/api/v1/", |c| c.is_ascii_lowercase() || c == '_');
    assert!(
        !bases.is_empty(),
        "extracted no /api/v1 endpoints from the served SPA"
    );

    for base in &bases {
        // A representative, parameter-free URL for this endpoint family.
        let url = match base.as_str() {
            "health" => "/api/v1/health".to_string(),
            "version" => "/api/v1/version".to_string(),
            "modules" => "/api/v1/modules".to_string(),
            "engines" => "/api/v1/engines/health".to_string(),
            "stats" => "/api/v1/stats".to_string(),
            "scans" => "/api/v1/scans".to_string(),
            "search" => "/api/v1/search?q=x".to_string(),
            "settings" => "/api/v1/settings/keys".to_string(),
            "selftest" => "/api/v1/selftest".to_string(),
            "logs" => "/api/v1/logs".to_string(),
            "live" => "/api/v1/live".to_string(),
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
    let (_, html) = fetch_text(&app, "/").await;
    let files = segments_after(&html, "/static/", |c| {
        c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_'
    });
    assert!(
        files.len() >= 5,
        "expected the SPA to load several vendored assets, found {files:?}"
    );
    for f in &files {
        let (status, body) = fetch_text(&app, &format!("/static/{f}")).await;
        assert_eq!(
            status,
            http::StatusCode::OK,
            "vendored asset /static/{f} not served (broken link)"
        );
        assert!(!body.is_empty(), "vendored asset /static/{f} served empty");
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
    let (status, html) = fetch_text(&app, "/").await;
    assert_eq!(status, http::StatusCode::OK, "SPA `/` must serve 200");

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
    // The uncompressed SPA is ~118 KB; gzip should bring the wire body well
    // under half that. (Generous bound so a future SPA edit doesn't flake.)
    assert!(
        bytes.len() < 60_000,
        "gzipped SPA should be much smaller than the ~118 KB source, got {} bytes",
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
    let app = test_app("keys-status");
    let resp = app.oneshot(get("/api/v1/keys/status")).await.unwrap();
    assert_eq!(resp.status(), 200);
    let j = body_json(resp).await;
    let services = j["services"].as_array().expect("services array");
    assert_eq!(j["count"].as_u64().unwrap() as usize, services.len());
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
    // downloadable text file (the Settings "Download debug log" button).
    let app = test_app("logs-ep");
    let resp = app.oneshot(get("/api/v1/logs")).await.unwrap();
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
}
