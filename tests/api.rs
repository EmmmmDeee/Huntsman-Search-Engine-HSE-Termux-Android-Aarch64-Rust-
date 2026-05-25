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
        scan::{Target, TargetKind},
    },
    storage::store::Store,
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
    });
    router(state, "127.0.0.1:8080")
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
    let body = r#"{"kind":"email","value":"test@example.com","options":{}}"#;
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
}

// ── 4. Scan create (valid) ────────────────────────────────────────────────

#[tokio::test]
async fn scan_create_accepts_valid_request() {
    let app = test_app("scan_create");
    let body = r#"{"kind":"email","value":"test@example.com","options":{}}"#;
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
