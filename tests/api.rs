//! API handler integration tests — exercises HTTP endpoints through
//! axum's test utilities with a real SQLite store.

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
        r.push(Entity::new(
            EntityKind::Email,
            &target.value,
            0.95,
            &ctx.scan_id,
        ));
        Ok(r)
    }
}

fn tmp_db(suffix: &str) -> String {
    let mut p = std::env::temp_dir();
    p.push(format!("hse-api-{}-{}.db", std::process::id(), suffix));
    let s = p.to_string_lossy().into_owned();
    let _ = std::fs::remove_file(&s);
    let _ = std::fs::remove_file(format!("{s}-wal"));
    let _ = std::fs::remove_file(format!("{s}-shm"));
    s
}

fn test_app(suffix: &str) -> axum::Router {
    let path = tmp_db(suffix);
    let store = Arc::new(Store::open(&path).unwrap());
    let (bus, _rx) = tokio::sync::broadcast::channel(256);
    let modules: Vec<Arc<dyn Module>> = vec![Arc::new(SyntheticModule)];
    let engine = Arc::new(ScanEngine::new(modules, Arc::clone(&store), bus.clone()));
    let live = LiveScanner::new(Arc::clone(&engine), bus.clone());
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

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 1_000_000)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn get(uri: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .body(Body::empty())
        .unwrap()
}

fn post_json(uri: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn delete(uri: &str) -> Request<Body> {
    Request::builder()
        .method("DELETE")
        .uri(uri)
        .body(Body::empty())
        .unwrap()
}

// ─── Health / Version ──────────────────────────────────────────────────────

#[tokio::test]
async fn health_returns_ok() {
    let app = test_app("health");
    let resp = app.oneshot(get("/api/v1/health")).await.unwrap();
    assert_eq!(resp.status(), 200);
    let json = body_json(resp).await;
    assert_eq!(json["status"], "ok");
    assert!(json["version"].is_string());
}

#[tokio::test]
async fn version_returns_version() {
    let app = test_app("version");
    let resp = app.oneshot(get("/api/v1/version")).await.unwrap();
    assert_eq!(resp.status(), 200);
    let json = body_json(resp).await;
    assert!(json["version"].is_string());
}

// ─── Modules ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn modules_list_returns_array() {
    let app = test_app("modules");
    let resp = app.oneshot(get("/api/v1/modules")).await.unwrap();
    assert_eq!(resp.status(), 200);
    let json = body_json(resp).await;
    assert!(json["modules"].is_array());
    assert!(json["count"].as_u64().unwrap() >= 1);
}

// ─── Stats ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn stats_returns_counts() {
    let app = test_app("stats");
    let resp = app.oneshot(get("/api/v1/stats")).await.unwrap();
    assert_eq!(resp.status(), 200);
    let json = body_json(resp).await;
    assert!(json["scans_total"].is_number());
    assert!(json["modules"].is_number());
    assert!(json["version"].is_string());
}

// ─── Scan CRUD ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn scan_create_accepts_valid_request() {
    let app = test_app("scan_create");
    let body = r#"{"kind":"email","value":"test@example.com","options":{}}"#;
    let resp = app
        .oneshot(post_json("/api/v1/scans", body))
        .await
        .unwrap();
    assert_eq!(resp.status(), 202);
    let json = body_json(resp).await;
    assert!(json["scan_id"].is_string());
    assert_eq!(json["status"], "queued");
}

#[tokio::test]
async fn scan_create_rejects_invalid_target() {
    let app = test_app("scan_bad");
    let body = r#"{"kind":"email","value":"not-an-email","options":{}}"#;
    let resp = app
        .oneshot(post_json("/api/v1/scans", body))
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let json = body_json(resp).await;
    assert!(json["error"].is_string());
}

#[tokio::test]
async fn scan_list_returns_scans() {
    let path = tmp_db("scan_list");
    let store = Arc::new(Store::open(&path).unwrap());
    let (bus, _rx) = tokio::sync::broadcast::channel(256);
    let modules: Vec<Arc<dyn Module>> = vec![Arc::new(SyntheticModule)];
    let engine = Arc::new(ScanEngine::new(modules, Arc::clone(&store), bus.clone()));
    let live = LiveScanner::new(Arc::clone(&engine), bus.clone());
    let state = Arc::new(AppState {
        store: Arc::clone(&store),
        engine,
        bus,
        live,
        http: reqwest::Client::new(),
        allow_key_write: false,
        cancellations: Arc::new(parking_lot::Mutex::new(HashMap::new())),
    });
    let app = router(state, "127.0.0.1:8080");

    let body = r#"{"kind":"email","value":"list@example.com","options":{}}"#;
    let resp = app
        .clone()
        .oneshot(post_json("/api/v1/scans", body))
        .await
        .unwrap();
    assert_eq!(resp.status(), 202);

    let resp = app.oneshot(get("/api/v1/scans")).await.unwrap();
    assert_eq!(resp.status(), 200);
    let json = body_json(resp).await;
    assert!(json["scans"].is_array());
    assert!(json["count"].as_u64().unwrap() >= 1);
}

#[tokio::test]
async fn scan_get_not_found() {
    let app = test_app("scan_nf");
    let resp = app
        .oneshot(get("/api/v1/scans/nonexistent-id"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn scan_delete_not_found() {
    let app = test_app("scan_del_nf");
    let resp = app
        .oneshot(delete("/api/v1/scans/nonexistent-id"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn scan_correlations_empty() {
    let path = tmp_db("scan_corr");
    let store = Arc::new(Store::open(&path).unwrap());
    let (bus, _rx) = tokio::sync::broadcast::channel(256);
    let modules: Vec<Arc<dyn Module>> = vec![Arc::new(SyntheticModule)];
    let engine = Arc::new(ScanEngine::new(modules, Arc::clone(&store), bus.clone()));
    let live = LiveScanner::new(Arc::clone(&engine), bus.clone());
    let state = Arc::new(AppState {
        store: Arc::clone(&store),
        engine,
        bus,
        live,
        http: reqwest::Client::new(),
        allow_key_write: false,
        cancellations: Arc::new(parking_lot::Mutex::new(HashMap::new())),
    });
    let app = router(state, "127.0.0.1:8080");

    let body = r#"{"kind":"email","value":"corr@example.com","options":{}}"#;
    let resp = app
        .clone()
        .oneshot(post_json("/api/v1/scans", body))
        .await
        .unwrap();
    let json = body_json(resp).await;
    let scan_id = json["scan_id"].as_str().unwrap().to_string();

    let resp = app
        .oneshot(get(&format!("/api/v1/scans/{scan_id}/correlations")))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let json = body_json(resp).await;
    assert!(json["correlations"].is_array());
}

// ─── API fallback / SPA ────────────────────────────────────────────────────

#[tokio::test]
async fn api_not_found_returns_json() {
    let app = test_app("api_nf");
    let resp = app
        .oneshot(get("/api/v1/nonexistent"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    let json = body_json(resp).await;
    assert!(json["error"].is_string());
}

#[tokio::test]
async fn spa_fallback_returns_html() {
    let app = test_app("spa");
    let resp = app.oneshot(get("/")).await.unwrap();
    assert_eq!(resp.status(), 200);
    let bytes = axum::body::to_bytes(resp.into_body(), 2_000_000)
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&bytes);
    assert!(body.contains("<html") || body.contains("<!DOCTYPE"));
}

// ─── Settings ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn settings_keys_get_lists_keys() {
    let app = test_app("settings_get");
    let resp = app
        .oneshot(get("/api/v1/settings/keys"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let json = body_json(resp).await;
    assert!(json["keys"].is_array());
    assert!(json["count"].is_number());
}

#[tokio::test]
async fn settings_keys_put_forbidden_without_flag() {
    use std::net::SocketAddr;

    let path = tmp_db("settings_put");
    let store = Arc::new(Store::open(&path).unwrap());
    let (bus, _rx) = tokio::sync::broadcast::channel(256);
    let modules: Vec<Arc<dyn Module>> = vec![Arc::new(SyntheticModule)];
    let engine = Arc::new(ScanEngine::new(modules, Arc::clone(&store), bus.clone()));
    let live = LiveScanner::new(Arc::clone(&engine), bus.clone());
    let state = Arc::new(AppState {
        store,
        engine,
        bus,
        live,
        http: reqwest::Client::new(),
        allow_key_write: false,
        cancellations: Arc::new(parking_lot::Mutex::new(HashMap::new())),
    });
    let app = router(state, "127.0.0.1:8080");

    let body = r#"{"updates":{"HUNTSMAN_TEST":"val"},"deletes":[]}"#;
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

// ─── Entity / Search ───────────────────────────────────────────────────────

#[tokio::test]
async fn entity_get_not_found() {
    let app = test_app("entity_nf");
    let resp = app
        .oneshot(get("/api/v1/entities/nonexistent-uid"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn search_requires_q_parameter() {
    let app = test_app("search_no_q");
    let resp = app
        .oneshot(get("/api/v1/search"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let json = body_json(resp).await;
    assert!(json["error"].as_str().unwrap().contains("'q'"));
}

#[tokio::test]
async fn search_with_valid_query() {
    let app = test_app("search_ok");
    let resp = app
        .oneshot(get("/api/v1/search?q=test&limit=10"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let json = body_json(resp).await;
    assert!(json["entities"].is_array());
}
