//! Router definition and SPA static fallback.
//!
//! Endpoint surface (v0.3):
//!
//! | Method | Path                              | Handler                  |
//! |--------|-----------------------------------|--------------------------|
//! | GET    | `/api/v1/health`                  | `health`                 |
//! | GET    | `/api/v1/version`                 | `version`                |
//! | GET    | `/api/v1/modules`                 | `modules_list`           |
//! | POST   | `/api/v1/scans`                   | `scan_create`            |
//! | GET    | `/api/v1/scans`                   | `scan_list`              |
//! | GET    | `/api/v1/scans/:id`               | `scan_get`               |
//! | GET    | `/api/v1/scans/:id/entities`      | `scan_entities`          |
//! | GET    | `/api/v1/scans/:id/events`        | `scan_events_sse` (SSE)  |
//! | GET    | `/*` (fallback)                   | `spa_handler` (static)   |

use std::sync::Arc;

use axum::{
    Router,
    response::Html,
    routing::{get, post},
};
use tower_http::cors::{Any, CorsLayer};

use super::{AppState, handlers};

/// Embedded SPA — single self-contained HTML file with inline CSS + JS.
/// Lives in `src/web/spa.html` and is compiled into the binary at build time
/// so the release artefact is still a single file.
const SPA_HTML: &str = include_str!("../web/spa.html");

/// Build the full router. CORS is permissive because the server binds to
/// `127.0.0.1` only — any browser tab on the same device may connect.
pub fn router(state: Arc<AppState>) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        // ── health / version ──
        .route("/api/v1/health", get(handlers::health))
        .route("/api/v1/version", get(handlers::version))
        // ── modules ──
        .route("/api/v1/modules", get(handlers::modules_list))
        // ── scans ──
        .route(
            "/api/v1/scans",
            post(handlers::scan_create).get(handlers::scan_list),
        )
        .route("/api/v1/scans/{id}", get(handlers::scan_get))
        .route("/api/v1/scans/{id}/entities", get(handlers::scan_entities))
        .route("/api/v1/scans/{id}/events", get(handlers::scan_events_sse))
        // ── SPA fallback (catch-all) ──
        .fallback(spa_handler)
        .with_state(state)
        .layer(cors)
}

async fn spa_handler() -> Html<&'static str> {
    Html(SPA_HTML)
}
