//! Router definition, JSON 404 for `/api` typos, and SPA static fallback.
//!
//! Endpoint surface:
//!
//! | Method | Path                              | Handler                  |
//! |--------|-----------------------------------|--------------------------|
//! | GET    | `/api/v1/health`                  | `health`                 |
//! | GET    | `/api/v1/version`                 | `version`                |
//! | GET    | `/api/v1/modules`                 | `modules_list`           |
//! | POST   | `/api/v1/scans`                   | `scan_create`            |
//! | GET    | `/api/v1/scans`                   | `scan_list`              |
//! | GET    | `/api/v1/scans/{id}`              | `scan_get`               |
//! | DELETE | `/api/v1/scans/{id}`              | `scan_delete`            |
//! | POST   | `/api/v1/scans/{id}/rerun`        | `scan_rerun`             |
//! | GET    | `/api/v1/scans/{id}/entities`     | `scan_entities`          |
//! | GET    | `/api/v1/scans/{id}/entities.csv` | `scan_entities_csv`      |
//! | GET    | `/api/v1/scans/{id}/correlations` | `scan_correlations` (v0.4+) |
//! | GET    | `/api/v1/scans/{id}/events`       | `scan_events_sse` (SSE)  |
//! | POST   | `/api/v1/live`                    | `live_create` (v0.5+)    |
//! | GET    | `/api/v1/live`                    | `live_list`              |
//! | GET    | `/api/v1/live/{id}`               | `live_get`               |
//! | DELETE | `/api/v1/live/{id}`               | `live_stop`              |
//! | GET    | `/api/v1/live/{id}/events`        | `live_events_sse` (SSE)  |
//! | GET    | `/api/v1/settings/keys`           | `settings_keys_get` (v0.10+) |
//! | PUT    | `/api/v1/settings/keys`           | `settings_keys_put`      |
//! | *      | `/api/*` (unmatched)              | `api_not_found` (JSON 404) |
//! | GET    | `/static/{file}`                  | `vendor_handler`         |
//! | GET    | `/*` (fallback)                   | `spa_handler` (static)   |

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{OriginalUri, Path},
    http::{HeaderValue, Method, StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use serde_json::json;
use tower_http::cors::CorsLayer;

use super::{AppState, handlers};

/// Embedded SPA — single self-contained HTML file with inline CSS + JS.
/// Lives in `src/web/spa.html` and is compiled into the binary at build time
/// so the release artefact is still a single file.
const SPA_HTML: &str = include_str!("../web/spa.html");

/// Vendor bundle — Spiderfoot's exact stack (Bootstrap 3.4.1, jQuery 3.7,
/// D3 v3, tablesorter, alertify) plus Spiderfoot's own CSS file. Embedded
/// at compile time so the release artefact is still a single binary.
///
/// All entries are served from `/static/{file}` with a one-year
/// `Cache-Control` header — browsers cache aggressively, so the ~510 KB
/// bundle is paid for exactly once per device.
const VENDOR_FILES: &[(&str, &str, &[u8])] = &[
    (
        "bootstrap.min.css",
        "text/css; charset=utf-8",
        include_bytes!("../web/vendor/bootstrap.min.css"),
    ),
    (
        "bootstrap.min.js",
        "application/javascript",
        include_bytes!("../web/vendor/bootstrap.min.js"),
    ),
    (
        "jquery.min.js",
        "application/javascript",
        include_bytes!("../web/vendor/jquery.min.js"),
    ),
    (
        "d3.min.js",
        "application/javascript",
        include_bytes!("../web/vendor/d3.min.js"),
    ),
    (
        "jquery.tablesorter.min.js",
        "application/javascript",
        include_bytes!("../web/vendor/jquery.tablesorter.min.js"),
    ),
    (
        "jquery.tablesorter.theme.css",
        "text/css; charset=utf-8",
        include_bytes!("../web/vendor/jquery.tablesorter.theme.css"),
    ),
    (
        "alertify.min.js",
        "application/javascript",
        include_bytes!("../web/vendor/alertify.min.js"),
    ),
    (
        "alertify.min.css",
        "text/css; charset=utf-8",
        include_bytes!("../web/vendor/alertify.min.css"),
    ),
    (
        "alertify.bootstrap.min.css",
        "text/css; charset=utf-8",
        include_bytes!("../web/vendor/alertify.bootstrap.min.css"),
    ),
    (
        "spiderfoot-style.css",
        "text/css; charset=utf-8",
        include_bytes!("../web/vendor/spiderfoot-style.css"),
    ),
];

/// Build the full router. `bind` is the host:port the server will listen on;
/// used **only** to decide the CORS policy:
///
/// * loopback bind (`127.0.0.1`, `::1`, `localhost`) → permissive CORS, so any
///   browser tab on the same device can talk to the API.
/// * any other bind (e.g. `0.0.0.0`, LAN address) → restrictive CORS that only
///   allows the matching `http://<bind>` origin. Prevents arbitrary websites
///   from issuing cross-origin requests when the user has exposed HSE on a
///   non-loopback interface.
pub fn router(state: Arc<AppState>, bind: &str) -> Router {
    let cors = build_cors_layer(bind);

    // /api/v1 — explicit, versioned API surface. Inner fallback emits a
    // JSON 404 for any unmatched path under this prefix so API consumers'
    // typos surface cleanly instead of being served the SPA HTML.
    let api_v1 = Router::new()
        // ── health / version ──
        .route("/health", get(handlers::health))
        .route("/version", get(handlers::version))
        // ── modules ──
        .route("/modules", get(handlers::modules_list))
        .route("/stats", get(handlers::stats))
        // ── scans ──
        .route(
            "/scans",
            post(handlers::scan_create).get(handlers::scan_list),
        )
        .route(
            "/scans/{id}",
            get(handlers::scan_get).delete(handlers::scan_delete),
        )
        .route("/scans/{id}/rerun", post(handlers::scan_rerun))
        .route("/scans/{id}/cancel", post(handlers::scan_cancel))
        .route("/scans/{id}/entities", get(handlers::scan_entities))
        .route(
            "/scans/{id}/entities/filter",
            get(handlers::scan_entities_filter),
        )
        .route(
            "/scans/{id}/entities/facets",
            get(handlers::scan_entities_facets),
        )
        .route("/scans/{id}/entities.csv", get(handlers::scan_entities_csv))
        .route("/scans/{id}/report.json", get(handlers::scan_report_json))
        .route("/scans/{id}/correlations", get(handlers::scan_correlations))
        .route("/scans/{id}/events", get(handlers::scan_events_sse))
        .route(
            "/scans/{id}/events.history",
            get(handlers::scan_events_history),
        )
        // ── live (v0.5+) ──
        .route(
            "/live",
            post(handlers::live_create).get(handlers::live_list),
        )
        .route(
            "/live/{id}",
            get(handlers::live_get).delete(handlers::live_stop),
        )
        .route("/live/{id}/events", get(handlers::live_events_sse))
        // ── entities (cross-scan) ──
        .route("/entities/{uid}", get(handlers::entity_get))
        .route("/search", get(handlers::search_entities))
        // ── settings (v0.10+) ──
        .route(
            "/settings/keys",
            get(handlers::settings_keys_get).put(handlers::settings_keys_put),
        )
        .fallback(api_not_found);

    // /api — outer layer catches `/api/v2/...` / `/api/typo` /
    // anything under /api but outside /v1, again returning JSON 404
    // rather than SPA HTML.
    let api = Router::new().nest("/v1", api_v1).fallback(api_not_found);

    Router::new()
        .nest("/api", api)
        // ── static vendor bundle (Bootstrap 3, jQuery, D3, tablesorter, alertify) ──
        .route("/static/{file}", get(vendor_handler))
        // ── SPA fallback — `/`, `/scan/...`, anything outside `/api` and
        //    `/static`; serves the embedded SPA for client-side routing.
        .fallback(spa_handler)
        .with_state(state)
        .layer(cors)
}

async fn spa_handler() -> Html<&'static str> {
    Html(SPA_HTML)
}

/// JSON 404 for any unmatched route under `/api`. Without this the SPA
/// fallback would catch API typos and silently return the embedded SPA
/// HTML with HTTP 200 — a real defense-in-depth concern for any consumer
/// that doesn't sanity-check `Content-Type` before parsing.
///
/// Uses `OriginalUri` rather than `Uri` so the JSON `path` shows the
/// caller-typed path (e.g. `/api/v1/typo`) instead of the
/// nest-stripped tail (`/typo`).
async fn api_not_found(method: Method, OriginalUri(uri): OriginalUri) -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        Json(json!({
            "error":  "endpoint not found",
            "method": method.as_str(),
            "path":   uri.path(),
        })),
    )
}

/// Serve one of the embedded vendor files (Bootstrap, jQuery, etc.).
/// Returns 404 for any name not in [`VENDOR_FILES`] — there's no
/// path traversal to worry about because the match is on the exact
/// filename and `Path<String>` doesn't decode slashes by default.
async fn vendor_handler(Path(file): Path<String>) -> Response {
    for (name, ct, bytes) in VENDOR_FILES {
        if *name == file {
            // ETag is the crate version (which uniquely identifies the
            // embedded bytes — the bundle ships in-binary). We deliberately
            // do NOT use `Cache-Control: immutable` because the URL
            // (`/static/bootstrap.min.css`) is stable across upgrades;
            // pairing immutable with a stable URL leaves the browser stuck
            // on old bytes after a binary upgrade. Without `immutable`,
            // browsers will revalidate via the ETag and pick up the new
            // bytes the moment the binary changes.
            let etag = HeaderValue::from_static(concat!("\"", env!("CARGO_PKG_VERSION"), "\""));
            return (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, HeaderValue::from_static(ct)),
                    (
                        header::CACHE_CONTROL,
                        HeaderValue::from_static("public, max-age=3600, must-revalidate"),
                    ),
                    (header::ETAG, etag),
                ],
                *bytes,
            )
                .into_response();
        }
    }
    (StatusCode::NOT_FOUND, "not found").into_response()
}

/// Loopback check. Robust to all reasonable bind syntaxes:
///   `127.0.0.1:8080`, `127.1.2.3:8080`, `0.0.0.0:8080`,
///   `[::1]:8080`, `::1`, `192.168.1.5:8080`, `localhost[:port]`.
///
/// Anything that doesn't parse as a loopback IP — and isn't literally
/// `localhost` — is treated as a network-exposed interface.
fn is_loopback_bind(bind: &str) -> bool {
    use std::net::{IpAddr, SocketAddr};

    if let Ok(sa) = bind.parse::<SocketAddr>() {
        return sa.ip().is_loopback();
    }
    if let Ok(ip) = bind.parse::<IpAddr>() {
        return ip.is_loopback();
    }
    // Hostname forms (no IP parse). Strip an optional trailing `:port`.
    let host = bind.rsplit_once(':').map_or(bind, |(h, _)| h);
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host == "localhost"
}

fn build_cors_layer(bind: &str) -> CorsLayer {
    // Bound to the matching `http(s)://<bind>` origin even on loopback —
    // the previous `allow_origin(Any)` for loopback meant ANY website the
    // user visited in Chrome could XHR to 127.0.0.1:8080 and read their
    // scan history (an attack vector copilot flagged on PR #9). The SPA
    // is served same-origin from this binary so it never needs cross-
    // origin in normal use.
    let base = CorsLayer::new()
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([axum::http::header::CONTENT_TYPE]);

    let mut allowed: Vec<HeaderValue> = Vec::new();
    let mut push = |o: String| {
        if let Ok(v) = HeaderValue::from_str(&o) {
            allowed.push(v);
        }
    };
    push(format!("http://{bind}"));
    push(format!("https://{bind}"));

    // For loopback binds, also accept the `localhost` alias (since users
    // routinely type both `127.0.0.1:8080` and `localhost:8080` in the
    // browser). If the user is intentionally exposing the API on a non-
    // loopback interface they get only the bind-matching origin and must
    // proxy through their own CORS-aware front-end for anything else.
    if is_loopback_bind(bind) {
        let port = bind.rsplit_once(':').map_or("8080", |(_, p)| p);
        push(format!("http://localhost:{port}"));
        push(format!("http://127.0.0.1:{port}"));
        push(format!("http://[::1]:{port}"));
    }

    base.allow_origin(allowed)
}

#[cfg(test)]
mod tests {
    use super::is_loopback_bind;

    #[test]
    fn loopback_recognised() {
        assert!(is_loopback_bind("127.0.0.1:8080"));
        assert!(is_loopback_bind("127.1.2.3:9000"));
        assert!(is_loopback_bind("localhost:8080"));
        assert!(is_loopback_bind("[::1]:8080"));
        assert!(is_loopback_bind("::1"));
    }

    #[test]
    fn non_loopback_rejected() {
        assert!(!is_loopback_bind("0.0.0.0:8080"));
        assert!(!is_loopback_bind("192.168.1.10:8080"));
        assert!(!is_loopback_bind("10.0.0.5:8080"));
        assert!(!is_loopback_bind("example.com:8080"));
    }
}
