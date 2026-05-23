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
//! | GET    | `/api/v1/scans/:id/correlations`  | `scan_correlations` (v0.4+) |
//! | GET    | `/api/v1/scans/:id/events`        | `scan_events_sse` (SSE)  |
//! | POST   | `/api/v1/live`                    | `live_create` (v0.5+)    |
//! | GET    | `/api/v1/live`                    | `live_list`              |
//! | GET    | `/api/v1/live/:id`                | `live_get`               |
//! | DELETE | `/api/v1/live/:id`                | `live_stop`              |
//! | GET    | `/api/v1/live/:id/events`         | `live_events_sse` (SSE)  |
//! | GET    | `/*` (fallback)                   | `spa_handler` (static)   |

use std::sync::Arc;

use axum::{
    Router,
    http::{HeaderValue, Method},
    response::Html,
    routing::{get, post},
};
use tower_http::cors::{Any, CorsLayer};

use super::{AppState, handlers};

/// Embedded SPA — single self-contained HTML file with inline CSS + JS.
/// Lives in `src/web/spa.html` and is compiled into the binary at build time
/// so the release artefact is still a single file.
const SPA_HTML: &str = include_str!("../web/spa.html");

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
        .route(
            "/api/v1/scans/{id}/correlations",
            get(handlers::scan_correlations),
        )
        .route("/api/v1/scans/{id}/events", get(handlers::scan_events_sse))
        // ── live (v0.5+) ──
        .route(
            "/api/v1/live",
            post(handlers::live_create).get(handlers::live_list),
        )
        .route(
            "/api/v1/live/{id}",
            get(handlers::live_get).delete(handlers::live_stop),
        )
        .route("/api/v1/live/{id}/events", get(handlers::live_events_sse))
        // ── SPA fallback (catch-all) ──
        .fallback(spa_handler)
        .with_state(state)
        .layer(cors)
}

async fn spa_handler() -> Html<&'static str> {
    Html(SPA_HTML)
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
    let host = bind.rsplit_once(':').map(|(h, _)| h).unwrap_or(bind);
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host == "localhost"
}

fn build_cors_layer(bind: &str) -> CorsLayer {
    let base = CorsLayer::new().allow_methods([
        Method::GET,
        Method::POST,
        Method::DELETE,
        Method::OPTIONS,
    ]);
    if is_loopback_bind(bind) {
        // Local-only bind: any local browser tab is trusted.
        base.allow_origin(Any).allow_headers(Any)
    } else {
        // Network-exposed: lock CORS down to the matching origin so random
        // websites can't make cross-origin requests against the API. If a
        // user genuinely wants a wider CORS policy, the right path is to
        // expose the API through their own reverse proxy.
        let http_origin = format!("http://{bind}");
        let https_origin = format!("https://{bind}");
        let mut allowed: Vec<HeaderValue> = Vec::new();
        if let Ok(v) = HeaderValue::from_str(&http_origin) {
            allowed.push(v);
        }
        if let Ok(v) = HeaderValue::from_str(&https_origin) {
            allowed.push(v);
        }
        base.allow_origin(allowed)
            .allow_headers([axum::http::header::CONTENT_TYPE])
    }
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
