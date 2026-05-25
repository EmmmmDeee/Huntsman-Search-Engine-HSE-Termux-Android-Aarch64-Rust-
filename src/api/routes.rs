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

const SPA_HTML: &str = include_str!("../web/spa.html");

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

pub fn router(state: Arc<AppState>, bind: &str) -> Router {
    let cors = build_cors_layer(bind);

    let api_v1 = Router::new()
        .route("/health", get(handlers::health))
        .route("/version", get(handlers::version))
        .route("/modules", get(handlers::modules_list))
        .route("/stats", get(handlers::stats))
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
        .route(
            "/live",
            post(handlers::live_create).get(handlers::live_list),
        )
        .route(
            "/live/{id}",
            get(handlers::live_get).delete(handlers::live_stop),
        )
        .route("/live/{id}/events", get(handlers::live_events_sse))
        .route("/entities/{uid}", get(handlers::entity_get))
        .route("/search", get(handlers::search_entities))
        .route(
            "/settings/keys",
            get(handlers::settings_keys_get).put(handlers::settings_keys_put),
        )
        .fallback(api_not_found);

    let api = Router::new().nest("/v1", api_v1).fallback(api_not_found);

    Router::new()
        .nest("/api", api)
        .route("/static/{file}", get(vendor_handler))
        .fallback(spa_handler)
        .with_state(state)
        .layer(cors)
}

async fn spa_handler() -> Html<&'static str> {
    Html(SPA_HTML)
}

/// Uses `OriginalUri` so the JSON `path` shows the full caller-typed
/// path rather than the nest-stripped tail.
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

async fn vendor_handler(Path(file): Path<String>) -> Response {
    for (name, ct, bytes) in VENDOR_FILES {
        if *name == file {
            // ETag is the crate version; we avoid `Cache-Control: immutable`
            // because the URL is stable across upgrades and browsers would
            // never revalidate after a binary upgrade.
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

fn is_loopback_bind(bind: &str) -> bool {
    use std::net::{IpAddr, SocketAddr};

    if let Ok(sa) = bind.parse::<SocketAddr>() {
        return sa.ip().is_loopback();
    }
    if let Ok(ip) = bind.parse::<IpAddr>() {
        return ip.is_loopback();
    }
    let host = bind.rsplit_once(':').map_or(bind, |(h, _)| h);
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host == "localhost"
}

fn build_cors_layer(bind: &str) -> CorsLayer {
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

    // For loopback binds, also accept the `localhost` alias.
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
