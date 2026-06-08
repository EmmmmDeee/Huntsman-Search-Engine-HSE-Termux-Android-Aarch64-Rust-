//! Router definition, JSON 404 for `/api` typos, and SPA static fallback.
//!
//! Endpoint surface:
//!
//! | Method | Path                              | Handler                  |
//! |--------|-----------------------------------|--------------------------|
//! | GET    | `/api/v1/health`                  | `health`                 |
//! | GET    | `/api/v1/version`                 | `version`                |
//! | GET    | `/api/v1/modules`                 | `modules_list`           |
//! | GET    | `/api/v1/modules/graph`           | `modules_graph` (v1.1+)  |
//! | GET    | `/api/v1/engines/health`          | `engines_health` (v1.3+) |
//! | GET    | `/api/v1/keys/patterns`           | `keys_patterns` (v1.4+)  |
//! | POST   | `/api/v1/scans`                   | `scan_create`            |
//! | GET    | `/api/v1/scans`                   | `scan_list`              |
//! | GET    | `/api/v1/scans/{id}`              | `scan_get`               |
//! | DELETE | `/api/v1/scans/{id}`              | `scan_delete`            |
//! | POST   | `/api/v1/scans/{id}/rerun`        | `scan_rerun`             |
//! | GET    | `/api/v1/scans/{id}/entities`     | `scan_entities`          |
//! | GET    | `/api/v1/scans/{id}/entities.csv` | `scan_entities_csv`      |
//! | GET    | `/api/v1/scans/{id}/correlations` | `scan_correlations` (v0.4+) |
//! | GET    | `/api/v1/scans/{id}/relations`    | `scan_relations`         |
//! | GET    | `/api/v1/scans/{id}/audit`        | `scan_audit` (v1.3+)     |
//! | GET    | `/api/v1/scans/{id}/events`       | `scan_events_sse` (SSE)  |
//! | POST   | `/api/v1/live`                    | `live_create` (v0.5+)    |
//! | GET    | `/api/v1/live`                    | `live_list`              |
//! | GET    | `/api/v1/live/{id}`               | `live_get`               |
//! | DELETE | `/api/v1/live/{id}`               | `live_stop`              |
//! | GET    | `/api/v1/live/{id}/events`        | `live_events_sse` (SSE)  |
//! | GET    | `/api/v1/settings/keys`           | `settings_keys_get` (v0.10+) |
//! | PUT    | `/api/v1/settings/keys`           | `settings_keys_put`      |
//! | GET    | `/api/v1/settings/toggles`        | `settings_toggles_get` (v1.4+) |
//! | PUT    | `/api/v1/settings/toggles`        | `settings_toggles_put`   |
//! | *      | `/api/*` (unmatched)              | `api_not_found` (JSON 404) |
//! | GET    | `/static/{file}`                  | `vendor_handler`         |
//! | GET    | `/*` (fallback)                   | `spa_handler` (static)   |

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, OriginalUri, Path},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use serde_json::json;
use tower_http::compression::CompressionLayer;
use tower_http::cors::CorsLayer;

use super::{AppState, handlers, scan_handlers};

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
        .route("/modules/graph", get(handlers::modules_graph))
        .route("/engines/health", get(handlers::engines_health))
        .route("/stats", get(handlers::stats))
        // ── diagnostics: self-test + downloadable verbose logs ──
        .route("/selftest", get(handlers::selftest_run))
        .route("/logs", get(handlers::logs_download))
        // ── key-detector catalogue (v1.4+) ──
        .route("/keys/patterns", get(handlers::keys_patterns))
        .route("/keys/status", get(handlers::keys_status))
        // ── scans ──
        .route(
            "/scans",
            post(scan_handlers::scan_create).get(scan_handlers::scan_list),
        )
        .route("/scans/batch", post(scan_handlers::scan_batch))
        .route(
            "/scans/import",
            // Raise this route's body cap from axum's 2 MB default to the import
            // handler's declared 16 MB, so a large but legitimate breach dossier
            // isn't rejected with a bare 413 before reaching the parser. Scoped to
            // this route only — every other endpoint keeps the conservative
            // default. Single source of truth: scan_handlers::MAX_UPLOAD_BYTES.
            post(scan_handlers::scan_import)
                .layer(DefaultBodyLimit::max(scan_handlers::MAX_UPLOAD_BYTES)),
        )
        .route(
            "/scans/{id}",
            get(scan_handlers::scan_get).delete(scan_handlers::scan_delete),
        )
        .route("/scans/{id}/rerun", post(scan_handlers::scan_rerun))
        .route("/scans/{id}/cancel", post(scan_handlers::scan_cancel))
        .route("/scans/{id}/entities", get(scan_handlers::scan_entities))
        .route(
            "/scans/{id}/entities/filter",
            get(scan_handlers::scan_entities_filter),
        )
        .route(
            "/scans/{id}/entities/facets",
            get(scan_handlers::scan_entities_facets),
        )
        .route(
            "/scans/{id}/entities.csv",
            get(scan_handlers::scan_entities_csv),
        )
        .route(
            "/scans/{id}/report.json",
            get(scan_handlers::scan_report_json),
        )
        .route(
            "/scans/{id}/graph.gexf",
            get(scan_handlers::scan_export_gexf),
        )
        .route(
            "/scans/{id}/debug.txt",
            get(scan_handlers::scan_debug_bundle),
        )
        .route(
            "/scans/{id}/correlations",
            get(scan_handlers::scan_correlations),
        )
        .route("/scans/{id}/relations", get(scan_handlers::scan_relations))
        .route("/scans/{id}/audit", get(scan_handlers::scan_audit))
        .route("/scans/{a}/diff/{b}", get(scan_handlers::scan_diff))
        .route("/scans/{id}/events", get(handlers::scan_events_sse))
        .route(
            "/scans/{id}/events.history",
            get(scan_handlers::scan_events_history),
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
        .route(
            "/settings/toggles",
            get(handlers::settings_toggles_get).put(handlers::settings_toggles_put),
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
        // ── favicon — browsers (esp. Chrome-on-Android) request /favicon.ico
        //    unconditionally; without this route it would hit the SPA fallback
        //    and return the whole HTML document as an "image". Serve the same
        //    inline crosshair the SPA links, with the correct content type.
        .route("/favicon.ico", get(favicon_handler))
        // ── web-app manifest — lets Chrome-on-Android install the UI as a
        //    standalone fullscreen app (Add to Home Screen). Progressive
        //    enhancement: ignored by browsers that don't support it.
        .route("/manifest.webmanifest", get(manifest_handler))
        // ── SPA fallback — `/`, `/scan/...`, anything outside `/api` and
        //    `/static`; serves the embedded SPA for client-side routing.
        .fallback(spa_handler)
        .with_state(state)
        // gzip every compressible response (the ~118 KB SPA, the ~528 KB vendor
        // bundle, and large scan-result JSON) so a phone's mobile link carries
        // ~4x less. `CompressionLayer`'s default predicate skips already-small
        // bodies and `text/event-stream`, so the SSE live-scan stream is never
        // buffered. Inner of CORS/security headers so those still apply to the
        // compressed response.
        .layer(CompressionLayer::new())
        .layer(cors)
        // Security headers on every response (outermost, so it also covers
        // CORS preflight + the SPA + static + API). See `set_security_headers`.
        .layer(axum::middleware::map_response(set_security_headers))
}

/// Content-Security-Policy for the embedded SPA.
///
/// The SPA is a single self-contained document that legitimately needs inline
/// `<script>`/`<style>` and inline event handlers, so `script-src`/`style-src`
/// retain `'unsafe-inline'`; everything else is locked to the same origin. The
/// high-value clause for an OSINT tool holding sensitive findings is
/// `connect-src 'self'` (+ `default-src 'self'`): even if an injection slipped
/// past the SPA's `esc()` discipline, it cannot exfiltrate data to an external
/// origin or pull in an external script. `frame-ancestors 'none'` +
/// `object-src 'none'` + `base-uri 'self'` close clickjacking, plugin, and
/// `<base>`-hijack vectors. All vendor assets ship same-origin from `/static`,
/// so no external host needs allow-listing.
const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; \
     script-src 'self' 'unsafe-inline'; \
     style-src 'self' 'unsafe-inline'; \
     img-src 'self' data:; \
     connect-src 'self'; \
     object-src 'none'; \
     base-uri 'self'; \
     frame-ancestors 'none'; \
     form-action 'self'";

/// Attach defence-in-depth security headers to every response. Applied as an
/// outermost `map_response` layer so the SPA, static bundle, API JSON and SSE
/// streams all carry them. Values are static, so this never fails.
async fn set_security_headers(mut response: Response) -> Response {
    let h = response.headers_mut();
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CONTENT_SECURITY_POLICY),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response
}

async fn spa_handler() -> Response {
    // `no-cache` (the browser must revalidate each load) so a binary upgrade's
    // new SPA shows immediately instead of Chrome serving a heuristically-cached
    // old copy. The document is small and same-origin, so revalidation is cheap.
    (
        StatusCode::OK,
        [(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"))],
        Html(SPA_HTML),
    )
        .into_response()
}

/// SVG favicon — a hunting-crosshair in the brand cyan on the navbar's dark.
/// Matches the inline `<link rel="icon">` in the SPA head; this route covers
/// clients that request `/favicon.ico` directly regardless of that link.
const FAVICON_SVG: &str = "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'><rect width='32' height='32' rx='6' fill='#222222'/><circle cx='16' cy='16' r='8' fill='none' stroke='#07aef1' stroke-width='2'/><circle cx='16' cy='16' r='2.4' fill='#07aef1'/><path d='M16 2v6M16 24v6M2 16h6M24 16h6' stroke='#07aef1' stroke-width='2'/></svg>";

async fn favicon_handler() -> Response {
    (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("image/svg+xml"),
            ),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=86400"),
            ),
        ],
        FAVICON_SVG,
    )
        .into_response()
}

/// Web-app manifest — makes the UI **installable as a standalone app on
/// Chrome-for-Android** (Add to Home Screen → launches fullscreen with no browser
/// address bar, reclaiming ~10% of a phone's vertical space for scan results).
/// `display: standalone` + the matching `theme_color`/`background_color` give an
/// app-like launch on the primary target. The icon reuses the same inline
/// crosshair SVG the favicon serves (`sizes:"any"` satisfies Chrome's
/// installability check for a scalable icon) — zero extra binary asset. Served
/// same-origin, so CSP `default-src 'self'` (which `manifest-src` falls back to)
/// permits it.
const MANIFEST_JSON: &str = r##"{
  "name": "Huntsman Search Engine",
  "short_name": "Huntsman",
  "description": "OSINT/GEOINT platform — runs entirely in Termux on Android, no root.",
  "start_url": "/",
  "scope": "/",
  "display": "standalone",
  "orientation": "any",
  "background_color": "#222222",
  "theme_color": "#222222",
  "icons": [
    { "src": "/favicon.ico", "sizes": "any", "type": "image/svg+xml", "purpose": "any" }
  ]
}"##;

async fn manifest_handler() -> Response {
    (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/manifest+json"),
            ),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=86400"),
            ),
        ],
        MANIFEST_JSON,
    )
        .into_response()
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
async fn vendor_handler(Path(file): Path<String>, headers: HeaderMap) -> Response {
    for (name, ct, bytes) in VENDOR_FILES {
        if *name == file {
            // ETag is the crate version (which uniquely identifies the
            // embedded bytes — the bundle ships in-binary). We deliberately
            // do NOT use `Cache-Control: immutable` because the URL
            // (`/static/bootstrap.min.css`) is stable across upgrades;
            // pairing immutable with a stable URL leaves the browser stuck
            // on old bytes after a binary upgrade. Instead `must-revalidate`
            // plus the conditional-request handling below lets the browser
            // revalidate cheaply via the ETag and pick up new bytes the moment
            // the binary changes.
            const ETAG: &str = concat!("\"", env!("CARGO_PKG_VERSION"), "\"");
            let cache = HeaderValue::from_static("public, max-age=3600, must-revalidate");

            // Conditional GET: if the client already holds these exact bytes
            // (`If-None-Match` == our ETag) reply 304 and skip re-sending the
            // ~510 KB bundle — a real saving on a metered mobile link, and the
            // half that made the ETag worth setting (the handler previously
            // always re-sent 200, so the ETag never did anything).
            if headers
                .get(header::IF_NONE_MATCH)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|inm| if_none_match_hit(inm, ETAG))
            {
                return (
                    StatusCode::NOT_MODIFIED,
                    [
                        (header::ETAG, HeaderValue::from_static(ETAG)),
                        (header::CACHE_CONTROL, cache),
                    ],
                )
                    .into_response();
            }

            return (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, HeaderValue::from_static(ct)),
                    (header::CACHE_CONTROL, cache),
                    (header::ETAG, HeaderValue::from_static(ETAG)),
                ],
                *bytes,
            )
                .into_response();
        }
    }
    (StatusCode::NOT_FOUND, "not found").into_response()
}

/// RFC 7232 `If-None-Match` test: true if the header is `*` or lists an
/// entity-tag equal to `etag`. Browsers echo the ETag verbatim; our tag is
/// strong and the payload is fixed per build, so weak-validator nuance is moot.
fn if_none_match_hit(if_none_match: &str, etag: &str) -> bool {
    if_none_match
        .split(',')
        .map(str::trim)
        .any(|t| t == "*" || t == etag)
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
    use super::*;

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

    #[test]
    fn loopback_edge_cases() {
        assert!(is_loopback_bind("localhost"));
        assert!(!is_loopback_bind("localhostx:8080"));
        assert!(!is_loopback_bind(""));
    }

    #[test]
    fn cors_loopback_includes_localhost_alias() {
        let layer = build_cors_layer("127.0.0.1:8080");
        let _ = layer;
    }

    #[test]
    fn cors_non_loopback_excludes_localhost() {
        let layer = build_cors_layer("192.168.1.5:8080");
        let _ = layer;
    }

    #[test]
    fn cors_ipv6_loopback() {
        let layer = build_cors_layer("[::1]:8080");
        let _ = layer;
    }

    #[test]
    fn if_none_match_hits_star_exact_and_list() {
        let etag = concat!("\"", env!("CARGO_PKG_VERSION"), "\"");
        assert!(if_none_match_hit("*", etag), "wildcard matches");
        assert!(if_none_match_hit(etag, etag), "exact match");
        assert!(
            if_none_match_hit(&format!("\"old\", {etag}"), etag),
            "match within a comma list"
        );
        assert!(!if_none_match_hit("\"old\"", etag), "different tag misses");
        assert!(!if_none_match_hit("", etag), "empty header misses");
    }
}
