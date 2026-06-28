//! Router definition, JSON 404 for `/api` typos, and SPA static fallback.
//!
//! # Endpoint surface
//!
//! The single source of truth for the route set is the [`router`] function
//! below — read it directly rather than trusting a hand-maintained table (an
//! earlier copy of that table drifted ~25 routes behind the real ~60). The
//! groups below are an orientation map, not an exhaustive contract; every
//! `.route(...)` call in [`router`] is the authority.
//!
//! All API endpoints are under `/api/v1`. Any unmatched path under `/api`
//! returns a JSON 404 ([`api_not_found`]) rather than the SPA HTML.
//!
//! * **Meta / health** — `/health`, `/version`, `/stats`, `/modules`,
//!   `/modules/graph`, `/engines/health`, `/selftest`, `/logs`.
//! * **Keys** — `/keys/patterns`, `/keys/status`, `/keys/pool`,
//!   `/keys/pool/revoke`, `/keys/pool/rotate`.
//! * **Scan lifecycle** — `POST`/`GET /scans`, `/scans/batch`,
//!   `/scans/import`, `/scans/{id}` (GET/DELETE), `/scans/{id}/rerun`,
//!   `/scans/{id}/cancel`.
//! * **Autonomous** — `/scan/auto`, `/scan/auto/plan`, `/scan/auto/sweep`,
//!   `/plan`, `/radar`, `/radar/live`.
//! * **Scan data** — `/scans/{id}/entities`, `entities/filter`,
//!   `entities/facets`, `entities.csv`, `report.json`, `graph.gexf`,
//!   `debug.txt`, `correlations`, `relations`, `network`, `identities`,
//!   `leads`, `timeline`, `communities`, `trust`, `path`, `metrics`,
//!   `duplicates`, `pivots`, `gaps`, `benchmark`, `audit`,
//!   `/scans/{a}/diff/{b}`, `/scans/{id}/events` (SSE), `events.history`.
//! * **Live** — `POST`/`GET /live`, `/live/{id}` (GET/DELETE),
//!   `/live/{id}/events` (SSE).
//! * **Cross-scan** — `/entities/{uid}`, `/search`.
//! * **Settings / update** — `/settings/keys` (GET/PUT),
//!   `/settings/toggles` (GET/PUT), `/update/status`, `/update/trigger`.
//!
//! Non-API routes: `/static/{file}` (vendor bundle), `/favicon.svg`,
//! `/favicon.ico`, `/manifest.webmanifest`, and the SPA fallback for any
//! other path.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use axum::{
    Json, Router,
    extract::{ConnectInfo, DefaultBodyLimit, OriginalUri, Path},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use parking_lot::Mutex;
use serde_json::json;
use tower_http::compression::CompressionLayer;
use tower_http::cors::CorsLayer;

use super::{AppState, handlers, scan_export, scan_handlers, settings_handlers, update_handlers};

/// Embedded SPA — single self-contained HTML file with inline CSS + JS.
/// Lives in `src/web/spa.html` and is compiled into the binary at build time
/// so the release artefact is still a single file.
const SPA_HTML: &str = include_str!("../../web/spa.html");

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
        include_bytes!("../../web/vendor/bootstrap.min.css"),
    ),
    (
        "bootstrap.min.js",
        "application/javascript",
        include_bytes!("../../web/vendor/bootstrap.min.js"),
    ),
    (
        "jquery.min.js",
        "application/javascript",
        include_bytes!("../../web/vendor/jquery.min.js"),
    ),
    (
        "d3.min.js",
        "application/javascript",
        include_bytes!("../../web/vendor/d3.min.js"),
    ),
    (
        "jquery.tablesorter.min.js",
        "application/javascript",
        include_bytes!("../../web/vendor/jquery.tablesorter.min.js"),
    ),
    (
        "jquery.tablesorter.theme.css",
        "text/css; charset=utf-8",
        include_bytes!("../../web/vendor/jquery.tablesorter.theme.css"),
    ),
    (
        "alertify.min.js",
        "application/javascript",
        include_bytes!("../../web/vendor/alertify.min.js"),
    ),
    (
        "alertify.min.css",
        "text/css; charset=utf-8",
        include_bytes!("../../web/vendor/alertify.min.css"),
    ),
    (
        "alertify.bootstrap.min.css",
        "text/css; charset=utf-8",
        include_bytes!("../../web/vendor/alertify.bootstrap.min.css"),
    ),
    (
        "spiderfoot-style.css",
        "text/css; charset=utf-8",
        include_bytes!("../../web/vendor/spiderfoot-style.css"),
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
        .route("/keys/patterns", get(settings_handlers::keys_patterns))
        .route("/keys/status", get(settings_handlers::keys_status))
        .route("/keys/pool", get(settings_handlers::keys_pool_get))
        .route(
            "/keys/pool/revoke",
            post(settings_handlers::keys_pool_revoke),
        )
        .route(
            "/keys/pool/rotate",
            post(settings_handlers::keys_pool_rotate),
        )
        // ── scans ──
        .route(
            "/scans",
            post(scan_handlers::scan_create).get(scan_handlers::scan_list),
        )
        .route("/scans/batch", post(scan_handlers::scan_batch))
        // Fully autonomous investigation: NO seed input — the platform auto-selects
        // the highest cross-investigation-leverage entity from its base and scans it.
        .route("/scan/auto", post(scan_handlers::scan_auto))
        // Read-only preview of the diversity-aware autonomous investigation queue:
        // what the platform would investigate next, in order — dispatches nothing.
        .route("/scan/auto/plan", get(scan_handlers::scan_auto_plan))
        // Fully autonomous MULTI-target sweep: plan the diversity-aware queue and
        // dispatch its top `breadth` targets in one input-free call (NO seed).
        .route("/scan/auto/sweep", post(scan_handlers::scan_auto_sweep))
        // Forward-only scan-plan preview: which modules a seed engages, no scan run.
        .route("/plan", get(scan_handlers::plan_preview))
        // Live-radar button: ONE autonomous device-sensor sweep, no target seed.
        .route("/radar", post(scan_handlers::radar_sweep))
        // Continuous autonomous radar: a zero-input live session that re-runs only
        // the on-device passive sensors, enumerating ambient signals in real time.
        .route("/radar/live", post(scan_handlers::radar_live))
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
            get(scan_export::scan_entities_csv),
        )
        .route(
            "/scans/{id}/report.json",
            get(scan_export::scan_report_json),
        )
        .route("/scans/{id}/graph.gexf", get(scan_export::scan_export_gexf))
        .route("/scans/{id}/debug.txt", get(scan_export::scan_debug_bundle))
        .route(
            "/scans/{id}/correlations",
            get(scan_handlers::scan_correlations),
        )
        .route("/scans/{id}/relations", get(scan_handlers::scan_relations))
        // Subject-centric relationship synthesis — powers the web UI Network view.
        .route("/scans/{id}/network", get(scan_handlers::scan_network))
        // People-centric co-reference resolution — scores which selectors name the
        // same individual (cross-identifier record linkage).
        .route(
            "/scans/{id}/identities",
            get(scan_handlers::scan_identities),
        )
        // Proactive next-best-action leads — powers the web UI Leads view.
        .route("/scans/{id}/leads", get(scan_handlers::scan_leads))
        // Chronological footprint reconstruction — powers the web UI Timeline view.
        .route("/scans/{id}/timeline", get(scan_handlers::scan_timeline))
        // Graph community detection — powers the web UI Communities view.
        .route(
            "/scans/{id}/communities",
            get(scan_handlers::scan_communities),
        )
        // Network trust propagation — powers the web UI Trust ranking view.
        .route("/scans/{id}/trust", get(scan_handlers::scan_trust))
        // Connection-path discovery between two named entities (link analysis).
        .route("/scans/{id}/path", get(scan_handlers::scan_path))
        // Objective per-scan quality / telemetry measures.
        .route("/scans/{id}/metrics", get(scan_handlers::scan_metrics))
        // Near-duplicate entity-resolution suggestions.
        .route(
            "/scans/{id}/duplicates",
            get(scan_handlers::scan_duplicates),
        )
        // Pivot-node detection — the graph's high-connectivity intermediaries.
        .route("/scans/{id}/pivots", get(scan_handlers::scan_pivots))
        // Discovery-gap analysis — isolated seeds and the corrective scans to link them.
        .route("/scans/{id}/gaps", get(scan_handlers::scan_gaps))
        // Consolidated benchmark scorecard (HTTP twin of `hse benchmark`).
        .route("/scans/{id}/benchmark", get(scan_handlers::scan_benchmark))
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
            get(settings_handlers::settings_keys_get).put(settings_handlers::settings_keys_put),
        )
        .route(
            "/settings/toggles",
            get(settings_handlers::settings_toggles_get)
                .put(settings_handlers::settings_toggles_put),
        )
        // ── update (v1.5+) ──
        .route("/update/status", get(update_handlers::get_status))
        .route("/update/trigger", post(update_handlers::post_trigger))
        .fallback(api_not_found);

    // /api — outer layer catches `/api/v2/...` / `/api/typo` /
    // anything under /api but outside /v1, again returning JSON 404
    // rather than SPA HTML.
    let api = Router::new().nest("/v1", api_v1).fallback(api_not_found);

    let app = Router::new()
        .nest("/api", api)
        // ── static vendor bundle (Bootstrap 3, jQuery, D3, tablesorter, alertify) ──
        .route("/static/{file}", get(vendor_handler))
        // ── favicon — browsers (esp. Chrome-on-Android) request /favicon.ico
        //    unconditionally; without this route it would hit the SPA fallback
        //    and return the whole HTML document as an "image". Serve the same
        //    inline locator-mark favicon the SPA links, with the correct content
        //    type. `/favicon.svg` is the canonical, correctly-typed source the
        //    manifest icon references (`.svg` URL ↔ `image/svg+xml`, self-
        //    consistent for Chrome's Add-to-Home-Screen installability check);
        //    `/favicon.ico` is a thin alias for legacy clients that request the
        //    `.ico` path directly. Both return the identical SVG bytes.
        .route("/favicon.svg", get(favicon_handler))
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
        .layer(cors);

    // Host-header allowlist (loopback binds only) — the single control that
    // defeats DNS rebinding. Under rebinding a browser resolves an attacker
    // domain to 127.0.0.1 and connects to loopback, so the per-handler
    // `peer.ip().is_loopback()` guard PASSES and CORS only blocks *reading* the
    // response, not *sending* the state-changing request (key writes, the
    // binary-swap `/update/trigger`, scan import, …). Pinning `Host` to the
    // loopback names the user actually types rejects the attacker's domain
    // before any handler runs. Skipped for a non-loopback bind: the operator
    // opted into exposure and the valid Host set (the box's own LAN IPs) isn't
    // enumerable here.
    let app = match host_allowlist(bind) {
        Some(allowed) => {
            let allowed = Arc::new(allowed);
            app.layer(axum::middleware::from_fn(
                move |req: axum::extract::Request, next: axum::middleware::Next| {
                    enforce_host_allowlist(Arc::clone(&allowed), req, next)
                },
            ))
        }
        None => app,
    };

    // Per-process rate limit on the mutating + compute-heavy surface. The only
    // other backpressure is `scan_semaphore` (`MAX_CONCURRENT_SCANS`), which
    // bounds *running* scans, not *request rate* — so a rapid loop of
    // `POST /scan/auto`, `/scans/batch`, or a heavy analysis GET
    // (`/network`, `/benchmark`, …) on a large scan can saturate the blocking
    // pool and starve the SSE reactor on a 2-core phone. This token bucket caps
    // the rate of exactly those routes (cheap reads — health, version, the SSE
    // streams themselves — are never charged), keyed by peer IP. On a loopback
    // bind every peer is `127.0.0.1`/`::1`, so it is effectively one global
    // throttle that stops a runaway SPA bug or a hostile same-device tab from
    // pinning the device, while a single interactive operator never notices the
    // generous ceiling. Placed inside the Host guard (a rejected-host request
    // must not consume a token) and inside the security-header layer (so the
    // `429` still carries CSP/COOP/etc.). See `enforce_rate_limit`.
    let limiter = Arc::new(RateLimiter::new(
        RATE_LIMIT_CAPACITY,
        RATE_LIMIT_REFILL_PER_SEC,
    ));
    let app = app.layer(axum::middleware::from_fn(
        move |req: axum::extract::Request, next: axum::middleware::Next| {
            enforce_rate_limit(Arc::clone(&limiter), req, next)
        },
    ));

    // Security headers on every response (outermost, so it also covers CORS
    // preflight, the SPA, static, the API, the Host-guard 403, and the
    // rate-limit 429). See `set_security_headers`.
    app.layer(axum::middleware::map_response(set_security_headers))
}

/// The exact `Host` header values accepted for a **loopback** bind — the
/// hostnames a user legitimately types to reach their own console
/// (`127.0.0.1:PORT`, `localhost:PORT`, `[::1]:PORT`, the bind string itself,
/// and the bare host forms). `None` for a non-loopback bind, where the valid
/// Host set is the machine's own (unknowable here) addresses and the operator
/// has explicitly accepted exposure — so the guard is not applied.
fn host_allowlist(bind: &str) -> Option<std::collections::HashSet<String>> {
    if !is_loopback_bind(bind) {
        return None;
    }
    let port = bind.rsplit_once(':').map_or("8080", |(_, p)| p);
    let mut set = std::collections::HashSet::new();
    set.insert(bind.to_ascii_lowercase());
    for h in ["localhost", "127.0.0.1", "[::1]"] {
        set.insert(format!("{h}:{port}"));
        set.insert(h.to_string());
    }
    Some(set)
}

/// Reject any request whose `Host` header is **present but not** in the loopback
/// allowlist ([`host_allowlist`]) — the DNS-rebinding defense described at the
/// call site. A rebind attack is browser-driven, and an HTTP/1.1 browser always
/// sends `Host` set to the attacker's domain, so the *present-and-mismatched*
/// case is exactly the attack. On HTTP/2 the browser sends `:authority` rather
/// than `Host`; axum/hyper normalise `:authority` into the `HeaderMap`'s `HOST`
/// entry before this middleware runs, so the same allowlist transparently covers
/// h2 — there is no separate `:authority` path to guard here.
///
/// An **absent** `Host` is handled by method: a header-less *safe* request
/// (`GET`/`HEAD`/`OPTIONS`) is allowed through — it is not the rebind threat (no
/// browser omits `Host`/`:authority`) and legitimate local probes/health-checks
/// may omit it — but a header-less *state-changing* request
/// (`POST`/`PUT`/`DELETE`/`PATCH`, per [`is_state_changing`]) is rejected as
/// defence-in-depth. HTTP/1.1 requires a `Host` header (RFC 7230 §5.4), so a
/// host-less mutation is already a non-conformant request; refusing it costs
/// conformant local tooling nothing (reqwest, curl and browsers all send `Host`)
/// while denying any non-browser caller that tries to mutate state without
/// naming the host it believes it is talking to. Returns `403` before any
/// handler in both the present-and-mismatched and the host-less-mutation cases.
async fn enforce_host_allowlist(
    allowed: Arc<std::collections::HashSet<String>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    match req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
    {
        // Present `Host`: must be in the loopback allowlist (the rebind case).
        Some(host) => {
            if !allowed.contains(&host.to_ascii_lowercase()) {
                return (StatusCode::FORBIDDEN, "host not in loopback allowlist").into_response();
            }
        }
        // Absent `Host`: tolerate safe methods, reject mutations (defence-in-depth).
        None => {
            if is_state_changing(req.method()) {
                return (StatusCode::FORBIDDEN, "host header required for mutations")
                    .into_response();
            }
        }
    }
    next.run(req).await
}

/// Whether `method` mutates server state (`POST`/`PUT`/`DELETE`/`PATCH`). Used by
/// [`is_rate_limited_request`] to decide which requests are charged against the
/// per-peer token bucket (every mutation, plus the compute-heavy analysis GETs).
fn is_state_changing(method: &Method) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::DELETE | Method::PATCH
    )
}

/// Token-bucket size for the rate limiter ([`RateLimiter`]): the burst a single
/// peer may fire before the steady-state [`RATE_LIMIT_REFILL_PER_SEC`] ceiling
/// applies. Sized so an interactive operator clicking through the SPA — which can
/// fan a single view out into a handful of analysis GETs — never trips it, while
/// a runaway loop is throttled within a second.
const RATE_LIMIT_CAPACITY: f64 = 40.0;

/// Steady-state refill rate (tokens per second) for the rate limiter. A generous
/// global ceiling: high enough that no human-driven session approaches it, low
/// enough that a hostile same-device tab or a buggy SPA retry-loop can't pin a
/// 2-core phone with autonomous-scan or full-graph-synthesis requests.
const RATE_LIMIT_REFILL_PER_SEC: f64 = 20.0;

/// `Retry-After` value (seconds) returned with a `429`. Whole seconds per
/// RFC 9110 §10.2.3; one second is the worst-case wait to regain a token at the
/// [`RATE_LIMIT_REFILL_PER_SEC`] rate.
const RATE_LIMIT_RETRY_AFTER_SECS: u64 = 1;

/// A single peer's token bucket: `tokens` available right now and the `Instant`
/// they were last refilled. Refill is lazy (computed on access from elapsed
/// time) so there is no background timer — a property that matters on a phone
/// where every spare wakeup costs battery.
struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

/// Per-process, per-peer token-bucket rate limiter for the mutating and
/// compute-heavy route surface (see the call site in [`router`] and the
/// classifier [`is_rate_limited_request`]).
///
/// A bucket holds at most `capacity` tokens and refills at `refill_per_sec`;
/// each charged request consumes one token, and a request that finds the bucket
/// empty is rejected with `429` + `Retry-After`. Buckets are keyed by peer
/// [`IpAddr`]; on the loopback bind this is a single key (`127.0.0.1`/`::1`), so
/// the limiter behaves as one global throttle, which is exactly the intent for a
/// same-device console. The map is pruned of long-idle (full) buckets on access
/// so it can't grow without bound on a non-loopback bind serving many clients.
struct RateLimiter {
    capacity: f64,
    refill_per_sec: f64,
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
}

impl RateLimiter {
    fn new(capacity: f64, refill_per_sec: f64) -> Self {
        Self {
            capacity,
            refill_per_sec,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Charge one token to `peer`'s bucket. Returns `true` if a token was
    /// available (request allowed) or `false` if the bucket was empty (reject
    /// with `429`). Refills lazily from elapsed wall time before charging.
    fn try_acquire(&self, peer: IpAddr) -> bool {
        let now = Instant::now();
        // `parking_lot::Mutex` does not poison and the guard is never held across
        // an `.await`, so this lock is contention-cheap on the 2-core target.
        let mut buckets = self.buckets.lock();

        let bucket = buckets.entry(peer).or_insert_with(|| Bucket {
            tokens: self.capacity,
            last_refill: now,
        });
        // Lazy refill: add the tokens accrued since the last touch, capped at
        // `capacity`. `saturating`-style clamp via `min` keeps it bounded.
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        bucket.last_refill = now;

        let allowed = if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        };

        // Opportunistic prune: drop any *other* peer whose bucket has been idle
        // long enough to have fully refilled, so a non-loopback bind serving many
        // short-lived clients can't accumulate dead entries. Bounded work (the
        // map is tiny in the loopback common case).
        if buckets.len() > 1 {
            let cap = self.capacity;
            let refill = self.refill_per_sec;
            buckets.retain(|&ip, b| {
                if ip == peer {
                    return true;
                }
                let restored = b.tokens + now.duration_since(b.last_refill).as_secs_f64() * refill;
                restored < cap
            });
        }

        allowed
    }
}

/// Whether a request should be charged against the [`RateLimiter`]: every
/// state-changing method ([`is_state_changing`]) — autonomous scans, the batch
/// endpoint, imports, key writes, the binary-swap trigger — plus the read-only
/// but **compute-heavy** analysis GETs that run full graph synthesis on a 2-core
/// device. Cheap reads (`/health`, `/version`, the SSE event streams, static
/// assets, the SPA) are never charged, so the limiter never interferes with the
/// console's normal liveness traffic or a long-lived SSE subscription.
fn is_rate_limited_request(method: &Method, path: &str) -> bool {
    if is_state_changing(method) {
        return true;
    }
    // Compute-heavy GET suffixes: the per-scan analysis endpoints whose handlers
    // synthesise the relationship graph / metrics from scratch. SSE streams
    // (`/events`) are deliberately excluded — they are long-lived and cheap to
    // hold open, and charging them would break live monitoring.
    const HEAVY_GET_SUFFIXES: &[&str] = &[
        "/network",
        "/identities",
        "/leads",
        "/timeline",
        "/communities",
        "/trust",
        "/path",
        "/metrics",
        "/duplicates",
        "/pivots",
        "/gaps",
        "/benchmark",
        "/correlations",
        "/relations",
        "/report.json",
        "/graph.gexf",
        "/debug.txt",
        "/entities/facets",
        "/entities/filter",
    ];
    method == Method::GET && HEAVY_GET_SUFFIXES.iter().any(|s| path.ends_with(s))
}

/// Reject mutating / compute-heavy requests that exceed the per-peer token-bucket
/// ceiling with `429 Too Many Requests` + a `Retry-After` header, in the shared
/// `{ "error": … }` JSON shape. Cheap reads pass through uncharged
/// ([`is_rate_limited_request`]). The peer IP is read from the
/// [`ConnectInfo<SocketAddr>`] the serve bootstrap installs; when it is absent
/// (e.g. a router built in a unit test without connect-info) the request is keyed
/// under the unspecified address, collapsing to a single global bucket — still a
/// correct, if coarser, throttle. Returns before the request reaches any handler.
async fn enforce_rate_limit(
    limiter: Arc<RateLimiter>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    if !is_rate_limited_request(req.method(), req.uri().path()) {
        return next.run(req).await;
    }
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map_or(IpAddr::from([0, 0, 0, 0]), |ci| ci.0.ip());
    if limiter.try_acquire(peer) {
        next.run(req).await
    } else {
        (
            StatusCode::TOO_MANY_REQUESTS,
            [(
                header::RETRY_AFTER,
                HeaderValue::from_static(const_retry_after()),
            )],
            Json(json!({ "error": "rate limit exceeded" })),
        )
            .into_response()
    }
}

/// The `Retry-After` header value as a `&'static str`, so the `429` path can use
/// `HeaderValue::from_static` (infallible, no per-request allocation). A `const fn`
/// can't `format!` the numeric [`RATE_LIMIT_RETRY_AFTER_SECS`] into a string, so
/// the literal is written out and a compile-time `assert!` pins it equal to the
/// constant — bumping the constant without updating the literal fails the build,
/// not just the `retry_after_constant_matches` test.
const fn const_retry_after() -> &'static str {
    const {
        assert!(
            RATE_LIMIT_RETRY_AFTER_SECS == 1,
            "update the Retry-After literal"
        );
    }
    "1"
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

/// Permissions-Policy: deny every powerful browser feature the console has no
/// use for. This matters most on the primary target — a **phone**: even if an
/// injection slipped past the SPA's `esc()` discipline, the browser refuses it
/// access to the device's camera, microphone, GPS, and motion/wireless sensors.
/// The empty allowlist `()` denies the feature to *every* origin, same-origin
/// included; the SPA itself uses none of these browser APIs (it works off the
/// server's GEOINT data), so denying them costs nothing. `interest-cohort=()`
/// opts the console out of Topics/FLoC ad-profiling.
const PERMISSIONS_POLICY: &str = "accelerometer=(), camera=(), geolocation=(), \
     gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=(), serial=(), \
     bluetooth=(), hid=(), midi=(), interest-cohort=()";

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
    // `Permissions-Policy` has no associated constant in the `http` crate, so
    // name it explicitly (lowercase, as `from_static` requires).
    h.insert(
        header::HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static(PERMISSIONS_POLICY),
    );
    // Cross-origin isolation, free for a strictly same-origin SPA. COOP severs
    // the `window.opener` relationship so a popup/opener on another origin can't
    // reach this console's window; CORP refuses to hand any of this origin's
    // bytes (the sensitive scan dossiers) to a cross-origin `<img>`/`<script>`/
    // `fetch` embed. The SPA loads every asset same-origin from this binary, so
    // neither restricts a single legitimate request — they only close the
    // cross-origin window/resource-leak gaps. Neither constant exists in the
    // `http` crate, so both are named explicitly (lowercase for `from_static`).
    h.insert(
        header::HeaderName::from_static("cross-origin-opener-policy"),
        HeaderValue::from_static("same-origin"),
    );
    h.insert(
        header::HeaderName::from_static("cross-origin-resource-policy"),
        HeaderValue::from_static("same-origin"),
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

/// SVG favicon — a concentric locator mark in the brand cyan on the navbar's dark.
/// Matches the inline `<link rel="icon">` in the SPA head; the `/favicon.svg`
/// and `/favicon.ico` routes both serve these bytes for clients that request a
/// favicon path directly regardless of that link.
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
/// app-like launch on the device. The icon reuses the same inline
/// locator-mark SVG the favicon serves, referenced via the canonical
/// `/favicon.svg` path so the icon's `src` extension and `type` agree
/// (`.svg` ↔ `image/svg+xml`) — a `.ico` path tagged `image/svg+xml` tripped
/// some Chrome installability checks. `sizes:"any"` satisfies Chrome's
/// installability check for a scalable icon; zero extra binary asset. Served
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
    { "src": "/favicon.svg", "sizes": "any", "type": "image/svg+xml", "purpose": "any" }
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

/// The exact set of request headers CORS permits cross-origin — the single
/// source of truth `build_cors_layer` feeds to `allow_headers`, lifted to a
/// named constant so the `cors_allow_headers_never_includes_csrf` regression
/// test can assert directly against it.
///
/// SECURITY — this list MUST NOT contain `X-HSE-CSRF` (the `/scans/import` CSRF
/// token). The import CSRF defence works precisely *because* that header is not
/// allow-listed: requiring it makes the import a CORS *non-simple* request, so a
/// cross-origin caller must preflight, and the preflight fails since the header
/// is absent here. `CONTENT_TYPE` is the only header the SPA's same-origin
/// requests need cross-checked.
const CORS_ALLOW_HEADERS: &[header::HeaderName] = &[header::CONTENT_TYPE];

fn build_cors_layer(bind: &str) -> CorsLayer {
    // Bound to the matching `http(s)://<bind>` origin even on loopback —
    // the previous `allow_origin(Any)` for loopback meant ANY website the
    // user visited in Chrome could XHR to 127.0.0.1:8080 and read their
    // scan history (an attack vector copilot flagged on PR #9). The SPA
    // is served same-origin from this binary so it never needs cross-
    // origin in normal use.
    // SECURITY — the allow-headers set is `CORS_ALLOW_HEADERS`; see its doc
    // comment. DO NOT add `X-HSE-CSRF` (the `/scans/import` CSRF token) to it:
    // its absence is what forces a cross-origin import to preflight and fail,
    // and the `cors_allow_headers_never_includes_csrf` test pins that invariant.
    let base = CorsLayer::new()
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers(CORS_ALLOW_HEADERS.to_vec());

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
    include!("tests.rs");
}
