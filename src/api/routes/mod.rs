//! Router definition, JSON 404 for `/api` typos, and SPA static fallback.
//!
//! Endpoint surface:
//!
//! | Method | Path                                     | Handler                        |
//! |--------|------------------------------------------|--------------------------------|
//! | GET    | `/api/v1/health`                         | `health`                       |
//! | GET    | `/api/v1/version`                        | `version`                      |
//! | GET    | `/api/v1/stats`                          | `stats`                        |
//! | GET    | `/api/v1/modules`                        | `modules_list`                 |
//! | GET    | `/api/v1/modules/graph`                  | `modules_graph` (v1.1+)        |
//! | GET    | `/api/v1/modules/health`                 | `modules_health`               |
//! | POST   | `/api/v1/capabilities/probe`             | `capabilities_probe` (v1.14+)  |
//! | GET    | `/api/v1/engines/health`                 | `engines_health` (v1.3+)       |
//! | GET    | `/api/v1/health/scrapers`                | `scraper_health` (v1.13+)      |
//! | GET    | `/api/v1/selftest`                       | `selftest_run`                 |
//! | GET    | `/api/v1/logs`                           | `logs_download`                |
//! | GET    | `/api/v1/debug/bundle`                   | `system_debug_bundle`          |
//! | GET    | `/api/v1/keys/patterns`                  | `keys_patterns` (v1.4+)        |
//! | GET    | `/api/v1/keys/status`                    | `keys_status` (v1.17+)         |
//! | GET    | `/api/v1/keys/health`                    | `keys_health` (v1.17+)         |
//! | GET    | `/api/v1/keys/harvest`                   | `keys_harvest`                 |
//! | GET    | `/api/v1/keys/pool`                      | `keys_pool_get`                |
//! | POST   | `/api/v1/keys/pool/add`                  | `keys_pool_add`                |
//! | POST   | `/api/v1/keys/pool/revoke`               | `keys_pool_revoke`             |
//! | POST   | `/api/v1/keys/pool/rotate`               | `keys_pool_rotate`             |
//! | POST   | `/api/v1/scans`                          | `scan_create`                  |
//! | GET    | `/api/v1/scans`                          | `scan_list`                    |
//! | POST   | `/api/v1/scans/batch`                    | `scan_batch`                   |
//! | POST   | `/api/v1/scans/import`                   | `scan_import` (16 MB body cap) |
//! | GET    | `/api/v1/scans/{id}`                     | `scan_get`                     |
//! | DELETE | `/api/v1/scans/{id}`                     | `scan_delete`                  |
//! | POST   | `/api/v1/scans/{id}/rerun`               | `scan_rerun`                   |
//! | POST   | `/api/v1/scans/{id}/cancel`              | `scan_cancel`                  |
//! | GET    | `/api/v1/scans/{id}/entities`            | `scan_entities`                |
//! | GET    | `/api/v1/scans/{id}/entities/filter`     | `scan_entities_filter`         |
//! | GET    | `/api/v1/scans/{id}/entities/facets`     | `scan_entities_facets`         |
//! | GET    | `/api/v1/scans/{id}/diamond`             | `scan_diamond`                 |
//! | GET    | `/api/v1/scans/{id}/exposure`            | `scan_exposure`                |
//! | GET    | `/api/v1/scans/{id}/attack`              | `scan_attack` (v1.13+)         |
//! | GET    | `/api/v1/scans/{id}/entities.csv`        | `scan_entities_csv`            |
//! | GET    | `/api/v1/scans/{id}/report.json`         | `scan_report_json`             |
//! | GET    | `/api/v1/scans/{id}/graph.gexf`          | `scan_export_gexf`             |
//! | GET    | `/api/v1/scans/{id}/stix.json`           | `scan_export_stix`             |
//! | GET    | `/api/v1/scans/{id}/debug.txt`           | `scan_debug_bundle`            |
//! | GET    | `/api/v1/scans/{id}/events.log`          | `scan_events_log` (download)   |
//! | GET    | `/api/v1/scans/{id}/correlations`        | `scan_correlations` (v0.4+)    |
//! | GET    | `/api/v1/scans/{id}/relations`           | `scan_relations`               |
//! | GET    | `/api/v1/scans/{id}/network`             | `scan_network`                 |
//! | GET    | `/api/v1/scans/{id}/cross-scan`          | `scan_cross_scan` (v1.35+)     |
//! | GET    | `/api/v1/scans/{id}/snake.svg`           | `scan_snake_svg` (v1.35+)      |
//! | GET    | `/api/v1/scans/{id}/stealer-rows`        | `scan_stealer_rows` (v1.13+)   |
//! | GET    | `/api/v1/scans/{id}/identities`          | `scan_identities`              |
//! | GET    | `/api/v1/scans/{id}/leads`               | `scan_leads`                   |
//! | GET    | `/api/v1/scans/{id}/timeline`            | `scan_timeline`                |
//! | GET    | `/api/v1/scans/{id}/communities`         | `scan_communities`             |
//! | GET    | `/api/v1/scans/{id}/trust`               | `scan_trust`                   |
//! | GET    | `/api/v1/scans/{id}/path`                | `scan_path`                    |
//! | GET    | `/api/v1/scans/{id}/metrics`             | `scan_metrics`                 |
//! | GET    | `/api/v1/scans/{id}/duplicates`          | `scan_duplicates`              |
//! | GET    | `/api/v1/scans/{id}/pivots`              | `scan_pivots`                  |
//! | GET    | `/api/v1/scans/{id}/gaps`                | `scan_gaps`                    |
//! | GET    | `/api/v1/scans/{id}/location`            | `scan_location`                |
//! | GET    | `/api/v1/scans/{id}/benchmark`           | `scan_benchmark`               |
//! | GET    | `/api/v1/scans/{id}/audit`               | `scan_audit` (v1.3+)           |
//! | GET    | `/api/v1/scans/{a}/diff/{b}`             | `scan_diff`                    |
//! | GET    | `/api/v1/scans/{id}/events`              | `scan_events_sse` (SSE)        |
//! | GET    | `/api/v1/scans/{id}/events.history`      | `scan_events_history`          |
//! | GET    | `/api/v1/scan/profiles`                  | `scan_profiles` (v1.13+)       |
//! | POST   | `/api/v1/scan/auto`                      | `scan_auto`                    |
//! | GET    | `/api/v1/scan/auto/plan`                 | `scan_auto_plan`               |
//! | POST   | `/api/v1/scan/auto/sweep`                | `scan_auto_sweep`              |
//! | GET    | `/api/v1/plan`                           | `plan_preview`                 |
//! | POST   | `/api/v1/radar`                          | `radar_sweep`                  |
//! | POST   | `/api/v1/radar/live`                     | `radar_live`                   |
//! | GET    | `/api/v1/radar/history`                  | `radar_history`                |
//! | GET    | `/api/v1/radar/recurring`                | `radar_recurring`              |
//! | POST   | `/api/v1/live`                           | `live_create` (v0.5+)          |
//! | GET    | `/api/v1/live`                           | `live_list`                    |
//! | GET    | `/api/v1/live/{id}`                      | `live_get`                     |
//! | DELETE | `/api/v1/live/{id}`                      | `live_stop`                    |
//! | GET    | `/api/v1/live/{id}/events`               | `live_events_sse` (SSE)        |
//! | GET    | `/api/v1/entities/{uid}`                 | `entity_get`                   |
//! | GET    | `/api/v1/search`                         | `search_entities`              |
//! | GET    | `/api/v1/settings/keys`                  | `settings_keys_get` (v0.10+)   |
//! | PUT    | `/api/v1/settings/keys`                  | `settings_keys_put`            |
//! | GET    | `/api/v1/settings/toggles`               | `settings_toggles_get` (v1.4+) |
//! | PUT    | `/api/v1/settings/toggles`               | `settings_toggles_put`         |
//! | GET    | `/api/v1/update/status`                  | `get_status` (v1.5+)           |
//! | POST   | `/api/v1/update/trigger`                 | `post_trigger` (v1.5+)         |
//! | GET    | `/api/v1/cells/status`                   | `cells_status` (v1.13+)        |
//! | POST   | `/api/v1/cells/import`                   | `cells_import` (v1.13+)        |
//! | POST   | `/api/v1/cells/clear`                    | `cells_clear` (v1.13+)         |
//! | *      | `/api/*` (unmatched)                     | `api_not_found` (JSON 404)     |
//! | GET    | `/static/{*file}`                        | `vendor_handler`               |
//! | GET    | `/*` (fallback)                          | `spa_handler` (static)         |

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

use super::{
    AppState, cells_handlers, handlers, key_harvest_handlers, scan_export, scan_handlers,
    settings_handlers, update_handlers,
};

/// Embedded SPA — single self-contained HTML file with inline CSS + JS.
/// Lives in `src/web/spa.html` and is compiled into the binary at build time
/// so the release artefact is still a single file.
const SPA_HTML: &str = include_str!("../../web/spa.html");

/// Vendor bundle — now just D3 v3, the force-directed graph rendering
/// engine. Bootstrap, jQuery, tablesorter, and alertify (SpiderFoot's
/// original UI-framework stack) were dropped entirely in favour of a
/// from-scratch design system (`src/web/css/app.css`) plus small vanilla-JS
/// replacements (`src/web/js/ui.js`) for the handful of interactive
/// behaviours those libraries provided (navbar collapse, the About modal,
/// sortable tables, toast/confirm/prompt dialogs) — see `ui.js`'s own doc
/// comment. D3 stays vendored because it is a rendering engine, not a
/// look-and-feel dependency: every visual property of the graph (node
/// colours, sizes, the canvas background) is already this project's own
/// code. Dropping the vendored alertify build also happens to close a
/// standing licensing question noted in `docs/PROBLEM_TREE.md` §7
/// (Deferred — Privacy/Legal/Licensing): alertify was GPL-licensed with no
/// accompanying `NOTICE`.
///
/// Embedded at compile time so the release artefact is still a single
/// binary. Served from `/static/{*file}`, alongside [`APP_FILES`], with a
/// one-hour `Cache-Control: must-revalidate` header — see
/// [`vendor_handler`]'s ETag/conditional-GET handling for why.
const VENDOR_FILES: &[(&str, &str, &[u8])] = &[(
    "d3.min.js",
    "application/javascript",
    include_bytes!("../../web/vendor/d3.min.js"),
)];

/// First-party SPA modules (split from the former monolithic `spa.html` for
/// maintainability — see each module's own doc comment in `src/web/js/`).
/// Embedded at compile time so the release artefact is still a single binary;
/// served from `/static/{path}` alongside [`VENDOR_FILES`], keyed on the path
/// relative to `src/web/` (e.g. `js/main.js`, `css/app.css`) so nested module
/// paths resolve exactly as written in each file's own
/// `import … from '/static/js/…';` statement.
const APP_FILES: &[(&str, &str, &[u8])] = &[
    (
        "css/app.css",
        "text/css; charset=utf-8",
        include_bytes!("../../web/css/app.css"),
    ),
    (
        "js/api.js",
        "application/javascript",
        include_bytes!("../../web/js/api.js"),
    ),
    (
        "js/helpers.js",
        "application/javascript",
        include_bytes!("../../web/js/helpers.js"),
    ),
    (
        "js/main.js",
        "application/javascript",
        include_bytes!("../../web/js/main.js"),
    ),
    (
        "js/router.js",
        "application/javascript",
        include_bytes!("../../web/js/router.js"),
    ),
    (
        "js/scan_info/audit.js",
        "application/javascript",
        include_bytes!("../../web/js/scan_info/audit.js"),
    ),
    (
        "js/scan_info/benchmark.js",
        "application/javascript",
        include_bytes!("../../web/js/scan_info/benchmark.js"),
    ),
    (
        "js/scan_info/browse.js",
        "application/javascript",
        include_bytes!("../../web/js/scan_info/browse.js"),
    ),
    (
        "js/scan_info/communities.js",
        "application/javascript",
        include_bytes!("../../web/js/scan_info/communities.js"),
    ),
    (
        "js/scan_info/correlations.js",
        "application/javascript",
        include_bytes!("../../web/js/scan_info/correlations.js"),
    ),
    (
        "js/scan_info/duplicates.js",
        "application/javascript",
        include_bytes!("../../web/js/scan_info/duplicates.js"),
    ),
    (
        "js/scan_info/gaps.js",
        "application/javascript",
        include_bytes!("../../web/js/scan_info/gaps.js"),
    ),
    (
        "js/scan_info/graph.js",
        "application/javascript",
        include_bytes!("../../web/js/scan_info/graph.js"),
    ),
    (
        "js/scan_info/identities.js",
        "application/javascript",
        include_bytes!("../../web/js/scan_info/identities.js"),
    ),
    (
        "js/scan_info/index.js",
        "application/javascript",
        include_bytes!("../../web/js/scan_info/index.js"),
    ),
    (
        "js/scan_info/info.js",
        "application/javascript",
        include_bytes!("../../web/js/scan_info/info.js"),
    ),
    (
        "js/scan_info/leads.js",
        "application/javascript",
        include_bytes!("../../web/js/scan_info/leads.js"),
    ),
    (
        "js/scan_info/location.js",
        "application/javascript",
        include_bytes!("../../web/js/scan_info/location.js"),
    ),
    (
        "js/scan_info/log.js",
        "application/javascript",
        include_bytes!("../../web/js/scan_info/log.js"),
    ),
    (
        "js/scan_info/metrics.js",
        "application/javascript",
        include_bytes!("../../web/js/scan_info/metrics.js"),
    ),
    (
        "js/scan_info/network.js",
        "application/javascript",
        include_bytes!("../../web/js/scan_info/network.js"),
    ),
    (
        "js/scan_info/path.js",
        "application/javascript",
        include_bytes!("../../web/js/scan_info/path.js"),
    ),
    (
        "js/scan_info/pivots.js",
        "application/javascript",
        include_bytes!("../../web/js/scan_info/pivots.js"),
    ),
    (
        "js/scan_info/relations.js",
        "application/javascript",
        include_bytes!("../../web/js/scan_info/relations.js"),
    ),
    (
        "js/scan_info/report.js",
        "application/javascript",
        include_bytes!("../../web/js/scan_info/report.js"),
    ),
    (
        "js/scan_info/status.js",
        "application/javascript",
        include_bytes!("../../web/js/scan_info/status.js"),
    ),
    (
        "js/scan_info/stealer.js",
        "application/javascript",
        include_bytes!("../../web/js/scan_info/stealer.js"),
    ),
    (
        "js/scan_info/timeline.js",
        "application/javascript",
        include_bytes!("../../web/js/scan_info/timeline.js"),
    ),
    (
        "js/scan_info/trust.js",
        "application/javascript",
        include_bytes!("../../web/js/scan_info/trust.js"),
    ),
    (
        "js/state.js",
        "application/javascript",
        include_bytes!("../../web/js/state.js"),
    ),
    (
        "js/theme.js",
        "application/javascript",
        include_bytes!("../../web/js/theme.js"),
    ),
    (
        "js/timers.js",
        "application/javascript",
        include_bytes!("../../web/js/timers.js"),
    ),
    (
        "js/ui.js",
        "application/javascript",
        include_bytes!("../../web/js/ui.js"),
    ),
    (
        "js/views/dash.js",
        "application/javascript",
        include_bytes!("../../web/js/views/dash.js"),
    ),
    (
        "js/views/diff.js",
        "application/javascript",
        include_bytes!("../../web/js/views/diff.js"),
    ),
    (
        "js/views/engines.js",
        "application/javascript",
        include_bytes!("../../web/js/views/engines.js"),
    ),
    (
        "js/views/key_harvest.js",
        "application/javascript",
        include_bytes!("../../web/js/views/key_harvest.js"),
    ),
    (
        "js/views/live.js",
        "application/javascript",
        include_bytes!("../../web/js/views/live.js"),
    ),
    (
        "js/views/new_scan.js",
        "application/javascript",
        include_bytes!("../../web/js/views/new_scan.js"),
    ),
    (
        "js/views/opts.js",
        "application/javascript",
        include_bytes!("../../web/js/views/opts.js"),
    ),
    (
        "js/views/scans.js",
        "application/javascript",
        include_bytes!("../../web/js/views/scans.js"),
    ),
    (
        "js/views/search.js",
        "application/javascript",
        include_bytes!("../../web/js/views/search.js"),
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
        .route("/modules/health", get(handlers::modules_health))
        .route("/engines/health", get(handlers::engines_health))
        .route("/health/scrapers", get(handlers::scraper_health))
        // POST, not GET: a live probe fires a real network request per keyless
        // module, so it is an explicit action — never something a prefetch or a
        // stray GET can trigger.
        .route("/capabilities/probe", post(handlers::capabilities_probe))
        .route("/stats", get(handlers::stats))
        // ── diagnostics: self-test + downloadable verbose logs ──
        .route("/selftest", get(handlers::selftest_run))
        .route("/logs", get(handlers::logs_download))
        // One-click consolidated system self-diagnosis bundle (loopback-only):
        // DETECTED ISSUES verdict + environment + self-test + module/engine/
        // scraper health + recent scans + logs + source manifest, in one file.
        .route("/debug/bundle", get(handlers::system_debug_bundle))
        // ── key-detector catalogue (v1.4+) ──
        .route("/keys/patterns", get(settings_handlers::keys_patterns))
        .route("/keys/status", get(settings_handlers::keys_status))
        .route("/keys/health", get(settings_handlers::keys_health))
        .route("/keys/harvest", get(key_harvest_handlers::keys_harvest))
        .route("/keys/pool", get(settings_handlers::keys_pool_get))
        .route("/keys/pool/add", post(settings_handlers::keys_pool_add))
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
        // Named scan-profile catalogue (recommended/passive/footprint/investigate/
        // fast/skiptrace) — feeds the New Scan wizard's profile picker.
        .route("/scan/profiles", get(scan_handlers::scan_profiles))
        // Live-radar button: ONE autonomous device-sensor sweep, no target seed.
        .route("/radar", post(scan_handlers::radar_sweep))
        // Continuous autonomous radar: a zero-input live session that re-runs only
        // the on-device passive sensors, enumerating ambient signals in real time.
        .route("/radar/live", post(scan_handlers::radar_live))
        // Historical review of past radar sweeps, sourced from the persisted
        // `scans` table rather than in-memory session state — survives a
        // `hse serve` restart, so "what was around me earlier" doesn't
        // require remembering a session id.
        .route("/radar/history", get(scan_handlers::radar_history))
        .route("/radar/recurring", get(scan_handlers::radar_recurring))
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
        .route("/scans/{id}/diamond", get(scan_handlers::scan_diamond))
        .route("/scans/{id}/exposure", get(scan_handlers::scan_exposure))
        .route("/scans/{id}/attack", get(scan_handlers::scan_attack))
        .route(
            "/scans/{id}/entities.csv",
            get(scan_export::scan_entities_csv),
        )
        .route(
            "/scans/{id}/report.json",
            get(scan_export::scan_report_json),
        )
        .route("/scans/{id}/graph.gexf", get(scan_export::scan_export_gexf))
        .route("/scans/{id}/stix.json", get(scan_export::scan_export_stix))
        .route("/scans/{id}/debug.txt", get(scan_export::scan_debug_bundle))
        .route("/scans/{id}/events.log", get(scan_export::scan_events_log))
        .route(
            "/scans/{id}/correlations",
            get(scan_handlers::scan_correlations),
        )
        .route("/scans/{id}/relations", get(scan_handlers::scan_relations))
        // Paired stealer-log credential rows (login+password+domain+machine,
        // kept together) — powers the web UI Stealer Logs Viewer.
        .route(
            "/scans/{id}/stealer-rows",
            get(scan_handlers::scan_stealer_rows),
        )
        // Subject-centric relationship synthesis — powers the web UI Network view.
        .route("/scans/{id}/network", get(scan_handlers::scan_network))
        // Entities this scan shares with earlier investigations, ranked by bridge
        // strength and carrying the prior scan ids each one expands into.
        .route(
            "/scans/{id}/cross-scan",
            get(scan_handlers::scan_cross_scan),
        )
        // Simplified concentric-ring projection of the relation graph, as SVG.
        .route("/scans/{id}/snake.svg", get(scan_handlers::scan_snake_svg))
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
        // The AU-059 residency fix — the "where is the subject" location verdict.
        .route("/scans/{id}/location", get(scan_handlers::scan_location))
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
        // ── cells (v1.14+): web-UI equivalent of `hse cells status|import|clear` ──
        .route("/cells/status", get(cells_handlers::cells_status))
        .route("/cells/import", post(cells_handlers::cells_import))
        .route("/cells/clear", post(cells_handlers::cells_clear))
        .fallback(api_not_found);

    // /api — outer layer catches `/api/v2/...` / `/api/typo` /
    // anything under /api but outside /v1, again returning JSON 404
    // rather than SPA HTML. The CSRF guard wraps every `/api` request so a
    // cross-site simple-request POST to any mutating endpoint is rejected.
    let api = Router::new()
        .nest("/v1", api_v1)
        .fallback(api_not_found)
        .layer(axum::middleware::from_fn(enforce_csrf));

    let app = Router::new()
        .nest("/api", api)
        // ── static bundle (D3 vendored + first-party app.css/js modules) ──
        // `{*file}` (wildcard, not `{file}`) so nested first-party module paths
        // (`js/scan_info/browse.js`) match, not just a single flat segment.
        .route("/static/{*file}", get(vendor_handler))
        // ── favicon — browsers (esp. Chrome-on-Android) request /favicon.ico
        //    unconditionally; without this route it would hit the SPA fallback
        //    and return the whole HTML document as an "image". Serve the same
        //    inline locator-mark favicon the SPA links, with the correct content type.
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

    // Security headers on every response (outermost, so it also covers CORS
    // preflight, the SPA, static, the API, and the Host-guard 403). See
    // `set_security_headers`.
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
/// case is exactly the attack; an **absent** `Host` is allowed through (a
/// non-browser local client — or the test harness — that omits it is not the
/// rebind threat and is already covered by the per-handler loopback guards).
/// Returns `403` before the request reaches any handler.
async fn enforce_host_allowlist(
    allowed: Arc<std::collections::HashSet<String>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let rebind = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .is_some_and(|h| !allowed.contains(&h.to_ascii_lowercase()));
    if rebind {
        (StatusCode::FORBIDDEN, "host not in loopback allowlist").into_response()
    } else {
        next.run(req).await
    }
}

/// CSRF guard on every state-changing API request.
///
/// A cross-site page can issue a CORS *simple request* (a bodyless or
/// `text/plain` `POST`) to `http://127.0.0.1:8080/...` with **no preflight**; the
/// Host-allowlist only defeats DNS rebinding (an attacker *domain*), and CORS
/// only blocks *reading* the response, not the state-changing side effect. The
/// one thing a cross-site page cannot do is set a **custom request header** on a
/// simple request without turning it into a *preflighted* request — which the
/// strict CORS layer then rejects. So requiring `X-HSE-CSRF` on every mutating
/// method is the control that blocks the drive-by-POST class: a malicious page
/// forcing `/update/trigger`'s binary self-update + `exec()`, activating the
/// phone's `radar` sensor sweep, or dispatching quota-burning `scan/auto` runs.
/// `scans/import` already required this header; this closes the same gap on every
/// other mutating endpoint uniformly (and future ones automatically). GET/HEAD
/// and the `OPTIONS` preflight pass through untouched; the same-origin SPA injects
/// the header on every mutating `fetch`, and a CLI/API client sends
/// `-H 'X-HSE-CSRF: 1'`.
async fn enforce_csrf(req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let mutating = matches!(
        *req.method(),
        Method::POST | Method::PUT | Method::DELETE | Method::PATCH
    );
    if mutating && !req.headers().contains_key("x-hse-csrf") {
        return (
            StatusCode::FORBIDDEN,
            [(header::CONTENT_TYPE, "application/json")],
            r#"{"error":"missing X-HSE-CSRF header (cross-site request blocked)"}"#,
        )
            .into_response();
    }
    next.run(req).await
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
/// app-like launch on the device. The icon reuses the same inline
/// locator-mark SVG the favicon serves (`sizes:"any"` satisfies Chrome's
/// installability check for a scalable icon) — zero extra binary asset. Served
/// same-origin, so CSP `default-src 'self'` (which `manifest-src` falls back to)
/// permits it.
const MANIFEST_JSON: &str = r##"{
  "name": "Huntsman Search Engine",
  "short_name": "Huntsman",
  "description": "All-source OSINT / GEOINT / NETINT reconnaissance in the GhostSec tradition — SpiderFoot-inspired breadth, runs entirely in Termux on Android, no root.",
  "start_url": "/",
  "scope": "/",
  "display": "standalone",
  "orientation": "any",
  "background_color": "#0a0d11",
  "theme_color": "#0a0d11",
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

/// Serve the one embedded vendor file (D3) or a first-party SPA module
/// (`js/…`, `css/app.css`). Returns 404 for any path
/// not in [`VENDOR_FILES`] or [`APP_FILES`] — there's no path traversal to
/// worry about despite the wildcard route (`/static/{*file}`, needed so
/// nested app paths like `js/scan_info/browse.js` match): every candidate
/// byte slice is already embedded in the binary at compile time, and the
/// match is exact-string equality against that fixed, known-good list, never
/// a filesystem lookup — a `file` value like `../../etc/passwd` simply
/// matches nothing and falls through to the 404 below.
async fn vendor_handler(Path(file): Path<String>, headers: HeaderMap) -> Response {
    for (name, ct, bytes) in VENDOR_FILES.iter().chain(APP_FILES.iter()) {
        if *name == file {
            // ETag is the crate version (which uniquely identifies the
            // embedded bytes — the bundle ships in-binary). We deliberately
            // do NOT use `Cache-Control: immutable` because the URL
            // (`/static/d3.min.js`) is stable across upgrades;
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
    include!("tests.rs");
}
