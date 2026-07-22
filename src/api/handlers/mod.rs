// HTTP handlers.
//
// Every handler returns `impl IntoResponse` so we can mix `Json`,
// `(StatusCode, Json)`, and `Sse<...>` freely. Error paths emit a
// `{"error": "..."}` JSON body with the appropriate status.

use std::{convert::Infallible, sync::Arc};

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::{
        IntoResponse,
        sse::{Event as SseEvent, KeepAlive, Sse},
    },
};
use futures::Stream;
use serde::Serialize;
use serde_json::{Value, json};
use tokio_stream::{StreamExt as _, wrappers::BroadcastStream};

use super::AppState;
use crate::core::{
    event::{Event, EventBus},
    module::ModuleContext,
    scan::{Target, TargetKind},
};
use crate::util::keys;

// ─── Shared response helpers ───────────────────────────────────────────────

/// Construct and validate a `Target`, mapping a validation failure to the
/// canonical client-facing `invalid target: …` message. The single source of
/// truth for target admission shared by the scan-create and live-create paths,
/// so the rule and its error wording can't diverge between them.
pub(crate) fn validated_target(kind: TargetKind, value: String) -> Result<Target, String> {
    let target = Target::new(kind, value);
    target
        .validate_verbose()
        .map_err(|msg| format!("invalid target: {msg}"))?;
    Ok(target)
}

/// A `500` with a `{ "error": <msg> }` body — the server-error sibling of
/// [`bad_request`] / [`not_found`], for a storage or internal failure. One shape
/// for every 500 so API consumers parse errors uniformly.
pub(crate) fn internal_error(err: &impl ToString) -> axum::response::Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "error": err.to_string() })),
    )
        .into_response()
}

/// A `404` with a `{ "error": "not found" }` body — returned when a scan / entity
/// / sub-resource id doesn't exist, in the shared error shape.
pub(crate) fn not_found() -> axum::response::Response {
    (StatusCode::NOT_FOUND, Json(json!({ "error": "not found" }))).into_response()
}

/// 400 with a `{ "error": <msg> }` body — the client-error sibling of
/// [`internal_error`] / [`not_found`]. Accepts both `&'static str` literals and
/// owned `String`s (e.g. a `format!`-built validation message), so the ~10
/// open-coded `(BAD_REQUEST, Json(json!({"error": …})))` sites share one shape.
pub(crate) fn bad_request(msg: impl Into<String>) -> axum::response::Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "error": msg.into() })),
    )
        .into_response()
}

/// A `403 Forbidden` JSON error, the access-control sibling of [`bad_request`]
/// (e.g. a failed CSRF/loopback check). One shape for every refusal.
pub(crate) fn forbidden(msg: impl Into<String>) -> axum::response::Response {
    (StatusCode::FORBIDDEN, Json(json!({ "error": msg.into() }))).into_response()
}

/// The canonical list envelope every list endpoint returns:
/// `{ "<key>": [items…], "count": <n> }`. One shape so the SPA and CLI parse
/// every collection response (entities, relations, correlations, …) identically.
pub(crate) fn ok_list<T: Serialize>(key: &str, items: Vec<T>) -> axum::response::Response {
    let n = items.len();
    let mut map = serde_json::Map::new();
    map.insert(
        key.to_string(),
        serde_json::to_value(items).unwrap_or(Value::Null),
    );
    map.insert("count".to_string(), Value::Number(n.into()));
    (StatusCode::OK, Json(Value::Object(map))).into_response()
}

/// Dispatch a created `scan` to run on the async runtime — the HTTP layer's
/// fire-and-forget hand-off to the engine (the request returns `202` immediately).
///
/// Wires up everything the background run needs: a [`crate::core::cancel::CancelHandle`]
/// registered so `POST /scans/{id}/cancel` can stop it, a per-scan HTTP client
/// stamped with the scan id (`x-huntsman-trace`) so outbound calls correlate in
/// upstream logs, and the scan-concurrency semaphore that bounds how many scans
/// run at once on a low-RAM device.
pub(crate) fn spawn_scan(state: &Arc<AppState>, scan: crate::core::scan::Scan, target: Target) {
    let sid = scan.id.clone();
    let cancel = crate::core::cancel::CancelHandle::new();
    let cancel_guard = super::CancelRegistryGuard::install(
        Arc::clone(&state.cancellations),
        sid.clone(),
        cancel.clone(),
    );
    let bus_clone = state.bus.clone();
    // Per-scan client stamped with the scan id (x-huntsman-trace) so outbound
    // calls correlate to this scan in a proxy/upstream log, mirroring the CLI.
    let http_clone = crate::util::http::build_client_with_trace(&sid);
    let engine = Arc::clone(&state.engine);
    let sem = Arc::clone(&state.scan_semaphore);
    let store_clone = Arc::clone(&state.store);
    tokio::spawn(async move {
        let _cancel_guard = cancel_guard;
        let api_keys = keys::populate_and_load().await;
        let ctx = ModuleContext {
            scan_id: sid.clone(),
            bus: bus_clone,
            http: http_clone,
            keys: api_keys,
            cancel,
        };
        let Ok(_permit) = sem.acquire().await else {
            tracing::warn!(scan_id = %sid, "scan semaphore closed");
            return;
        };
        match engine.run(scan, target, ctx).await {
            Ok(completed) => {
                // Mirror the CLI's post-scan diagnostics: update the cross-scan
                // module-stats ledger so API/web scans feed adaptive routing the
                // same as `hse scan` CLI runs do.
                if let Ok(entities) = store_clone.entities_for_scan(&sid) {
                    let wall_ms = completed
                        .finished_at
                        .and_then(|f| f.checked_sub(completed.started_at))
                        .unwrap_or(0)
                        .saturating_mul(1000);
                    crate::util::diagnostics::analyse(
                        &sid,
                        completed.target.kind.canonical_str(),
                        &completed.target.value,
                        wall_ms,
                        &entities,
                    );
                }
            }
            Err(e) => tracing::warn!(scan_id = %sid, error = %e, "scan failed"),
        }
    });
}

// ─── Scan CRUD handlers ──────────────────────────────────────────────────
// Scan CRUD handlers: create, get, list, delete, rerun, cancel,
// entities, correlations, events, CSV/JSON export.

pub async fn health() -> Json<Value> {
    Json(json!({ "status": "ok", "version": crate::VERSION }))
}

/// Pure aggregation of dashboard scan statistics — the per-status histogram and
/// the entity/dedup totals — over a scan list. Split out of [`stats`] so the
/// summation logic is unit-testable without a live store + async handler.
#[derive(Default, PartialEq, Eq, Debug)]
pub(crate) struct ScanStatsAgg {
    pub by_status: std::collections::BTreeMap<&'static str, u64>,
    pub total_entities: u64,
    pub total_deduped: u64,
}

pub(crate) fn aggregate_scan_stats(scans: &[crate::core::scan::Scan]) -> ScanStatsAgg {
    let mut agg = ScanStatsAgg::default();
    for scan in scans {
        *agg.by_status.entry(scan.status.as_str()).or_insert(0) += 1;
        agg.total_entities += scan.entity_count as u64;
        agg.total_deduped += scan.modules_deduped as u64;
    }
    agg
}

pub async fn stats(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    let store = Arc::clone(&s.store);
    let scans = match tokio::task::spawn_blocking(move || store.list_scans(10_000)).await {
        Ok(Ok(scans)) => scans,
        Ok(Err(e)) => return internal_error(&e),
        Err(e) => return internal_error(&format!("stats query failed: {e}")),
    };
    let ScanStatsAgg {
        by_status,
        total_entities,
        total_deduped,
    } = aggregate_scan_stats(&scans);
    let modules = s.engine.modules().len();
    let live_sessions = s.live.list().len();

    // Surface SeekNow + OathNet + WiGLE budget consumption so operators
    // can see how much of each daily quota the current process has
    // burned. All providers share `util::budget::QuotaBudget` so the
    // wire format is identical; WiGLE has four sub-budgets (geo /
    // bssid / cell / bluetooth) so its block nests one level deeper.
    let seeknow = budget_block(crate::util::see_know::budget_snapshot());
    let oathnet = budget_block(crate::util::oathnet::budget_snapshot());
    let wigle = crate::modules::wigle::budget_snapshot();
    let wigle_account = crate::modules::wigle::account_status();
    let wigle_block = json!({
        "geo":       budget_block(wigle.geo),
        "bssid":     budget_block(wigle.bssid),
        "cell":      budget_block(wigle.cell),
        "bluetooth": budget_block(wigle.bluetooth),
        "account":   {
            // `verified == false` means the WiGLE account has not yet
            // confirmed the email-verification step, which gates the
            // database queries (operator-facing warning). `null` means
            // we haven't polled `/profile/user` yet this process. WiGLE
            // exposes no per-call usage endpoint, so quota counts aren't
            // reported here.
            "verified":           wigle_account.verified,
            "user":               wigle_account.user,
            "last_polled_ts":     wigle_account.last_polled_ts,
        },
    });

    (
        StatusCode::OK,
        Json(json!({
            "scans_total": scans.len(),
            "scans_by_status": by_status,
            "entities_total": total_entities,
            "modules_deduped_total": total_deduped,
            "modules": modules,
            "live_sessions": live_sessions,
            "version": crate::VERSION,
            "seeknow": seeknow,
            "oathnet": oathnet,
            "wigle":   wigle_block,
        })),
    )
        .into_response()
}

/// Convert a [`crate::util::budget::BudgetSnapshot`] into the
/// JSON shape used by the `/api/v1/stats` endpoint. Centralised so
/// every quota-spending provider serialises identically.
fn budget_block(snap: crate::util::budget::BudgetSnapshot) -> Value {
    json!({
        "scan_used":       snap.scan_used,
        "scan_cap":        snap.scan_cap,
        "session_used":    snap.session_used,
        "session_cap":     snap.session_cap,
        "quota_exhausted": snap.quota_exhausted,
    })
}

pub async fn version() -> Json<Value> {
    Json(json!({ "version": crate::VERSION }))
}

/// Search-engine liveness panel data. Serves the latest cached sweep (populated
/// by the periodic + startup background task in `hse serve`); if no sweep has run
/// yet, runs one lazily. Each engine reports up/blocked/down + latency + result
/// count. Backs the web liveness panel and `hse engines`.
pub async fn engines_health() -> Json<Value> {
    use crate::modules::search_engines::health::{EngineStatus, cached_or_empty};
    // Serve the cached sweep (instant, hermetic); never probe on the request
    // path. The startup/periodic sweep in `hse serve` populates it; a cold cache
    // returns an empty snapshot and the panel auto-refreshes.
    let snap = cached_or_empty();
    let count = |st: EngineStatus| snap.engines.iter().filter(|h| h.status == st).count();
    let engines: Vec<Value> = snap
        .engines
        .iter()
        .map(|h| {
            json!({
                "engine": h.name,
                "status": h.status.as_str(),
                "latency_ms": h.latency_ms,
                "results": h.results,
                "detail": h.detail,
                // True when this engine has been silenced for the current scan
                // after returning nothing for 3+ consecutive seeds.
                "session_dead": crate::modules::search_engines::session_dead(h.name),
            })
        })
        .collect();
    Json(json!({
        "checked_at": snap.checked_at,
        "total": snap.engines.len(),
        "up": count(EngineStatus::Up),
        "blocked": count(EngineStatus::Blocked),
        "down": count(EngineStatus::Down),
        "engines": engines,
    }))
}

/// Shape a module-health snapshot into the `GET /api/v1/modules/health` wire
/// JSON. Split out of the handler so the mapping is unit-testable without
/// depending on the live process-global health state — that state is shared
/// across the whole test binary (mirrors why `cli::doctor::format_module_health`
/// takes a plain [`crate::core::engine::ModuleHealth`] rather than reading the
/// global directly).
pub(crate) fn module_health_json(unhealthy: &[crate::core::engine::ModuleHealth]) -> Value {
    let modules: Vec<Value> = unhealthy
        .iter()
        .map(|h| {
            json!({
                "name": h.name,
                "consecutive_failures": h.consecutive_failures,
                "last_success_at": h.last_success_at,
            })
        })
        .collect();
    let count = modules.len();
    json!({ "modules": modules, "count": count })
}

/// `GET /api/v1/modules/health` — every module currently showing a failure
/// streak this process, worst-first (`PROBLEM_TREE` T2.7 / `SOLUTION_TREE`
/// SOL-HEALTH-SIGNAL). Empty `modules: []` on a freshly-started or fully
/// healthy process — mirrors `hse doctor`'s "quiet unless something's
/// actually wrong" behaviour, the same live dispatch-outcome data that
/// backs it, just reachable from the web/API surface instead of only the CLI.
pub async fn modules_health() -> Json<Value> {
    Json(module_health_json(
        &crate::core::engine::module_health_report(),
    ))
}

/// `GET /api/v1/health/scrapers` — per-source scraper health (`PROBLEM_TREE`
/// T2.7 / `SOLUTION_TREE` SOL-HEALTH-SIGNAL), the SPA counterpart of `hse
/// doctor`'s "Scraper health" section: derived from the persisted
/// `ModuleDone`/`ModuleError` event log across ALL scans (a rolling window,
/// not just the current one — see [`crate::util::scraper_health`]'s doc), so
/// a source that has errored on every one of its last N dispatches is
/// visible even if those scans ran days ago in unrelated invocations. Powers
/// the Engines page's "Scraper health" panel.
pub async fn scraper_health(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    use crate::util::scraper_health::{RECENT_EVENTS_WINDOW, aggregate_source_health};

    let store = Arc::clone(&s.store);
    let events = match tokio::task::spawn_blocking(move || {
        store.recent_module_outcome_events(RECENT_EVENTS_WINDOW)
    })
    .await
    {
        Ok(Ok(events)) => events,
        Ok(Err(e)) => return internal_error(&e),
        Err(e) => return internal_error(&format!("scraper health query failed: {e}")),
    };
    let health = aggregate_source_health(&events);
    let drifted: Vec<Value> = health
        .iter()
        .filter(|h| h.is_drifted())
        .map(|h| {
            json!({
                "module": h.module,
                "consecutive_failures": h.consecutive_failures,
                "last_success_at": h.last_success_at,
                "last_error": h.last_error,
            })
        })
        .collect();
    // Silent zero-yield ("parse-rate") drift: a module that completes
    // without erroring but has quietly stopped finding anything, on a
    // source proven capable of yielding — distinct from `drifted` above.
    let yield_drifted: Vec<Value> = health
        .iter()
        .filter(|h| h.is_yield_drifted())
        .map(|h| {
            json!({
                "module": h.module,
                "consecutive_zero_yield": h.consecutive_zero_yield,
                "last_success_at": h.last_success_at,
            })
        })
        .collect();
    Json(json!({
        "tracked": health.len(),
        "events_checked": events.len(),
        "drifted_threshold": crate::util::scraper_health::DRIFTED_THRESHOLD,
        "drifted": drifted,
        "yield_drift_threshold": crate::util::scraper_health::YIELD_DRIFT_THRESHOLD,
        "yield_drifted": yield_drifted,
    }))
    .into_response()
}

/// `GET /api/v1/selftest` — run the full module + feature self-validation suite
/// on demand and return the structured report. Powers the Settings page's
/// "Run self-test" button. Offline + side-effect-free (a throwaway temp DB).
pub async fn selftest_run() -> impl IntoResponse {
    Json(crate::selftest::run().await)
}

/// `GET /api/v1/logs` — download the in-memory verbose debug-log ring buffer as
/// a text attachment. The buffer captures the project's default TRACE-level
/// logs for the life of the process (bounded; see `util::log_capture`).
///
/// **Loopback-only.** The ring buffer holds TRACE-level logs — scan targets and
/// discovered PII — the same operator-data class the key-pool and settings
/// endpoints already restrict. Under a LAN bind it must not stream to arbitrary
/// peers, so it carries the identical `peer.ip().is_loopback()` gate they do.
pub async fn logs_download(
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
) -> impl IntoResponse {
    if !peer.ip().is_loopback() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "debug logs are loopback-only" })),
        )
            .into_response();
    }
    let body = crate::util::log_capture::dump();
    let filename = format!("hse-debug-{}.log", crate::core::entity::unix_now());
    (
        [
            (
                axum::http::header::CONTENT_TYPE,
                "text/plain; charset=utf-8".to_string(),
            ),
            (
                axum::http::header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{filename}\""),
            ),
        ],
        body,
    )
        .into_response()
}

/// `GET /api/v1/debug/bundle` — the consolidated **system self-diagnosis
/// bundle**: one download that encompasses the whole engine's diagnostic +
/// validation state (an auto-computed DETECTED ISSUES verdict, the environment
/// fingerprint, the full self-test, live + cross-scan module/engine/scraper
/// health, the recent-scan index with each failed scan's error, the recent
/// verbose log ring, and the source-file manifest). It joins the otherwise-
/// scattered `/health` · `/selftest` · `/modules/health` · `/engines/health` ·
/// `/health/scrapers` · `/logs` surfaces into ONE artifact organised so the
/// engine can be repaired from this one file. Backs the Settings page's
/// "Download full diagnostic bundle" button.
///
/// **Loopback-only** — like [`logs_download`], the artifact embeds the TRACE
/// log ring (scan targets + discovered PII), so under a LAN bind it must not
/// stream to arbitrary peers. Secret-free otherwise (key NAMES only, never
/// values).
pub async fn system_debug_bundle(
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    State(s): State<Arc<AppState>>,
) -> impl IntoResponse {
    if !peer.ip().is_loopback() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "the system debug bundle is loopback-only" })),
        )
            .into_response();
    }
    // Validation runs against a throwaway temp DB (offline, side-effect-free).
    let selftest = crate::selftest::run().await;
    // Store reads are blocking — off the reactor (matches `scan_debug_bundle`).
    let store = Arc::clone(&s.store);
    let loaded = tokio::task::spawn_blocking(move || {
        let scans = store.list_scans(200)?;
        let events = store
            .recent_module_outcome_events(crate::util::scraper_health::RECENT_EVENTS_WINDOW)?;
        // Real on-disk DB health. An integrity check that can't even run is
        // itself a problem, so fold the error into a problem row rather than
        // dropping it. The `-wal` size is best-effort off the default path
        // (`None` when overridden / absent — an honest omission, never a false
        // "healthy").
        let db_integrity = store
            .integrity_check()
            .unwrap_or_else(|e| vec![format!("integrity check could not run: {e}")]);
        let wal_bytes = std::fs::metadata(format!("{}-wal", crate::default_db_path()))
            .ok()
            .map(|m| m.len());
        Ok::<_, crate::core::error::Error>((scans, events, db_integrity, wal_bytes))
    })
    .await;
    let (scans, events, db_integrity, wal_bytes) = match loaded {
        Ok(Ok(tuple)) => tuple,
        Ok(Err(e)) => return internal_error(&e),
        Err(e) => return internal_error(&format!("debug-bundle query task failed: {e}")),
    };
    let scraper_events_checked = events.len();
    let scraper_health = crate::util::scraper_health::aggregate_source_health(&events);
    // One lock for body + count so the "N lines" header can't disagree with the
    // dumped body (a line landing between two separate ring locks).
    let (log_dump, log_lines) = crate::util::log_capture::dump_with_count();
    // Update / build-freshness snapshot, read once under a poison-safe lock
    // (mirrors `update_handlers::get_status`), preserving the `Error` payload.
    let (update_commits_behind, update_last_checked, update_phase) = {
        let info = s
            .update_info
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let phase = match &info.phase {
            crate::api::UpdatePhase::Idle => "idle".to_string(),
            crate::api::UpdatePhase::Checking => "checking".to_string(),
            crate::api::UpdatePhase::Applying => "applying".to_string(),
            crate::api::UpdatePhase::Restarting => "restarting".to_string(),
            crate::api::UpdatePhase::Error(msg) => format!("error: {msg}"),
        };
        (info.commits_behind, info.last_checked, phase)
    };
    // Value-free per-service key-pool summary (reuses `keys_status`'
    // `summarize_pool`; never copies a key value). Mapped to the renderer's own
    // owned type so `cli::export` stays self-contained.
    let key_pool: Vec<crate::cli::export::KeyPoolSummary> =
        super::settings_handlers::summarize_pool(&crate::util::key_pool::global_pool().snapshot())
            .into_iter()
            .map(|q| crate::cli::export::KeyPoolSummary {
                service: q.service,
                total: q.total,
                active: q.active,
                untested: q.untested,
                rate_limited: q.rate_limited,
                exhausted: q.exhausted,
                invalid: q.invalid,
                revoked: q.revoked,
                avg_health: q.avg_health,
            })
            .collect();
    let inputs = crate::cli::export::SystemDebugInputs {
        selftest,
        scans,
        scraper_health,
        scraper_events_checked,
        log_dump,
        log_lines,
        key_pool,
        db_integrity,
        wal_bytes,
        update_commits_behind,
        update_last_checked,
        update_phase,
    };
    // Render off the reactor too: it reads the log ring + spawns `curl` (via the
    // environment fingerprint) — both blocking — and builds a potentially large
    // string, so on the ~2-worker reactor it would otherwise stall peers.
    let rendered = tokio::task::spawn_blocking(move || {
        crate::cli::export::render_system_debug_bundle(&inputs)
    })
    .await;
    let body = match rendered {
        Ok(b) => b,
        Err(e) => return internal_error(&format!("debug-bundle render task failed: {e}")),
    };
    let filename = format!("hse-system-debug-{}.txt", crate::core::entity::unix_now());
    (
        [
            (
                axum::http::header::CONTENT_TYPE,
                "text/plain; charset=utf-8".to_string(),
            ),
            (
                axum::http::header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{filename}\""),
            ),
        ],
        body,
    )
        .into_response()
}

pub async fn modules_list(State(s): State<Arc<AppState>>) -> Json<Value> {
    let mods: Vec<Value> = s
        .engine
        .modules()
        .iter()
        .map(|m| {
            let cost = serde_json::to_value(m.cost()).unwrap_or(Value::Null);
            // Pull declared consumes via the trait method — falls back to
            // the probe-based default for legacy modules. Mirrors what the
            // dispatch index and dependency graph see.
            let accepts: Vec<&'static str> = m
                .consumes()
                .iter()
                .map(super::super::core::scan::TargetKind::canonical_str)
                .collect();
            let produces: Vec<String> = m
                .produces()
                .iter()
                .map(std::string::ToString::to_string)
                .collect();
            json!({
                "name":        m.name(),
                "priority":    m.priority(),
                "cost":        cost,
                "passive":     m.is_passive(),
                "category":    m.category().as_str(),
                "accepts":     accepts,
                "produces":    produces,
                "description": m.description(),
            })
        })
        .collect();
    let count = mods.len();
    Json(json!({ "modules": mods, "count": count }))
}

/// `GET /api/v1/modules/graph` — pre-computed module dependency graph.
///
/// Returns the per-`TargetKind` dispatch index (with module counts and
/// normalised richness scores) plus the per-module `consumes/produces`
/// edges. The SPA renders this as a Sankey-style flow that shows
/// "what does seed X unlock?" — a Spiderfoot 4.0 capability HSE
/// surfaces with explicit data-flow declarations.
pub async fn modules_graph(State(s): State<Arc<AppState>>) -> Json<Value> {
    let graph = s.engine.graph();
    let summary = graph.to_summary(s.engine.modules());
    Json(json!({
        "kinds":           summary.kinds,
        "edges":           summary.edges,
        "produced_kinds":  summary.produced_entity_kinds(),
        "module_count":    s.engine.modules().len(),
    }))
}

pub async fn entity_get(
    State(s): State<Arc<AppState>>,
    Path(uid): Path<String>,
) -> impl IntoResponse {
    // Off-reactor: up to three sequential SQLite reads under the global
    // connection mutex. Running them inline on the async reactor would block it,
    // unlike every sibling handler here — so the whole read group moves to a
    // blocking thread.
    let store = Arc::clone(&s.store);
    let loaded = tokio::task::spawn_blocking(move || -> crate::core::error::Result<Option<_>> {
        let Some(entity) = store.get_entity(&uid)? else {
            return Ok(None);
        };
        let scan_ids = store.scan_ids_for_entity(&uid)?;
        let obs_count = store.observation_count(&uid)?;
        Ok(Some((entity, scan_ids, obs_count)))
    })
    .await;
    match loaded {
        Ok(Ok(Some((entity, scan_ids, obs_count)))) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "entity": entity,
                "scan_ids": scan_ids,
                "observation_count": obs_count,
            })),
        )
            .into_response(),
        Ok(Ok(None)) => not_found(),
        Ok(Err(e)) => internal_error(&e),
        Err(e) => internal_error(&format!("query task failed: {e}")),
    }
}

pub async fn search_entities(
    State(s): State<Arc<AppState>>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let query = match params.get("q") {
        Some(q) if !q.trim().is_empty() && q.len() <= 256 => q.trim(),
        Some(q) if q.len() > 256 => {
            return bad_request("query too long (max 256 chars)");
        }
        _ => {
            return bad_request("missing or empty 'q' parameter");
        }
    };
    let limit = params
        .get("limit")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(50)
        .min(200);
    // Off-reactor: the FTS query runs under the global SQLite mutex on a blocking
    // thread, matching the sibling handlers' discipline.
    let store = Arc::clone(&s.store);
    let query = query.to_string();
    match tokio::task::spawn_blocking(move || store.search_entities(&query, limit)).await {
        Ok(Ok(entities)) => ok_list("entities", entities),
        Ok(Err(e)) => internal_error(&e),
        Err(e) => internal_error(&format!("query task failed: {e}")),
    }
}

// ─── SSE event stream ──────────────────────────────────────────────────────
//
// The live event stream (scan progress + log lines pushed to the browser as
// the graph grows) uses **Server-Sent Events, deliberately not WebSockets**.
// The channel is strictly one-way (server → browser): there is no client→
// server messaging over it — control actions (cancel a scan, stop a live
// session) go through ordinary REST endpoints (`POST /scans/{id}/cancel`,
// `DELETE /live/{id}`). For one-way server push, SSE is the lighter, simpler
// fit: it is plain HTTP/1.1 with no upgrade handshake, the browser's native
// `EventSource` reconnects automatically, and it avoids the bidirectional
// framing/ping-pong machinery a WebSocket stack would add for zero benefit
// here — which matters on low-power Termux. axum's `Sse` response sets the
// `text/event-stream` content-type the `EventSource` client requires; the
// `scan_events_endpoint_is_server_sent_events` test in `tests/api.rs` pins
// that wire contract.

const SSE_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// Build the SSE body stream shared by the scan- and live-event endpoints.
///
/// `accept` selects which bus events belong on this stream (by `scan_id` and/or
/// live-session ownership). Centralising the plumbing here is what keeps the two
/// endpoints from drifting — every subtle SSE property lives in one place:
///
/// * **Lag tolerance** — a slow client that overflows its broadcast buffer
///   yields `Err(Lagged)`, which falls through to `_ => None`: the missed events
///   are skipped but the stream stays open (dropping a few live-log lines under
///   load beats tearing the stream down).
/// * **Idle timeout** — if no *matching* event arrives within
///   [`SSE_IDLE_TIMEOUT`] the stream ends, reclaiming a client that vanished
///   without a clean close (half-open TCP the keep-alive write hasn't tripped
///   yet). A finished scan stops emitting, so its stream closes ~timeout later,
///   as intended; the browser's `EventSource` transparently reconnects if the
///   session is still live (only relevant when an interval exceeds the timeout).
/// * **Keep-alive** — periodic comment pings hold the connection open and surface
///   a dead socket promptly via the failing write.
///
/// On client disconnect axum drops this stream, dropping the broadcast receiver
/// and unsubscribing it — so there is no per-connection resource to leak.
fn sse_event_stream<F>(
    bus: &EventBus,
    accept: F,
) -> Sse<impl Stream<Item = Result<SseEvent, Infallible>> + use<F>>
where
    F: Fn(&Event) -> bool + Send + 'static,
{
    let stream = BroadcastStream::new(bus.subscribe())
        .filter_map(move |msg| match msg {
            Ok(event) if accept(&event) => {
                let payload = serde_json::to_string(&event.kind).unwrap_or_default();
                Some(Ok(SseEvent::default().data(payload)))
            }
            _ => None,
        })
        .timeout(SSE_IDLE_TIMEOUT)
        .take_while(std::result::Result::is_ok)
        .filter_map(std::result::Result::ok);

    Sse::new(stream).keep_alive(KeepAlive::default())
}

pub async fn scan_events_sse(
    State(s): State<Arc<AppState>>,
    Path(target_sid): Path<String>,
) -> Sse<impl Stream<Item = Result<SseEvent, Infallible>>> {
    sse_event_stream(&s.bus, move |event| event.scan_id == target_sid)
}

// ─── Settings handlers ─────────────────────────────────────────────────────

// ─── Live-mode handlers ────────────────────────────────────────────────────

pub async fn live_create(
    State(s): State<Arc<AppState>>,
    Json(req): Json<crate::core::live::LiveRequest>,
) -> impl IntoResponse {
    let kind = req.resolved_kind();
    let target = match validated_target(kind, req.value) {
        Ok(t) => t,
        Err(msg) => return bad_request(msg),
    };
    let live_id = s.live.start(target, req.options, req.live);
    (
        StatusCode::ACCEPTED,
        Json(json!({ "live_id": live_id, "status": "running" })),
    )
        .into_response()
}

pub async fn live_list(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    ok_list("sessions", s.live.list())
}

pub async fn live_get(State(s): State<Arc<AppState>>, Path(id): Path<String>) -> impl IntoResponse {
    match s.live.get(&id) {
        Some(session) => (
            StatusCode::OK,
            Json(serde_json::to_value(&session).unwrap_or_else(|e| {
                tracing::warn!(error = %e, "failed to serialize live session");
                json!({})
            })),
        )
            .into_response(),
        None => not_found(),
    }
}

pub async fn live_stop(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if s.live.stop(&id) {
        (
            StatusCode::OK,
            Json(json!({ "live_id": id, "status": "stopping" })),
        )
            .into_response()
    } else {
        not_found()
    }
}

pub async fn live_events_sse(
    State(s): State<Arc<AppState>>,
    Path(target_lid): Path<String>,
) -> Sse<impl Stream<Item = Result<SseEvent, Infallible>>> {
    // A live session's stream carries both its own lifecycle events (emitted
    // under `scan_id == live_id`) and every per-iteration scan it spawned.
    let live = s.live.clone();
    sse_event_stream(&s.bus, move |event| {
        event.scan_id == target_lid || live.session_owns_scan(&target_lid, &event.scan_id)
    })
}

// ─── Tests (from scan.rs) ─────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
