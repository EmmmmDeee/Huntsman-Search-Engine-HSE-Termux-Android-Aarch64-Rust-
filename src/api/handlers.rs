// HTTP handlers.
//
// Every handler returns `impl IntoResponse` so we can mix `Json`,
// `(StatusCode, Json)`, and `Sse<...>` freely. Error paths emit a
// `{"error": "..."}` JSON body with the appropriate status.

use std::{collections::BTreeMap, convert::Infallible, net::SocketAddr, sync::Arc};

use axum::{
    Json,
    extract::{ConnectInfo, Path, State},
    http::StatusCode,
    response::{
        IntoResponse,
        sse::{Event as SseEvent, KeepAlive, Sse},
    },
};
use futures::Stream;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio_stream::{StreamExt as _, wrappers::BroadcastStream};

use super::AppState;
use crate::core::{
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
        .validate()
        .map_err(|msg| format!("invalid target: {msg}"))?;
    Ok(target)
}

pub(crate) fn internal_error(err: &impl ToString) -> axum::response::Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "error": err.to_string() })),
    )
        .into_response()
}

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

pub(crate) fn spawn_scan(state: &Arc<AppState>, scan: crate::core::scan::Scan, target: Target) {
    let sid = scan.id.clone();
    let cancel = crate::core::cancel::CancelHandle::new();
    let cancel_guard = super::CancelRegistryGuard::install(
        Arc::clone(&state.cancellations),
        sid.clone(),
        cancel.clone(),
    );
    let bus_clone = state.bus.clone();
    let http_clone = state.http.clone();
    let proxy_clone = std::sync::Arc::clone(&state.proxy_pool);
    let engine = Arc::clone(&state.engine);
    let sem = Arc::clone(&state.scan_semaphore);
    tokio::spawn(async move {
        let _cancel_guard = cancel_guard;
        let api_keys = keys::populate_and_load().await;
        let ctx = ModuleContext {
            scan_id: sid.clone(),
            bus: bus_clone,
            http: http_clone,
            keys: api_keys,
            cancel,
            proxy_pool: proxy_clone,
        };
        let Ok(_permit) = sem.acquire().await else {
            tracing::warn!(scan_id = %sid, "scan semaphore closed");
            return;
        };
        if let Err(e) = engine.run(scan, target, ctx).await {
            tracing::warn!(scan_id = %sid, error = %e, "scan failed");
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
    let scans = match s.store.list_scans(10_000) {
        Ok(scans) => scans,
        Err(e) => return internal_error(&e),
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
            // we haven't polled `/profile/user` yet this process.
            "verified":           wigle_account.verified,
            "user":               wigle_account.user,
            "daily_api_calls":    wigle_account.daily_api_calls,
            "monthly_api_calls":  wigle_account.monthly_api_calls,
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

/// Expose the API-key detector's prefix-match coverage. Returns the
/// full ordered table from `key_harvest::patterns` so operators can
/// see what shapes the scanner recognises — and so dashboards can
/// surface per-service coverage stats.
pub async fn keys_patterns() -> Json<Value> {
    let patterns = crate::modules::oathnet_pro::key_harvest::pattern_catalogue();
    let by_service: std::collections::BTreeMap<&str, usize> =
        patterns
            .iter()
            .fold(std::collections::BTreeMap::new(), |mut acc, p| {
                *acc.entry(p.service).or_default() += 1;
                acc
            });
    Json(json!({
        "patterns": patterns,
        "count": patterns.len(),
        "unique_services": by_service.len(),
    }))
}

/// Per-service key-pool status summary. **Value-free by construction** — no
/// `KeyEntry.value` is ever copied here — so it is safe to surface to the
/// (localhost-only) operator dashboard.
#[derive(Debug, Default, Serialize)]
pub(crate) struct ServiceQuota {
    pub service: String,
    pub total: usize,
    pub active: usize,
    pub rate_limited: usize,
    pub exhausted: usize,
    pub invalid: usize,
    pub untested: usize,
    pub uses: u64,
    pub errors: u64,
}

/// Summarise a key-pool snapshot into per-service status counts, dropping every
/// key value. Pure (no global state) so it is unit-testable; sorted by service.
pub(crate) fn summarize_pool(data: &crate::util::key_pool::PoolData) -> Vec<ServiceQuota> {
    use crate::util::key_pool::KeyStatus;
    let mut out: Vec<ServiceQuota> = data
        .services
        .iter()
        .map(|(service, entries)| {
            let mut q = ServiceQuota {
                service: service.clone(),
                total: entries.len(),
                ..Default::default()
            };
            for e in entries {
                match e.status {
                    KeyStatus::Active => q.active += 1,
                    KeyStatus::RateLimited => q.rate_limited += 1,
                    KeyStatus::Exhausted => q.exhausted += 1,
                    KeyStatus::Invalid => q.invalid += 1,
                    KeyStatus::Untested => q.untested += 1,
                }
                q.uses += e.use_count;
                q.errors += e.error_count;
            }
            q
        })
        .collect();
    out.sort_by(|a, b| a.service.cmp(&b.service));
    out
}

/// `GET /api/v1/keys/status` — per-service key-pool health (counts by status +
/// aggregate use/error totals) for the operator quota view. Never exposes key
/// values. Reads the process-global pool.
pub async fn keys_status() -> Json<Value> {
    let services = summarize_pool(&crate::util::key_pool::global_pool().snapshot());
    Json(json!({ "count": services.len(), "services": services }))
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
pub async fn logs_download() -> impl IntoResponse {
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
    match s.store.get_entity(&uid) {
        Ok(Some(entity)) => {
            let scan_ids = match s.store.scan_ids_for_entity(&uid) {
                Ok(ids) => ids,
                Err(e) => {
                    tracing::warn!(entity_uid = %uid, error = %e, "scan_ids_for_entity failed");
                    return internal_error(&e);
                }
            };
            let obs_count = match s.store.observation_count(&uid) {
                Ok(n) => n,
                Err(e) => {
                    tracing::warn!(entity_uid = %uid, error = %e, "observation_count failed");
                    return internal_error(&e);
                }
            };
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "entity": entity,
                    "scan_ids": scan_ids,
                    "observation_count": obs_count,
                })),
            )
                .into_response()
        }
        Ok(None) => not_found(),
        Err(e) => internal_error(&e),
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
    match s.store.search_entities(query, limit) {
        Ok(entities) => ok_list("entities", entities),
        Err(e) => internal_error(&e),
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

pub async fn scan_events_sse(
    State(s): State<Arc<AppState>>,
    Path(target_sid): Path<String>,
) -> Sse<impl Stream<Item = Result<SseEvent, Infallible>>> {
    let rx = s.bus.subscribe();

    let stream = BroadcastStream::new(rx)
        .filter_map(move |msg| match msg {
            Ok(event) if event.scan_id == target_sid => {
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

// ─── Settings handlers ─────────────────────────────────────────────────────

pub async fn settings_keys_get(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    use std::path::PathBuf;
    let path = keys::env_path();
    let loaded = keys::load_from_file_only(&PathBuf::from(&path));
    let mut all_names: std::collections::BTreeSet<String> =
        keys::KNOWN_KEYS.iter().map(|s| (*s).to_string()).collect();
    for k in loaded.keys() {
        all_names.insert(k.clone());
    }
    let entries: Vec<Value> = all_names
        .into_iter()
        .map(|name| {
            let set = loaded.contains_key(&name);
            json!({ "name": name, "set": set })
        })
        .collect();
    let count = entries.len();
    Json(json!({
        "keys": entries,
        "count": count,
        "write_enabled": s.allow_key_write,
        "env_path": path,
    }))
    .into_response()
}

#[derive(Deserialize)]
pub struct KeysPutRequest {
    #[serde(default)]
    pub updates: BTreeMap<String, String>,
    #[serde(default)]
    pub deletes: Vec<String>,
}

pub async fn settings_keys_put(
    State(s): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(req): Json<KeysPutRequest>,
) -> impl IntoResponse {
    if !s.allow_key_write {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "key writes disabled; restart with `hse serve --allow-key-write`"
            })),
        )
            .into_response();
    }
    if !peer.ip().is_loopback() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "key writes are loopback-only" })),
        )
            .into_response();
    }
    if req.updates.is_empty() && req.deletes.is_empty() {
        return bad_request("no updates or deletes");
    }
    match keys::write_keys(&req.updates, &req.deletes) {
        Ok(()) => {
            tracing::info!(
                updates = req.updates.len(),
                deletes = req.deletes.len(),
                "settings/keys written"
            );
            (
                StatusCode::OK,
                Json(json!({
                    "status": "ok",
                    "updated": req.updates.len(),
                    "deleted": req.deletes.len(),
                })),
            )
                .into_response()
        }
        Err(e) => bad_request(e.to_string()),
    }
}

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
    let rx = s.bus.subscribe();
    let live = s.live.clone();

    let stream = BroadcastStream::new(rx)
        .filter_map(move |msg| match msg {
            Ok(event)
                if event.scan_id == target_lid
                    || live.session_owns_scan(&target_lid, &event.scan_id) =>
            {
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

// ─── Tests (from scan.rs) ─────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use crate::api::scan_handlers::csv_escape;

    #[test]
    fn validated_target_accepts_good_and_prefixes_bad() {
        use super::validated_target;
        use crate::core::scan::TargetKind;
        let ok = validated_target(TargetKind::Domain, "cloudflare.com".to_string());
        assert!(ok.is_ok());
        assert_eq!(ok.unwrap().value, "cloudflare.com");
        let err = validated_target(TargetKind::Domain, "no-dot".to_string()).unwrap_err();
        assert!(
            err.starts_with("invalid target: "),
            "must carry client-facing prefix, got: {err}"
        );
    }

    #[test]
    fn aggregate_scan_stats_sums_counts_and_histograms_status() {
        use super::aggregate_scan_stats;
        use crate::core::scan::{Scan, ScanStatus, Target, TargetKind};

        let mk = |id: &str, status: ScanStatus, ents: usize, dedup: usize| {
            let mut s = Scan::new(id, Target::new(TargetKind::Email, "x@y.com"));
            s.status = status;
            s.entity_count = ents;
            s.modules_deduped = dedup;
            s
        };
        let scans = [
            mk("a", ScanStatus::Complete, 10, 2),
            mk("b", ScanStatus::Complete, 5, 1),
            mk("c", ScanStatus::Failed, 0, 0),
            mk("d", ScanStatus::Running, 3, 4),
        ];
        let agg = aggregate_scan_stats(&scans);
        assert_eq!(agg.total_entities, 18);
        assert_eq!(agg.total_deduped, 7);
        assert_eq!(agg.by_status.get("complete"), Some(&2));
        assert_eq!(agg.by_status.get("failed"), Some(&1));
        assert_eq!(agg.by_status.get("running"), Some(&1));
        assert_eq!(agg.by_status.get("pending"), None);

        // Empty input yields all-zero totals and an empty histogram.
        let empty = aggregate_scan_stats(&[]);
        assert_eq!(empty, super::ScanStatsAgg::default());
    }

    #[test]
    fn csv_escape_plain() {
        assert_eq!(csv_escape("hello"), "hello");
    }

    #[test]
    fn csv_escape_comma() {
        assert_eq!(csv_escape("a,b"), "\"a,b\"");
    }

    #[test]
    fn csv_escape_quotes() {
        assert_eq!(csv_escape("say \"hi\""), "\"say \"\"hi\"\"\"");
    }

    #[test]
    fn csv_escape_newline() {
        assert_eq!(csv_escape("line1\nline2"), "\"line1\nline2\"");
    }

    #[test]
    fn csv_escape_cr() {
        assert_eq!(csv_escape("a\rb"), "\"a\rb\"");
    }

    #[test]
    fn csv_escape_empty() {
        assert_eq!(csv_escape(""), "");
    }

    // ── Formula-injection neutralization ─────────────────────────────

    #[test]
    fn csv_escape_neutralizes_excel_formula() {
        // Excel-style formula prefixes get a leading apostrophe
        // prepended so Excel/LibreOffice render the cell as text
        // instead of evaluating it. The apostrophe alone is enough —
        // outer quoting fires only when the body also carries CSV
        // metachars (comma, quote, CR, LF).
        assert_eq!(csv_escape("=cmd|/c calc"), "'=cmd|/c calc");
        assert_eq!(csv_escape("+1234"), "'+1234");
        assert_eq!(csv_escape("-SUM(A1:A2)"), "'-SUM(A1:A2)");
        assert_eq!(csv_escape("@evil"), "'@evil");
        // Tab and CR are also formula triggers in some spreadsheet
        // implementations. CR also forces outer quoting (CSV metachar).
        assert_eq!(csv_escape("\tHELLO"), "'\tHELLO");
        assert_eq!(csv_escape("\rDANGER"), "\"'\rDANGER\"");
    }

    #[test]
    fn csv_escape_formula_with_comma_quotes_outer() {
        // Leading `=` triggers the apostrophe guard, AND the embedded
        // comma forces outer double-quoting.
        assert_eq!(csv_escape("=A1,B2"), "\"'=A1,B2\"");
    }

    #[test]
    fn csv_escape_keeps_negative_numbers_safe_but_escaped() {
        // `-3.5` would be interpreted as a formula. Cell still
        // round-trips to the same number after the apostrophe is
        // stripped by spreadsheet apps.
        let r = csv_escape("-3.5");
        assert!(r.starts_with('\''));
    }

    #[test]
    fn csv_escape_does_not_alter_safe_leading_chars() {
        assert_eq!(csv_escape("hello"), "hello");
        assert_eq!(csv_escape("3 apples"), "3 apples");
        assert_eq!(csv_escape("Mr. Jones"), "Mr. Jones");
    }

    #[test]
    fn summarize_pool_counts_by_status_and_never_leaks_values() {
        use super::summarize_pool;
        use crate::util::key_pool::{KeyEntry, KeyStatus, PoolData};
        let mut data = PoolData::default();
        let mut active = KeyEntry::new("SECRET-ACTIVE");
        active.status = KeyStatus::Active;
        active.use_count = 5;
        let mut limited = KeyEntry::new("SECRET-RL");
        limited.status = KeyStatus::RateLimited;
        limited.error_count = 2;
        data.services.insert("shodan".into(), vec![active, limited]);
        let mut invalid = KeyEntry::new("SECRET-INVALID");
        invalid.status = KeyStatus::Invalid;
        data.services.insert("censys".into(), vec![invalid]);

        let summary = summarize_pool(&data);
        // Sorted by service name.
        assert_eq!(summary[0].service, "censys");
        assert_eq!(summary[1].service, "shodan");
        let shodan = &summary[1];
        assert_eq!(shodan.total, 2);
        assert_eq!(shodan.active, 1);
        assert_eq!(shodan.rate_limited, 1);
        assert_eq!(shodan.uses, 5);
        assert_eq!(shodan.errors, 2);
        assert_eq!(summary[0].invalid, 1);

        // CRITICAL: no key value may appear in the serialised summary.
        let json = serde_json::to_string(&summary).unwrap();
        assert!(
            !json.contains("SECRET"),
            "key values must never be exposed: {json}"
        );
    }
}
