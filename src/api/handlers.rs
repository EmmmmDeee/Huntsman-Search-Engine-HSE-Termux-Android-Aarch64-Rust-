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
use crate::core::{module::ModuleContext, scan::Target};
use crate::util::keys;

// ─── Shared response helpers ───────────────────────────────────────────────

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

pub async fn stats(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    let scans = match s.store.list_scans(10_000) {
        Ok(scans) => scans,
        Err(e) => return internal_error(&e),
    };
    let mut by_status: std::collections::BTreeMap<&'static str, u64> =
        std::collections::BTreeMap::new();
    let mut total_entities = 0u64;
    let mut total_deduped = 0u64;
    for scan in &scans {
        *by_status.entry(scan.status.as_str()).or_insert(0) += 1;
        total_entities += scan.entity_count as u64;
        total_deduped += scan.modules_deduped as u64;
    }
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
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "query too long (max 256 chars)"})),
            )
                .into_response();
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "missing or empty 'q' parameter"})),
            )
                .into_response();
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
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "no updates or deletes"})),
        )
            .into_response();
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
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

// ─── Live-mode handlers ────────────────────────────────────────────────────

pub async fn live_create(
    State(s): State<Arc<AppState>>,
    Json(req): Json<crate::core::live::LiveRequest>,
) -> impl IntoResponse {
    let target = Target::new(req.kind, req.value);
    if let Err(msg) = target.validate() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": format!("invalid target: {msg}") })),
        )
            .into_response();
    }
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
}
