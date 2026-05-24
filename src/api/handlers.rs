//! HTTP handlers.
//!
//! Every handler returns `impl IntoResponse` so we can mix `Json`,
//! `(StatusCode, Json)`, and `Sse<...>` freely. Error paths emit a
//! `{"error": "..."}` JSON body with the appropriate status.

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
use serde::Deserialize;
use serde_json::{Value, json};
use tokio_stream::{StreamExt as _, wrappers::BroadcastStream};
use tracing::info;

use super::AppState;
use crate::{
    core::{
        module::ModuleContext,
        scan::{Scan, ScanRequest, Target},
    },
    util::{keys, uid::scan_id},
};

/// `(500, {"error": "..."})` JSON response for an unexpected failure.
fn internal_error(err: &impl ToString) -> axum::response::Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "error": err.to_string() })),
    )
        .into_response()
}

/// `(404, {"error": "not found"})` — used by `/scans/:id` and `/live/:id`.
fn not_found() -> axum::response::Response {
    (StatusCode::NOT_FOUND, Json(json!({ "error": "not found" }))).into_response()
}

// ─── Health / Version ────────────────────────────────────────────────────────

pub async fn health() -> Json<Value> {
    Json(json!({ "status": "ok", "version": crate::VERSION }))
}

pub async fn version() -> Json<Value> {
    Json(json!({ "version": crate::VERSION }))
}

// ─── Modules ─────────────────────────────────────────────────────────────────

pub async fn modules_list(State(s): State<Arc<AppState>>) -> Json<Value> {
    use crate::core::scan::TargetKind;
    // Probe each module against a dummy of every TargetKind to surface
    // which kinds it accepts. The wizard uses this to skip impossible
    // module/target combinations without round-tripping back to the API.
    const ALL_KINDS: [TargetKind; 9] = [
        TargetKind::Email,
        TargetKind::Username,
        TargetKind::Phone,
        TargetKind::FullName,
        TargetKind::IpAddress,
        TargetKind::Domain,
        TargetKind::Asn,
        TargetKind::Coordinates,
        TargetKind::Address,
    ];

    let mods: Vec<Value> = s
        .engine
        .modules()
        .iter()
        .map(|m| {
            // Serialise `ModuleCost` via serde so JSON callers see the
            // canonical snake_case form (`"key_gated"`, not `"keygated"`
            // that `format!("{:?}", ...).to_lowercase()` would produce).
            let cost = serde_json::to_value(m.cost()).unwrap_or(Value::Null);
            let accepts: Vec<&'static str> = ALL_KINDS
                .iter()
                .filter(|k| m.accepts(&Target::new(**k, "probe")))
                .map(|k| k.canonical_str())
                .collect();
            json!({
                "name":     m.name(),
                "priority": m.priority(),
                "cost":     cost,
                "passive":  m.is_passive(),
                "accepts":  accepts,
            })
        })
        .collect();
    let count = mods.len();
    Json(json!({ "modules": mods, "count": count }))
}

// ─── Scans ───────────────────────────────────────────────────────────────────

pub async fn scan_create(
    State(s): State<Arc<AppState>>,
    Json(req): Json<ScanRequest>,
) -> impl IntoResponse {
    let target = Target::new(req.kind, req.value.clone());
    // Shape-check the target before queuing the scan. This is the only
    // place user input enters the system from the network, so it's
    // where we catch obvious mis-typed values fast (e.g. an "email"
    // field that has no `@`).
    if let Err(msg) = target.validate() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": format!("invalid target: {msg}") })),
        )
            .into_response();
    }
    // The CLI and API both feed `kind.canonical_str()` into `scan_id()` so
    // both interfaces hash the same canonical kind string. `scan_id()`
    // itself mixes `unix_now()`, so the resulting id is NOT deterministic
    // across re-scans of the same target — each invocation gets a fresh id.
    let sid = scan_id(req.kind.canonical_str(), &req.value);
    let scan = Scan::new(sid.clone(), target.clone()).with_options(req.options);

    if let Err(e) = s.store.upsert_scan(&scan) {
        return internal_error(&e);
    }

    let ctx = ModuleContext {
        scan_id: sid.clone(),
        bus: s.bus.clone(),
        http: s.http.clone(),
        keys: keys::load(),
    };

    // Spawn the scan — handler returns immediately with the scan id so the
    // client can subscribe to /events for live progress.
    let engine = Arc::clone(&s.engine);
    let scan_for_run = scan.clone();
    tokio::spawn(async move {
        if let Err(e) = engine.run(scan_for_run, target, ctx).await {
            tracing::warn!(scan_id = %sid, error = %e, "scan failed");
        }
    });

    info!(scan_id = %scan.id, kind = ?scan.target.kind, "scan queued");
    (
        StatusCode::ACCEPTED,
        Json(json!({ "scan_id": scan.id, "status": "queued" })),
    )
        .into_response()
}

pub async fn scan_list(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    // 200 most recent scans is plenty for the prototype's History tab —
    // older results stay in the DB and reachable via GET /api/v1/scans/{id}.
    match s.store.list_scans(200) {
        Ok(scans) => {
            let n = scans.len();
            (StatusCode::OK, Json(json!({ "scans": scans, "count": n }))).into_response()
        }
        Err(e) => internal_error(&e),
    }
}

pub async fn scan_get(State(s): State<Arc<AppState>>, Path(id): Path<String>) -> impl IntoResponse {
    match s.store.get_scan(&id) {
        Ok(Some(scan)) => (
            StatusCode::OK,
            Json(serde_json::to_value(&scan).unwrap_or_else(|_| json!({}))),
        )
            .into_response(),
        Ok(None) => not_found(),
        Err(e) => internal_error(&e),
    }
}

pub async fn scan_entities(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match s.store.entities_for_scan(&id) {
        Ok(entities) => {
            let n = entities.len();
            (
                StatusCode::OK,
                Json(json!({ "entities": entities, "count": n })),
            )
                .into_response()
        }
        Err(e) => internal_error(&e),
    }
}

pub async fn scan_correlations(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match s.store.correlations_for_scan(&id) {
        Ok(corr) => {
            let n = corr.len();
            (
                StatusCode::OK,
                Json(json!({ "correlations": corr, "count": n })),
            )
                .into_response()
        }
        Err(e) => internal_error(&e),
    }
}

/// `DELETE /api/v1/scans/{id}` — cascade-delete a scan and its
/// correlations / observations / orphaned entities.
pub async fn scan_delete(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match s.store.delete_scan(&id) {
        Ok(true) => {
            info!(scan_id = %id, "scan deleted");
            (StatusCode::OK, Json(json!({ "deleted": id }))).into_response()
        }
        Ok(false) => not_found(),
        Err(e) => internal_error(&e),
    }
}

/// `POST /api/v1/scans/{id}/rerun` — clone an existing scan with a
/// fresh scan id and the same target + options. Mirrors Spiderfoot's
/// "Rescan" button.
pub async fn scan_rerun(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let original = match s.store.get_scan(&id) {
        Ok(Some(scan)) => scan,
        Ok(None) => return not_found(),
        Err(e) => return internal_error(&e),
    };

    let sid = scan_id(original.target.kind.canonical_str(), &original.target.value);
    let new_scan =
        Scan::new(sid.clone(), original.target.clone()).with_options(original.options.clone());

    if let Err(e) = s.store.upsert_scan(&new_scan) {
        return internal_error(&e);
    }

    let ctx = ModuleContext {
        scan_id: sid.clone(),
        bus: s.bus.clone(),
        http: s.http.clone(),
        keys: keys::load(),
    };

    let engine = Arc::clone(&s.engine);
    let scan_for_run = new_scan.clone();
    let target_for_run = original.target.clone();
    tokio::spawn(async move {
        if let Err(e) = engine.run(scan_for_run, target_for_run, ctx).await {
            tracing::warn!(scan_id = %sid, error = %e, "rerun failed");
        }
    });

    info!(scan_id = %new_scan.id, source = %id, "scan rerun queued");
    (
        StatusCode::ACCEPTED,
        Json(json!({
            "scan_id": new_scan.id,
            "source_scan_id": id,
            "status": "queued"
        })),
    )
        .into_response()
}

/// `GET /api/v1/scans/{id}/entities.csv` — Spiderfoot-style CSV export.
/// Columns: kind, value, raw_value, confidence, c_effective, corroboration,
/// classification, observed_at, sources, tags.
pub async fn scan_entities_csv(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    use std::collections::BTreeSet;
    let entities = match s.store.entities_for_scan(&id) {
        Ok(es) => es,
        Err(e) => return internal_error(&e),
    };

    let mut body = String::with_capacity(2048);
    body.push_str("kind,value,raw_value,confidence,c_effective,corroboration,classification,observed_at,sources,tags\n");
    for e in entities {
        let eff = e.c_effective();
        let tier = e.classify().to_string();
        let sources: BTreeSet<&str> = e.evidence.iter().map(|ev| ev.source.as_str()).collect();
        let sources = sources.into_iter().collect::<Vec<_>>().join("|");
        let tags = e.tags.join("|");
        body.push_str(&format!(
            "{},{},{},{:.3},{:.3},{},{},{},{},{}\n",
            csv_escape(&e.kind.to_string()),
            csv_escape(&e.value),
            csv_escape(&e.raw_value),
            e.confidence,
            eff,
            e.corroboration,
            tier,
            e.observed_at,
            csv_escape(&sources),
            csv_escape(&tags),
        ));
    }

    let filename = format!("hse-scan-{}.csv", id.chars().take(12).collect::<String>());
    let disposition = format!("attachment; filename=\"{filename}\"");
    let mut resp = (StatusCode::OK, body).into_response();
    let headers = resp.headers_mut();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("text/csv; charset=utf-8"),
    );
    if let Ok(v) = axum::http::HeaderValue::from_str(&disposition) {
        headers.insert(axum::http::header::CONTENT_DISPOSITION, v);
    }
    resp
}

fn csv_escape(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

// ─── Live mode (v0.5+) ───────────────────────────────────────────────────────

pub async fn live_create(
    State(s): State<Arc<AppState>>,
    Json(req): Json<crate::core::live::LiveRequest>,
) -> impl IntoResponse {
    let target = Target::new(req.kind, req.value);
    let live_id = s.live.start(target, req.options, req.live);
    (
        StatusCode::ACCEPTED,
        Json(json!({ "live_id": live_id, "status": "running" })),
    )
        .into_response()
}

pub async fn live_list(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    let sessions = s.live.list();
    let n = sessions.len();
    (
        StatusCode::OK,
        Json(json!({ "sessions": sessions, "count": n })),
    )
        .into_response()
}

pub async fn live_get(State(s): State<Arc<AppState>>, Path(id): Path<String>) -> impl IntoResponse {
    match s.live.get(&id) {
        Some(session) => (
            StatusCode::OK,
            Json(serde_json::to_value(&session).unwrap_or_else(|_| json!({}))),
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

/// SSE stream for one live session. Forwards:
///  * live-level events whose `scan_id` field equals `live_id`
///  * scan-level events whose `scan_id` field is owned by `live_id`
///
/// Live sessions can spawn multiple scans over their lifetime, so the
/// scan-ownership check is re-evaluated on every event.
pub async fn live_events_sse(
    State(s): State<Arc<AppState>>,
    Path(target_lid): Path<String>,
) -> Sse<impl Stream<Item = Result<SseEvent, Infallible>>> {
    let rx = s.bus.subscribe();
    let live = s.live.clone();

    let stream = BroadcastStream::new(rx).filter_map(move |msg| match msg {
        Ok(event)
            if event.scan_id == target_lid
                || live.session_owns_scan(&target_lid, &event.scan_id) =>
        {
            let payload = serde_json::to_string(&event.kind).unwrap_or_default();
            Some(Ok(SseEvent::default().data(payload)))
        }
        _ => None,
    });

    Sse::new(stream).keep_alive(KeepAlive::default())
}

// ─── SSE event stream ────────────────────────────────────────────────────────
//
// Subscribes to the shared `EventBus` (tokio broadcast) and forwards events
// whose `scan_id` matches the path parameter. Stream stays open until the
// client disconnects — the browser's `EventSource` API handles teardown
// when the user navigates away. Per-event keep-alive defaults are sufficient
// for prototype use.

pub async fn scan_events_sse(
    State(s): State<Arc<AppState>>,
    Path(target_sid): Path<String>,
) -> Sse<impl Stream<Item = Result<SseEvent, Infallible>>> {
    let rx = s.bus.subscribe();

    let stream = BroadcastStream::new(rx).filter_map(move |msg| match msg {
        Ok(event) if event.scan_id == target_sid => {
            let payload = serde_json::to_string(&event.kind).unwrap_or_default();
            Some(Ok(SseEvent::default().data(payload)))
        }
        _ => None,
    });

    Sse::new(stream).keep_alive(KeepAlive::default())
}

// ─── Settings ────────────────────────────────────────────────────────────────
//
// `GET /api/v1/settings/keys`  — list known + currently-set HUNTSMAN_* keys.
//                               Values are NEVER returned, only set-or-not.
// `PUT /api/v1/settings/keys`  — write `~/.huntsman.env`. Two-layer guard:
//                               server must be started with `--allow-key-write`
//                               AND the request must come from a loopback peer.

pub async fn settings_keys_get(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    use std::path::PathBuf;
    let path = keys::env_path();
    // Read the env file directly — see `keys::load_from_file_only`
    // docs for why we can't reuse `load()` here.
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
            Json(json!({
                "error": "key writes are loopback-only"
            })),
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
            info!(
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
