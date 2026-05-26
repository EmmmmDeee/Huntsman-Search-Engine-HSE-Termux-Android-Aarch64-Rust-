//! HTTP handlers.
//!
//! Every handler returns `impl IntoResponse` so we can mix `Json`,
//! `(StatusCode, Json)`, and `Sse<...>` freely. Error paths emit a
//! `{"error": "..."}` JSON body with the appropriate status.

mod live;
mod scan;
mod settings;

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
use crate::core::{module::ModuleContext, scan::Target};
use crate::util::keys;

// ─── Re-exports (stable public surface for routes.rs) ──────────────────────

pub use live::{live_create, live_events_sse, live_get, live_list, live_stop};
pub use scan::{
    scan_cancel, scan_correlations, scan_create, scan_delete, scan_entities, scan_entities_csv,
    scan_entities_facets, scan_entities_filter, scan_events_history, scan_get, scan_list,
    scan_report_json, scan_rerun,
};
pub use settings::{settings_keys_get, settings_keys_put};

// ─── Shared response helpers ───────────────────────────────────────────────

fn internal_error(err: &impl ToString) -> axum::response::Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "error": err.to_string() })),
    )
        .into_response()
}

fn not_found() -> axum::response::Response {
    (StatusCode::NOT_FOUND, Json(json!({ "error": "not found" }))).into_response()
}

fn ok_list<T: Serialize>(key: &str, items: Vec<T>) -> axum::response::Response {
    let n = items.len();
    let mut map = serde_json::Map::new();
    map.insert(
        key.to_string(),
        serde_json::to_value(items).unwrap_or(Value::Null),
    );
    map.insert("count".to_string(), Value::Number(n.into()));
    (StatusCode::OK, Json(Value::Object(map))).into_response()
}

fn spawn_scan(state: &Arc<AppState>, scan: crate::core::scan::Scan, target: Target) {
    let sid = scan.id.clone();
    let cancel = crate::core::cancel::CancelHandle::new();
    let cancel_guard = super::CancelRegistryGuard::install(
        Arc::clone(&state.cancellations),
        sid.clone(),
        cancel.clone(),
    );
    let ctx = ModuleContext {
        scan_id: sid.clone(),
        bus: state.bus.clone(),
        http: state.http.clone(),
        keys: keys::load(),
        cancel,
        proxy_pool: std::sync::Arc::clone(&state.proxy_pool),
    };
    let engine = Arc::clone(&state.engine);
    tokio::spawn(async move {
        let _cancel_guard = cancel_guard;
        if let Err(e) = engine.run(scan, target, ctx).await {
            tracing::warn!(scan_id = %sid, error = %e, "scan failed");
        }
    });
}

// ─── Health / Version / Stats / Modules ────────────────────────────────────

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
    for scan in &scans {
        *by_status.entry(scan.status.as_str()).or_insert(0) += 1;
        total_entities += scan.entity_count as u64;
    }
    let modules = s.engine.modules().len();
    let live_sessions = s.live.list().len();
    (
        StatusCode::OK,
        Json(json!({
            "scans_total": scans.len(),
            "scans_by_status": by_status,
            "entities_total": total_entities,
            "modules": modules,
            "live_sessions": live_sessions,
            "version": crate::VERSION,
        })),
    )
        .into_response()
}

pub async fn version() -> Json<Value> {
    Json(json!({ "version": crate::VERSION }))
}

pub async fn modules_list(State(s): State<Arc<AppState>>) -> Json<Value> {
    use crate::core::scan::TargetKind;
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
            let cost = serde_json::to_value(m.cost()).unwrap_or(Value::Null);
            let accepts: Vec<&'static str> = ALL_KINDS
                .iter()
                .filter(|k| m.accepts(&Target::new(**k, "probe")))
                .map(|k| k.canonical_str())
                .collect();
            json!({
                "name":        m.name(),
                "priority":    m.priority(),
                "cost":        cost,
                "passive":     m.is_passive(),
                "accepts":     accepts,
                "description": m.description(),
            })
        })
        .collect();
    let count = mods.len();
    Json(json!({ "modules": mods, "count": count }))
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
        Some(q) if !q.trim().is_empty() => q.trim(),
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
