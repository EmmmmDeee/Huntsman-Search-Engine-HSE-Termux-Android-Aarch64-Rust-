//! HTTP handlers.
//!
//! Every handler returns `impl IntoResponse` so we can mix `Json`,
//! `(StatusCode, Json)`, and `Sse<...>` freely. Error paths emit a
//! `{"error": "..."}` JSON body with the appropriate status.

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
use serde_json::{Value, json};
use tokio_stream::{StreamExt as _, wrappers::BroadcastStream};
use tracing::info;

use super::AppState;
use crate::{
    core::{
        event::EventKind,
        module::ModuleContext,
        scan::{Scan, ScanRequest, Target},
    },
    util::{http::build_client, keys, uid::scan_id},
};

// ─── Health / Version ────────────────────────────────────────────────────────

pub async fn health() -> Json<Value> {
    Json(json!({ "status": "ok", "version": crate::VERSION }))
}

pub async fn version() -> Json<Value> {
    Json(json!({ "version": crate::VERSION }))
}

// ─── Modules ─────────────────────────────────────────────────────────────────

pub async fn modules_list(State(s): State<Arc<AppState>>) -> Json<Value> {
    let mods: Vec<Value> = s
        .engine
        .modules()
        .iter()
        .map(|m| {
            json!({
                "name":       m.name(),
                "priority":   m.priority(),
                "cost":       format!("{:?}", m.cost()).to_lowercase(),
                "passive":    m.is_passive(),
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
    let sid = scan_id(&format!("{:?}", req.kind).to_lowercase(), &req.value);
    let scan = Scan::new(sid.clone(), target.clone()).with_options(req.options.clone());

    if let Err(e) = s.store.upsert_scan(&scan) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response();
    }

    let ctx = ModuleContext {
        scan_id: sid.clone(),
        bus: s.bus.clone(),
        http: build_client(),
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
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

pub async fn scan_get(State(s): State<Arc<AppState>>, Path(id): Path<String>) -> impl IntoResponse {
    match s.store.get_scan(&id) {
        Ok(Some(scan)) => (
            StatusCode::OK,
            Json(serde_json::to_value(&scan).unwrap_or(json!({}))),
        )
            .into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, Json(json!({ "error": "not found" }))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
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
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
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

// Force the EventKind import to remain (clippy::unused_imports otherwise);
// we serialise it implicitly via Event in the broadcast.
const _: fn() = || {
    let _ = EventKind::ScanComplete {
        scan_id: String::new(),
        entity_count: 0,
    };
};
