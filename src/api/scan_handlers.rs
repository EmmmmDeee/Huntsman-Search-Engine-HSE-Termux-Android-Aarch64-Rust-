use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use std::sync::Arc;
use tracing::info;

use super::handlers::{internal_error, not_found, ok_list, spawn_scan};
use crate::api::AppState;
use crate::core::entity::scan_id;
use crate::core::scan::{Scan, ScanRequest, Target};

pub async fn scan_create(
    State(s): State<Arc<AppState>>,
    Json(req): Json<ScanRequest>,
) -> impl IntoResponse {
    let target = Target::new(req.kind, req.value.clone());
    if let Err(msg) = target.validate() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": format!("invalid target: {msg}") })),
        )
            .into_response();
    }
    let sid = scan_id(req.kind.canonical_str(), &req.value);
    let mut opts = req.options;
    if let Some(ref profile_name) = opts.profile
        && let Some(profile_opts) = crate::core::profiles::resolve_profile(profile_name)
    {
        opts = profile_opts;
    }
    let scan = Scan::new(sid.clone(), target.clone()).with_options(opts);

    if let Err(e) = s.store.upsert_scan(&scan) {
        return internal_error(&e);
    }

    spawn_scan(&s, scan.clone(), target);

    info!(scan_id = %scan.id, kind = ?scan.target.kind, "scan queued");
    (
        StatusCode::ACCEPTED,
        Json(json!({ "scan_id": scan.id, "status": "queued" })),
    )
        .into_response()
}

pub async fn scan_batch(
    State(s): State<Arc<AppState>>,
    Json(requests): Json<Vec<ScanRequest>>,
) -> impl IntoResponse {
    if requests.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "empty batch" })),
        )
            .into_response();
    }
    if requests.len() > 50 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "batch too large (max 50)" })),
        )
            .into_response();
    }

    let mut scan_ids = Vec::with_capacity(requests.len());
    for req in requests {
        let target = Target::new(req.kind, req.value.clone());
        if let Err(msg) = target.validate() {
            scan_ids.push(json!({ "error": format!("invalid target: {msg}") }));
            continue;
        }
        let sid = scan_id(req.kind.canonical_str(), &req.value);
        let mut opts = req.options;
        if let Some(ref profile_name) = opts.profile
            && let Some(profile_opts) = crate::core::profiles::resolve_profile(profile_name)
        {
            opts = profile_opts;
        }
        let scan = Scan::new(sid.clone(), target.clone()).with_options(opts);
        if let Err(e) = s.store.upsert_scan(&scan) {
            scan_ids.push(json!({ "error": e.to_string() }));
            continue;
        }
        spawn_scan(&s, scan, target);
        scan_ids.push(json!({ "scan_id": sid, "status": "queued" }));
    }

    (
        StatusCode::ACCEPTED,
        Json(json!({ "scans": scan_ids, "count": scan_ids.len() })),
    )
        .into_response()
}

pub async fn scan_cancel(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let handle = s.cancellations.lock().get(&id).cloned();
    match handle {
        Some(h) => {
            h.cancel();
            info!(scan_id = %id, "scan cancellation requested");
            (
                StatusCode::OK,
                Json(json!({ "scan_id": id, "status": "cancelling" })),
            )
                .into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "no in-flight scan with that id" })),
        )
            .into_response(),
    }
}

pub async fn scan_list(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    match s.store.list_scans(200) {
        Ok(scans) => ok_list("scans", scans),
        Err(e) => internal_error(&e),
    }
}

pub async fn scan_get(State(s): State<Arc<AppState>>, Path(id): Path<String>) -> impl IntoResponse {
    match s.store.get_scan(&id) {
        Ok(Some(scan)) => (
            StatusCode::OK,
            Json(serde_json::to_value(&scan).unwrap_or_else(|e| {
                tracing::warn!(error = %e, "failed to serialize scan to JSON value");
                json!({})
            })),
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
        Ok(entities) => ok_list("entities", entities),
        Err(e) => internal_error(&e),
    }
}

pub async fn scan_entities_filter(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    if params.get("kind").is_some_and(|k| k.len() > 32) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "kind too long (max 32 chars)"})),
        )
            .into_response();
    }
    if params.get("q").is_some_and(|v| v.len() > 256) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "query too long (max 256 chars)"})),
        )
            .into_response();
    }
    let kind = params.get("kind").map(String::as_str);
    let min_conf = params
        .get("min_confidence")
        .and_then(|v| v.parse::<f64>().ok())
        .filter(|&c| (0.0..=1.0).contains(&c));
    let q = params.get("q").map(String::as_str);
    match s.store.entities_filtered(&id, kind, min_conf, q) {
        Ok(entities) => ok_list("entities", entities),
        Err(e) => internal_error(&e),
    }
}

pub async fn scan_entities_facets(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match s.store.entity_facets(&id) {
        Ok(facets) => {
            let items: Vec<serde_json::Value> = facets
                .iter()
                .map(|(kind, count)| json!({ "kind": kind, "count": count }))
                .collect();
            Json(json!({ "facets": items, "count": items.len() })).into_response()
        }
        Err(e) => internal_error(&e),
    }
}

pub async fn scan_correlations(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match s.store.correlations_for_scan(&id) {
        Ok(corr) => ok_list("correlations", corr),
        Err(e) => internal_error(&e),
    }
}

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

    spawn_scan(&s, new_scan.clone(), original.target.clone());

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

pub async fn scan_events_history(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match s.store.events_for_scan(&id) {
        Ok(events) => ok_list("events", events),
        Err(e) => internal_error(&e),
    }
}

pub async fn scan_entities_csv(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let entities = match s.store.entities_for_scan(&id) {
        Ok(es) => es,
        Err(e) => return internal_error(&e),
    };
    download_response(
        entities_to_csv(&entities),
        "text/csv; charset=utf-8",
        &id,
        "csv",
    )
}

/// Canonical CSV rendering for a scan's entities. Shared by the HTTP
/// endpoint `/api/v1/scans/{id}/entities.csv` and the `hse export
/// --format csv` CLI subcommand so both produce byte-identical
/// output — operators piping the two interchangeably can rely on
/// the column shape staying in sync.
pub(crate) fn entities_to_csv(entities: &[crate::core::entity::Entity]) -> String {
    use std::fmt::Write as _;
    let mut body = String::with_capacity(192 + entities.len() * 128);
    body.push_str("kind,value,raw_value,confidence,c_effective,corroboration,classification,observed_at,sources,tags\n");
    for e in entities {
        let eff = e.c_effective();
        let tier = e.classify().to_string();
        let mut sources: Vec<&str> = e.evidence_sources().into_iter().collect();
        sources.sort_unstable();
        let sources = sources.join("|");
        let tags = e.tags.join("|");
        let _ = writeln!(
            body,
            "{},{},{},{:.3},{:.3},{},{},{},{},{}",
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
        );
    }
    body
}

pub async fn scan_report_json(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match build_scan_report(&*s.store, &id) {
        Ok(Some(report)) => {
            let body = serde_json::to_string_pretty(&report).unwrap_or_else(|e| {
                tracing::warn!(error = %e, "failed to serialize scan report to JSON string");
                "{}".into()
            });
            download_response(body, "application/json; charset=utf-8", &id, "json")
        }
        Ok(None) => not_found(),
        Err(e) => internal_error(&e),
    }
}

/// Canonical scan-report JSON envelope. Shared by the HTTP endpoint
/// `/api/v1/scans/{id}/report.json` and the `hse export --format
/// report` CLI subcommand so the on-device and over-the-wire
/// dossiers stay byte-equivalent.
///
/// Generic over the storage handle: the HTTP layer hands in an
/// `Arc<dyn StoragePort>` (via `&*s.store`), the CLI hands in a
/// `&Store` directly. Both expose `get_scan / entities_for_scan /
/// correlations_for_scan` with matching signatures.
///
/// Returns `Ok(None)` when no scan with that id exists, so callers
/// can map straight to a 404. Bubbles storage errors otherwise.
pub(crate) fn build_scan_report(
    store: &dyn crate::core::port::StoragePort,
    scan_id: &str,
) -> crate::core::error::Result<Option<serde_json::Value>> {
    let Some(scan) = store.get_scan(scan_id)? else {
        return Ok(None);
    };
    let entities = store.entities_for_scan(scan_id)?;
    let correlations = store.correlations_for_scan(scan_id)?;
    Ok(Some(json!({
        "scan": scan,
        "entities": entities,
        "entity_count": entities.len(),
        "correlations": correlations,
        "correlation_count": correlations.len(),
        "exported_at": crate::core::entity::unix_now(),
    })))
}

pub async fn scan_export_gexf(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let entities = match s.store.entities_for_scan(&id) {
        Ok(entities) => entities,
        Err(e) => return internal_error(&e),
    };
    let body = crate::core::gexf::entities_to_gexf(&entities, &id);
    download_response(body, "application/xml; charset=utf-8", &id, "gexf")
}

fn download_response(
    body: String,
    content_type: &'static str,
    scan_id: &str,
    ext: &str,
) -> axum::response::Response {
    let short_id: String = scan_id.chars().take(12).collect();
    let filename = format!("hse-{ext}-{short_id}.{ext}");
    let disposition = format!("attachment; filename=\"{filename}\"");
    let mut resp = (StatusCode::OK, body).into_response();
    let headers = resp.headers_mut();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static(content_type),
    );
    if let Ok(v) = axum::http::HeaderValue::from_str(&disposition) {
        headers.insert(axum::http::header::CONTENT_DISPOSITION, v);
    }
    resp
}

pub(crate) fn csv_escape(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

// ─── Health / Version / Stats / Modules ────────────────────────────────────
