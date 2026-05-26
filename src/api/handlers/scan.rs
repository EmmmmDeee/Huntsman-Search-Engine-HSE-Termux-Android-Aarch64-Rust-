//! Scan CRUD handlers: create, get, list, delete, rerun, cancel,
//! entities, correlations, events, CSV/JSON export.

use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use tracing::info;

use super::{internal_error, not_found, ok_list, spawn_scan};
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
    let scan = Scan::new(sid.clone(), target.clone()).with_options(req.options);

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
    let kind = params.get("kind").map(String::as_str);
    let min_conf = params
        .get("min_confidence")
        .and_then(|v| v.parse::<f64>().ok());
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
                .map(|(kind, count)| serde_json::json!({ "kind": kind, "count": count }))
                .collect();
            let n = items.len();
            Json(serde_json::json!({ "facets": items, "count": n })).into_response()
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
    use std::collections::BTreeSet;
    use std::fmt::Write as _;
    let entities = match s.store.entities_for_scan(&id) {
        Ok(es) => es,
        Err(e) => return internal_error(&e),
    };

    let mut body = String::with_capacity(192 + entities.len() * 128);
    body.push_str("kind,value,raw_value,confidence,c_effective,corroboration,classification,observed_at,sources,tags\n");
    for e in &entities {
        let eff = e.c_effective();
        let tier = e.classify().to_string();
        let sources: BTreeSet<&str> = e.evidence.iter().map(|ev| ev.source.as_str()).collect();
        let sources = sources.into_iter().collect::<Vec<_>>().join("|");
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

pub async fn scan_report_json(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let scan = match s.store.get_scan(&id) {
        Ok(Some(scan)) => scan,
        Ok(None) => return not_found(),
        Err(e) => return internal_error(&e),
    };
    let entities = match s.store.entities_for_scan(&id) {
        Ok(entities) => entities,
        Err(e) => return internal_error(&e),
    };
    let correlations = match s.store.correlations_for_scan(&id) {
        Ok(correlations) => correlations,
        Err(e) => return internal_error(&e),
    };

    let report = json!({
        "scan": scan,
        "entities": entities,
        "entity_count": entities.len(),
        "correlations": correlations,
        "correlation_count": correlations.len(),
        "exported_at": crate::core::entity::unix_now(),
    });

    let filename = format!(
        "hse-report-{}.json",
        id.chars().take(12).collect::<String>()
    );
    let body = serde_json::to_string_pretty(&report).unwrap_or_else(|e| {
        tracing::warn!(error = %e, "failed to serialize scan report to JSON string");
        "{}".into()
    });
    let disposition = format!("attachment; filename=\"{filename}\"");
    let mut resp = (StatusCode::OK, body).into_response();
    let headers = resp.headers_mut();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json; charset=utf-8"),
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

#[cfg(test)]
mod tests {
    use super::*;

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
