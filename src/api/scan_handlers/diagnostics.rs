use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use std::sync::Arc;

use super::super::handlers::{internal_error, not_found, ok_list};
use crate::api::AppState;
use crate::core::scan::Target;

/// `GET /api/v1/scans/{id}/audit` — the scored self-audit of a stored scan.
pub async fn scan_audit(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Some(resp) = super::scan_missing(&s, &id) {
        return resp;
    }
    let store = std::sync::Arc::clone(&s.store);
    let id2 = id.clone();
    // Both the entities read AND the event-log read are synchronous SQLite — run
    // them together off the ~2-worker reactor. The event-log read was the residual
    // on-reactor gap (the entities read was already offloaded).
    let loaded = tokio::task::spawn_blocking(move || {
        let entities = store.entities_for_scan(&id2)?;
        let events = store.events_for_scan(&id2).unwrap_or_default();
        Ok::<_, crate::core::error::Error>((entities, events))
    })
    .await;
    let (entities, events) = match loaded {
        Ok(Ok(pair)) => pair,
        Ok(Err(e)) => return internal_error(&e),
        Err(e) => return internal_error(&format!("query task failed: {e}")),
    };
    let normalised: Vec<crate::audit::AuditEntity> = entities
        .iter()
        .map(crate::audit::AuditEntity::from_entity)
        .collect();
    let mut signals = engine_health_signals();
    crate::audit::fold_events(&mut signals, &events);
    let report = crate::audit::audit(&normalised, signals);
    Json(report.to_json()).into_response()
}

/// Translate the latest cached search-engine liveness sweep into auditor
/// source-health signals (parser-defect vs down vs blocked).
fn engine_health_signals() -> crate::audit::LogSignals {
    use crate::modules::search_engines::health::{self, EngineStatus};
    let mut sig = crate::audit::LogSignals::default();
    if let Some(snap) = health::cached() {
        for h in &snap.engines {
            match h.status {
                EngineStatus::Down => sig.engines_down.push(h.name.to_string()),
                EngineStatus::Blocked => {
                    if h.detail.contains("PARSER") {
                        sig.engine_parser_defects.push(h.name.to_string());
                    } else {
                        sig.engines_blocked.push(h.name.to_string());
                    }
                }
                EngineStatus::Up => {}
            }
        }
    }
    sig
}

/// `GET /api/v1/scans/{id}/metrics` — objective per-scan quality / telemetry measures.
pub async fn scan_metrics(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Some(resp) = super::scan_missing(&s, &id) {
        return resp;
    }
    let store = std::sync::Arc::clone(&s.store);
    let id2 = id.clone();
    let loaded = tokio::task::spawn_blocking(move || {
        Ok::<_, crate::core::error::Error>((
            store.entities_for_scan(&id2)?,
            store.relations_for_scan(&id2)?,
        ))
    })
    .await;
    let (entities, relations) = match loaded {
        Ok(Ok(pair)) => pair,
        Ok(Err(e)) => return internal_error(&e),
        Err(e) => return internal_error(&format!("query task failed: {e}")),
    };
    let metrics = crate::core::metrics::compute(&entities, &relations);
    (StatusCode::OK, Json(metrics)).into_response()
}

/// `GET /api/v1/scans/{id}/duplicates` — near-duplicate entity-resolution suggestions.
pub async fn scan_duplicates(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Some(resp) = super::scan_missing(&s, &id) {
        return resp;
    }
    let store = std::sync::Arc::clone(&s.store);
    let id2 = id.clone();
    let loaded = tokio::task::spawn_blocking(move || store.entities_for_scan(&id2)).await;
    let entities = match loaded {
        Ok(Ok(e)) => e,
        Ok(Err(e)) => return internal_error(&e),
        Err(e) => return internal_error(&format!("query task failed: {e}")),
    };
    let groups = crate::core::resolve::suggest_merges(&entities);
    ok_list("duplicates", groups)
}

/// `GET /api/v1/scans/{id}/pivots` — pivot-node detection.
pub async fn scan_pivots(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Some(resp) = super::scan_missing(&s, &id) {
        return resp;
    }
    let store = std::sync::Arc::clone(&s.store);
    let id2 = id.clone();
    let loaded = tokio::task::spawn_blocking(move || {
        Ok::<_, crate::core::error::Error>((
            store.entities_for_scan(&id2)?,
            store.relations_for_scan(&id2)?,
        ))
    })
    .await;
    let (entities, relations) = match loaded {
        Ok(Ok(pair)) => pair,
        Ok(Err(e)) => return internal_error(&e),
        Err(e) => return internal_error(&format!("query task failed: {e}")),
    };
    let pivots = crate::core::pivot::detect(&entities, &relations);
    let bridges = crate::core::pivot::bridges(&entities, &relations);
    let count = pivots.len();
    (
        StatusCode::OK,
        Json(json!({
            "pivots": pivots,
            "bridges": bridges,
            "count": count,
        })),
    )
        .into_response()
}

/// `GET /api/v1/scans/{id}/gaps` — discovery-gap analysis.
pub async fn scan_gaps(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Some(resp) = super::scan_missing(&s, &id) {
        return resp;
    }
    let store = std::sync::Arc::clone(&s.store);
    let id2 = id.clone();
    let loaded = tokio::task::spawn_blocking(move || {
        Ok::<_, crate::core::error::Error>((
            store.entities_for_scan(&id2)?,
            store.relations_for_scan(&id2)?,
        ))
    })
    .await;
    let (entities, relations) = match loaded {
        Ok(Ok(pair)) => pair,
        Ok(Err(e)) => return internal_error(&e),
        Err(e) => return internal_error(&format!("query task failed: {e}")),
    };

    let report = crate::core::gap::analyze(&entities, &relations);

    let by_uid: std::collections::HashMap<&str, &crate::core::entity::Entity> =
        entities.iter().map(|e| (e.uid.as_str(), e)).collect();
    let reg = crate::modules::registry();
    let orphans: Vec<serde_json::Value> = report
        .orphans
        .iter()
        .map(|o| {
            let corrective: Vec<&'static str> = by_uid
                .get(o.uid.as_str())
                .and_then(|e| {
                    crate::core::scan::TargetKind::from_entity_kind(&e.kind)
                        .map(|tk| Target::new(tk, e.value.clone()))
                })
                .map(|target| {
                    reg.iter()
                        .filter(|m| m.accepts(&target))
                        .map(|m| m.name())
                        .collect()
                })
                .unwrap_or_default();
            json!({
                "uid": o.uid.clone(),
                "kind": o.kind.clone(),
                "value": o.value.clone(),
                "confidence": o.confidence,
                "isolation": o.isolation,
                "reinjection_target": o.reinjection_target.clone(),
                "action": o.action,
                "corrective_modules": corrective,
            })
        })
        .collect();

    (
        StatusCode::OK,
        Json(json!({
            "null_state": report.null_state,
            "total_seeds": report.total_seeds,
            "linked_seeds": report.linked_seeds,
            "isolated_seeds": report.isolated_seeds,
            "linked_fraction": report.linked_fraction,
            "isolation": report.isolation,
            "orphans": orphans,
        })),
    )
        .into_response()
}

/// `GET /api/v1/scans/{id}/benchmark` — consolidated, auditable benchmark report.
pub async fn scan_benchmark(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let scan = match s.store.get_scan(&id) {
        Ok(Some(sc)) => sc,
        Ok(None) => return not_found(),
        Err(e) => return internal_error(&e),
    };
    let store = std::sync::Arc::clone(&s.store);
    let id2 = id.clone();
    let loaded = tokio::task::spawn_blocking(move || {
        Ok::<_, crate::core::error::Error>((
            store.entities_for_scan(&id2)?,
            store.relations_for_scan(&id2)?,
        ))
    })
    .await;
    let (entities, relations) = match loaded {
        Ok(Ok(pair)) => pair,
        Ok(Err(e)) => return internal_error(&e),
        Err(e) => return internal_error(&format!("query task failed: {e}")),
    };
    let report = crate::core::benchmark::report(&scan, &entities, &relations);
    (StatusCode::OK, Json(report)).into_response()
}
