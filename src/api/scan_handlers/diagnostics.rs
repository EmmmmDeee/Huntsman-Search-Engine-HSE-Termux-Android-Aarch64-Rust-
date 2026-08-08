use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use std::sync::Arc;

use super::super::handlers::{not_found, ok_list};
use crate::api::AppState;
use crate::core::scan::Target;

/// `GET /api/v1/scans/{id}/audit` — the scored self-audit of a stored scan.
pub async fn scan_audit(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Some(resp) = super::scan_missing(&s, &id).await {
        return resp;
    }
    let store = std::sync::Arc::clone(&s.store);
    let id2 = id.clone();
    // The scan record itself is read alongside entities/events so the audit
    // can anchor the engine-health signal to WHEN this scan actually ran,
    // not to whatever the live liveness cache says right now (see
    // `engine_health_signals`). Same off-reactor batching as before.
    let (scan, entities, events) = match super::offload_store(move || {
        let scan = store.get_scan(&id2)?;
        let entities = store.entities_for_scan(&id2)?;
        let events = store.events_for_scan(&id2).unwrap_or_default();
        Ok((scan, entities, events))
    })
    .await
    {
        Ok(triple) => triple,
        Err(resp) => return resp,
    };
    let normalised: Vec<crate::audit::AuditEntity> = entities
        .iter()
        .map(crate::audit::AuditEntity::from_entity)
        .collect();
    // `scan_missing` above already confirmed the id exists; `get_scan`
    // returning `None` here would only happen on a delete racing this
    // request, so `finished_at`/`started_at` unavailable just means the
    // engine-health signal is honestly omitted (see below) rather than
    // guessed at.
    let scan_reference_ts = scan
        .as_ref()
        .map(|sc| sc.finished_at.unwrap_or(sc.started_at));
    let mut signals = engine_health_signals(scan_reference_ts);
    crate::audit::fold_events(&mut signals, &events);
    let report = crate::audit::audit(&normalised, signals);
    Json(report.to_json()).into_response()
}

/// Translate the latest cached search-engine liveness sweep into auditor
/// source-health signals (parser-defect vs down vs blocked) — but ONLY when
/// that snapshot plausibly still describes conditions as of `scan_reference_ts`
/// (a scan's own `finished_at`/`started_at`, or `None` if the scan record
/// couldn't be read).
///
/// The liveness cache is a single, continuously-refreshed, process-global
/// snapshot of "conditions right now" (`crate::modules::search_engines::health`),
/// while `hse audit` is a historical explanation of ONE scan's results. Blending
/// the two without checking their relative timing is a silent stale-attribution
/// bug in BOTH directions: engines that break weeks after a scan with full
/// coverage would wrongly mark that old (actually-complete) scan as
/// coverage-degraded (false positive); engines that recover before a later
/// audit of a scan that genuinely ran during an outage would hide that real
/// historical gap entirely (false negative). Gating on
/// [`snapshot_still_relevant_to`] — using the health sweep's own refresh
/// cadence as the tolerance, not an invented number — means a routine
/// audit-shortly-after-scan still gets the signal, while a scan audited long
/// after it ran gets an honest omission instead of a misattributed one.
fn engine_health_signals(scan_reference_ts: Option<u64>) -> crate::audit::LogSignals {
    use crate::modules::search_engines::health::{self, EngineStatus};
    let mut sig = crate::audit::LogSignals::default();
    let Some(snap) = health::cached() else {
        return sig;
    };
    let Some(scan_ts) = scan_reference_ts else {
        return sig;
    };
    if !snapshot_still_relevant_to(snap.checked_at, scan_ts) {
        return sig;
    }
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
    sig
}

/// True if a liveness snapshot taken at `checked_at` plausibly still
/// describes conditions as of `scan_reference_ts`. Tolerance is
/// [`crate::modules::search_engines::health::DEFAULT_REFRESH_SECS`] × 2 — one
/// full periodic-sweep cycle of slack beyond the shortest interval the cache
/// would normally have been re-measured within, so an audit run shortly
/// after its scan (the common case) still gets the signal. `checked_at`
/// predating `scan_reference_ts` (the cache hasn't caught up to a
/// just-finished scan yet) is never rejected here — that's the cache being
/// merely incomplete, not misattributed, and `health::cached()` returning
/// `None` already covers "no data yet" separately.
#[must_use]
pub(crate) fn snapshot_still_relevant_to(checked_at: u64, scan_reference_ts: u64) -> bool {
    use crate::modules::search_engines::health::DEFAULT_REFRESH_SECS;
    checked_at.saturating_sub(scan_reference_ts) <= DEFAULT_REFRESH_SECS * 2
}

/// `GET /api/v1/scans/{id}/metrics` — objective per-scan quality / telemetry measures.
pub async fn scan_metrics(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Some(resp) = super::scan_missing(&s, &id).await {
        return resp;
    }
    let (entities, relations) = match super::entities_and_relations(&s, &id).await {
        Ok(pair) => pair,
        Err(resp) => return resp,
    };
    let metrics = crate::core::metrics::compute(&entities, &relations);
    (StatusCode::OK, Json(metrics)).into_response()
}

/// `GET /api/v1/scans/{id}/duplicates` — near-duplicate entity-resolution suggestions.
pub async fn scan_duplicates(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Some(resp) = super::scan_missing(&s, &id).await {
        return resp;
    }
    let entities = match super::scan_entities_only(&s, &id).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let groups = crate::core::resolve::suggest_merges(&entities);
    ok_list("duplicates", groups)
}

/// `GET /api/v1/scans/{id}/pivots` — pivot-node detection.
pub async fn scan_pivots(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Some(resp) = super::scan_missing(&s, &id).await {
        return resp;
    }
    let (entities, relations) = match super::entities_and_relations(&s, &id).await {
        Ok(pair) => pair,
        Err(resp) => return resp,
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
    if let Some(resp) = super::scan_missing(&s, &id).await {
        return resp;
    }
    let (entities, relations) = match super::entities_and_relations(&s, &id).await {
        Ok(pair) => pair,
        Err(resp) => return resp,
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
    // The `scan` record is needed for the report, so it rides along in the same
    // off-reactor batch as the entity/relation loads (see `scan_with_graph`,
    // which also folds in the 404 existence probe).
    let (scan, entities, relations) = match super::scan_with_graph(&s, &id).await {
        Ok(Some(triple)) => triple,
        Ok(None) => return not_found(),
        Err(resp) => return resp,
    };
    let report = crate::core::benchmark::report(&scan, &entities, &relations);
    (StatusCode::OK, Json(report)).into_response()
}
