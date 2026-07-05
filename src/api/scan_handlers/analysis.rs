use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use std::sync::Arc;

use super::super::handlers::{bad_request, internal_error, ok_list};
use crate::api::AppState;

pub async fn scan_entities(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    if let Some(resp) = super::scan_missing(&s, &id) {
        return resp;
    }
    let store = std::sync::Arc::clone(&s.store);
    let id2 = id.clone();
    match tokio::task::spawn_blocking(move || store.entities_for_scan(&id2)).await {
        Ok(Ok(mut entities)) => {
            if !super::wants_candidates(&params) {
                entities.retain(|e| !e.has_tag(crate::core::tags::CANDIDATE));
            }
            ok_list("entities", entities)
        }
        Ok(Err(e)) => internal_error(&e),
        Err(e) => internal_error(&format!("query task failed: {e}")),
    }
}

/// `GET /api/v1/scans/{a}/diff/{b}` — entity-level diff of scan `a` (baseline)
/// vs scan `b`. The HTTP surface of `hse diff`: returns the `ScanDiff` JSON
/// (`{ added, removed, common, confidence_shifts }`) computed by the shared
/// `core::diff`. 404 if either scan is unknown, matching the other
/// `/scans/{id}/...` sub-resources.
pub async fn scan_diff(
    State(s): State<Arc<AppState>>,
    Path((a, b)): Path<(String, String)>,
) -> impl IntoResponse {
    if let Some(resp) = super::scan_missing(&s, &a) {
        return resp;
    }
    if let Some(resp) = super::scan_missing(&s, &b) {
        return resp;
    }
    let store = std::sync::Arc::clone(&s.store);
    let (a2, b2) = (a.clone(), b.clone());
    let (baseline, later) = match tokio::task::spawn_blocking(move || {
        Ok::<_, crate::core::error::Error>((
            store.entities_for_scan(&a2)?,
            store.entities_for_scan(&b2)?,
        ))
    })
    .await
    {
        Ok(Ok(pair)) => pair,
        Ok(Err(e)) => return internal_error(&e),
        Err(e) => return internal_error(&format!("query task failed: {e}")),
    };
    let diff = crate::core::diff::diff_entities(&baseline, &later);
    (StatusCode::OK, Json(diff)).into_response()
}

pub async fn scan_entities_filter(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    if let Some(resp) = super::scan_missing(&s, &id) {
        return resp;
    }
    if params.get("kind").is_some_and(|k| k.len() > 32) {
        return bad_request("kind too long (max 32 chars)");
    }
    if params.get("q").is_some_and(|v| v.len() > 256) {
        return bad_request("query too long (max 256 chars)");
    }
    let kind = params.get("kind").cloned();
    let min_conf = params
        .get("min_confidence")
        .and_then(|v| v.parse::<f64>().ok())
        .filter(|&c| (0.0..=1.0).contains(&c));
    let q = params.get("q").cloned();
    let store = std::sync::Arc::clone(&s.store);
    let id2 = id.clone();
    match tokio::task::spawn_blocking(move || {
        store.entities_filtered(&id2, kind.as_deref(), min_conf, q.as_deref())
    })
    .await
    {
        Ok(Ok(mut entities)) => {
            // Quarantine by default (opt in with `?include_candidates=1`) — matches
            // `scan_entities`, `scan_entities_csv`, and `report.json` so this filtered
            // view can't be used to route around the candidate quarantine the other
            // entity-listing endpoints already enforce.
            if !super::wants_candidates(&params) {
                entities.retain(|e| !e.has_tag(crate::core::tags::CANDIDATE));
            }
            ok_list("entities", entities)
        }
        Ok(Err(e)) => internal_error(&e),
        Err(e) => internal_error(&format!("query task failed: {e}")),
    }
}

pub async fn scan_entities_facets(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Some(resp) = super::scan_missing(&s, &id) {
        return resp;
    }
    let store = std::sync::Arc::clone(&s.store);
    let id2 = id.clone();
    match tokio::task::spawn_blocking(move || store.entity_facets(&id2)).await {
        Ok(Ok(facets)) => {
            let items: Vec<serde_json::Value> = facets
                .iter()
                .map(|(kind, count)| json!({ "kind": kind, "count": count }))
                .collect();
            Json(json!({ "facets": items, "count": items.len() })).into_response()
        }
        Ok(Err(e)) => internal_error(&e),
        Err(e) => internal_error(&format!("query task failed: {e}")),
    }
}

pub async fn scan_correlations(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Some(resp) = super::scan_missing(&s, &id) {
        return resp;
    }
    let store = std::sync::Arc::clone(&s.store);
    let id2 = id.clone();
    match tokio::task::spawn_blocking(move || store.correlations_for_scan(&id2)).await {
        Ok(Ok(corr)) => ok_list("correlations", corr),
        Ok(Err(e)) => internal_error(&e),
        Err(e) => internal_error(&format!("query task failed: {e}")),
    }
}

/// `GET /api/v1/scans/{id}/location` — the structured AU-059 residency fix: the
/// "where is the subject" verdict (locality / state / lat / lon / precision
/// radius / confidence and the independent signal classes that corroborate it).
///
/// A lightweight twin of the `best_location` field embedded in the full
/// `report.json`, so the SPA can surface the headline location finding without
/// downloading every entity — the Termux-friendly path. Reuses the same
/// structural extractor the export uses, so the two never diverge. `best_location`
/// is `null` when the scan found no AU location signal at all.
pub async fn scan_location(
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
            store.correlations_for_scan(&id2)?,
            store.entities_for_scan(&id2)?,
        ))
    })
    .await;
    let (correlations, entities) = match loaded {
        Ok(Ok(pair)) => pair,
        Ok(Err(e)) => return internal_error(&e),
        Err(e) => return internal_error(&format!("query task failed: {e}")),
    };
    let best = crate::api::scan_export::extract_au_location_fix(&correlations, &entities);
    Json(json!({ "best_location": best })).into_response()
}

/// Typed entity-relation edges for a scan (the attribution graph). Powers the
/// SPA force-graph's relation layer.
pub async fn scan_relations(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Some(resp) = super::scan_missing(&s, &id) {
        return resp;
    }
    // Resolve both endpoints of every edge to their display value + kind so the
    // SPA never has to render a raw entity UID. The Relations view previously
    // showed opaque SHA hashes (e.g. `91cceeaccaaa11e9…`) for any endpoint whose
    // entity hadn't been paged into the browser's entity map — on a 397-entity
    // scan that was most of the graph. Joining here makes every edge verifiable
    // on its own: "jordanavery@gmail.com (email) → gmail.com (domain)".
    let store = std::sync::Arc::clone(&s.store);
    let id2 = id.clone();
    let loaded = tokio::task::spawn_blocking(move || {
        Ok::<_, crate::core::error::Error>((
            store.relations_for_scan(&id2)?,
            store.entities_for_scan(&id2)?,
        ))
    })
    .await;
    let (rels, ents) = match loaded {
        Ok(Ok(pair)) => pair,
        Ok(Err(e)) => return internal_error(&e),
        Err(e) => return internal_error(&format!("query task failed: {e}")),
    };
    let by_uid: std::collections::HashMap<String, (String, String)> = ents
        .into_iter()
        .map(|e| (e.uid, (e.value, e.kind.to_string())))
        .collect();
    let resolved: Vec<serde_json::Value> = rels
        .into_iter()
        .map(|r| {
            let (from_value, from_kind) = by_uid
                .get(&r.from_uid)
                .cloned()
                .unwrap_or_else(|| (r.from_uid.clone(), "unknown".to_string()));
            let (to_value, to_kind) = by_uid
                .get(&r.to_uid)
                .cloned()
                .unwrap_or_else(|| (r.to_uid.clone(), "unknown".to_string()));
            json!({
                "id": r.id,
                "from_uid": r.from_uid,
                "to_uid": r.to_uid,
                "from_value": from_value,
                "from_kind": from_kind,
                "to_value": to_value,
                "to_kind": to_kind,
                "kind": r.kind.as_str(),
                "confidence": r.confidence,
                "scan_id": r.scan_id,
                "observed_at": r.observed_at,
            })
        })
        .collect();
    ok_list("relations", resolved)
}

/// `GET /api/v1/scans/{id}/network` — the subject-centric relationship synthesis
/// ([`crate::core::network`]) that powers the web UI's Network view: the seed hub
/// plus its connections grouped into people / identifiers / aliases / locations /
/// infrastructure, ranked by link strength and bounded for a phone. The synthesis
/// is pure Rust over the persisted entities + relations; 404 if the scan is
/// unknown, matching the other `/scans/{id}/...` sub-resources.
pub async fn scan_network(
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
    let network = crate::core::network::synthesize(&entities, &relations);
    (StatusCode::OK, Json(network)).into_response()
}

/// `GET /api/v1/scans/{id}/identities` — people-centric **co-reference**
/// resolution over the scan's entities.
///
/// Scores every pair of identity-bearing selectors (email / username / phone /
/// person) by how strongly they appear to name the **same individual**
/// ([`crate::core::coref::resolve_coreferences`]) — the cross-identifier
/// record-linkage layer that complements the same-identifier dedup and the
/// relation-graph clustering. Read-only; suggests, never mutates. Optional query
/// params: `min_score` (emission threshold, default
/// [`crate::core::coref::DEFAULT_MIN_SCORE`]) and `limit` (default 200, capped
/// 1000).
pub async fn scan_identities(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    if let Some(resp) = super::scan_missing(&s, &id) {
        return resp;
    }
    let min_score = params
        .get("min_score")
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(crate::core::coref::DEFAULT_MIN_SCORE);
    let limit = params
        .get("limit")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(200)
        .clamp(1, 1000);

    let store = std::sync::Arc::clone(&s.store);
    let id2 = id.clone();
    let loaded = tokio::task::spawn_blocking(move || store.entities_for_scan(&id2)).await;
    let entities = match loaded {
        Ok(Ok(ents)) => ents,
        Ok(Err(e)) => return internal_error(&e),
        Err(e) => return internal_error(&format!("query task failed: {e}")),
    };
    let corefs = crate::core::coref::resolve_coreferences(&entities, min_score, limit);
    (
        StatusCode::OK,
        Json(json!({
            "min_score": min_score,
            "count": corefs.len(),
            "coreferences": corefs,
        })),
    )
        .into_response()
}
