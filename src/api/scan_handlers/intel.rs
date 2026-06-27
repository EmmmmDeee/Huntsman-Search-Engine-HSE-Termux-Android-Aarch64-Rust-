use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use std::sync::Arc;

use super::super::handlers::{internal_error, not_found, ok_list};
use crate::api::AppState;

/// `GET /api/v1/scans/{id}/leads` — proactive next-best-action recommendations
/// ([`crate::core::leads`]): the untapped identities this scan surfaced but did
/// not pivot (family/associate connections held below the expansion floor most of
/// all), ranked by pivot value — each a one-click follow-up scan from the web UI.
/// 404 if the scan is unknown, matching the other sub-resources.
pub async fn scan_leads(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let scan = match s.store.get_scan(&id) {
        Ok(Some(scan)) => scan,
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
    let leads =
        crate::core::leads::recommend(&entities, &relations, scan.options.min_expand_confidence);
    ok_list("leads", leads)
}

/// `GET /api/v1/scans/{id}/timeline` — the subject's footprint reconstructed as a
/// single chronology ([`crate::core::timeline`]): every dated event the evidence
/// implies (a breach exposure, a domain registration, an account creation, …),
/// ordered oldest-first. Pure synthesis over the persisted entities; 404 if the
/// scan is unknown, matching the other `/scans/{id}/...` sub-resources.
pub async fn scan_timeline(
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
    let events = crate::core::timeline::reconstruct(&entities);
    // Additive: alongside the event list (unchanged `events` + `count` shape),
    // surface the online-tenure summary — the span and breach-depth of the
    // subject's digital footprint ("online since 2008, 17 years, 9 breaches").
    let tenure = crate::core::timeline::online_tenure(&events);
    // Footprint recency: how current the latest activity is (active vs dormant) —
    // a live footprint means exposed credentials are likely still in use.
    let now = i64::try_from(crate::core::entity::unix_now()).unwrap_or(i64::MAX);
    let recency = tenure
        .as_ref()
        .map(|t| crate::core::timeline::footprint_recency(t.latest_ts, now));
    let count = events.len();
    (
        StatusCode::OK,
        Json(json!({
            "events": events,
            "count": count,
            "tenure": tenure,
            "recency": recency,
        })),
    )
        .into_response()
}

/// `GET /api/v1/scans/{id}/communities` — relationship-graph community detection
/// ([`crate::core::community`]): the scan's graph partitioned into sub-clusters by
/// deterministic label propagation (e.g. the family cluster vs the infrastructure
/// estate), each community carrying its member UIDs, size, and a derived label.
/// Pure synthesis over the persisted entities + relations; 404 if the scan is
/// unknown, matching the other `/scans/{id}/...` sub-resources.
pub async fn scan_communities(
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
    let communities = crate::core::community::detect(&entities, &relations);
    ok_list("communities", communities)
}

/// `GET /api/v1/scans/{id}/trust` — relationship-graph trust propagation
/// ([`crate::core::trust`]): every entity ranked by how strongly the graph
/// corroborates it, via damped personalized-PageRank-style propagation from
/// high-confidence anchors, attenuating with graph distance. Read-only — never
/// mutates stored confidence. Pure synthesis over the persisted entities +
/// relations; 404 if the scan is unknown, matching the other sub-resources.
pub async fn scan_trust(
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
    let scores = crate::core::trust::propagate(&entities, &relations);
    ok_list("trust", scores)
}

/// Query parameters for [`scan_path`]: the two endpoint VALUES to connect, an optional
/// cap on how many distinct pathways to return, and an optional `cross` flag to extend
/// the search across the WHOLE local intelligence database rather than this scan alone.
#[derive(serde::Deserialize)]
pub struct PathQuery {
    pub from: String,
    pub to: String,
    pub paths: Option<usize>,
    pub cross: Option<bool>,
}

/// `GET /api/v1/scans/{id}/path?from=<value>&to=<value>[&paths=N][&cross=true]` —
/// connection-path discovery ([`crate::core::path`]): the shortest chain of
/// relationships linking two named entities, plus up to N distinct alternative routes.
/// The universal "how are A and B connected?" query — e.g. `from=Kyle Diegmann` to
/// `to=Erik Diegmann`. By default it searches THIS scan's graph; with `cross=true` it
/// reaches across every scan in the local intelligence database (bounded), so a seed
/// connects to an entity discovered in a SEPARATE investigation. Node UIDs are resolved
/// to display labels server-side so the chain renders standalone. 404 if the scan is
/// unknown, matching the other sub-resources.
pub async fn scan_path(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(q): Query<PathQuery>,
) -> impl IntoResponse {
    if let Some(resp) = super::scan_missing(&s, &id) {
        return resp;
    }
    let store = std::sync::Arc::clone(&s.store);
    let id2 = id.clone();
    let from = q.from.clone();
    let to = q.to.clone();
    let cross = q.cross.unwrap_or(false);
    let max_paths = q
        .paths
        .unwrap_or(crate::core::path::DEFAULT_MAX_PATHS)
        .clamp(1, 10);
    // Path discovery touches the store (cross-scan pulls in other scans), so the whole
    // computation — paths plus node-label resolution — runs off the async runtime.
    type PathResult = (
        Vec<crate::core::path::ConnectionPath>,
        serde_json::Map<String, serde_json::Value>,
    );
    let computed =
        tokio::task::spawn_blocking(move || -> Result<PathResult, crate::core::error::Error> {
            let paths = if cross {
                crate::core::path::connect_cross_scan(store.as_ref(), &from, &to, max_paths)
            } else {
                let entities = store.entities_for_scan(&id2)?;
                let relations = store.relations_for_scan(&id2)?;
                crate::core::path::connect_values(&entities, &relations, &from, &to, max_paths)
            };
            // Resolve each node UID to a display label via a point lookup, so the chain
            // renders standalone regardless of which scan a node came from.
            let mut nodes = serde_json::Map::new();
            for p in &paths {
                for uid in &p.nodes {
                    if !nodes.contains_key(uid)
                        && let Ok(Some(e)) = store.get_entity(uid)
                    {
                        let label = if e.raw_value.is_empty() {
                            e.value
                        } else {
                            e.raw_value
                        };
                        nodes.insert(
                            uid.clone(),
                            json!({ "value": label, "kind": e.kind.to_string() }),
                        );
                    }
                }
            }
            Ok((paths, nodes))
        })
        .await;
    let (paths, nodes) = match computed {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => return internal_error(&e),
        Err(e) => return internal_error(&format!("query task failed: {e}")),
    };
    let connected = !paths.is_empty();
    (
        StatusCode::OK,
        Json(json!({
            "from": q.from,
            "to": q.to,
            "cross_scan": cross,
            "connected": connected,
            "paths": paths,
            "nodes": nodes,
        })),
    )
        .into_response()
}
