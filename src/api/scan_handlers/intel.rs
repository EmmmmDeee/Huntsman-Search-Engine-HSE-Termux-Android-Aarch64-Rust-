use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use std::sync::Arc;

use super::super::handlers::{not_found, ok_list};
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
    // `scan.options` is needed below, so the record rides along in the same
    // off-reactor batch as the entity/relation loads (see `scan_with_graph`,
    // which also folds in the 404 existence probe).
    let (scan, entities, relations) = match super::scan_with_graph(&s, &id).await {
        Ok(Some(triple)) => triple,
        Ok(None) => return not_found(),
        Err(resp) => return resp,
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
    if let Some(resp) = super::scan_missing(&s, &id).await {
        return resp;
    }
    let entities = match super::scan_entities_only(&s, &id).await {
        Ok(v) => v,
        Err(resp) => return resp,
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
    // Movement path: chronologically walks the timeline's own `LocationVisited`
    // fixes (currently `exif_geo`'s dated GPS extractions) into a "was at A,
    // then B, C km apart" reconstruction — `None` when fewer than 2 dated
    // fixes exist, so a single photo never fabricates a "path".
    let movement = crate::core::timeline::movement_path(&events);
    let count = events.len();
    (
        StatusCode::OK,
        Json(json!({
            "events": events,
            "count": count,
            "tenure": tenure,
            "recency": recency,
            "movement": movement,
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
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    if let Some(resp) = super::scan_missing(&s, &id).await {
        return resp;
    }
    let (entities, relations) = match super::entities_and_relations(&s, &id).await {
        Ok(pair) => pair,
        Err(resp) => return resp,
    };
    // Same quarantine gate every other entity-serving read endpoint enforces by
    // default: a candidate-tagged (unconfirmed) entity's raw value must not be
    // able to name or join a community — `Community::label` uses a member's raw
    // value verbatim, so an ungated candidate could surface as, or inside, a
    // "family cluster" alongside confirmed relatives with no distinguishing mark.
    let (entities, relations) =
        super::EntityViewGate::from_params(&params).apply_to_graph(entities, relations);
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
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    if let Some(resp) = super::scan_missing(&s, &id).await {
        return resp;
    }
    let (entities, relations) = match super::entities_and_relations(&s, &id).await {
        Ok(pair) => pair,
        Err(resp) => return resp,
    };
    // Same quarantine gate as scan_communities above: an unconfirmed candidate must
    // not be ranked (or lend its raw value to propagation) alongside verified entities.
    let (entities, relations) =
        super::EntityViewGate::from_params(&params).apply_to_graph(entities, relations);
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
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    if let Some(resp) = super::scan_missing(&s, &id).await {
        return resp;
    }
    // Same quarantine gate every other entity-serving read endpoint enforces by
    // default (`?include_candidates=1` to opt in) — /path previously ran the raw,
    // ungated entity/relation set through connect_values/connect_cross_scan, so a
    // same-name-stranger record the correlator quarantined as unconfirmed could
    // still surface by value, or as a labelled intermediate hop, in the returned
    // chain. See `EntityViewGate`'s own doc for why this must not be optional.
    let include_candidates = super::EntityViewGate::from_params(&params).include_candidates;
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
    let (paths, nodes) =
        match super::offload_store(move || -> Result<PathResult, crate::core::error::Error> {
            let paths = if cross {
                crate::core::path::connect_cross_scan(
                    store.as_ref(),
                    &from,
                    &to,
                    max_paths,
                    include_candidates,
                )
            } else {
                let mut entities = store.entities_for_scan(&id2)?;
                if !include_candidates {
                    entities.retain(|e| !e.has_tag(crate::core::tags::CANDIDATE));
                }
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
        .await
        {
            Ok(v) => v,
            Err(resp) => return resp,
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
