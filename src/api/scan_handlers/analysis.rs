use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use std::sync::Arc;

use super::super::handlers::{bad_request, internal_error, ok_list, ok_paginated_list};
use crate::api::AppState;

pub async fn scan_entities(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    if let Some(resp) = super::scan_missing(&s, &id).await {
        return resp;
    }

    // Parse pagination parameters: offset (default 0) and limit (default 1000, max 10000).
    // Reject invalid values so clients can detect mistakes.
    let offset: usize = if let Some(s) = params.get("offset") {
        match s.parse() {
            Ok(n) => n,
            Err(_) => return bad_request("invalid offset: must be a non-negative integer"),
        }
    } else {
        0
    };
    let limit: usize = if let Some(s) = params.get("limit") {
        match s.parse::<usize>() {
            Ok(0) => return bad_request("invalid limit: must be > 0"),
            Ok(n) => n.min(10000),
            Err(_) => return bad_request("invalid limit: must be a positive integer"),
        }
    } else {
        1000
    };

    let store = std::sync::Arc::clone(&s.store);
    let id2 = id.clone();
    match tokio::task::spawn_blocking(move || store.entities_for_scan(&id2)).await {
        Ok(Ok(mut entities)) => {
            super::apply_candidate_gate(&mut entities, &params);
            let total = entities.len();

            // Paginate: slice the result set to [offset, offset+limit).
            let paginated = entities
                .into_iter()
                .skip(offset)
                .take(limit)
                .collect::<Vec<_>>();

            ok_paginated_list("entities", paginated, total, offset, limit)
        }
        Ok(Err(e)) => internal_error(&e),
        Err(e) => internal_error(&format!("query task failed: {e}")),
    }
}

/// `GET /api/v1/scans/{id}/exposure` — the scan's **Exposure Index**: the
/// calibrated 0–100 headline verdict with its transparent per-signal breakdown
/// (breach exposure, sensitive PII, identifier surface, correlation severity).
///
/// [`crate::core::exposure::assess`] already headlines the CLI dossier and the
/// debug bundle, but had no API consumer at all — so the operator working from
/// the web console (the primary interface on a Termux/Android device, where
/// there is no second terminal to run `hse export` in) never saw the one number
/// that summarises the whole scan. Same assessment, same inputs, same
/// candidate-gating as `/entities`, so the browser and the on-disk artifacts
/// cannot disagree about how exposed a subject is.
pub async fn scan_exposure(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    if let Some(resp) = super::scan_missing(&s, &id).await {
        return resp;
    }
    let store = std::sync::Arc::clone(&s.store);
    let id2 = id.clone();
    // Both reads are blocking SQLite work, so they share one off-reactor hop
    // rather than two — matching how the other analysis handlers stay off the
    // async runtime.
    let loaded = tokio::task::spawn_blocking(move || {
        let entities = store.entities_for_scan(&id2)?;
        let correlations = store.correlations_for_scan(&id2)?;
        Ok::<_, crate::core::error::Error>((entities, correlations))
    })
    .await;
    match loaded {
        Ok(Ok((mut entities, correlations))) => {
            super::apply_candidate_gate(&mut entities, &params);
            let idx = crate::core::exposure::assess(&entities, &correlations);
            // `summary_line` is the exact headline the CLI prints, carried over
            // so the web console can render the identical wording instead of
            // reassembling it (and drifting from it) client-side.
            Json(json!({
                "score": idx.score,
                "band": idx.band.label(),
                "summary": idx.summary_line(),
                "components": idx.components,
            }))
            .into_response()
        }
        Ok(Err(e)) => internal_error(&e),
        Err(e) => internal_error(&format!("query task failed: {e}")),
    }
}

/// `GET /api/v1/scans/{id}/diamond` — the scan's entities rolled up by **Diamond
/// Model vertex** (`victim` / `infrastructure` / `capability`; `adversary` is a
/// relational role the kind classifier never produces — see [`crate::core::diamond`]).
/// Each vertex carries its total and a per-kind sub-breakdown, so the attribution
/// structure — and the deterministic kind→vertex mapping behind it — is visible
/// over a real scan graph. Honours `?include_candidates=…` exactly like
/// `/entities`. This is the live consumer of `core::diamond`'s classifier.
pub async fn scan_diamond(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    if let Some(resp) = super::scan_missing(&s, &id).await {
        return resp;
    }
    let store = std::sync::Arc::clone(&s.store);
    let id2 = id.clone();
    match tokio::task::spawn_blocking(move || store.entities_for_scan(&id2)).await {
        Ok(Ok(mut entities)) => {
            super::apply_candidate_gate(&mut entities, &params);
            let by_vertex = crate::core::diamond::partition_by_vertex(&entities);
            let vertices: Vec<serde_json::Value> = by_vertex
                .iter()
                .map(|(vertex, ents)| {
                    // Per-kind sub-breakdown within the vertex, kind-sorted for a
                    // deterministic response (and so the debatable taxonomy calls
                    // are inspectable against real output, not hidden in a total).
                    let mut kind_counts: std::collections::BTreeMap<String, usize> =
                        std::collections::BTreeMap::new();
                    for e in ents {
                        *kind_counts.entry(e.kind.to_string()).or_insert(0) += 1;
                    }
                    let kinds: Vec<serde_json::Value> = kind_counts
                        .into_iter()
                        .map(|(kind, count)| json!({ "kind": kind, "count": count }))
                        .collect();
                    json!({ "vertex": vertex.as_str(), "count": ents.len(), "kinds": kinds })
                })
                .collect();
            Json(json!({ "vertices": vertices, "total": entities.len() })).into_response()
        }
        Ok(Err(e)) => internal_error(&e),
        Err(e) => internal_error(&format!("query task failed: {e}")),
    }
}

/// `GET /api/v1/scans/{id}/attack` — the scan's MITRE ATT&CK **Reconnaissance**
/// (TA0043) coverage: every technique the scan exercised (resolved from the
/// `attack:<id>` provenance tags the engine stamps on each finding, with the
/// count of entities collected via it) plus the honest uncovered TA0043 gaps,
/// straight from [`crate::core::attack::coverage`]. This is the scan-level rollup
/// of the alignment that until now lived only per-finding in the CLI dossier.
///
/// With `?format=navigator` it returns a MITRE ATT&CK **Navigator layer** JSON
/// instead, so the coverage renders directly in the official ATT&CK Navigator.
/// With `?breakdown=entity_type` it returns a detailed per-technique breakdown
/// by entity kind (e.g., which entity types carry each technique). Honours
/// `?include_candidates=…` exactly like `/entities`.
pub async fn scan_attack(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    if let Some(resp) = super::scan_missing(&s, &id).await {
        return resp;
    }
    let store = std::sync::Arc::clone(&s.store);
    let id2 = id.clone();
    match tokio::task::spawn_blocking(move || store.entities_for_scan(&id2)).await {
        Ok(Ok(mut entities)) => {
            super::apply_candidate_gate(&mut entities, &params);
            // Count entities per exercised Reconnaissance technique from their
            // `attack:<id>` provenance tags — one entity may span several.
            let mut exercised: std::collections::BTreeMap<String, usize> =
                std::collections::BTreeMap::new();
            for e in &entities {
                for tid in e.tags.iter().filter_map(|t| t.strip_prefix("attack:")) {
                    *exercised.entry(tid.to_string()).or_insert(0) += 1;
                }
            }
            // Fold in the techniques the scan's RELATIONS exercised. An
            // officership established from a companies register IS T1591.004
            // (Identify Roles) whether or not any single entity carries the tag,
            // and the technique lives in the edge — so a tag-only rollup
            // under-reported exactly what the graph layer contributes. A store
            // that can't return the relations degrades to the entity-only count
            // rather than failing the whole endpoint: an incomplete coverage
            // figure is still useful, a 500 is not.
            let store = std::sync::Arc::clone(&s.store);
            let id3 = id.clone();
            if let Ok(Ok(relations)) =
                tokio::task::spawn_blocking(move || store.relations_for_scan(&id3)).await
            {
                crate::core::attack::fold_relation_techniques(&mut exercised, &relations);
            }
            let coverage = crate::core::attack::coverage(&exercised);
            if params.get("format").map(String::as_str) == Some("navigator") {
                let layer = crate::core::attack::navigator_layer(&coverage, &id);
                // `?download=1` saves the layer as a file rather than rendering it
                // inline — the entire point of a Navigator layer is to LOAD the
                // `.json` into the MITRE ATT&CK Navigator, so it must be a real
                // download. Routed through the same attachment helper as every
                // other scan export (→ `hse-navigator-<id>.json`).
                if params.get("download").map(String::as_str) == Some("1") {
                    let body =
                        serde_json::to_string_pretty(&layer).unwrap_or_else(|_| layer.to_string());
                    return crate::api::scan_export::download_response(
                        body,
                        "application/json; charset=utf-8",
                        &id,
                        "navigator",
                        "json",
                    );
                }
                return Json(layer).into_response();
            }
            if params.get("breakdown").map(String::as_str) == Some("entity_type") {
                // Breakdown by entity type: for each entity, extract its attack
                // techniques and pair them with the entity's kind for aggregation.
                let entity_techniques: Vec<(String, String)> = entities
                    .iter()
                    .flat_map(|e| {
                        e.tags
                            .iter()
                            .filter_map(|t| t.strip_prefix("attack:").map(String::from))
                            .map(move |tid| (e.kind.to_string(), tid))
                    })
                    .collect();
                let by_type = crate::core::attack::coverage_by_entity_type(&entity_techniques);
                return Json(json!({
                    "tactic_id": coverage.tactic_id,
                    "tactic_name": coverage.tactic_name,
                    "coverage_fraction": coverage.coverage_fraction,
                    "techniques": by_type,
                    "uncovered": coverage.uncovered,
                }))
                .into_response();
            }
            Json(json!(coverage)).into_response()
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
    if let Some(resp) = super::scan_missing(&s, &a).await {
        return resp;
    }
    if let Some(resp) = super::scan_missing(&s, &b).await {
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
    if let Some(resp) = super::scan_missing(&s, &id).await {
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
            // Quarantine by default (opt in with `?include_candidates=1`) so this
            // filtered view can't route around the candidate quarantine the other
            // entity-listing endpoints enforce — see `apply_candidate_gate`.
            super::apply_candidate_gate(&mut entities, &params);
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
    if let Some(resp) = super::scan_missing(&s, &id).await {
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

/// `GET /api/v1/scans/{id}/stealer-rows` — paired stealer-log credential
/// rows (login + password + domain + capture date + source machine, kept
/// together) for the Stealer Logs Viewer. The generic `entities` endpoint
/// above already carries the same credentials, but flattened into
/// independent Email/Username/Credential entities that lose this pairing —
/// this is the dedicated read for getting it back. Empty for a scan with no
/// stealer-log import (never an error).
pub async fn scan_stealer_rows(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Some(resp) = super::scan_missing(&s, &id).await {
        return resp;
    }
    let store = std::sync::Arc::clone(&s.store);
    let id2 = id.clone();
    match tokio::task::spawn_blocking(move || store.stealer_rows_for_scan(&id2)).await {
        Ok(Ok(rows)) => ok_list("rows", rows),
        Ok(Err(e)) => internal_error(&e),
        Err(e) => internal_error(&format!("query task failed: {e}")),
    }
}

pub async fn scan_correlations(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Some(resp) = super::scan_missing(&s, &id).await {
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
    if let Some(resp) = super::scan_missing(&s, &id).await {
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
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    if let Some(resp) = super::scan_missing(&s, &id).await {
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
    // Hide candidate endpoints (as node values AND as dangling edges) unless
    // opted in — the Relations view must not route around the entity quarantine.
    let (ents, rels) = super::confine_graph_to_visible(ents, rels, &params);
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
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    if let Some(resp) = super::scan_missing(&s, &id).await {
        return resp;
    }
    let (entities, relations) = match super::entities_and_relations(&s, &id).await {
        Ok(pair) => pair,
        Err(resp) => return resp,
    };
    // Hide quarantined `candidate` entities (and any edge to them) unless opted
    // in, so the Network graph can't re-leak a non-subject the entity list hides.
    let (entities, relations) = super::confine_graph_to_visible(entities, relations, &params);
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
    if let Some(resp) = super::scan_missing(&s, &id).await {
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

    // Both the entity READ and the coreference COMPUTE run on the blocking pool.
    // `resolve_coreferences` is an all-pairs O(n²) pass and `n` is unbounded: an
    // imported breach/stealer dossier can seat 10^5+ identity entities, so running
    // the compute inline on an async reactor worker would freeze one of Termux's
    // two workers for minutes (health/SSE/cancel all stall) with real OOM risk.
    // `limit` only truncates the OUTPUT, not the pairwise work, so it is no bound.
    let store = std::sync::Arc::clone(&s.store);
    let id2 = id.clone();
    let computed = tokio::task::spawn_blocking(move || {
        store.entities_for_scan(&id2).map(|mut entities| {
            // Co-reference must not cluster quarantined candidates into the
            // subject's identity set (opt in with `?include_candidates=1`).
            // Filtering first also shrinks the O(n²) pairwise work.
            super::apply_candidate_gate(&mut entities, &params);
            crate::core::coref::resolve_coreferences(&entities, min_score, limit)
        })
    })
    .await;
    let corefs = match computed {
        Ok(Ok(corefs)) => corefs,
        Ok(Err(e)) => return internal_error(&e),
        Err(e) => return internal_error(&format!("query task failed: {e}")),
    };
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

/// `GET /api/v1/scans/{id}/cross-scan` — the scan's **cross-scan bridge
/// category**: every entity this scan shares with earlier investigations, ranked
/// by how strongly it is bridged, each carrying the prior scan ids it expands
/// into.
///
/// The engine's finalise passes tag entities that recur across investigations
/// (same-kind recurrence, co-occurrence, a recalled typed relation, or a
/// cross-kind local-part alias); this endpoint assembles those tags into one
/// browsable facet — a history-aware search category rather than a scattering of
/// tags. `prior_scan_ids` is what makes it expandable: each row names the earlier
/// scans to open next.
///
/// Ranked strongest tier first (`relation` > `cooccurrence` > `recurrence` >
/// `kind_alias`), then confidence, then uid, so the order is total and stable.
/// `?min_tier=` filters to a tier and above. `lookups_failed` reports bridges
/// whose prior-scan lookup errored, so an empty `prior_scan_ids` is never
/// silently mistaken for "no history". Honours `?include_candidates=…` exactly
/// like `/entities`.
///
/// # `transitive`
///
/// The response also carries the **second- and third-degree closure**: what an
/// operator would find by opening each `prior_scan_ids` entry by hand and
/// following the identifiers it shares onward. That manual walk is the whole
/// point of the category, so the endpoint does it — bounded to
/// `MAX_TRANSITIVE_SCANS` scan loads, inside the same blocking task, and
/// reporting `scans_over_budget` / `dropped_over_cap` / `lookups_failed` so a
/// short closure is never mistaken for an exhausted one. Pass `?transitive=0`
/// to skip the walk entirely.
///
/// `transitive.links` is kept OUT of `bridges` and shaped differently on
/// purpose: a bridge is a fact about this scan's subject, a transitive link is a
/// lead about somebody a prior scan touched. Each link carries the exact chain
/// (`via_uids` / `via_scan_ids`) that reached it. The walk refuses quarantined
/// candidates unconditionally — `?include_candidates=1` widens the direct
/// bridges only, never the closure, so opting in cannot pull a quarantined value
/// out of a scan other than this one.
pub async fn scan_cross_scan(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    if let Some(resp) = super::scan_missing(&s, &id).await {
        return resp;
    }
    let min_tier = match params.get("min_tier").map(String::as_str) {
        None => crate::core::cross_scan::BridgeTier::KindAlias,
        Some("kind_alias") => crate::core::cross_scan::BridgeTier::KindAlias,
        Some("recurrence") => crate::core::cross_scan::BridgeTier::Recurrence,
        Some("cooccurrence") => crate::core::cross_scan::BridgeTier::Cooccurrence,
        Some("relation") => crate::core::cross_scan::BridgeTier::Relation,
        Some(other) => {
            return bad_request(format!(
                "unknown min_tier `{other}` (expected kind_alias, recurrence, \
                 cooccurrence or relation)"
            ));
        }
    };

    // Default ON: the category exists to be walked, and the walk is bounded.
    // `?transitive=0` is the escape hatch for a caller that only wants degree 1.
    let want_transitive = !matches!(
        params.get("transitive").map(String::as_str),
        Some("0" | "false" | "no")
    );

    let store = std::sync::Arc::clone(&s.store);
    let id2 = id.clone();
    // The candidate quarantine runs BEFORE the category is assembled, so a
    // quarantined entity is absent from the category rather than filtered after
    // its prior-scan history has already been resolved.
    let loaded = tokio::task::spawn_blocking(move || {
        let mut entities = store.entities_for_scan(&id2)?;
        super::apply_candidate_gate(&mut entities, &params);
        let mut category =
            crate::core::cross_scan::category_from_entities(&*store, &id2, &entities);
        if want_transitive {
            // Runs here, on the blocking pool, because it is up to
            // MAX_TRANSITIVE_SCANS synchronous store reads — never on the
            // reactor.
            category.expand_transitively(&*store);
        }
        Ok::<_, crate::core::error::Error>((category, min_tier))
    })
    .await;

    let (category, min_tier) = match loaded {
        Ok(Ok(pair)) => pair,
        Ok(Err(e)) => return internal_error(&e),
        Err(e) => return internal_error(&format!("query task failed: {e}")),
    };

    let bridges: Vec<serde_json::Value> = category
        .at_least(min_tier)
        .into_iter()
        .map(|b| {
            json!({
                "uid": b.uid,
                "value": b.value,
                "kind": b.kind.to_string(),
                "confidence": b.confidence,
                "tier": b.tier.as_str(),
                "hub": b.hub,
                "prior_scan_ids": b.prior_scan_ids,
                "prior_scan_count": b.prior_scan_ids.len(),
            })
        })
        .collect();

    let t = &category.transitive;
    let links: Vec<serde_json::Value> = t
        .links
        .iter()
        .map(|l| {
            json!({
                "uid": l.uid,
                "value": l.value,
                "kind": l.kind.to_string(),
                // Named `confidence_in_source_scan`, not `confidence`: it is the
                // score the scan we reached it from recorded, and calling it
                // `confidence` here would read as a claim about THIS subject.
                "confidence_in_source_scan": l.confidence,
                "degree": l.degree,
                "via_uids": l.via_uids,
                "via_scan_ids": l.via_scan_ids,
                "prior_scan_ids": l.prior_scan_ids,
                "prior_scan_count": l.prior_scan_ids.len(),
                "hub": l.hub,
            })
        })
        .collect();

    Json(json!({
        "scan_id": category.scan_id,
        "bridges": bridges,
        "total": bridges.len(),
        "prior_scans": category.prior_scans(),
        "lookups_failed": category.lookups_failed,
        "transitive": json!({
            "requested": want_transitive,
            "links": links,
            "total": links.len(),
            "max_degree": crate::core::cross_scan::MAX_BRIDGE_DEGREE,
            "scans_visited": t.scans_visited,
            // Everything the walk declined to do, so a caller can tell an
            // exhausted closure from a truncated one.
            "scans_over_budget": t.scans_over_budget,
            "dropped_over_cap": t.dropped_over_cap,
            "hubs_not_traversed": t.hubs_not_traversed,
            "lookups_failed": t.lookups_failed,
            "complete": t.scans_over_budget == 0
                && t.dropped_over_cap == 0
                && t.lookups_failed == 0,
        }),
    }))
    .into_response()
}

/// `GET /api/v1/scans/{id}/snake.svg` — the scan's relation graph as a
/// **concentric-ring ("snake") projection**, rendered as a standalone SVG.
///
/// The full relation graph is a hairball; this picks one entity as the centre and
/// lays the rest out in rings by hop distance, keeping only edges between
/// adjacent rings, so the result reads as nested circles rather than a mesh.
/// Every node in reach stays visible and radial distance carries meaning.
///
/// `?center=<uid>` chooses the centre (default: the scan subject, else the
/// most-connected entity). `?depth=` sets the ring horizon (default 4, capped 8)
/// and `?size=` the pixel square (default 900, clamped 200–4000). Entities
/// reachable but past the horizon are reported in `X-Snake-Beyond-Horizon`
/// rather than silently dropped. `?download=1` returns it as a file. Candidate
/// entities and any edge touching them are hidden unless `?include_candidates=…`,
/// exactly as on `/network`.
pub async fn scan_snake_svg(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    if let Some(resp) = super::scan_missing(&s, &id).await {
        return resp;
    }
    let depth = match params.get("depth").map(|v| v.parse::<usize>()) {
        None => 4,
        Some(Ok(d)) if d >= 1 => d.min(8),
        Some(_) => return bad_request("depth must be a positive integer (capped at 8)"),
    };
    let size = match params.get("size").map(|v| v.parse::<f64>()) {
        None => 900.0,
        Some(Ok(v)) if v.is_finite() => v.clamp(200.0, 4000.0),
        Some(_) => return bad_request("size must be a number between 200 and 4000"),
    };

    let (entities, relations) = match super::entities_and_relations(&s, &id).await {
        Ok(pair) => pair,
        Err(resp) => return resp,
    };
    // Hide quarantined candidates AND every edge touching one, so the drawing
    // re-leaks a non-subject neither as a labelled node nor as a stub edge.
    let (entities, relations) = super::confine_graph_to_visible(entities, relations, &params);

    let center = match params.get("center") {
        Some(uid) => {
            if !entities.iter().any(|e| &e.uid == uid) {
                return bad_request("center uid is not an entity in this scan");
            }
            uid.clone()
        }
        // An empty scan renders an empty graph rather than 404-ing: the resource
        // exists, it just has nothing in it. 404 here means "no such scan".
        None => crate::core::snake_graph::default_center(&entities, &relations).unwrap_or_default(),
    };

    let graph = crate::core::snake_graph::SnakeGraph::build(&center, &entities, &relations, depth);
    let svg = graph.to_svg(size);

    if params.get("download").map(String::as_str) == Some("1") {
        return crate::api::scan_export::download_response(
            svg,
            "image/svg+xml",
            &id,
            "snake",
            "svg",
        );
    }

    // Rendered inline. Node labels are XML-escaped and every colour comes from a
    // fixed table, so the document carries no scriptable input — the CSP and
    // nosniff headers are belt-and-braces in case a future serializer regresses.
    (
        StatusCode::OK,
        [
            (
                axum::http::header::CONTENT_TYPE,
                "image/svg+xml".to_string(),
            ),
            (
                axum::http::header::CONTENT_SECURITY_POLICY,
                "default-src 'none'; style-src 'unsafe-inline'".to_string(),
            ),
            (
                axum::http::header::X_CONTENT_TYPE_OPTIONS,
                "nosniff".to_string(),
            ),
            (
                axum::http::HeaderName::from_static("x-snake-beyond-horizon"),
                graph.nodes_beyond_horizon.to_string(),
            ),
        ],
        svg,
    )
        .into_response()
}
