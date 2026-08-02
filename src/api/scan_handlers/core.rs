use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use std::sync::Arc;
use tracing::info;

use super::super::handlers::{
    bad_request, internal_error, not_found, offload, ok_list, spawn_scan,
};
use crate::api::AppState;
use crate::core::entity::scan_id;
use crate::core::scan::{Scan, ScanRequest, Target};

pub async fn scan_create(
    State(s): State<Arc<AppState>>,
    Json(req): Json<ScanRequest>,
) -> impl IntoResponse {
    let (scan, target) = match super::build_scan_from_request(req) {
        Ok(pair) => pair,
        Err(msg) => return bad_request(msg),
    };

    let store = Arc::clone(&s.store);
    let scan_db = scan.clone();
    if let Err(resp) = offload("db", move || store.upsert_scan(&scan_db)).await {
        return resp;
    }

    spawn_scan(&s, scan.clone(), target);

    info!(scan_id = %scan.id, kind = ?scan.target.kind, "scan queued");
    (
        StatusCode::ACCEPTED,
        Json(json!({ "scan_id": scan.id, "status": "queued" })),
    )
        .into_response()
}

/// `GET /api/v1/scan/profiles` — the named scan-profile catalogue
/// ([`crate::core::profiles::list_profiles`]) as JSON, so the web SPA's New
/// Scan wizard can render a profile picker without hardcoding the name/
/// description list — the single source `resolve_profile`/`--profile`'s own
/// unknown-name error already use, now also reachable from the browser.
/// Previously `profile` was already accepted in `ScanRequest.options` (the
/// CLI's `--profile` and a raw `"profile":"…"` POST both worked), but there
/// was no way for a browser-only operator to discover which names exist —
/// this closes that gap, including for `skiptrace` (the debtor-location
/// profile), which had no web UI path at all before this.
pub async fn scan_profiles() -> impl IntoResponse {
    let profiles: Vec<_> = crate::core::profiles::list_profiles()
        .into_iter()
        .map(|(name, description)| json!({ "name": name, "description": description }))
        .collect();
    Json(json!({ "profiles": profiles }))
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
    // Off-reactor: list_scans(200) deserializes up to 200 rows under the global
    // connection mutex — two concurrent inline calls could block both ~2 workers
    // and starve SSE keep-alives / `/health`. Matches the sibling handlers.
    let store = std::sync::Arc::clone(&s.store);
    match offload("query", move || store.list_scans(200)).await {
        Ok(scans) => ok_list("scans", scans),
        Err(resp) => resp,
    }
}

pub async fn scan_get(State(s): State<Arc<AppState>>, Path(id): Path<String>) -> impl IntoResponse {
    // Off-reactor: synchronous SQLite read under the global connection mutex.
    let store = std::sync::Arc::clone(&s.store);
    match offload("query", move || store.get_scan(&id)).await {
        Ok(Some(scan)) => (
            StatusCode::OK,
            Json(serde_json::to_value(&scan).unwrap_or_else(|e| {
                tracing::warn!(error = %e, "failed to serialize scan to JSON value");
                json!({})
            })),
        )
            .into_response(),
        Ok(None) => not_found(),
        Err(resp) => resp,
    }
}

pub async fn scan_delete(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    // Refuse to delete a scan that's still in-flight: `s.cancellations` holds
    // an entry for exactly as long as the scan's spawned task is alive
    // (installed at `spawn_scan`, removed by `CancelRegistryGuard`'s Drop when
    // the task returns — success, error, or panic). Without this check,
    // deleting a running scan raced the engine's own mid-scan checkpoint
    // writes and finalisation: `delete_scan`'s cascade would remove all rows
    // for the id, but the still-running engine task (nothing here stops it)
    // keeps calling `upsert_entities_batch`/`upsert_scan`/`upsert_correlation`
    // under the SAME scan_id, silently resurrecting a "deleted" scan in a
    // partially/fully rebuilt, potentially internally-inconsistent state —
    // with the client having already been told 200 "deleted". Rejecting up
    // front closes the multi-second window the live engine run occupies;
    // the client's documented recovery is to cancel first, then retry delete.
    if s.cancellations.lock().contains_key(&id) {
        return (
            StatusCode::CONFLICT,
            Json(json!({
                "error": "scan is still running — cancel it first (POST /api/v1/scans/{id}/cancel), then retry delete",
                "scan_id": id,
            })),
        )
            .into_response();
    }
    // `delete_scan` is a multi-table cascade transaction (scans, correlations,
    // observations, events, relations, stealer_rows, entities + FTS sync) under
    // the global connection mutex — the heaviest write in the API. Run it off the
    // reactor so a large-scan delete can't stall unrelated requests.
    let store = Arc::clone(&s.store);
    let id_db = id.clone();
    match offload("db", move || store.delete_scan(&id_db)).await {
        Ok(true) => {
            info!(scan_id = %id, "scan deleted");
            (StatusCode::OK, Json(json!({ "deleted": id }))).into_response()
        }
        Ok(false) => not_found(),
        Err(resp) => resp,
    }
}

pub async fn scan_rerun(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let store = Arc::clone(&s.store);
    let id_db = id.clone();
    let original = match offload("db", move || store.get_scan(&id_db)).await {
        Ok(Some(scan)) => scan,
        Ok(None) => return not_found(),
        Err(resp) => return resp,
    };

    let sid = scan_id(original.target.kind.canonical_str(), &original.target.value);
    let new_scan = Scan::new(sid, original.target.clone()).with_options(original.options.clone());

    let store = Arc::clone(&s.store);
    let scan_db = new_scan.clone();
    if let Err(resp) = offload("db", move || store.upsert_scan(&scan_db)).await {
        return resp;
    }

    spawn_scan(&s, new_scan.clone(), original.target);

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

pub async fn scan_import(
    State(s): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    body: String,
) -> impl IntoResponse {
    use super::super::handlers::forbidden;
    use crate::core::entity::{EntityKind, unix_now};
    use crate::core::scan::{ScanStatus, TargetKind};

    // CSRF guard. The body is `text/plain`, which is a CORS *simple request*
    // (no preflight) — so without this, any website the operator has open could
    // `fetch()` a fabricated dossier into their DB (CORS blocks reading the
    // response, not sending the request). Requiring a custom header makes the
    // request non-simple: a cross-origin caller must now preflight, and the
    // preflight fails because `X-HSE-CSRF` is not in the CORS allow-headers set.
    // The same-origin SPA sends it and never preflights. The header's mere
    // presence is the token (it cannot be set cross-origin without the blocked
    // preflight); the value is irrelevant.
    if !headers.contains_key("x-hse-csrf") {
        return forbidden("missing X-HSE-CSRF header (cross-site request blocked)");
    }

    // Bound the upload so a hostile/huge paste can't exhaust phone memory.
    // NOTE: this in-handler check is the friendly-message backstop; the binding
    // limit is enforced at the route via `DefaultBodyLimit::max(MAX_UPLOAD_BYTES)`
    // (see api::routes), because axum's *default* 2 MB body cap would otherwise
    // reject a 2-16 MB dossier with a bare 413 before this handler ever runs —
    // making this constant a lie. Both read the one constant, so they can't drift.
    if body.trim().is_empty() {
        return bad_request("empty upload");
    }
    if body.len() > super::MAX_UPLOAD_BYTES {
        return bad_request("upload too large (max 16 MB)");
    }
    // Throttle concurrent imports via the shared scan semaphore — mirrors the
    // gate in spawn_scan so an import flood can't crowd out live scans on a
    // 2-core Termux device. Permit is held for the entire handler (parse + DB).
    let sem = Arc::clone(&s.scan_semaphore);
    let Ok(_permit) = sem.acquire().await else {
        return internal_error(&"scan semaphore closed".to_string());
    };
    // `scan_id` is collision-free per call, so the value just needs to be
    // descriptive — the upload size, not a redundant timestamp.
    let sid = scan_id("import-upload", &body.len().to_string());
    // Detect the format from content and parse via the SAME `app::import` path
    // the CLI uses — OathNet JSON/HTML/stealer-TXT and breach/dossier all work.
    let (entities, format) = match crate::app::import::entities_from_upload(&body, &sid).await {
        Ok(pair) => pair,
        Err(e) => return bad_request(format!("could not parse upload: {e}")),
    };
    if entities.is_empty() {
        return bad_request("no verifiable entities were parsed from the upload");
    }
    // Paired stealer-log credential rows (login+password+machine, kept
    // together) for the Stealer Logs Viewer — empty for every non-stealer
    // upload format. See `stealer_rows_from_upload`'s own doc for why this
    // is a second, separate parse rather than a widened `entities_from_upload`.
    let stealer_rows = crate::app::import::stealer_rows_from_upload(&body);

    // A readable scan label: the strongest identity in the file, else a generic.
    let label = entities
        .iter()
        .find(|e| e.kind == EntityKind::Person)
        .or_else(|| entities.iter().find(|e| e.kind == EntityKind::Email))
        .map_or_else(|| "uploaded dossier".to_string(), |e| e.value.clone());

    let entity_count = entities.len();
    let mut scan = Scan::new(sid.clone(), Target::new(TargetKind::FullName, label));
    scan.status = ScanStatus::Complete;
    scan.finished_at = Some(unix_now());
    scan.entity_count = entity_count;

    // Cross-entry enrichment (relation derivation + the correlator) is pairwise
    // WITHIN same-key buckets, so a pathological single-domain dossier — e.g.
    // tens of thousands of `*@one-domain.tld` rows — degrades to a multi-minute
    // O(n²) pass that would lock a 2-core Termux phone (a 16 MB upload can hold
    // ~500k rows). The import's PRIMARY contract — persist every parsed entity —
    // is met unconditionally below; only the best-effort enrichment is bounded,
    // so a huge upload always COMPLETES. A realistic dossier (well under the cap)
    // still gets full relations + correlations; a larger one stores every entity
    // and can be correlated on demand via `/scans/{id}/rerun`.
    const IMPORT_ENRICH_MAX_ENTITIES: usize = 5_000;

    // Persist scan, entities, relations, and correlations on a blocking thread
    // so SQLite commits don't stall the 2-worker async reactor.
    let store = Arc::clone(&s.store);
    let sid2 = sid.clone();
    // The third element is `false` when enrichment was skipped for size — the
    // caller must be able to tell that apart from a genuinely relation-free
    // dossier, both of which otherwise report `relation_count: 0`.
    let (relation_count, correlation_count, enriched) =
        match offload("import", move || -> crate::core::error::Result<_> {
            store.upsert_scan(&scan)?;
            store.upsert_entities_batch(&entities)?;
            // Best-effort: a stealer-row persistence hiccup must not fail an
            // otherwise-successful import — the entity graph above already
            // carries the same credentials, just unpaired.
            let _ = store.insert_stealer_rows_batch(&sid2, &stealer_rows);
            // Device-safety bound: skip the O(n²) enrichment on a pathologically
            // large import (entities are already persisted above; nothing lost).
            if entities.len() > IMPORT_ENRICH_MAX_ENTITIES {
                return Ok((0usize, 0usize, false));
            }
            let mut relations = 0usize;
            // Wall-clock bound on the super-linear derivation chain, matching a
            // live scan (the entity-count guard above already skips the
            // pathological case; this bounds the rest).
            let derive_deadline =
                Some(std::time::Instant::now() + crate::core::relation::DERIVE_BUDGET);
            for r in &crate::core::relation::derive_all_within(&entities, &sid2, derive_deadline) {
                if store.upsert_relation(r).is_ok() {
                    relations += 1;
                }
            }
            // Run the correlator so cross-entry handle-reuse / breach clusters
            // surface exactly as they would for a live scan. Best-effort: a
            // correlator hiccup must not fail an otherwise-successful import.
            let correlator = crate::core::correlator::Correlator::new(Arc::clone(&store));
            let mut correlations = 0usize;
            if let Ok(hits) = correlator.run(&sid2) {
                for c in &hits {
                    if store.upsert_correlation(c).is_ok() {
                        correlations += 1;
                    }
                }
            }
            Ok((relations, correlations, true))
        })
        .await
        {
            Ok(counts) => counts,
            Err(resp) => return resp,
        };

    info!(scan_id = %sid, format, entities = entity_count, "file imported via web");
    (
        StatusCode::OK,
        Json(json!({
            "scan_id": sid,
            "format": format,
            "entity_count": entity_count,
            "relation_count": relation_count,
            "correlation_count": correlation_count,
            // `true` only when the upload exceeded `IMPORT_ENRICH_MAX_ENTITIES` —
            // disambiguates a size-skipped enrichment pass from a dossier that
            // genuinely yielded zero relations/correlations. Every entity is
            // still persisted either way; the scan can be enriched on demand
            // via `/scans/{id}/rerun`.
            "enrichment_skipped": !enriched,
            "status": "complete",
        })),
    )
        .into_response()
}

pub async fn scan_batch(
    State(s): State<Arc<AppState>>,
    Json(requests): Json<Vec<ScanRequest>>,
) -> impl IntoResponse {
    if requests.is_empty() {
        return bad_request("empty batch");
    }
    if requests.len() > 50 {
        return bad_request("batch too large (max 50)");
    }

    let mut scan_ids = Vec::with_capacity(requests.len());
    for req in requests {
        let (scan, target) = match super::build_scan_from_request(req) {
            Ok(pair) => pair,
            Err(msg) => {
                scan_ids.push(json!({ "error": msg }));
                continue;
            }
        };
        let store = Arc::clone(&s.store);
        let scan_db = scan.clone();
        match tokio::task::spawn_blocking(move || store.upsert_scan(&scan_db)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                scan_ids.push(json!({ "error": e.to_string() }));
                continue;
            }
            Err(e) => {
                scan_ids.push(json!({ "error": format!("db task failed: {e}") }));
                continue;
            }
        }
        let sid = scan.id.clone();
        spawn_scan(&s, scan, target);
        scan_ids.push(json!({ "scan_id": sid, "status": "queued" }));
    }

    (
        StatusCode::ACCEPTED,
        Json(json!({ "scans": scan_ids, "count": scan_ids.len() })),
    )
        .into_response()
}

/// `GET /api/v1/plan?value=<seed>` — forward-only scan-plan PREVIEW.
pub async fn plan_preview(
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    use crate::core::module::Module;

    let value = params.get("value").map_or("", |v| v.trim());
    if value.is_empty() {
        return bad_request("value is empty");
    }
    let target = Target::detect(value);

    let mut accepting: Vec<std::sync::Arc<dyn Module>> = crate::modules::registry()
        .into_iter()
        .filter(|m| m.accepts(&target))
        .collect();

    // Convex query value per module: the return-per-unit-budget of firing it as
    // one query (cheap keyless identity-/key-unlocking modules high, expensive
    // terminal providers low). This is the order a default scan actually
    // dispatches in (`convex_budget` is on by default), so the preview reflects
    // where the phone's budget is spent FIRST — highest query value leading, ties
    // broken by static priority then name, exactly as the engine's convex
    // dispatch index orders them.
    let qv = |m: &std::sync::Arc<dyn Module>| -> f64 {
        crate::core::convex::query_value(
            m.cost(),
            m.is_passive(),
            crate::core::convex::module_cascade(m.produces(), m.category()),
        )
    };
    accepting.sort_by(|a, b| {
        qv(b)
            .total_cmp(&qv(a))
            .then_with(|| b.priority().cmp(&a.priority()))
            .then_with(|| a.name().cmp(b.name()))
    });

    let mut by_category: std::collections::BTreeMap<&'static str, usize> =
        std::collections::BTreeMap::new();
    for m in &accepting {
        *by_category.entry(m.category().as_str()).or_insert(0) += 1;
    }

    // Coarse optionality label from the module's cascade, for the UI badge.
    let optionality = |cascade: f64| -> &'static str {
        if cascade >= 0.70 {
            "high"
        } else if cascade >= 0.40 {
            "moderate"
        } else {
            "terminal"
        }
    };

    let modules: Vec<serde_json::Value> = accepting
        .iter()
        .map(|m| {
            let cascade = crate::core::convex::module_cascade(m.produces(), m.category());
            json!({
                "name": m.name(),
                "category": m.category().as_str(),
                "priority": m.priority(),
                "cost": m.cost().as_str(),
                "passive": m.is_passive(),
                // Round to 3 dp so the wire value is stable and compact.
                "query_value": (qv(m) * 1000.0).round() / 1000.0,
                "optionality": optionality(cascade),
                "description": m.description(),
            })
        })
        .collect();
    let categories: Vec<serde_json::Value> = by_category
        .into_iter()
        .map(|(c, n)| json!({ "category": c, "count": n }))
        .collect();

    (
        StatusCode::OK,
        Json(json!({
            "value": value,
            "kind": target.kind.canonical_str(),
            "module_count": modules.len(),
            // The preview is ordered by convex query value — the order a default
            // (convex_budget-on) scan dispatches in, so a budget-truncated run
            // keeps the highest-return queries.
            "order": "convex_query_value",
            "categories": categories,
            "modules": modules,
        })),
    )
        .into_response()
}

pub async fn scan_events_history(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Some(resp) = super::scan_missing(&s, &id).await {
        return resp;
    }
    // Off-reactor: the per-scan event log can be large and the read is synchronous
    // SQLite (matches the sibling entity/report handlers' spawn_blocking).
    let store = std::sync::Arc::clone(&s.store);
    let id2 = id.clone();
    match offload("query", move || store.events_for_scan(&id2)).await {
        Ok(events) => ok_list("events", events),
        Err(resp) => resp,
    }
}
