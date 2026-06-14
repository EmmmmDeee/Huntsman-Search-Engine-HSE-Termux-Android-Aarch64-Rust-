use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use std::sync::Arc;
use tracing::info;

use super::handlers::{
    bad_request, internal_error, not_found, ok_list, spawn_scan, validated_target,
};
use crate::api::AppState;
use crate::core::entity::scan_id;
use crate::core::scan::{Scan, ScanRequest, Target};

/// Maximum size of an uploaded import body (breach dossier / OathNet export).
/// 16 MB comfortably fits a large multi-entry compilation while bounding peak
/// memory on a low-RAM Termux device. Single source of truth: the `/scans/import`
/// route installs this as a `DefaultBodyLimit` (overriding axum's 2 MB default,
/// which would otherwise 413 a valid large dossier), and `scan_import` re-checks
/// it for a friendly error message. Keep the two in sync via this constant.
pub const MAX_UPLOAD_BYTES: usize = 16 * 1024 * 1024;

/// Build a validated, profile-resolved `Scan` (+ its `Target`) from a request,
/// or a client-facing error message. Shared by `scan_create` (single) and
/// `scan_batch` (per-item) so the validation, deterministic scan-id derivation,
/// and `profile`→options resolution can't drift between the two paths. Pure:
/// no store or engine access, so it's unit-testable on its own.
fn build_scan_from_request(req: ScanRequest) -> Result<(Scan, Target), String> {
    // Resolve the kind once: explicit if given, else auto-detected from the
    // value (the unified-scan path). Both `validated_target` and the
    // deterministic scan-id then key off the same resolved kind.
    let kind = req.resolved_kind();
    let target = validated_target(kind, req.value.clone())?;
    let sid = scan_id(kind.canonical_str(), &req.value);
    let mut opts = req.options;
    if let Some(ref profile_name) = opts.profile
        && let Some(profile_opts) = crate::core::profiles::resolve_profile(profile_name)
    {
        opts = profile_opts;
    }
    let scan = Scan::new(sid, target.clone()).with_options(opts.clamp_depth());
    Ok((scan, target))
}

pub async fn scan_create(
    State(s): State<Arc<AppState>>,
    Json(req): Json<ScanRequest>,
) -> impl IntoResponse {
    let (scan, target) = match build_scan_from_request(req) {
        Ok(pair) => pair,
        Err(msg) => return bad_request(msg),
    };

    if let Err(e) = s.store.upsert_scan(&scan) {
        return internal_error(&e);
    }

    let sid = scan.id.clone();
    let kind = scan.target.kind;
    spawn_scan(&s, scan, target);

    info!(scan_id = %sid, kind = ?kind, "scan queued");
    (
        StatusCode::ACCEPTED,
        Json(json!({ "scan_id": sid, "status": "queued" })),
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
        let (scan, target) = match build_scan_from_request(req) {
            Ok(pair) => pair,
            Err(msg) => {
                scan_ids.push(json!({ "error": msg }));
                continue;
            }
        };
        if let Err(e) = s.store.upsert_scan(&scan) {
            scan_ids.push(json!({ "error": e.to_string() }));
            continue;
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

/// `POST /api/v1/scans/import` — ingest an uploaded breach/dossier compilation
/// (the `Entry #N:` + `USERNAMES:`/`EMAILS:`/`PASSWORDS:` text format) straight
/// from the Termux/Chrome UI, with no CLI round-trip. The file is POSTed as a raw
/// text body (axum's `multipart` feature is intentionally off to keep the binary
/// lean), parsed by the SAME `cli::import` path the CLI uses, then persisted as a
/// completed scan so it appears in the scan list and every view/export
/// (entities, dossier, debug bundle) works on it identically to a live scan.
pub async fn scan_import(State(s): State<Arc<AppState>>, body: String) -> impl IntoResponse {
    use crate::core::entity::{EntityKind, unix_now};
    use crate::core::scan::{ScanStatus, TargetKind};

    // Bound the upload so a hostile/huge paste can't exhaust phone memory.
    // NOTE: this in-handler check is the friendly-message backstop; the binding
    // limit is enforced at the route via `DefaultBodyLimit::max(MAX_UPLOAD_BYTES)`
    // (see api::routes), because axum's *default* 2 MB body cap would otherwise
    // reject a 2-16 MB dossier with a bare 413 before this handler ever runs —
    // making this constant a lie. Both read the one constant, so they can't drift.
    if body.trim().is_empty() {
        return bad_request("empty upload");
    }
    if body.len() > MAX_UPLOAD_BYTES {
        return bad_request("upload too large (max 16 MB)");
    }
    // `scan_id` is collision-free per call, so the value just needs to be
    // descriptive — the upload size, not a redundant timestamp.
    let sid = scan_id("import-upload", &body.len().to_string());
    // Detect the format from content and parse via the SAME `cli::import` path
    // the CLI uses — OathNet JSON/HTML/stealer-TXT and breach/dossier all work.
    let (entities, format) = match crate::cli::import::entities_from_upload(&body, &sid).await {
        Ok(pair) => pair,
        Err(e) => return bad_request(format!("could not parse upload: {e}")),
    };
    if entities.is_empty() {
        return bad_request("no verifiable entities were parsed from the upload");
    }

    // A readable scan label: the strongest identity in the file, else a generic.
    let label = entities
        .iter()
        .find(|e| e.kind == EntityKind::Person)
        .or_else(|| entities.iter().find(|e| e.kind == EntityKind::Email))
        .map(|e| e.value.clone())
        .unwrap_or_else(|| "uploaded dossier".to_string());

    let mut scan = Scan::new(sid.clone(), Target::new(TargetKind::FullName, label));
    scan.status = ScanStatus::Complete;
    scan.finished_at = Some(unix_now());
    scan.entity_count = entities.len();
    if let Err(e) = s.store.upsert_scan(&scan) {
        return internal_error(&e);
    }
    if let Err(e) = s.store.upsert_entities_batch(&entities) {
        return internal_error(&e);
    }
    // Derive and persist the deterministic entity relations (structural/geo/
    // DNS/WHOIS/name-lineage) so the imported scan carries the same graph a live
    // scan would — the dossier/graph/debug views and GEXF export all read these
    // edges. Best-effort: an import whose entities persisted must not fail on a
    // relation hiccup. Mirrors the engine's finalise-time `persist_relations`.
    let mut relation_count = 0usize;
    for r in &crate::core::relation::derive_all(&entities, &sid) {
        if s.store.upsert_relation(r).is_ok() {
            relation_count += 1;
        }
    }
    // Run the correlator so cross-entry handle-reuse / breach clusters surface,
    // exactly as they would for a live scan. Best-effort — a correlator hiccup
    // must not fail an otherwise-successful import.
    let mut correlation_count = 0usize;
    let correlator = crate::core::correlator::Correlator::new(Arc::clone(&s.store));
    if let Ok(hits) = correlator.run(&sid) {
        for c in &hits {
            if s.store.upsert_correlation(c).is_ok() {
                correlation_count += 1;
            }
        }
    }

    info!(scan_id = %sid, format, entities = entities.len(), "file imported via web");
    (
        StatusCode::OK,
        Json(json!({
            "scan_id": sid,
            "format": format,
            "entity_count": entities.len(),
            "relation_count": relation_count,
            "correlation_count": correlation_count,
            "status": "complete",
        })),
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

/// `Some(404)` when no scan with `id` exists (or `Some(500)` on a store error),
/// else `None`. Sub-resource handlers call this first so an unknown scan yields
/// 404 — consistent with `GET /scans/{id}` and `report.json` — rather than a
/// misleading empty `200` that a client cannot distinguish from a real scan
/// that simply found nothing.
pub(crate) fn scan_missing(s: &AppState, id: &str) -> Option<axum::response::Response> {
    match s.store.get_scan(id) {
        Ok(Some(_)) => None,
        Ok(None) => Some(not_found()),
        Err(e) => Some(internal_error(&e)),
    }
}

/// True if the request opts into the quarantined `candidate` entities via
/// `?include_candidates=1|true|yes|on`. Default (absent/anything else) is to
/// hide them — the clean, confirmed-only default view.
pub(crate) fn wants_candidates(params: &std::collections::HashMap<String, String>) -> bool {
    params
        .get("include_candidates")
        .is_some_and(|v| matches!(v.as_str(), "1" | "true" | "yes" | "on"))
}

pub async fn scan_entities(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    if let Some(resp) = scan_missing(&s, &id) {
        return resp;
    }
    match s.store.entities_for_scan(&id) {
        Ok(mut entities) => {
            if !wants_candidates(&params) {
                entities.retain(|e| !e.has_tag(crate::core::tags::CANDIDATE));
            }
            ok_list("entities", entities)
        }
        Err(e) => internal_error(&e),
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
    if let Some(resp) = scan_missing(&s, &a) {
        return resp;
    }
    if let Some(resp) = scan_missing(&s, &b) {
        return resp;
    }
    let baseline = match s.store.entities_for_scan(&a) {
        Ok(e) => e,
        Err(e) => return internal_error(&e),
    };
    let later = match s.store.entities_for_scan(&b) {
        Ok(e) => e,
        Err(e) => return internal_error(&e),
    };
    let diff = crate::core::diff::diff_entities(&baseline, &later);
    (StatusCode::OK, Json(diff)).into_response()
}

pub async fn scan_entities_filter(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    if let Some(resp) = scan_missing(&s, &id) {
        return resp;
    }
    if params.get("kind").is_some_and(|k| k.len() > 32) {
        return bad_request("kind too long (max 32 chars)");
    }
    if params.get("q").is_some_and(|v| v.len() > 256) {
        return bad_request("query too long (max 256 chars)");
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
    if let Some(resp) = scan_missing(&s, &id) {
        return resp;
    }
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
    if let Some(resp) = scan_missing(&s, &id) {
        return resp;
    }
    match s.store.correlations_for_scan(&id) {
        Ok(corr) => ok_list("correlations", corr),
        Err(e) => internal_error(&e),
    }
}

/// `GET /api/v1/scans/{id}/audit` — the scored self-audit of a stored scan
/// (noise, infrastructure pollution, fragment values, missed PII, source
/// health) with actionable recommendations. Same engine and JSON shape as
/// `hse audit`, folding the latest cached search-engine liveness sweep in as the
/// source-health signal so the web panel and CLI agree.
pub async fn scan_audit(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Some(resp) = scan_missing(&s, &id) {
        return resp;
    }
    let entities = match s.store.entities_for_scan(&id) {
        Ok(e) => e,
        Err(e) => return internal_error(&e),
    };
    let normalised: Vec<crate::audit::AuditEntity> = entities
        .iter()
        .map(crate::audit::AuditEntity::from_entity)
        .collect();
    // Source-health from the live engine sweep, enriched with this scan's own
    // recorded expansion decisions (stop reasons + per-reason exclusion counts)
    // so the web audit surfaces the recursion ledger — why pivots were pruned —
    // without needing a debug-log upload.
    let mut signals = engine_health_signals();
    if let Ok(events) = s.store.events_for_scan(&id) {
        crate::audit::fold_events(&mut signals, &events);
    }
    let report = crate::audit::audit(&normalised, signals);
    Json(report.to_json()).into_response()
}

/// Translate the latest cached search-engine liveness sweep into auditor
/// source-health signals (parser-defect vs down vs blocked), so the web audit
/// surfaces broken providers without needing a debug-log upload.
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

/// Typed entity-relation edges for a scan (the attribution graph). Powers the
/// SPA force-graph's relation layer.
pub async fn scan_relations(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Some(resp) = scan_missing(&s, &id) {
        return resp;
    }
    // Resolve both endpoints of every edge to their display value + kind so the
    // SPA never has to render a raw entity UID. The Relations view previously
    // showed opaque SHA hashes (e.g. `91cceeaccaaa11e9…`) for any endpoint whose
    // entity hadn't been paged into the browser's entity map — on a 397-entity
    // scan that was most of the graph. Joining here makes every edge verifiable
    // on its own: "jordanavery@gmail.com (email) → gmail.com (domain)".
    let rels = match s.store.relations_for_scan(&id) {
        Ok(rels) => rels,
        Err(e) => return internal_error(&e),
    };
    let by_uid: std::collections::HashMap<String, (String, String)> =
        match s.store.entities_for_scan(&id) {
            Ok(ents) => ents
                .into_iter()
                .map(|e| (e.uid, (e.value, e.kind.to_string())))
                .collect(),
            Err(e) => return internal_error(&e),
        };
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
    let new_scan = Scan::new(sid, original.target.clone()).with_options(original.options.clone());

    if let Err(e) = s.store.upsert_scan(&new_scan) {
        return internal_error(&e);
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

pub async fn scan_events_history(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Some(resp) = scan_missing(&s, &id) {
        return resp;
    }
    match s.store.events_for_scan(&id) {
        Ok(events) => ok_list("events", events),
        Err(e) => internal_error(&e),
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
