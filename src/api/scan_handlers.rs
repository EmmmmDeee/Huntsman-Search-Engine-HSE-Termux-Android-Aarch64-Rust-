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
fn scan_missing(s: &AppState, id: &str) -> Option<axum::response::Response> {
    match s.store.get_scan(id) {
        Ok(Some(_)) => None,
        Ok(None) => Some(not_found()),
        Err(e) => Some(internal_error(&e)),
    }
}

/// True if the request opts into the quarantined `candidate` entities via
/// `?include_candidates=1|true|yes|on`. Default (absent/anything else) is to
/// hide them — the clean, confirmed-only default view.
fn wants_candidates(params: &std::collections::HashMap<String, String>) -> bool {
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

pub async fn scan_entities_csv(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Some(resp) = scan_missing(&s, &id) {
        return resp;
    }
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
    let mut body = String::with_capacity(192 + entities.len() * 192);
    // `evidence_urls` + `evidence` make every row self-verifiable: the operator
    // can follow the source links and read each module's finding without
    // reconstructing anything from the value alone.
    body.push_str("kind,value,raw_value,confidence,c_effective,corroboration,classification,observed_at,sources,evidence_urls,evidence,tags\n");
    for e in entities {
        let eff = e.c_effective();
        let tier = e.classify().to_string();
        let mut sources: Vec<&str> = e.evidence_sources().into_iter().collect();
        sources.sort_unstable();
        let sources = sources.join("|");
        let tags = e.tags.join("|");

        // Distinct full URLs across all evidence (the verifiable links), and a
        // per-source summary trail of what each module actually found.
        let mut urls: Vec<&str> = Vec::new();
        for ev in &e.evidence {
            for key in ["url", "source_url", "profile_url", "permalink"] {
                if let Some(u) = ev.attributes.get(key)
                    && !u.is_empty()
                    && !urls.contains(&u.as_str())
                {
                    urls.push(u.as_str());
                }
            }
        }
        let evidence_urls = urls.join(" | ");
        let evidence = e
            .evidence
            .iter()
            .map(|ev| format!("[{}] {}", ev.source, ev.summary))
            .collect::<Vec<_>>()
            .join(" || ");

        let _ = writeln!(
            body,
            "{},{},{},{:.3},{:.3},{},{},{},{},{},{},{}",
            csv_escape(&e.kind.to_string()),
            csv_escape(&e.value),
            csv_escape(&e.raw_value),
            e.confidence,
            eff,
            e.corroboration,
            tier,
            e.observed_at,
            csv_escape(&sources),
            csv_escape(&evidence_urls),
            csv_escape(&evidence),
            csv_escape(&tags),
        );
    }
    body
}

pub async fn scan_report_json(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    match build_scan_report(&*s.store, &id, wants_candidates(&params)) {
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
/// Parse the structured geo-fix fields that AU-059 embeds in its description.
///
/// AU-059 description format:
/// `"N AU coordinate(s) from M orthogonal source class(es) [C1, C2] converge on
///  LAT,LON (geohash=GH, state=STATE); synergy confidence SC — MITRE T1591.001"`
///
/// Returns a JSON object `{lat, lon, geohash, state, synergy_confidence,
/// source_count, class_count, severity}` from the highest-rank AU-059 firing,
/// or `serde_json::Value::Null` when no AU-059 correlation exists for the scan.
pub(crate) fn extract_au_location_fix(
    correlations: &[crate::core::correlator::Correlation],
) -> serde_json::Value {
    let best = correlations
        .iter()
        .filter(|c| c.rule_id == "AU-059")
        .max_by(|a, b| {
            a.rank
                .partial_cmp(&b.rank)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
    let Some(c) = best else {
        return serde_json::Value::Null;
    };
    let desc = &c.description;

    // source_count: first token before " AU coordinate"
    let source_count: Option<u32> = desc
        .split_once(" AU coordinate")
        .and_then(|(n, _)| n.trim().parse().ok());

    // class_count: token before " orthogonal source class"
    let class_count: Option<u32> = desc
        .split_once(" orthogonal source class")
        .and_then(|(pre, _)| pre.rsplit_once(' ').map(|(_, n)| n))
        .and_then(|n| n.parse().ok());

    // lat,lon: after "converge on "
    let (lat, lon) = desc
        .split_once("converge on ")
        .and_then(|(_, rest)| rest.split_once(' '))
        .and_then(|(coord, _)| coord.split_once(','))
        .and_then(|(la, lo)| {
            let la: f64 = la.parse().ok()?;
            let lo: f64 = lo.parse().ok()?;
            Some((la, lo))
        })
        .unwrap_or((0.0, 0.0));

    // geohash: between "geohash=" and ","
    let geohash = desc
        .split_once("geohash=")
        .and_then(|(_, rest)| rest.split_once(','))
        .map(|(gh, _)| gh.to_string())
        .unwrap_or_default();

    // state: between "state=" and ")"
    let state = desc
        .split_once("state=")
        .and_then(|(_, rest)| rest.split_once(')'))
        .map(|(st, _)| st.to_string())
        .unwrap_or_default();

    // synergy_confidence: after "synergy confidence " and before " —"
    let synergy_confidence: f64 = desc
        .split_once("synergy confidence ")
        .and_then(|(_, rest)| rest.split_once(" —"))
        .and_then(|(sc, _)| sc.parse().ok())
        .unwrap_or(0.0);

    json!({
        "lat": lat,
        "lon": lon,
        "geohash": geohash,
        "state": state,
        "synergy_confidence": synergy_confidence,
        "severity": c.severity.as_canonical(),
        "rank": c.rank,
        "source_count": source_count,
        "class_count": class_count,
        "rule_id": "AU-059",
    })
}

pub(crate) fn build_scan_report(
    store: &dyn crate::core::port::StoragePort,
    scan_id: &str,
    include_candidates: bool,
) -> crate::core::error::Result<Option<serde_json::Value>> {
    let Some(scan) = store.get_scan(scan_id)? else {
        return Ok(None);
    };
    let mut entities = store.entities_for_scan(scan_id)?;
    // Quarantine in the dossier too: speculative `candidate` entities (the
    // non-target breach-dump rows) are hidden by default so the report reads
    // as the target's confirmed footprint. `include_candidates=true` returns
    // the full set for investigation.
    if !include_candidates {
        entities.retain(|e| !e.has_tag(crate::core::tags::CANDIDATE));
    }
    let correlations = store.correlations_for_scan(scan_id)?;
    let best_location = extract_au_location_fix(&correlations);
    Ok(Some(json!({
        "scan": scan,
        "entities": entities,
        "entity_count": entities.len(),
        "correlations": correlations,
        "correlation_count": correlations.len(),
        // Best AU geolocation fix synthesised by AU-059 cross-seed geo synergy.
        // `null` when no AU-059 fired; present with full structured fields when
        // ≥2 orthogonal AU source classes converged on a location.
        "best_location": best_location,
        // DETERMINISM: `exported_at` is the SOLE intentional source of
        // non-determinism in any export. It is meaningful here — report.json is a
        // point-in-time snapshot whose "when was this pulled" is part of its
        // value — and is the documented exception to byte-reproducibility. The
        // diffable/reproducible artifacts are the debug bundle (no timestamp,
        // proven byte-stable) and entity-level `scan_diff`. The
        // `export_formats_determinism_audit` test pins that NO OTHER field of the
        // report varies across renders, so any newly-introduced non-determinism
        // fails CI rather than silently breaking reproducibility.
        "exported_at": crate::core::entity::unix_now(),
    })))
}

pub async fn scan_export_gexf(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Some(resp) = scan_missing(&s, &id) {
        return resp;
    }
    let entities = match s.store.entities_for_scan(&id) {
        Ok(entities) => entities,
        Err(e) => return internal_error(&e),
    };
    let relations = match s.store.relations_for_scan(&id) {
        Ok(relations) => relations,
        Err(e) => return internal_error(&e),
    };
    let body = crate::core::gexf::entities_to_gexf(&entities, &relations, &id);
    download_response(body, "application/xml; charset=utf-8", &id, "gexf")
}

/// `GET /api/v1/scans/{id}/debug.txt` — the one-click debug bundle: the entire
/// scan state (every entity + evidence, relations, correlations, the complete
/// event sequence, and the scored self-audit with every weakness) in one
/// downloadable text file. The web "Debug bundle" button and the CLI
/// `hse export {id} --format debug` produce the same artifact.
pub async fn scan_debug_bundle(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Some(resp) = scan_missing(&s, &id) {
        return resp;
    }
    match crate::cli::export::render_debug_bundle(s.store.as_ref(), &id) {
        Ok(body) => download_response(body, "text/plain; charset=utf-8", &id, "debug.txt"),
        Err(e) => internal_error(&e),
    }
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
    // Formula-injection neutralization: a leading =/+/-/@/CR/TAB causes
    // Excel and LibreOffice to interpret the cell as a formula on file
    // open — a hostile API response with `first_name = "=cmd|'/c calc'!A1"`
    // could otherwise turn an exported scan CSV into RCE on the operator's
    // workstation. Prepend a single quote to defang per OWASP guidance.
    let needs_formula_guard = s
        .as_bytes()
        .first()
        .is_some_and(|b| matches!(*b, b'=' | b'+' | b'-' | b'@' | b'\t' | b'\r'));
    let body = if needs_formula_guard {
        format!("'{s}")
    } else {
        s.to_string()
    };
    if body.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", body.replace('"', "\"\""))
    } else {
        body
    }
}

// ─── Health / Version / Stats / Modules ────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::scan::TargetKind;

    #[test]
    fn fold_expansion_signals_counts_exclusions_and_collects_stops() {
        use crate::core::event::{Event, EventKind};
        let evs = vec![
            Event::new(
                "s",
                EventKind::EntityExcluded {
                    kind: "username".into(),
                    value: "arizonambb".into(),
                    reason: "identity_mismatch".into(),
                },
            ),
            Event::new(
                "s",
                EventKind::EntityExcluded {
                    kind: "username".into(),
                    value: "centenario".into(),
                    reason: "identity_mismatch".into(),
                },
            ),
            Event::new(
                "s",
                EventKind::EntityExcluded {
                    kind: "credential".into(),
                    value: "x".into(),
                    reason: "non_pivotable_kind".into(),
                },
            ),
            Event::new(
                "s",
                EventKind::ExpansionStop {
                    reason: "depth exhausted".into(),
                },
            ),
            // An unrelated event must be ignored.
            Event::new(
                "s",
                EventKind::ModuleStart {
                    module: "dns".into(),
                },
            ),
        ];
        let mut sig = crate::audit::LogSignals::default();
        crate::audit::fold_events(&mut sig, &evs);
        assert_eq!(sig.excluded_reasons.get("identity_mismatch"), Some(&2));
        assert_eq!(sig.excluded_reasons.get("non_pivotable_kind"), Some(&1));
        assert_eq!(sig.expansion_stops, vec!["depth exhausted".to_string()]);
    }

    #[test]
    fn wants_candidates_parses_truthy_values_only() {
        use std::collections::HashMap;
        let mut p: HashMap<String, String> = HashMap::new();
        assert!(!wants_candidates(&p), "absent ⇒ hide candidates");
        for v in ["1", "true", "yes", "on"] {
            p.insert("include_candidates".into(), v.into());
            assert!(wants_candidates(&p), "{v} should opt in");
        }
        p.insert("include_candidates".into(), "0".into());
        assert!(!wants_candidates(&p));
    }

    #[test]
    fn report_hides_candidates_by_default_and_includes_on_request() {
        use crate::core::entity::{Entity, EntityKind};
        use crate::core::scan::{Scan, Target};
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("report.db");
        let store = crate::storage::Store::open(db.to_str().unwrap()).unwrap();
        let sid = "rep-scan";
        store
            .upsert_scan(&Scan::new(
                sid,
                Target::new(TargetKind::FullName, "Jordan Avery"),
            ))
            .unwrap();
        store
            .upsert_entity(&Entity::new(EntityKind::Email, "me@real.com", 0.85, sid))
            .unwrap();
        let mut candidate = Entity::new(EntityKind::Email, "stranger@bank.com", 0.25, sid);
        candidate.tag(crate::core::tags::CANDIDATE);
        store.upsert_entity(&candidate).unwrap();

        let port = &store as &dyn crate::core::port::StoragePort;
        let default = build_scan_report(port, sid, false).unwrap().unwrap();
        assert_eq!(
            default["entity_count"].as_u64(),
            Some(1),
            "default report hides the candidate"
        );
        let full = build_scan_report(port, sid, true).unwrap().unwrap();
        assert_eq!(
            full["entity_count"].as_u64(),
            Some(2),
            "include_candidates returns the full set"
        );
    }

    #[test]
    fn build_scan_from_request_valid_is_deterministic() {
        let req = ScanRequest {
            kind: Some(TargetKind::Domain),
            value: "cloudflare.com".to_string(),
            options: Default::default(),
        };
        let (scan, target) = build_scan_from_request(req).expect("valid domain should build");
        assert_eq!(target.value, "cloudflare.com");
        assert_eq!(target.kind, TargetKind::Domain);
        // `scan_id` mixes `unix_now()` (so re-scans of one target get a fresh
        // id), so assert the id's SHAPE — not equality to a recomputed
        // `scan_id(...)`, which flakes across a one-second boundary.
        assert_eq!(scan.id.len(), 64);
        assert!(scan.id.chars().all(|c| c.is_ascii_hexdigit()));
        // The deterministic part — the resolved target — is identical across
        // two builds of the same request.
        let req2 = ScanRequest {
            kind: Some(TargetKind::Domain),
            value: "cloudflare.com".to_string(),
            options: Default::default(),
        };
        let (_, target2) = build_scan_from_request(req2).unwrap();
        assert_eq!(target.kind, target2.kind);
        assert_eq!(target.value, target2.value);
    }

    #[test]
    fn build_scan_from_request_auto_detects_omitted_kind() {
        // Unified scan: no kind supplied → detected from the value, and the
        // scan id keys off the *detected* kind (here, email).
        let req = ScanRequest {
            kind: None,
            value: "alice@proton.me".to_string(),
            options: Default::default(),
        };
        let (scan, target) = build_scan_from_request(req).expect("auto-detected email builds");
        assert_eq!(target.kind, TargetKind::Email);
        assert_eq!(target.value, "alice@proton.me");
        // `scan_id` mixes a timestamp — assert id shape, not a recomputed value.
        assert_eq!(scan.id.len(), 64);
        assert!(scan.id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn build_scan_from_request_rejects_invalid_target() {
        let req = ScanRequest {
            kind: Some(TargetKind::Domain),
            value: "no-dot-here".to_string(),
            options: Default::default(),
        };
        let err = build_scan_from_request(req).unwrap_err();
        assert!(
            err.starts_with("invalid target: "),
            "error must carry the client-facing prefix, got: {err}"
        );
    }

    #[test]
    fn entities_to_csv_assembles_header_and_escaped_rows() {
        use crate::core::entity::{Entity, EntityKind};

        // Empty input still emits exactly the column header — export consumers
        // (the SPA download button, external tooling) parse this header row.
        assert_eq!(
            entities_to_csv(&[]).trim_end(),
            "kind,value,raw_value,confidence,c_effective,corroboration,classification,observed_at,sources,evidence_urls,evidence,tags"
        );

        let mut e = Entity::new(EntityKind::Email, "a@b.com", 0.60, "src");
        e.tag("plain");
        e.tag("has,comma"); // a comma inside an assembled field must be quoted
        let csv = entities_to_csv(&[e]);
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 2, "header + exactly one row per entity");

        let row = lines[1];
        // Column order + 3-dp numeric formatting (kind,value,raw_value,conf,c_eff,…).
        assert!(
            row.starts_with("email,a@b.com,a@b.com,0.600,0.600,"),
            "field order / numeric formatting drifted: {row}"
        );
        // `tags` is the final column; the comma-bearing tag is RFC-4180 quoted,
        // proving entities_to_csv routes assembled fields through csv_escape.
        // (The GEXF export has a byte-golden test; this is the CSV analogue.)
        assert!(
            row.ends_with(",\"plain|has,comma\""),
            "tags column not escaped through csv_escape: {row}"
        );
    }

    #[test]
    fn csv_carries_verifiable_evidence_urls_and_summaries() {
        use crate::core::entity::{Entity, EntityKind, Evidence};
        let mut e = Entity::new(EntityKind::Username, "jordanavery", 0.80, "src");
        e.add_evidence(
            Evidence::new("username_search", "@jordanavery has a profile on GitHub")
                .with_attr("url", "https://github.com/jordanavery"),
        );
        e.add_evidence(
            Evidence::new("github_user", "12 public events")
                .with_attr("profile_url", "https://github.com/jordanavery?tab=overview"),
        );
        let csv = entities_to_csv(&[e]);
        let row = csv.lines().nth(1).unwrap();
        // The full, clickable source URLs are present (no reconstruction needed).
        assert!(
            row.contains("https://github.com/jordanavery"),
            "evidence URL missing: {row}"
        );
        assert!(
            row.contains("?tab=overview"),
            "second evidence URL missing: {row}"
        );
        // The per-source finding summaries are present and source-attributed.
        assert!(
            row.contains("[username_search]") && row.contains("[github_user]"),
            "evidence trail missing: {row}"
        );
        assert!(
            row.contains("has a profile on GitHub"),
            "evidence summary missing: {row}"
        );
    }
}
