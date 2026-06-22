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

/// Query for [`plan_preview`]: the seed value to preview.
#[derive(serde::Deserialize)]
pub struct PlanQuery {
    value: String,
}

/// `GET /api/v1/plan?value=<seed>` — forward-only scan-plan PREVIEW.
///
/// Detects the seed's [`TargetKind`](crate::core::scan::TargetKind) and lists the
/// modules that WOULD run on it (name, category, priority, description) **without
/// executing a scan**. Pure and offline: it builds the module registry and filters it
/// through the very same [`Module::accepts`](crate::core::module::Module::accepts) gate
/// the engine uses at dispatch, so the preview is faithful to what a real scan will
/// run. This lets an operator preview a scan's SCOPE and COST — how many modules, of
/// which categories — before committing battery and time on a phone, and gives a
/// reproducible, auditable "seed → engaged capabilities" trace with no side effects.
pub async fn plan_preview(Query(q): Query<PlanQuery>) -> impl IntoResponse {
    use crate::core::module::Module;

    let value = q.value.trim();
    if value.is_empty() {
        return bad_request("value is empty");
    }
    let target = Target::detect(value);

    let mut accepting: Vec<std::sync::Arc<dyn Module>> = crate::modules::registry()
        .into_iter()
        .filter(|m| m.accepts(&target))
        .collect();
    // Engine dispatch order: highest priority first, ties broken by name so the
    // preview is deterministic.
    accepting.sort_by(|a, b| {
        b.priority()
            .cmp(&a.priority())
            .then_with(|| a.name().cmp(b.name()))
    });

    // Per-category tallies so the plan's shape is legible at a glance.
    let mut by_category: std::collections::BTreeMap<&'static str, usize> =
        std::collections::BTreeMap::new();
    for m in &accepting {
        *by_category.entry(m.category().as_str()).or_insert(0) += 1;
    }

    let modules: Vec<serde_json::Value> = accepting
        .iter()
        .map(|m| {
            json!({
                "name": m.name(),
                "category": m.category().as_str(),
                "priority": m.priority(),
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
            "categories": categories,
            "modules": modules,
        })),
    )
        .into_response()
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

/// Build the `(target, options)` for a radar sweep from the optional seed
/// **type**. Pure (no store / engine access) so the radar's invariants — *only*
/// the live device sensors run, `allow_live_sensors` is set (the sole activation
/// path), the sweep is passive and single-round, and it carries no real target —
/// are unit-testable without an `AppState`. `Some("mac"|"mac_address"|"bssid")`
/// anchors the sweep on the local network (a sentinel MAC); anything else (incl.
/// `None`) is the default GPS/RF ambient survey (a sentinel coordinate). The
/// sensors ignore the seed value, so it is always a sentinel, never a target.
fn radar_scan_spec(seed: Option<&str>) -> (Target, crate::core::scan::ScanOptions) {
    use crate::core::scan::TargetKind;
    let (kind, value) = match seed {
        Some("mac" | "mac_address" | "bssid") => (TargetKind::MacAddress, "00:00:00:00:00:00"),
        _ => (TargetKind::Coordinates, "0,0"),
    };
    let opts = crate::core::scan::ScanOptions {
        modules: Some(
            crate::core::engine::LOCAL_PASSIVE_MODULES
                .iter()
                .map(|m| (*m).to_string())
                .collect(),
        ),
        passive_only: true,
        depth: 0,
        allow_live_sensors: true,
        ..Default::default()
    };
    (Target::new(kind, value), opts)
}

/// `POST /api/v1/radar` — run ONE autonomous live-sensor sweep (the radar button).
///
/// The dedicated, user-triggered activation for the live device sensors
/// (`signal_radar`, `device_sensors`, `wifi_intel`, `cell_intel`, `local_net`).
/// It takes **no target** — it surveys the device's own ambient RF / network
/// environment (Wi-Fi APs, Bluetooth, cell towers, GPS fix, LAN ARP) — and is
/// entirely separate from target seed scanning: an ordinary scan never runs these
/// modules (the `allow_live_sensors` gate keeps them off); only this endpoint sets
/// it. The sweep is seeded with a sentinel value purely so the sensors (which gate
/// on `Coordinates`/`MacAddress` and ignore the value) dispatch.
///
/// The *only* input is an optional seed **type** via `?seed=` — `coordinates`
/// (default; GPS/RF ambient survey) or `mac`/`mac_address`/`bssid` (a
/// BSSID-anchored local-network survey). Every sensor accepts both kinds and
/// ignores the value, so this just labels the sweep's anchor; it never carries a
/// real target.
pub async fn radar_sweep(
    State(s): State<Arc<AppState>>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    // Completely disabled until deliberately enabled in a place separate from
    // seed scans (`feature.live_radar`). The radar surveys the host device's own
    // surroundings, so it stays walled off from target scanning until opted in.
    if !crate::util::settings::live_radar_enabled() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "live radar disabled",
                "detail": "the live-sensor radar is off by default and separate from scans; \
                           enable it deliberately before use",
                "enable": "set the feature.live_radar toggle on (CLI: hse config feature.live_radar on)",
            })),
        )
            .into_response();
    }
    let (target, opts) = radar_scan_spec(params.get("seed").map(String::as_str));
    let sid = scan_id("radar", target.kind.canonical_str());
    let scan = Scan::new(sid.clone(), target.clone()).with_options(opts);
    if let Err(e) = s.store.upsert_scan(&scan) {
        return internal_error(&e);
    }
    spawn_scan(&s, scan, target);
    info!(scan_id = %sid, "radar sweep queued — live device sensors (button activation)");
    (
        StatusCode::ACCEPTED,
        Json(json!({ "scan_id": sid, "status": "queued", "mode": "radar" })),
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
        .map_or_else(|| "uploaded dossier".to_string(), |e| e.value.clone());

    let entity_count = entities.len();
    let mut scan = Scan::new(sid.clone(), Target::new(TargetKind::FullName, label));
    scan.status = ScanStatus::Complete;
    scan.finished_at = Some(unix_now());
    scan.entity_count = entity_count;

    // Persist scan, entities, relations, and correlations on a blocking thread
    // so SQLite commits don't stall the 2-worker async reactor.
    let store = Arc::clone(&s.store);
    let sid2 = sid.clone();
    let (relation_count, correlation_count) =
        match tokio::task::spawn_blocking(move || -> crate::core::error::Result<_> {
            store.upsert_scan(&scan)?;
            store.upsert_entities_batch(&entities)?;
            let mut relations = 0usize;
            for r in &crate::core::relation::derive_all(&entities, &sid2) {
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
            Ok((relations, correlations))
        })
        .await
        {
            Ok(Ok(counts)) => counts,
            Ok(Err(e)) => return internal_error(&e),
            Err(e) => return internal_error(&format!("import task failed: {e}")),
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
    let store = std::sync::Arc::clone(&s.store);
    let id2 = id.clone();
    match tokio::task::spawn_blocking(move || store.entities_for_scan(&id2)).await {
        Ok(Ok(mut entities)) => {
            if !wants_candidates(&params) {
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
    if let Some(resp) = scan_missing(&s, &a) {
        return resp;
    }
    if let Some(resp) = scan_missing(&s, &b) {
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
    if let Some(resp) = scan_missing(&s, &id) {
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
        Ok(Ok(entities)) => ok_list("entities", entities),
        Ok(Err(e)) => internal_error(&e),
        Err(e) => internal_error(&format!("query task failed: {e}")),
    }
}

pub async fn scan_entities_facets(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Some(resp) = scan_missing(&s, &id) {
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
    if let Some(resp) = scan_missing(&s, &id) {
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
    let store = std::sync::Arc::clone(&s.store);
    let id2 = id.clone();
    let entities = match tokio::task::spawn_blocking(move || store.entities_for_scan(&id2)).await {
        Ok(Ok(e)) => e,
        Ok(Err(e)) => return internal_error(&e),
        Err(e) => return internal_error(&format!("query task failed: {e}")),
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
    if let Some(resp) = scan_missing(&s, &id) {
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
    if let Some(resp) = scan_missing(&s, &id) {
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
    ok_list("events", events)
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
    if let Some(resp) = scan_missing(&s, &id) {
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
    if let Some(resp) = scan_missing(&s, &id) {
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
    from: String,
    to: String,
    paths: Option<usize>,
    cross: Option<bool>,
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
    if let Some(resp) = scan_missing(&s, &id) {
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

/// `GET /api/v1/scans/{id}/metrics` — objective per-scan quality / telemetry measures
/// ([`crate::core::metrics`]): entity & relation counts, the verified/probable/candidate
/// tier breakdown, mean & median confidence, corroborated fraction, graph density and
/// linked-entity fraction, cross-scan bridges, and distinct evidence sources — the
/// empirical measure of how much corroborated intelligence the scan actually formed.
/// Pure synthesis over the persisted entities + relations; 404 if the scan is unknown.
pub async fn scan_metrics(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Some(resp) = scan_missing(&s, &id) {
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

/// `GET /api/v1/scans/{id}/duplicates` — near-duplicate entity-resolution suggestions
/// ([`crate::core::resolve`]): groups of entities that are probably the SAME identity
/// in different contexts (Gmail dot/`+tag` variants, phone formats, reordered names)
/// that the exact-UID correlator missed. Read-only suggestions for the operator to
/// confirm. Pure synthesis over the persisted entities; 404 if the scan is unknown.
pub async fn scan_duplicates(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Some(resp) = scan_missing(&s, &id) {
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

/// `GET /api/v1/scans/{id}/pivots` — pivot-node detection ([`crate::core::pivot`]): the
/// high-connectivity INTERMEDIARIES of the relationship graph (the shared address,
/// registrant, or phone that bridges many otherwise-separate entities), ranked by
/// betweenness + degree centrality. These are the highest-leverage nodes to expand or
/// confirm — pivot-driven traversal. Pure synthesis over the persisted entities +
/// relations; 404 if the scan is unknown, matching the other sub-resources.
pub async fn scan_pivots(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Some(resp) = scan_missing(&s, &id) {
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
    // {pivots, bridges, count}: the ranked intermediaries plus the graph's exact cut
    // edges (single-point-of-failure links). `count` mirrors `ok_list` so existing
    // clients reading `.pivots`/`.count` are unaffected.
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

/// `GET /api/v1/scans/{id}/gaps` — discovery-gap analysis ([`crate::core::gap`]): the
/// validated seeds a scan produced that are ISOLATED (no evidence-backed link), each
/// classified by why it is isolated and given a concrete corrective action — including
/// the registered modules that would query its re-injection kind, so an operator (or the
/// engine) can force the missing observable path. This is the gap-resolution loop's
/// instrument: it turns "no links" into "run these scans next". Pure synthesis over the
/// persisted entities + relations; 404 if the scan is unknown.
pub async fn scan_gaps(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Some(resp) = scan_missing(&s, &id) {
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

    // Attach, per orphan, the registered modules that would query its re-injection kind —
    // the concrete "additional data sources" the gap-resolution loop should run. Computed
    // here because the registry lives in the module layer, not in `core`.
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

/// `GET /api/v1/scans/{id}/benchmark` — the consolidated, auditable benchmark report
/// ([`crate::core::benchmark`]): the scan's measurable OSINT dimensions (discovery
/// depth, graph coverage, corroboration, density, throughput, module reliability,
/// pivots) rolled into one scorecard for a reproducible A/B. The HTTP twin of
/// `hse benchmark`, so a deployed Termux/web instance can emit the same evidence over
/// the network. Pure synthesis over the persisted scan + entities + relations; 404 if
/// the scan is unknown.
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
