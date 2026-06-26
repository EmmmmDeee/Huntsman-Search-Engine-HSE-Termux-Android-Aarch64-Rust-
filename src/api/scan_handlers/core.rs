use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use std::sync::Arc;
use tracing::info;

use super::super::handlers::{bad_request, internal_error, not_found, ok_list, spawn_scan};
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

/// Build the `(target, options)` for a radar sweep from the optional seed
/// **type**. Pure (no store / engine access) so the radar's invariants — *only*
/// the live device sensors run, `allow_live_sensors` is set (the sole activation
/// path), the sweep is passive and single-round, and it carries no real target —
/// are unit-testable without an `AppState`. `Some("mac"|"mac_address"|"bssid")`
/// anchors the sweep on the local network (a sentinel MAC); anything else (incl.
/// `None`) is the default GPS/RF ambient survey (a sentinel coordinate). The
/// sensors ignore the seed value, so it is always a sentinel, never a target.
pub(crate) fn radar_scan_spec(seed: Option<&str>) -> (Target, crate::core::scan::ScanOptions) {
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

/// `POST /api/v1/radar/live` — start a CONTINUOUS autonomous live-sensor radar.
///
/// The single-button, zero-input radar: it takes **no body, no target, no seed,
/// no interval** — every parameter is fixed server-side. It starts a live
/// session that re-runs ONLY the on-device passive sensors
/// (`signal_radar`, `device_sensors`, `wifi_intel`, `cell_intel`, `local_net`)
/// on a loop, so the device's ambient signals — Wi-Fi APs, Bluetooth, cell
/// towers, the GPS/last-known fix and the local network — are enumerated in
/// real time as they appear and change (e.g. as the device moves). Purely
/// passive: depth 0 means no pivoting onto external/active modules, so nothing
/// but the device's own sensors ever runs. Returns the `live_id` to watch.
///
/// Same activation wall as the one-shot sweep: gated behind `feature.live_radar`
/// and `allow_live_sensors` (set here, server-side), so an ordinary scan can
/// neither reach nor accidentally start it.
pub async fn radar_live(State(s): State<Arc<AppState>>) -> impl IntoResponse {
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
    // No seed: the autonomous ambient survey. The sensors ignore the sentinel.
    let (target, opts) = radar_scan_spec(None);
    // Continuous, uncapped, radar-mode (one shared ledger across sweeps). The
    // interval is the product default — no operator input.
    let live = crate::core::live::LiveOptions {
        radar: true,
        ..Default::default()
    };
    let live_id = s.live.start(target, opts, live);
    info!(live_id = %live_id, "continuous radar started — autonomous passive-sensor enumeration");
    (
        StatusCode::ACCEPTED,
        Json(json!({ "live_id": live_id, "status": "running", "mode": "radar" })),
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
    accepting.sort_by(|a, b| {
        b.priority()
            .cmp(&a.priority())
            .then_with(|| a.name().cmp(b.name()))
    });

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

pub async fn scan_events_history(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Some(resp) = super::scan_missing(&s, &id) {
        return resp;
    }
    match s.store.events_for_scan(&id) {
        Ok(events) => ok_list("events", events),
        Err(e) => internal_error(&e),
    }
}
