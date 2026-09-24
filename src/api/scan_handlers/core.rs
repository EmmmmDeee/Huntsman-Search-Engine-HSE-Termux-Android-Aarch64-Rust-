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
use crate::core::scan::{Scan, Target, TargetKind};

pub async fn scan_create(
    State(s): State<Arc<AppState>>,
    // Decoded as raw JSON, not `Json<ScanRequest>`, so an `options` key that
    // `ScanOptions` does not define can be REJECTED rather than silently
    // dropped — see `scan_request_from_json`.
    Json(raw): Json<serde_json::Value>,
) -> impl IntoResponse {
    let req = match super::scan_request_from_json(raw) {
        Ok(req) => req,
        Err(msg) => return bad_request(msg),
    };
    let (scan, target) = match super::build_scan_from_request(req) {
        Ok(pair) => pair,
        Err(msg) => return bad_request(msg),
    };

    let store = Arc::clone(&s.store);
    let scan_db = scan.clone();
    if let Err(resp) = super::offload_store(move || store.upsert_scan(&scan_db)).await {
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

/// The scan-history bound for [`scan_auto`]/[`scan_auto_plan`]/[`scan_auto_sweep`]'s
/// candidate pool. Each handler's own doc promises it ranks "everything the
/// platform has discovered" — a hardcoded `list_scans(50)` silently broke that
/// promise on any device with more than 50 scans in its history, quietly
/// excluding older (but potentially higher-leverage) entities from ever being
/// selected. `10_000` mirrors the same "effectively all, but SQL-bounded for
/// device safety" convention [`crate::api::handlers::stats`] already uses for
/// its own full-history aggregation, so the two full-history reads agree.
const AUTONOMOUS_POOL_MAX_SCANS: usize = 10_000;

/// Total-entity ceiling on the in-memory autonomous target pool. `MAX_SCANS`
/// alone bounds the number of scans read, but 10_000 scans × hundreds of
/// entities each is millions of `Entity` structs in one `Vec` — multi-hundred-MB
/// on a 2–4 GB Termux phone, before `plan_autonomous_sweep` even runs. The pool
/// is a target-selection heuristic, so a deterministic prefix of the (recent-
/// first) scan history is more than enough to pick the top `limit` (≤200)
/// targets. Loading stops once the pool reaches this size.
const AUTONOMOUS_POOL_MAX_ENTITIES: usize = 50_000;

/// The operator-local default seed (`HUNTSMAN_DEFAULT_SEED`), with its kind
/// auto-detected from the value — the autonomous scan's fallback when the local
/// intelligence base is still empty.
fn default_seed_from_env() -> Option<(crate::core::scan::TargetKind, String)> {
    let v = std::env::var("HUNTSMAN_DEFAULT_SEED")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())?;
    Some((crate::core::scan::TargetKind::detect(&v), v))
}

/// `POST /api/v1/scan/auto` — fully autonomous investigation, NO seed input.
///
/// The platform discovers, prioritises and investigates on its own: it ranks the
/// entities it has already collected by cross-investigation leverage (the
/// identifier whose enrichment most empowers the rest of the intelligence base),
/// selects the strongest pivotable one, and runs a comprehensive scan on it — so
/// the operator never has to choose a seed. Falls back to `HUNTSMAN_DEFAULT_SEED`
/// when the base is empty, and returns a clear 422 (not an error) only when there
/// is genuinely nothing to investigate yet. The response names the seed it chose.
pub async fn scan_auto(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    use std::collections::HashSet;

    // Assemble the candidate pool from recent scans (everything the platform has
    // discovered) — entities AND relations — and rank it by RESOLVED IDENTITY: the
    // co-reference clusters collapse each person's selectors to one target whose
    // score aggregates the whole identity's leverage, so the platform investigates
    // the individual it knows the most about (not three handles of one person).
    // Identity-aware ranking is a strict generalisation of the flat ranker — with
    // no relations it yields the same order — so this is fully backward-compatible.
    // All store work on the blocking pool so the async workers stay free.
    let store = Arc::clone(&s.store);
    let from_base = match super::offload_store(
        move || -> crate::core::error::Result<Option<crate::core::engine::ClusteredTarget>> {
            let scans = store.list_scans(AUTONOMOUS_POOL_MAX_SCANS)?;
            let mut pool: Vec<crate::core::entity::Entity> = Vec::new();
            let mut rels: Vec<crate::core::relation::Relation> = Vec::new();
            let mut seen: HashSet<String> = HashSet::new();
            let mut rel_seen: HashSet<String> = HashSet::new();
            for sc in &scans {
                if pool.len() >= AUTONOMOUS_POOL_MAX_ENTITIES {
                    break;
                }
                for e in store.entities_for_scan(&sc.id)? {
                    if seen.insert(e.uid.clone()) {
                        pool.push(e);
                    }
                }
                for r in store.relations_for_scan(&sc.id)? {
                    if rel_seen.insert(r.id.clone()) {
                        rels.push(r);
                    }
                }
            }
            // Degree from the realised cross-scan observation count; a store error
            // on a point lookup degrades to 0 (neutral leverage) rather than failing
            // the whole selection. Nothing is excluded — every pivotable candidate
            // competes on its composite (identity-aggregated) score.
            let exclude = HashSet::new();
            let ranked = crate::core::engine::rank_identity_aware_targets(
                &pool,
                &rels,
                |uid| store.observation_count(uid).unwrap_or(0),
                &exclude,
                64,
            );
            Ok(ranked.into_iter().next())
        },
    )
    .await
    {
        Ok(s) => s,
        Err(resp) => return resp,
    };

    // The identity-aware ranker yields a clustered target; flatten to its
    // representative selector + the cluster context, falling back to the configured
    // default seed (a singleton, score 0.0) when the base is bare.
    let chosen = from_base
        .map(|t| {
            (
                t.representative.kind,
                t.representative.value,
                t.representative.score,
                t.cluster_size,
                t.distinct_kinds,
            )
        })
        .or_else(|| default_seed_from_env().map(|(k, v)| (k, v, 0.0, 1, 1)));
    let Some((kind, value, score, cluster_size, distinct_kinds)) = chosen else {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({
                "error": "nothing to investigate autonomously yet",
                "detail": "the local intelligence base holds no high-leverage identifier; \
                           run one seeded scan to seed it, or set HUNTSMAN_DEFAULT_SEED",
                "mode": "autonomous",
            })),
        )
            .into_response();
    };

    let target = Target::new(kind, value.clone());
    let sid = scan_id(kind.canonical_str(), &value);
    let scan = Scan::new(sid.clone(), target.clone())
        .with_options(crate::core::scan::default_scan_options());
    let store = Arc::clone(&s.store);
    let scan_db = scan.clone();
    if let Err(resp) = super::offload_store(move || store.upsert_scan(&scan_db)).await {
        return resp;
    }
    spawn_scan(&s, scan, target);
    info!(scan_id = %sid, kind = ?kind, "autonomous scan queued — seed auto-selected");
    (
        StatusCode::ACCEPTED,
        Json(json!({
            "scan_id": sid,
            "status": "queued",
            "mode": "autonomous",
            "selected_seed": {
                "kind": kind.canonical_str(),
                "value": value,
                "priority_score": score,
                // Identity context: how many co-referent selectors / distinct kinds
                // the chosen individual is resolved across (1 = a singleton seed).
                "identity_cluster_size": cluster_size,
                "identity_distinct_kinds": distinct_kinds,
            },
        })),
    )
        .into_response()
}

/// `GET /api/v1/scan/auto/plan` — preview the autonomous investigation queue
/// **without dispatching anything**.
///
/// The read-only counterpart to [`scan_auto`]: it ranks the collected base with
/// the same multi-factor priority, then applies diversity-aware
/// ([`crate::core::engine::plan_autonomous_sweep`]) selection so the queue spreads
/// effort across identifier kinds instead of tunnelling on the single
/// most-represented one. Lets the operator (or the SPA) see exactly what the
/// platform would investigate next, and in what order, before committing. Optional
/// query params: `limit` (queue length, default 20, capped at 200) and `diversity`
/// (0.0 = pure score order, higher interleaves kinds; default
/// [`crate::core::engine::DEFAULT_SWEEP_DIVERSITY`]).
pub async fn scan_auto_plan(
    State(s): State<Arc<AppState>>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    use std::collections::HashSet;

    let limit = params
        .get("limit")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(20)
        .clamp(1, 200);
    let diversity = params
        .get("diversity")
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(crate::core::engine::DEFAULT_SWEEP_DIVERSITY);

    let store = Arc::clone(&s.store);
    let plan = match super::offload_store(
        move || -> crate::core::error::Result<crate::core::engine::AutonomousPlan> {
            let scans = store.list_scans(AUTONOMOUS_POOL_MAX_SCANS)?;
            let mut pool: Vec<crate::core::entity::Entity> = Vec::new();
            let mut seen: HashSet<String> = HashSet::new();
            for sc in &scans {
                if pool.len() >= AUTONOMOUS_POOL_MAX_ENTITIES {
                    break;
                }
                for e in store.entities_for_scan(&sc.id)? {
                    if seen.insert(e.uid.clone()) {
                        pool.push(e);
                    }
                }
            }
            let exclude = HashSet::new();
            Ok(crate::core::engine::plan_autonomous_sweep(
                &pool,
                |uid| store.observation_count(uid).unwrap_or(0),
                &exclude,
                limit,
                diversity,
            ))
        },
    )
    .await
    {
        Ok(p) => p,
        Err(resp) => return resp,
    };

    (
        StatusCode::OK,
        Json(json!({
            "mode": "autonomous",
            "diversity": diversity,
            "considered": plan.considered,
            "kinds_covered": plan.kinds_covered,
            "queue": plan.queue,
        })),
    )
        .into_response()
}

/// `POST /api/v1/scan/auto/sweep` — fully autonomous **multi-target** investigation,
/// NO seed input.
///
/// The capstone of the autonomous loop: where [`scan_auto`] dispatches the single
/// strongest target, this plans the diversity-aware queue
/// ([`crate::core::engine::plan_autonomous_sweep`]) and dispatches its top
/// `breadth` targets in one input-free call — so a single activation investigates a
/// *spread* of the highest-value leads across identifier kinds, not just one. Each
/// dispatched scan is an ordinary comprehensive scan (so cancel / rerun / export all
/// work identically); the multi-dispatch mirrors the established
/// [`scan_batch`] path. Bounded by `breadth` (default 5,
/// capped at 25) so it can never flood a low-RAM device. Optional query params:
/// `breadth` and `diversity` (see [`scan_auto_plan`]). Returns 202 with the
/// dispatched scans, or a clean 422 (never a 500) when the base holds nothing to
/// investigate yet.
pub async fn scan_auto_sweep(
    State(s): State<Arc<AppState>>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    use std::collections::HashSet;

    let breadth = params
        .get("breadth")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(5)
        .clamp(1, 25);
    let diversity = params
        .get("diversity")
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(crate::core::engine::DEFAULT_SWEEP_DIVERSITY);

    let store = Arc::clone(&s.store);
    let plan = match super::offload_store(
        move || -> crate::core::error::Result<crate::core::engine::AutonomousPlan> {
            let scans = store.list_scans(AUTONOMOUS_POOL_MAX_SCANS)?;
            let mut pool: Vec<crate::core::entity::Entity> = Vec::new();
            let mut seen: HashSet<String> = HashSet::new();
            for sc in &scans {
                if pool.len() >= AUTONOMOUS_POOL_MAX_ENTITIES {
                    break;
                }
                for e in store.entities_for_scan(&sc.id)? {
                    if seen.insert(e.uid.clone()) {
                        pool.push(e);
                    }
                }
            }
            let exclude = HashSet::new();
            Ok(crate::core::engine::plan_autonomous_sweep(
                &pool,
                |uid| store.observation_count(uid).unwrap_or(0),
                &exclude,
                breadth,
                diversity,
            ))
        },
    )
    .await
    {
        Ok(p) => p,
        Err(resp) => return resp,
    };

    if plan.queue.is_empty() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({
                "error": "nothing to investigate autonomously yet",
                "detail": "the local intelligence base holds no high-leverage identifier; \
                           run one seeded scan to seed it, or set HUNTSMAN_DEFAULT_SEED",
                "mode": "autonomous",
            })),
        )
            .into_response();
    }

    // Dispatch each planned target as an ordinary comprehensive scan,
    // de-duplicating by TARGET IDENTITY so two queue entries for the same
    // `(kind, value)` don't double-spawn (idempotent like rerun). NOTE: dedup must
    // key on the target, NOT the derived `scan_id` — `scan_id` mixes a monotonic
    // counter + sub-second nanos and is unique per call, so keying on it made the
    // de-dup a silent no-op (two identical queue entries would both dispatch).
    let mut dispatched = Vec::with_capacity(plan.queue.len());
    let mut spawned: std::collections::HashSet<(TargetKind, String)> =
        std::collections::HashSet::new();
    for t in &plan.queue {
        if !spawned.insert((t.kind, t.value.clone())) {
            continue;
        }
        let target = Target::new(t.kind, t.value.clone());
        let sid = scan_id(t.kind.canonical_str(), &t.value);
        let scan = Scan::new(sid.clone(), target.clone())
            .with_options(crate::core::scan::default_scan_options());
        let store = Arc::clone(&s.store);
        let scan_db = scan.clone();
        // Deliberately NOT `offload_store`: a persist failure here records a
        // per-target error and lets the sweep continue, whereas `offload_store`
        // would abort the whole request with a 500 on the first bad target.
        match tokio::task::spawn_blocking(move || store.upsert_scan(&scan_db)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                dispatched.push(json!({ "error": e.to_string(), "value": t.value }));
                continue;
            }
            Err(e) => {
                dispatched
                    .push(json!({ "error": format!("db task failed: {e}"), "value": t.value }));
                continue;
            }
        }
        spawn_scan(&s, scan, target);
        dispatched.push(json!({
            "scan_id": sid,
            "status": "queued",
            "kind": t.kind.canonical_str(),
            "value": t.value,
            "priority_score": t.score,
        }));
    }

    info!(
        count = dispatched.len(),
        kinds_covered = plan.kinds_covered,
        "autonomous sweep queued — multi-target, no seed input"
    );
    (
        StatusCode::ACCEPTED,
        Json(json!({
            "mode": "autonomous",
            "diversity": diversity,
            "considered": plan.considered,
            "kinds_covered": plan.kinds_covered,
            "dispatched": dispatched,
            "count": dispatched.len(),
        })),
    )
        .into_response()
}

pub async fn scan_cancel(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    // One-shot scans and live iterations alike: the registry holds whichever
    // handle the engine is polling for this scan id. For a live iteration that
    // is the ITERATION's handle, so the session continues to its next tick.
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
    let scans = match super::offload_store(move || store.list_scans(200)).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    // Derived `interrupted` flag per row — see `handlers::is_interrupted`.
    let in_flight = super::super::handlers::in_flight_scan_ids(&s.cancellations);
    let rows: Vec<serde_json::Value> = scans
        .iter()
        .map(|sc| super::super::handlers::scan_json(sc, &in_flight))
        .collect();
    ok_list("scans", rows)
}

pub async fn scan_get(State(s): State<Arc<AppState>>, Path(id): Path<String>) -> impl IntoResponse {
    // Off-reactor: synchronous SQLite read under the global connection mutex.
    let store = std::sync::Arc::clone(&s.store);
    let scan = match super::offload_store(move || store.get_scan(&id)).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    match scan {
        Some(scan) => {
            let in_flight = super::super::handlers::in_flight_scan_ids(&s.cancellations);
            (
                StatusCode::OK,
                Json(super::super::handlers::scan_json(&scan, &in_flight)),
            )
                .into_response()
        }
        None => not_found(),
    }
}

pub async fn scan_delete(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    // Refuse to delete a scan that's still in-flight: `s.cancellations` holds
    // an entry for exactly as long as the engine is running the scan — a
    // one-shot scan's from `spawn_scan`, a live iteration's from the live loop
    // — removed by `CancelRegistryGuard`'s Drop when the engine returns
    // (success, error, or panic). Without this check,
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
    // observations, events, relations, stealer_rows,
    // rf_sightings, entities + FTS sync) under the global connection mutex —
    // the heaviest write in the API. Run it off the reactor so a large-scan
    // delete can't stall unrelated requests.
    let store = Arc::clone(&s.store);
    let id_db = id.clone();
    match super::offload_store(move || store.delete_scan(&id_db)).await {
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
    let original = match super::offload_store(move || store.get_scan(&id_db)).await {
        Ok(Some(scan)) => scan,
        Ok(None) => return not_found(),
        Err(resp) => return resp,
    };

    let sid = scan_id(original.target.kind.canonical_str(), &original.target.value);
    let new_scan = Scan::new(sid, original.target.clone()).with_options(original.options.clone());

    let store = Arc::clone(&s.store);
    let scan_db = new_scan.clone();
    if let Err(resp) = super::offload_store(move || store.upsert_scan(&scan_db)).await {
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
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
    body: String,
) -> impl IntoResponse {
    use super::super::handlers::forbidden;
    use crate::core::entity::EntityKind;
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

    // An explicit `?format=<name>` bypasses content detection — for a file the
    // detector cannot classify (a combolist of bare usernames with no
    // email-shaped line) or classifies wrongly. The names and the parser are
    // the same authority `hse import --input-format` uses; an unknown name is
    // an actionable 400 naming the accepted spellings, never a silent fall
    // back to the detection the operator asked to bypass.
    let forced = match params.get("format").map(String::as_str) {
        None | Some("") => None,
        Some(name) => match crate::app::import::ImportFormat::parse_name(name) {
            Ok(f) => Some(f),
            Err(e) => return bad_request(e),
        },
    };

    // Bound the upload so a hostile/huge paste can't exhaust phone memory.
    // The route's `DefaultBodyLimit` (see api::routes) is set to
    // `MAX_UPLOAD_BYTES + IMPORT_ROUTE_BODY_LIMIT_HEADROOM_BYTES`, deliberately
    // a bit higher than this handler's own cap — so a body over
    // `MAX_UPLOAD_BYTES` but within that headroom still reaches this check and
    // gets this API's normal JSON `bad_request` shape, rather than axum's bare
    // plain-text 413 (which is reserved for the truly pathological case that
    // exceeds even the headroom). Both read `MAX_UPLOAD_BYTES`, so the two
    // limits can't drift apart.
    if body.trim().is_empty() {
        return bad_request("empty upload");
    }
    if body.len() > super::MAX_UPLOAD_BYTES {
        return bad_request("upload too large (max 16 MB)");
    }
    // Throttle concurrent imports via the shared scan semaphore — mirrors the
    // gate in spawn_scan so an import flood can't crowd out live scans on a
    // 2-core Termux device. Owned, so it can move into the blocking import
    // below and be held until the import's last write — not only for as long
    // as this handler's future lives (see the in-flight guard below).
    let Ok(permit) = Arc::clone(&s.scan_semaphore).acquire_owned().await else {
        return internal_error(&"scan semaphore closed".to_string());
    };
    // `scan_id` is collision-free per call, so the value just needs to be
    // descriptive — the upload size, not a redundant timestamp.
    let sid = scan_id("import-upload", &body.len().to_string());
    // Detect the format from content (unless forced above) and parse via the
    // SAME `app::import` path the CLI uses, so every format it supports works.
    let (entities, format) =
        match crate::app::import::entities_from_upload(&body, &sid, forced).await {
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
    let stealer_rows = crate::app::import::stealer_rows_from_upload(&body, forced);

    // A readable scan label: the strongest identity in the file, else a generic.
    let label = entities
        .iter()
        .find(|e| e.kind == EntityKind::Person)
        .or_else(|| entities.iter().find(|e| e.kind == EntityKind::Email))
        .map_or_else(|| "uploaded dossier".to_string(), |e| e.value.clone());

    // Written `Running` first and turned `Complete` only once the entities,
    // relations and correlations are all stored (the commit at the end of the
    // blocking closure below). Exports classify a scan by its stored status,
    // so a `Complete` written first let an export taken mid-import brand a
    // half-written scan whole — the window the live engine's finalise had too
    // (`ScanEngine::finalise_scan`'s commit step). The row's lifecycle is
    // `app::persist::ImportScanRow`'s, shared with the CLI import: any exit
    // before the commit records `Failed`, and a kill leaves `Running`, which
    // reads as interrupted once this process no longer holds the import in its
    // in-flight registry (REQ-SCANSTATUS-005).
    // The row's entity count is set by `ImportScanRow::store_entities` once the
    // batch is stored, never claimed ahead of it (REQ-SCANSTATUS-009).
    let scan = Scan::new(sid.clone(), Target::new(TargetKind::FullName, label));

    // Cross-entry enrichment (relation derivation + the correlator) is pairwise
    // WITHIN same-key buckets, so a pathological single-domain dossier — e.g.
    // tens of thousands of `*@one-domain.tld` rows — degrades to a multi-minute
    // O(n²) pass that would lock a 2-core Termux phone (a 16 MB upload can hold
    // ~500k rows). The import's PRIMARY contract — persist every parsed entity —
    // is met unconditionally below; only the best-effort enrichment is bounded
    // (`app::persist::skip_enrichment_over_cap`, the CLI import's own cap), so a
    // huge upload always COMPLETES. A realistic dossier (well under the cap)
    // still gets full relations + correlations; a larger one stores every entity
    // and is recorded partial. `/scans/{id}/rerun` does not enrich it — a re-run
    // is a live scan of the import's label — so the remedy is to re-import the
    // data in batches under `PERSIST_ENRICH_MAX_ENTITIES`, each enriched on its
    // own: links between entities in different batches are not derived
    // (REQ-SCANSTATUS-017).

    // Persist scan, entities, relations, and correlations on a blocking thread
    // so SQLite commits don't stall the 2-worker async reactor.
    let store = Arc::clone(&s.store);
    let sid2 = sid.clone();
    // The third element is `false` when enrichment was skipped for size — the
    // caller must be able to tell that apart from a genuinely relation-free
    // dossier, both of which otherwise report `relation_count: 0`.
    let stealer_rows_parsed = stealer_rows.len();
    // In flight in THIS process from before the row's first write until after
    // its terminal one — the registry every "is this scan running here?" reader
    // consults (`core::cancel::CancelRegistry`): so the import never reads as
    // interrupted while it runs, cannot be deleted mid-write, and honours
    // `POST /scans/{id}/cancel` at its two enrichment boundaries (the row then
    // reads `Aborted`, entities and whatever enrichment finished kept, as for
    // a cancelled live scan).
    //
    // The guard (and the semaphore permit) MOVE INTO the blocking closure,
    // which owns them until its last write. They used to live in this
    // handler's future, but `spawn_blocking` keeps running when the future
    // awaiting it is dropped — and hyper drops an in-flight handler when its
    // client goes away (a closed tab, a suspended browser, a proxy timeout).
    // The guard then left the registry while the import was still writing:
    // `GET /scans` read the `Running` row as interrupted, `DELETE
    // /scans/{id}` passed its in-flight check and cascaded, and the import's
    // `finish` then resurrected the row `Complete` with its entities gone,
    // and the import could no longer be cancelled (REQ-SCANSTATUS-006).
    let cancel = crate::core::cancel::CancelHandle::new();
    let in_flight = crate::core::cancel::CancelRegistryGuard::install(
        Arc::clone(&s.cancellations),
        sid.clone(),
        cancel.clone(),
    );
    let (
        entity_count,
        (
            relation_count,
            correlation_count,
            enriched,
            stealer_rows_stored,
            terminal,
            finalise_error,
        ),
    ) = match super::offload_store(move || -> crate::core::error::Result<_> {
        use crate::core::scan::{FinaliseTally, FinaliseWrite};
        // Declared before `row`, so they drop after it: after its terminal
        // write, or after the `Failed` its Drop records on an early exit.
        let _in_flight = in_flight;
        let _permit = permit;
        // The same preparation the CLI import applies before storing
        // (`app::persist::prepare_import_batch`): the offline geo enrichment
        // and the strongest-first ranking. It appends derived Coordinates, so
        // the batch is counted after it (REQ-GEOLABEL-033).
        let mut entities = entities;
        crate::app::persist::prepare_import_batch(&mut entities, &sid2);
        let entity_count = entities.len();
        let mut row = crate::app::persist::ImportScanRow::begin(Arc::clone(&store), scan)?;
        row.store_entities(&entities)?;
        // Every relation / correlation write below counts into this; its
        // message is the scan's recorded shortfall (see `FinaliseTally`).
        let mut tally = FinaliseTally::default();
        // The terminal write, run on every exit below — nothing after it
        // may add to what the scan's exports read. It is the row's one
        // terminal write (`ImportScanRow::finish`): the status — `Complete`,
        // or `Aborted` when a cancel reached an enrichment boundary — and,
        // beside it, what the finalise did not complete (the tally's
        // message, the one `scan.error` authority), where every export's
        // completeness check reads it.
        let commit =
            |row: crate::app::persist::ImportScanRow, status: ScanStatus, tally: &FinaliseTally| {
                row.finish(status, tally).map(|error| (status, error))
            };
        // Best-effort: a stealer-row persistence hiccup must not fail an
        // otherwise-successful import — the entity graph above already
        // carries the same credentials, just unpaired. Logged and
        // surfaced in the response below (never silently dropped),
        // mirroring the CLI import path's own
        // `persist_stealer_rows_best_effort`.
        let stealer_rows_stored = match store.insert_stealer_rows_batch(&sid2, &stealer_rows) {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!(
                    scan_id = %sid2,
                    rows = stealer_rows.len(),
                    error = %e,
                    "web upload: could not persist stealer rows — the entity \
                     graph was still stored, but the paired credential rows \
                     (Stealer Logs Viewer) were not"
                );
                0
            }
        };
        // Device-safety bound: skip the O(n²) enrichment on a pathologically
        // large import (entities are already persisted above; nothing lost).
        // The skip is recorded on the tally, so the row is committed
        // `Complete` with it in `error` and the response answers `partial`
        // (REQ-SCANSTATUS-010).
        if crate::app::persist::skip_enrichment_over_cap(entities.len(), &mut tally) {
            let (status, error) = commit(row, ScanStatus::Complete, &tally)?;
            return Ok((
                entity_count,
                (0usize, 0usize, false, stealer_rows_stored, status, error),
            ));
        }
        if cancel.is_cancelled() {
            let (status, error) = commit(row, ScanStatus::Aborted, &tally)?;
            return Ok((
                entity_count,
                (0usize, 0usize, false, stealer_rows_stored, status, error),
            ));
        }
        // Wall-clock bound on the super-linear derivation chain, matching a
        // live scan (the entity-count guard above already skips the
        // pathological case; this bounds the rest), through the same step the
        // live finalise and the CLI import use, which records a budget cut on
        // the tally (REQ-SCANSTATUS-024). Persisted through the same counted
        // step too, so a refused edge is recorded rather than dropped by
        // `.is_ok()`.
        let derived = crate::core::engine::derive_finalise_relations(&entities, &sid2, &mut tally);
        let relations =
            crate::core::engine::persist_relations(store.as_ref(), &sid2, &derived, &mut tally);
        // The second cancel boundary: the relations above are kept, and so is
        // whatever the tally recorded about them.
        if cancel.is_cancelled() {
            let (status, error) = commit(row, ScanStatus::Aborted, &tally)?;
            return Ok((
                entity_count,
                (relations, 0usize, false, stealer_rows_stored, status, error),
            ));
        }
        // Run the correlator so cross-entry handle-reuse / breach clusters
        // surface exactly as they would for a live scan. Not fatal: a
        // correlator hiccup must not fail an otherwise-successful import.
        // `correlate_and_persist` runs it under the canonical panic guard
        // (`guarded_correlation_pass`), exactly as the CLI import path
        // (`app::persist`) and the live finalise do — a correlator rule
        // panicking on adversarial imported entities degrades to "no
        // correlations", not an unwind after the entities were committed —
        // and records a pass that failed and every firing the store refuses.
        let _firings = crate::core::engine::correlate_and_persist(&store, &sid2, &mut tally);
        let correlations = tally.persisted(FinaliseWrite::Correlations);
        let (status, error) = commit(row, ScanStatus::Complete, &tally)?;
        Ok((
            entity_count,
            (
                relations,
                correlations,
                true,
                stealer_rows_stored,
                status,
                error,
            ),
        ))
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
            // `true` when relations/correlations were not run to the end —
            // the upload exceeded the import enrichment cap
            // (`app::persist::PERSIST_ENRICH_MAX_ENTITIES`), or a cancel
            // reached it first — which disambiguates a skipped pass from a
            // dossier that genuinely yielded zero relations/correlations.
            // Every entity is still persisted either way. `/scans/{id}/rerun`
            // does not enrich it (a re-run is a live scan of the import's
            // label); re-importing the data in batches under
            // `PERSIST_ENRICH_MAX_ENTITIES` enriches each batch on its own,
            // and links between entities in different batches are not
            // derived (REQ-SCANSTATUS-017).
            "enrichment_skipped": !enriched,
            // Together these disambiguate a stealer-log upload's paired
            // credential rows the same way `enrichment_skipped` does for
            // relations/correlations above: `parsed > 0 && stored == 0` is an
            // unambiguous persistence failure (also `tracing::warn!`-logged
            // server-side), never confusable with `parsed == 0` (a non-stealer
            // upload, nothing to store) or `parsed == stored` (success).
            "stealer_rows_parsed": stealer_rows_parsed,
            "stealer_rows_stored": stealer_rows_stored,
            // The status the row was committed with — `aborted` when a cancel
            // reached the import before its enrichment finished — except that
            // a `Complete` row whose finalise did not complete answers
            // `partial`: the store refused some of the relations or
            // correlations derived above, the derivation's time budget cut
            // it short, the correlator's time budget cut it short, the
            // correlation pass failed outright, or both were skipped for size. That row is stored `Complete` (the upload was imported
            // in full) with the shortfall in its `error`, and every export of
            // it reads "partial, finalise-incomplete". Answering `complete`
            // told the client the import was whole while the counts above
            // silently excluded what was lost. `finalise_error` names the
            // shortfall on any terminal status, `null` when there is none.
            "status": match (terminal, &finalise_error) {
                (ScanStatus::Complete, Some(_)) => "partial",
                (status, _) => status.as_str(),
            },
            "finalise_error": finalise_error,
        })),
    )
        .into_response()
}

pub async fn scan_batch(
    State(s): State<Arc<AppState>>,
    // Raw JSON per entry for the same reason as `scan_create`: a batch entry's
    // misspelled option must be a per-entry error, not a silent default.
    Json(requests): Json<Vec<serde_json::Value>>,
) -> impl IntoResponse {
    if requests.is_empty() {
        return bad_request("empty batch");
    }
    if requests.len() > 50 {
        return bad_request("batch too large (max 50)");
    }

    let mut scan_ids = Vec::with_capacity(requests.len());
    for raw in requests {
        let req = match super::scan_request_from_json(raw) {
            Ok(req) => req,
            Err(msg) => {
                scan_ids.push(json!({ "error": msg }));
                continue;
            }
        };
        let (scan, target) = match super::build_scan_from_request(req) {
            Ok(pair) => pair,
            Err(msg) => {
                scan_ids.push(json!({ "error": msg }));
                continue;
            }
        };
        let store = Arc::clone(&s.store);
        let scan_db = scan.clone();
        // Deliberately NOT `offload_store`: a persist failure here records a
        // per-request error and lets the batch continue, whereas `offload_store`
        // would abort the whole batch with a 500 on the first bad entry.
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

/// Build the `(target, options)` for a radar sweep from the optional seed
/// **type**. Pure (no store / engine access) so the radar's invariants — *only*
/// the live device sensors run, `allow_live_sensors` is set (the sole activation
/// path), the sweep is passive and single-round, and it carries no real target —
/// are unit-testable without an `AppState`. `Some("mac"|"mac_address"|"bssid")`
/// anchors the sweep on the local network (a sentinel MAC); anything else (incl.
/// `None`) is the default GPS/RF ambient survey (a sentinel coordinate). The
/// sensors ignore the seed value, so it is always a sentinel, never a target.
pub(crate) fn radar_scan_spec() -> (Target, crate::core::scan::ScanOptions) {
    use crate::core::scan::TargetKind;
    // A fixed sentinel. All five sensors gate on `Coordinates | MacAddress` and
    // ignore the value entirely, so the old `?seed=` knob — which chose only
    // WHICH sentinel kind to use — could not change what any of them collected.
    // The radar has two states, running and stopped; a parameter that alters
    // nothing is a way to think you configured something.
    let (kind, value) = (
        TargetKind::Coordinates,
        crate::core::scan::RADAR_SENTINEL_COORD_RAW,
    );
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
/// it. The sweep is seeded with a sentinel value purely so the sensors (which
/// gate on `Coordinates`/`MacAddress` and ignore the value) dispatch.
///
/// It takes **no parameters at all** — running or stopped is the whole
/// interface.
pub async fn radar_sweep(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    // Armed by default: hitting this endpoint IS the deliberate activation. The
    // `feature.live_radar` toggle is a kill-switch — it only refuses here if the
    // operator has explicitly switched the radar OFF. (Seed scans can never run the
    // sensors regardless — they hard-set `allow_live_sensors:false`.)
    if !crate::util::settings::live_radar_enabled() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "live radar switched off",
                "detail": "the live-sensor radar is armed by default but has been switched off",
                "enable": "re-arm it: set the feature.live_radar toggle on (CLI: hse config feature.live_radar on)",
            })),
        )
            .into_response();
    }
    let (target, opts) = radar_scan_spec();
    let sid = scan_id("radar", target.kind.canonical_str());
    let scan = Scan::new(sid.clone(), target.clone()).with_options(opts);
    let store = Arc::clone(&s.store);
    let scan_db = scan.clone();
    if let Err(resp) = super::offload_store(move || store.upsert_scan(&scan_db)).await {
        return resp;
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
/// Armed by default: this endpoint is the deliberate activation, so no prior
/// opt-in is required. `allow_live_sensors` is set here (server-side); the
/// `feature.live_radar` toggle is a kill-switch that only refuses if explicitly
/// switched off. An ordinary scan can neither reach nor accidentally start it.
pub async fn radar_live(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    if !crate::util::settings::live_radar_enabled() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "live radar switched off",
                "detail": "the live-sensor radar is armed by default but has been switched off",
                "enable": "re-arm it: set the feature.live_radar toggle on (CLI: hse config feature.live_radar on)",
            })),
        )
            .into_response();
    }
    // No seed: the autonomous ambient survey. The sensors ignore the sentinel.
    let (target, opts) = radar_scan_spec();
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

/// `GET /api/v1/radar/history?limit=<n>` — chronological (newest-first) list
/// of past radar sweeps for historical review.
///
/// Unlike `GET /api/v1/live` (which only shows sessions still held in the
/// server's in-memory `LiveSession` map — cleared on every restart), this
/// reads directly from the persisted `scans` table: every sweep a `radar`/
/// `radar/live` call ever queued survives a restart here, so an operator
/// reconstructing "what was around me" after the fact doesn't need to
/// remember a session id — only that a radar sweep ran at some point. This
/// is the sole purpose-built historical-review surface for the live radar
/// feature: personal-safety / situational-awareness review under limited
/// information.
pub async fn radar_history(
    State(s): State<Arc<AppState>>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let limit: usize = params
        .get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(100)
        .clamp(1, 1000);
    let store = Arc::clone(&s.store);
    match super::offload_store(move || store.radar_history(limit)).await {
        Ok(scans) => ok_list("sweeps", scans),
        Err(resp) => resp,
    }
}

/// `GET /api/v1/radar/recurring?min=2&limit=100` — cross-sweep persistent-device
/// review. Walks the radar sweep history (`radar_history`) and reports the
/// devices that recur across ≥`min` distinct sweeps, counting ONLY
/// universally-administered (real hardware) MACs the operator's phone is NOT
/// bonded to — a randomized privacy address rotates and can't recur, and the
/// operator's own paired kit (AU-117) is not a foreign tail. What survives is an
/// UNKNOWN persistent device seen across multiple sweeps: a fixed installation
/// the operator keeps passing, or a device that tracks their movement. This is
/// the counter-surveillance view a single per-scan correlation can never give —
/// it needs the whole sweep history. All analysis is the pure, offline
/// [`crate::core::radar_track`] primitive.
///
/// Each sweep's observations come from the sighting table
/// (`rf_devices_for_scan`: the level and the place, which the entity graph
/// dissolves), with the AU-117 bonded flag looked up on the same sweep's
/// entities, where it lives. A sweep with no sighting rows — one from before
/// the sighting writer existed (REQ-RADAR-001) — is read from its entities
/// as it always was and counted in `legacy_sweeps`, so the review says how
/// much of its window is level-blind rather than hiding it; that path retires
/// with the last such sweep in the window.
pub async fn radar_recurring(
    State(s): State<Arc<AppState>>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    use crate::core::radar_track::{
        Sweep, SweepObservation, observation_from_device, observation_from_entity,
        recurring_devices,
    };

    let limit: usize = params
        .get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(100)
        .clamp(1, 1000);
    let min_sweeps: usize = params.get("min").and_then(|v| v.parse().ok()).unwrap_or(2);

    // Off-reactor: one `radar_history` plus up to `limit` (≤1000) sweeps' worth
    // of sequential reads under the global SQLite mutex, then the pure offline
    // analysis — all on a blocking thread, as every sibling here does.
    let store = Arc::clone(&s.store);
    let read = super::offload_store(move || -> crate::core::error::Result<_> {
        let scans = store.radar_history(limit)?;
        let mut sweeps: Vec<Sweep> = Vec::with_capacity(scans.len());
        let mut legacy_sweeps = 0usize;
        for scan in &scans {
            // A single unreadable sweep must not abort the whole review.
            let Ok(entities) = store.entities_for_scan(&scan.id) else {
                continue;
            };
            let Ok(rows) = store.rf_devices_for_scan(&scan.id) else {
                continue;
            };
            let devices: Vec<SweepObservation> = if rows.is_empty() {
                legacy_sweeps += 1;
                entities
                    .iter()
                    .filter(|e| e.has_tag("bluetooth") || e.has_tag(crate::core::tags::WIFI_AP))
                    .filter_map(observation_from_entity)
                    .collect()
            } else {
                let bonded: std::collections::HashSet<String> = entities
                    .iter()
                    .filter(|e| e.has_tag("bond:bonded"))
                    .map(|e| e.value.trim().to_lowercase())
                    .collect();
                rows.iter()
                    .filter(|d| d.radio.has_hardware_address())
                    .map(|d| observation_from_device(d, bonded.contains(&d.network_id)))
                    .collect()
            };
            sweeps.push(Sweep {
                scan_id: scan.id.clone(),
                ts: scan.started_at,
                devices,
            });
        }
        let devices = recurring_devices(&sweeps, min_sweeps);
        Ok((devices, sweeps.len(), legacy_sweeps))
    })
    .await;
    match read {
        Ok((devices, sweeps, legacy_sweeps)) => {
            let count = devices.len();
            (
                StatusCode::OK,
                Json(json!({
                    "devices": devices,
                    "count": count,
                    "sweeps": sweeps,
                    "legacy_sweeps": legacy_sweeps,
                    "min_sweeps": min_sweeps.max(2),
                })),
            )
                .into_response()
        }
        Err(resp) => resp,
    }
}

/// `GET /api/v1/radar/disruptions?limit=<n>&live=1` — what the sweep history
/// says about the device's own Wi-Fi link (REQ-RESILIENCE-002): forced
/// disconnections (off the network while the access point is still heard),
/// a deauthentication pattern, an evil twin, outages on a schedule, and the
/// outage timeline, over the newest `limit` radar sweeps. Each sweep's link
/// record comes from `wifi_links`; the access points it heard from the
/// sighting table. A sweep that recorded no link (from before the record
/// existed, or one that did not run `device_sensors`) is counted in
/// `unrecorded_sweeps` and left out — the review is not padded with guesses.
/// All analysis is the pure [`crate::core::link::review`]; every finding
/// carries the same `advice` the CLI prints.
///
/// `live=1` additionally runs the network-path probe (REQ-RESILIENCE-003)
/// and carries its verdict beside the Wi-Fi-link findings under an
/// `"outage"` key — a new finding kind, not a separate surface. Opt-in and
/// deliberately NOT part of the default response: unlike everything else
/// this handler reads, it is live network I/O (a DNS lookup, an HTTP fetch,
/// a TLS handshake), and the Radar view's auto-refreshing disruption panel
/// polls this endpoint on every sweep/stream tick — issuing that probe on
/// every poll would add real latency and traffic to a network HSE may
/// already be struggling on. Requested, it runs concurrently with the DB
/// read below, so opting in costs the slower of the two, not their sum.
pub async fn radar_disruptions(
    State(s): State<Arc<AppState>>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let limit: usize = params
        .get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(100)
        .clamp(1, 1000);
    let live = params.get("live").is_some_and(|v| v == "1" || v == "true");
    let store = Arc::clone(&s.store);
    // Off-reactor: the history plus two reads per sweep under the SQLite
    // mutex, then the pure review — the one assembly the CLI uses too.
    let read = super::offload_store(move || {
        let (sweeps, unrecorded) = crate::app::signal::link_sweeps_from_history(&*store, limit)?;
        Ok((crate::core::link::review(&sweeps), unrecorded))
    });
    let outage = async {
        if live {
            Some(crate::core::outage::classify(
                &crate::app::outage::collect().await,
            ))
        } else {
            None
        }
    };
    let (read, outage) = tokio::join!(read, outage);
    match read {
        Ok((report, unrecorded)) => {
            let mut v = crate::app::signal::disruption_report_json(&report, unrecorded);
            if let Some(o) = &outage
                && let serde_json::Value::Object(m) = &mut v
            {
                m.insert(
                    "outage".to_string(),
                    crate::app::outage::outage_report_json(o),
                );
            }
            (StatusCode::OK, Json(v)).into_response()
        }
        Err(resp) => resp,
    }
}

/// `GET /api/v1/radar/devices/{network_id}/track?limit=<n>` — one device's
/// sightings across EVERY sweep and import, oldest first, capped to the newest
/// `limit` (default 500, at most 5000): the movement record the per-sweep
/// track (`/radar/signals/{network_id}`) cannot give, and the trail the map
/// draws. The id is canonicalised the way the store keys it. A device never
/// heard is an empty 200 — the question was answerable.
pub async fn radar_device_track(
    State(s): State<Arc<AppState>>,
    Path(network_id): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let limit: usize = params
        .get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(500)
        .clamp(1, 5000);
    let canonical = crate::core::rf::canonical_network_id(&network_id);
    let wanted = canonical.clone();
    let store = Arc::clone(&s.store);
    match super::offload_store(move || store.rf_device_track(&wanted, limit)).await {
        Ok(points) => {
            let count = points.len();
            let sweeps = points
                .iter()
                .map(|p| p.scan_id.as_str())
                .collect::<std::collections::HashSet<_>>()
                .len();
            (
                StatusCode::OK,
                Json(json!({
                    "network_id": canonical,
                    "points": points,
                    "count": count,
                    "sweeps": sweeps,
                    "limit": limit,
                })),
            )
                .into_response()
        }
        Err(resp) => resp,
    }
}

/// Why a `/radar/signals*` read has no scan to answer about.
enum SignalRefusal {
    /// An explicit `scan_id` that names no scan.
    NoSuchScan,
    /// No `scan_id` given and no sighting recorded anywhere yet, so there is
    /// nothing to default to.
    NothingRecorded,
}

impl SignalRefusal {
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::NoSuchScan => not_found(),
            // A refusal with the CLI's own hint rather than an empty 200: an
            // empty list would read as "nothing around you" when the truth is
            // "nothing recorded".
            Self::NothingRecorded => (
                StatusCode::NOT_FOUND,
                Json(json!({
                    "error": "no RF sightings recorded yet",
                    "detail": "run a radar sweep (POST /api/v1/radar) or import a wardriving capture (hse import <file.kml>) first",
                })),
            )
                .into_response(),
        }
    }
}

/// Which scan a `/radar/signals*` read is about: the explicit `scan_id` when
/// given (it must exist), else the scan of the most recent sighting — "the
/// survey you just ran" — exactly as `hse signal` resolves it, so the CLI and
/// the web reader default the same way.
fn resolve_signal_scan(
    store: &dyn crate::core::StoragePort,
    requested: Option<String>,
) -> crate::core::error::Result<std::result::Result<String, SignalRefusal>> {
    Ok(match requested {
        Some(id) if store.get_scan(&id)?.is_some() => Ok(id),
        Some(_) => Err(SignalRefusal::NoSuchScan),
        None => store
            .rf_latest_scan_id()?
            .ok_or(SignalRefusal::NothingRecorded),
    })
}

/// What the off-reactor read for `radar_signals` brings back.
type SignalsRead = std::result::Result<
    (
        String,
        crate::core::rf::RfSummary,
        Vec<crate::core::rf::RfDeviceRow>,
    ),
    SignalRefusal,
>;

/// `GET /api/v1/radar/signals?scan_id=<id>&trackable=1&limit=<n>` — the
/// sighting table's web reader: one sweep's summary and its device roll-up,
/// strongest first. These are the rows `hse signal` prints, through the same
/// presenters (`app::signal::{summary_json, device_json}`), so the CLI and the
/// web cannot disagree about a field. `scan_id` defaults to the scan of the
/// most recent sighting, as the CLI does; `trackable=1` keeps only
/// fixed-hardware addresses, through the port's one `rf_trackable_devices`
/// definition (AU-122); `limit` caps the rows returned while `total` says how
/// many there were, so a cap never reads as completeness.
pub async fn radar_signals(
    State(s): State<Arc<AppState>>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let requested = params.get("scan_id").cloned();
    let trackable = params
        .get("trackable")
        .is_some_and(|v| v == "1" || v == "true");
    let limit: usize = params
        .get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(500)
        .clamp(1, 5000);
    let store = Arc::clone(&s.store);
    let read = super::offload_store(move || -> crate::core::error::Result<SignalsRead> {
        let sid = match resolve_signal_scan(&*store, requested)? {
            Ok(sid) => sid,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let summary = store.rf_summary(&sid)?;
        let devices = if trackable {
            store.rf_trackable_devices(&sid)?
        } else {
            store.rf_devices_for_scan(&sid)?
        };
        Ok(Ok((sid, summary, devices)))
    })
    .await;
    match read {
        Ok(Ok((sid, summary, devices))) => {
            let total = devices.len();
            let rows: Vec<serde_json::Value> = devices
                .iter()
                .take(limit)
                .map(crate::app::signal::device_json)
                .collect();
            let count = rows.len();
            (
                StatusCode::OK,
                Json(json!({
                    "scan_id": sid,
                    "summary": crate::app::signal::summary_json(&sid, &summary),
                    "devices": rows,
                    "count": count,
                    "total": total,
                    "trackable_only": trackable,
                })),
            )
                .into_response()
        }
        Ok(Err(refusal)) => refusal.into_response(),
        Err(resp) => resp,
    }
}

/// What the off-reactor read for `radar_signal_track` brings back.
type TrackRead = std::result::Result<(String, Vec<crate::core::rf::RfSighting>), SignalRefusal>;

/// `GET /api/v1/radar/signals/{network_id}?scan_id=<id>` — one device's every
/// sighting in a sweep, oldest first: the movement track `hse signal --track`
/// prints, as the same `RfSighting` records. The id is canonicalised the way
/// the store keys it, so an operator's `AA:BB:…` finds `aa:bb:…`. A device
/// never heard in that sweep is an empty track (200), because the question
/// was answerable; only an unknown sweep, or no sighting anywhere yet, refuses.
pub async fn radar_signal_track(
    State(s): State<Arc<AppState>>,
    Path(network_id): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let requested = params.get("scan_id").cloned();
    let canonical = crate::core::rf::canonical_network_id(&network_id);
    let wanted = canonical.clone();
    let store = Arc::clone(&s.store);
    let read = super::offload_store(move || -> crate::core::error::Result<TrackRead> {
        let sid = match resolve_signal_scan(&*store, requested)? {
            Ok(sid) => sid,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let rows = store.rf_sightings_for_device(&sid, &wanted)?;
        Ok(Ok((sid, rows)))
    })
    .await;
    match read {
        Ok(Ok((sid, rows))) => {
            let count = rows.len();
            (
                StatusCode::OK,
                Json(json!({
                    "scan_id": sid,
                    "network_id": canonical,
                    "sightings": rows,
                    "count": count,
                })),
            )
                .into_response()
        }
        Ok(Err(refusal)) => refusal.into_response(),
        Err(resp) => resp,
    }
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
    let events = match super::offload_store(move || store.events_for_scan(&id2)).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    ok_list("events", events)
}
