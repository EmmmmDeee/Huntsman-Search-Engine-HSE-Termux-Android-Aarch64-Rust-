//! Fully autonomous investigation handlers — no seed input. The platform
//! ranks entities it has already collected and dispatches a scan on its own
//! initiative: a single strongest target ([`scan_auto`]), a read-only queue
//! preview ([`scan_auto_plan`]), or a diversity-aware multi-target sweep
//! ([`scan_auto_sweep`]).

use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use std::sync::Arc;
use tracing::info;

use super::super::handlers::{offload, spawn_scan};
use crate::api::AppState;
use crate::core::entity::scan_id;
use crate::core::scan::{Scan, Target, TargetKind};

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
    let selected = offload(
        "query",
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
    .await;

    let from_base = match selected {
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
    if let Err(resp) = offload("db", move || store.upsert_scan(&scan_db)).await {
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

/// Build the candidate pool from recent-scan history (bounded by
/// [`AUTONOMOUS_POOL_MAX_SCANS`]/[`AUTONOMOUS_POOL_MAX_ENTITIES`]) and run
/// [`crate::core::engine::plan_autonomous_sweep`] against it, all on the
/// blocking pool via [`offload`]. Shared by [`scan_auto_plan`] (`target_count`
/// is the preview `limit`) and [`scan_auto_sweep`] (`target_count` is the
/// dispatch `breadth`) — the two differ only in how many queue entries they
/// ask for and what they do with the plan afterward.
async fn plan_autonomous_sweep_via_store(
    store: Arc<dyn crate::core::StoragePort>,
    target_count: usize,
    diversity: f64,
) -> Result<crate::core::engine::AutonomousPlan, axum::response::Response> {
    use std::collections::HashSet;
    offload(
        "query",
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
                target_count,
                diversity,
            ))
        },
    )
    .await
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
    let limit = params
        .get("limit")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(20)
        .clamp(1, 200);
    let diversity = params
        .get("diversity")
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(crate::core::engine::DEFAULT_SWEEP_DIVERSITY);

    let plan = match plan_autonomous_sweep_via_store(Arc::clone(&s.store), limit, diversity).await {
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
/// [`super::core::scan_batch`] path. Bounded by `breadth` (default 5,
/// capped at 25) so it can never flood a low-RAM device. Optional query params:
/// `breadth` and `diversity` (see [`scan_auto_plan`]). Returns 202 with the
/// dispatched scans, or a clean 422 (never a 500) when the base holds nothing to
/// investigate yet.
pub async fn scan_auto_sweep(
    State(s): State<Arc<AppState>>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let breadth = params
        .get("breadth")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(5)
        .clamp(1, 25);
    let diversity = params
        .get("diversity")
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(crate::core::engine::DEFAULT_SWEEP_DIVERSITY);

    let plan = match plan_autonomous_sweep_via_store(Arc::clone(&s.store), breadth, diversity).await
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
