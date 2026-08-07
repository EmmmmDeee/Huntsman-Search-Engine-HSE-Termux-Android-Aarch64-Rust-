//! HTTP handlers for the `/api/v1/scans` family of routes.
//!
//! Split by responsibility:
//! - [`core`] — CRUD lifecycle: create, cancel, list, get, delete, rerun,
//!   import, batch, radar, plan preview, events history.
//! - [`analysis`] — Entity analysis: entities, diff, filter, facets,
//!   correlations, relations, network.
//! - [`intel`] — Intelligence synthesis: leads, timeline, communities,
//!   trust, path.
//! - [`diagnostics`] — Diagnostic scorecards: audit, metrics, duplicates,
//!   pivots, gaps, benchmark.

use super::handlers::{not_found, offload_store, validated_target};
use crate::api::AppState;
use crate::core::entity::scan_id;
use crate::core::scan::{Scan, ScanRequest, Target};

pub mod analysis;
pub mod core;
pub mod diagnostics;
pub mod intel;

// ─── Public re-exports ────────────────────────────────────────────────────────

pub use analysis::{
    scan_attack, scan_correlations, scan_cross_scan, scan_diamond, scan_diff, scan_entities,
    scan_entities_facets, scan_entities_filter, scan_exposure, scan_identities, scan_location,
    scan_network, scan_relations, scan_snake_svg, scan_stealer_rows,
};
pub use core::{
    plan_preview, radar_history, radar_live, radar_recurring, radar_sweep, scan_auto,
    scan_auto_plan, scan_auto_sweep, scan_batch, scan_cancel, scan_create, scan_delete,
    scan_events_history, scan_get, scan_import, scan_list, scan_profiles, scan_rerun,
};
pub use diagnostics::{
    scan_audit, scan_benchmark, scan_duplicates, scan_gaps, scan_metrics, scan_pivots,
};
pub use intel::{scan_communities, scan_leads, scan_path, scan_timeline, scan_trust};

// Re-exported for tests (private helper, only needed in the test module).
#[cfg(test)]
pub(crate) use core::radar_scan_spec;
#[cfg(test)]
pub(crate) use diagnostics::snapshot_still_relevant_to;

// ─── Constants ────────────────────────────────────────────────────────────────

/// Maximum upload body size for `POST /scans/import`. Shared with the route
/// `DefaultBodyLimit` so both limits stay in sync. 16 MB comfortably fits a
/// large multi-entry dossier on a low-RAM Termux device.
pub const MAX_UPLOAD_BYTES: usize = 16 * 1024 * 1024;

// ─── Shared helpers ───────────────────────────────────────────────────────────

/// Build a validated, profile-resolved `Scan` (+ its `Target`) from a request,
/// or a client-facing error message. Shared by `scan_create` and `scan_batch`
/// so validation, scan-id derivation, and profile→options resolution can't drift.
pub(super) fn build_scan_from_request(req: ScanRequest) -> Result<(Scan, Target), String> {
    let kind = req.resolved_kind();
    let target = validated_target(kind, req.value.clone())?;
    let sid = scan_id(kind.canonical_str(), &req.value);
    let mut opts = req.options;
    if let Some(ref profile_name) = opts.profile
        && let Some(profile_opts) = crate::core::profiles::resolve_profile(profile_name)
    {
        // Field-by-field overlay — the SAME policy the CLI's `--profile` flag
        // uses — not a wholesale replace. A full `opts = profile_opts` used to
        // silently discard every other client-supplied option (`modules`,
        // `min_confidence`, `webhook_url`, …) the moment a profile was named.
        opts = crate::core::profiles::apply_profile_overlay(opts, profile_opts);
    }
    let scan = Scan::new(sid, target.clone()).with_options(opts.clamp_depth());
    Ok((scan, target))
}

/// `Some(404)` when no scan with `id` exists (or `Some(500)` on a store error),
/// else `None`. Sub-resource handlers call this first so an unknown scan yields
/// 404 rather than a misleading empty 200. Runs its `get_scan` probe off the
/// reactor via [`offload_store`].
pub(crate) async fn scan_missing(s: &AppState, id: &str) -> Option<axum::response::Response> {
    let store = std::sync::Arc::clone(&s.store);
    let id = id.to_string();
    match offload_store(move || store.get_scan(&id)).await {
        Ok(Some(_)) => None,
        Ok(None) => Some(not_found()),
        Err(resp) => Some(resp),
    }
}

/// Load a scan's entities and relations together, off the async reactor.
///
/// Both reads are synchronous SQLite under the global connection mutex, so they
/// run on the blocking pool in ONE hop rather than stalling one of the ~2 async
/// workers. This is THE place every read-only synthesis handler that needs the
/// full graph (communities, trust, metrics, pivots, gaps, network, snake-svg)
/// loads it — seven handlers had an identical hand-rolled `spawn_blocking`
/// copy — so a new such handler cannot reintroduce a raw off-reactor copy or,
/// worse, forget the hop and block a worker on the persisted read.
///
/// Returns the `(entities, relations)` pair, or the ready `Response` (500) to
/// return on a store or join failure. The caller is expected to have already run
/// the [`scan_missing`] 404 probe, exactly as the inline copies did.
pub(super) async fn entities_and_relations(
    s: &AppState,
    id: &str,
) -> Result<
    (
        Vec<crate::core::entity::Entity>,
        Vec<crate::core::relation::Relation>,
    ),
    axum::response::Response,
> {
    let store = std::sync::Arc::clone(&s.store);
    let id = id.to_string();
    offload_store(move || {
        Ok((
            store.entities_for_scan(&id)?,
            store.relations_for_scan(&id)?,
        ))
    })
    .await
}

/// Load a scan's entities off the async reactor — the single-set analogue of
/// [`entities_and_relations`], for the read handlers that synthesise from the
/// entity set alone (`/entities`, `/diamond`, `/attack`, `/duplicates`,
/// `/timeline`, …). Same rationale: `entities_for_scan` is synchronous SQLite
/// under the global connection mutex, so it runs on the blocking pool rather
/// than stalling one of the ~2 async workers, and routing every such handler
/// through here means a new one cannot reintroduce a raw `spawn_blocking` copy
/// or forget the off-reactor hop. Returns the entities, or the ready `Response`
/// (500) to return on a store/join failure; the caller has already run the
/// [`scan_missing`] 404 probe.
pub(super) async fn scan_entities_only(
    s: &AppState,
    id: &str,
) -> Result<Vec<crate::core::entity::Entity>, axum::response::Response> {
    let store = std::sync::Arc::clone(&s.store);
    let id = id.to_string();
    offload_store(move || store.entities_for_scan(&id)).await
}

/// Load a scan RECORD together with its entities and relations, off the async
/// reactor and in one hop.
///
/// The sibling of [`entities_and_relations`] for the handlers that also need the
/// `Scan` record itself (`/leads` reads `scan.options`, `/benchmark` reports over
/// it). Unlike the entity-only loaders — which pair with a prior [`scan_missing`]
/// 404 probe — this folds the existence check into the SAME `spawn_blocking`
/// batch: `Ok(None)` means the scan is unknown (the caller renders 404), so the
/// handler pays for one off-reactor round-trip, not a separate `get_scan` probe
/// followed by the load. `Err` is the ready 500 `Response` on a store/join
/// failure.
#[allow(clippy::type_complexity)]
pub(super) async fn scan_with_graph(
    s: &AppState,
    id: &str,
) -> Result<
    Option<(
        Scan,
        Vec<crate::core::entity::Entity>,
        Vec<crate::core::relation::Relation>,
    )>,
    axum::response::Response,
> {
    let store = std::sync::Arc::clone(&s.store);
    let id = id.to_string();
    offload_store(move || {
        let Some(scan) = store.get_scan(&id)? else {
            return Ok(None);
        };
        Ok(Some((
            scan,
            store.entities_for_scan(&id)?,
            store.relations_for_scan(&id)?,
        )))
    })
    .await
}

/// True if the request opts into quarantined `candidate` entities via
/// `?include_candidates=1|true|yes|on`. Default is to hide them.
pub(crate) fn wants_candidates(params: &std::collections::HashMap<String, String>) -> bool {
    params
        .get("include_candidates")
        .is_some_and(|v| matches!(v.as_str(), "1" | "true" | "yes" | "on"))
}

/// True when the query string contains `?include_infra=1|true|yes|on`.
/// Default is to suppress `platform-infra`-tagged entities (cloud buckets,
/// CDN IPs, analytics IDs sourced from third-party pages) so the report
/// shows only subject-owned entities.
pub(crate) fn wants_infra(params: &std::collections::HashMap<String, String>) -> bool {
    params
        .get("include_infra")
        .is_some_and(|v| matches!(v.as_str(), "1" | "true" | "yes" | "on"))
}

/// Drop quarantined `candidate` entities in place unless the request opted in
/// via `?include_candidates=1`. THE single enforcement point for the candidate
/// quarantine on every entity-serving read endpoint (`/entities`, `/diamond`,
/// `/attack`, the filtered `/entities` view, `/identities`, …) — so a new
/// handler physically cannot forget it and re-leak low-confidence, non-subject
/// PII by default. Mirrors the download-side quarantine (`report.json`, CSV,
/// `graph.gexf`).
pub(crate) fn apply_candidate_gate(
    entities: &mut Vec<crate::core::entity::Entity>,
    params: &std::collections::HashMap<String, String>,
) {
    if !wants_candidates(params) {
        entities.retain(|e| !e.has_tag(crate::core::tags::CANDIDATE));
    }
}

/// Graph analogue of [`apply_candidate_gate`]: hide quarantined `candidate`
/// entities AND drop every relation with a now-hidden endpoint, so a
/// graph / network / relations view leaks a candidate neither as a node value
/// nor as a dangling edge whose `from_uid`/`to_uid` re-exposes the quarantined
/// entity's UID (the class of leak the CLI/GEXF dangling-edge fix already closed
/// on the export side). Returns the visible entities paired with the relations
/// confined to them; when the caller opts into candidates the pair is returned
/// untouched.
pub(crate) fn confine_graph_to_visible(
    mut entities: Vec<crate::core::entity::Entity>,
    relations: Vec<crate::core::relation::Relation>,
    params: &std::collections::HashMap<String, String>,
) -> (
    Vec<crate::core::entity::Entity>,
    Vec<crate::core::relation::Relation>,
) {
    if wants_candidates(params) {
        return (entities, relations);
    }
    apply_candidate_gate(&mut entities, params);
    let visible: std::collections::HashSet<&str> =
        entities.iter().map(|e| e.uid.as_str()).collect();
    let relations = relations
        .into_iter()
        .filter(|r| visible.contains(r.from_uid.as_str()) && visible.contains(r.to_uid.as_str()))
        .collect();
    (entities, relations)
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
