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

use super::handlers::{internal_error, not_found, validated_target};
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
/// 404 rather than a misleading empty 200.
///
/// The `get_scan` probe is synchronous SQLite under the global connection mutex,
/// so it runs on the blocking pool — not inline on the ~2-worker async reactor
/// where it would block a worker before each sub-resource handler's own
/// `spawn_blocking` read.
pub(crate) async fn scan_missing(s: &AppState, id: &str) -> Option<axum::response::Response> {
    let store = std::sync::Arc::clone(&s.store);
    let id = id.to_string();
    match tokio::task::spawn_blocking(move || store.get_scan(&id)).await {
        Ok(Ok(Some(_))) => None,
        Ok(Ok(None)) => Some(not_found()),
        Ok(Err(e)) => Some(internal_error(&e)),
        Err(e) => Some(internal_error(&format!("query task failed: {e}"))),
    }
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
