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
    scan_correlations, scan_diff, scan_entities, scan_entities_facets, scan_entities_filter,
    scan_identities, scan_network, scan_relations,
};
pub use core::{
    plan_preview, radar_live, radar_sweep, scan_auto, scan_auto_plan, scan_auto_sweep, scan_batch,
    scan_cancel, scan_create, scan_delete, scan_events_history, scan_get, scan_import, scan_list,
    scan_rerun,
};
pub use diagnostics::{
    scan_audit, scan_benchmark, scan_duplicates, scan_gaps, scan_metrics, scan_pivots,
};
pub use intel::{scan_communities, scan_leads, scan_path, scan_timeline, scan_trust};

// Re-exported for tests (private helper, only needed in the test module).
#[cfg(test)]
pub(crate) use core::radar_scan_spec;

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
        opts = profile_opts;
    }
    let scan = Scan::new(sid, target.clone()).with_options(opts.clamp_depth());
    Ok((scan, target))
}

/// `Some(404)` when no scan with `id` exists (or `Some(500)` on a store error),
/// else `None`. Sub-resource handlers call this first so an unknown scan yields
/// 404 rather than a misleading empty 200.
pub(crate) fn scan_missing(s: &AppState, id: &str) -> Option<axum::response::Response> {
    match s.store.get_scan(id) {
        Ok(Some(_)) => None,
        Ok(None) => Some(not_found()),
        Err(e) => Some(internal_error(&e)),
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

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
