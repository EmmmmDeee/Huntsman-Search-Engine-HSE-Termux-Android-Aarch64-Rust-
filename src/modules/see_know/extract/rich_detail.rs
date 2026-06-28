//! Rich-detail (context) extraction from SeekNow records.
//!
//! A thin see_know-specific adapter over the shared, source-parameterised
//! [`crate::modules::breach_rich::extract_rich_detail`]. The long-tail field
//! mapping (device fingerprints, social handles, address parts, employer, and
//! the catch-all scalar pass) lives there once so see_know and oathnet_pro
//! surface the identical field set with the same semantics and can't drift.
//! Reaches parent imports (`Value`, `Evidence`, `ModuleResult`, `HashSet`) via
//! `use super::*`.

use super::*;

/// Maximum-raw-data extractor for a SeekNow record, tagging the `see-know`
/// provider source. Pushes at full confidence; the caller demotes a non-target
/// row's contributed range (see `extract_entities`).
pub(super) fn extract_rich_detail(
    item: &Value,
    scan_id: &str,
    ev: &Evidence,
    seen: &mut HashSet<String>,
    result: &mut ModuleResult,
) {
    crate::modules::breach_rich::extract_rich_detail(item, scan_id, "see-know", ev, seen, result);
}
