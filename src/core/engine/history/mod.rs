//! Cross-scan historical linking — the local intelligence flywheel.
//!
//! Recall ([`crate::core::engine::ScanEngine::recall_prior_entities`]) is
//! seed-centric: it replays prior scans OF THE SAME subject. But a fresh finding
//! in this scan often appears in a DIFFERENT subject's earlier scan — a shared
//! address, phone, email or named person — and recall never makes that link
//! because the seeds differ. This finalize pass closes the gap: for each specific
//! personal identifier the scan produced, it asks the store whether any earlier
//! scan recorded the same value, and tags the recurrence so each scan compounds
//! the next.
//!
//! Provenance only: the [`crate::core::entity::CROSS_SCAN_SOURCE`] evidence it
//! attaches is non-corroborating (a recurrence can't tell a re-scan of one subject
//! from an independent sighting), so it never inflates confidence — the value is
//! the surfaced cross-investigation LINK, not a score bump. Pure over a
//! [`StoragePort`] (point lookups only, bounded), so it never fails a scan over a
//! history query.

use crate::core::entity::{CROSS_SCAN_SOURCE, Entity, EntityKind, Evidence};
use crate::core::port::StoragePort;

/// Max entities probed against history per scan — bounds the indexed point-queries
/// at finalise on a low-RAM Termux device. Specific identifiers in a scan number a
/// few dozen at most, so this rarely bites; it just caps the pathological case.
const MAX_PROBES: usize = 48;

/// True if `e` is a SPECIFIC personal identifier worth checking against history —
/// the kind of value whose recurrence across scans genuinely bridges two
/// investigations. Excludes infrastructure (every scan touches `google.com`),
/// speculative permutations, coarse geo (a postcode is shared by thousands), and
/// already-recalled nodes (those are known historical by construction).
#[must_use]
pub(super) fn is_cross_scan_candidate(e: &Entity) -> bool {
    if e.has_tag(crate::core::tags::RECALLED) || e.has_tag("name-derived") || e.has_tag("permuted")
    {
        return false;
    }
    match e.kind {
        EntityKind::Email | EntityKind::Phone | EntityKind::CryptoAddress => e.confidence >= 0.40,
        EntityKind::Username => e.confidence >= 0.40 && e.value.len() >= 4,
        EntityKind::Person => e.confidence >= 0.40 && e.value.split_whitespace().count() >= 2,
        // A SPECIFIC address only — a coarse postcode/suburb centroid is shared by
        // far too many people to be a meaningful cross-investigation bridge.
        EntityKind::Address => {
            e.confidence >= 0.40
                && !e.has_tag("coarse")
                && !e.has_tag("postcode-only")
                && !e.has_tag("candidate-suburb")
        }
        _ => false,
    }
}

/// Link this scan's findings to the local intelligence history.
///
/// For each [`is_cross_scan_candidate`] identifier, ask the store whether any
/// EARLIER scan recorded the same value (the entity isn't persisted for this scan
/// yet, so any hit is genuinely prior). A recurrence earns a `cross-scan` tag and a
/// [`CROSS_SCAN_SOURCE`] evidence record naming how many prior scans share it — the
/// bridge that turns a pile of isolated scans into one connected intelligence base.
/// Non-corroborating (never inflates confidence), bounded ([`MAX_PROBES`]),
/// idempotent, and store errors are skipped (a history lookup must never fail a
/// scan). Returns the number of entities bridged.
pub(super) fn link_cross_scan_history(
    store: &dyn StoragePort,
    entities: &mut [Entity],
    scan_id: &str,
) -> usize {
    let mut linked = 0usize;
    let mut probes = 0usize;
    for e in entities.iter_mut() {
        if probes >= MAX_PROBES {
            break;
        }
        if e.has_tag("cross-scan") || !is_cross_scan_candidate(e) {
            continue;
        }
        probes += 1;
        let Ok(ids) = store.scan_ids_for_entity(&e.uid) else {
            continue;
        };
        let prior = ids.iter().filter(|id| id.as_str() != scan_id).count();
        if prior == 0 {
            continue;
        }
        e.tag("cross-scan");
        e.add_evidence(Evidence::new(
            CROSS_SCAN_SOURCE,
            format!(
                "Also recorded in {prior} earlier scan(s) in the local intelligence database — \
                 this identifier bridges investigations"
            ),
        ));
        linked += 1;
    }
    if linked > 0 {
        tracing::info!(
            linked,
            "cross-scan history: findings bridged to earlier investigations"
        );
    }
    linked
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
