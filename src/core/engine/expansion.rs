//! Pure expansion/dedup bookkeeping helpers used by the round loop: stable
//! dedup keys for correlations and visited targets, and the deterministic total
//! order over expansion candidates. No engine state — split out so the loop reads
//! as control flow while the key/ordering policy lives in one place.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use crate::core::entity::normalise;
use crate::core::scan::{ScanOptions, Target, TargetKind};

use super::StopReason;

/// Stable dedup key for a correlation: rule id + its entity uids (sorted), joined
/// with control characters that can't appear in either, so two correlations are
/// "the same finding" iff they share a rule and entity set regardless of order.
pub(super) fn correlation_key(c: &crate::core::correlator::Correlation) -> String {
    let mut uids = c.entity_uids.clone();
    uids.sort();
    format!("{}\u{1f}{}", c.rule_id, uids.join("\u{1e}"))
}

/// Visit-key for the expansion visited-set. Normalises the value the same
/// way `Entity::new` does, so the seed target matches entities that point
/// back at it.
pub(super) fn visit_key(target: &Target) -> (TargetKind, String) {
    let entity_kind = target.kind.to_entity_kind();
    let normalised = normalise(&entity_kind, &target.value);
    (target.kind, normalised)
}

/// Deterministic total order for expansion candidates `(Target, weight, parent)`:
/// highest weight first, ties broken by target kind then value. A NaN weight
/// sorts last (treated as the lowest) rather than silently comparing Equal. This
/// is what makes a budgeted scan reproducible — see the call site in the
/// expansion loop for why the HashMap-iteration input order must not leak through
/// a weight tie into which candidates a `truncate(keep)` keeps.
pub(super) fn cmp_expansion_candidates(
    a: &(Target, f64, String),
    b: &(Target, f64, String),
) -> std::cmp::Ordering {
    // Descending weight: `b` vs `a`. NaN is pushed to the bottom deterministically.
    let by_weight = match (a.1.is_nan(), b.1.is_nan()) {
        (false, false) => b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal),
        (true, false) => std::cmp::Ordering::Greater, // a is NaN → a after b
        (false, true) => std::cmp::Ordering::Less,
        (true, true) => std::cmp::Ordering::Equal,
    };
    by_weight
        .then_with(|| a.0.kind.canonical_str().cmp(b.0.kind.canonical_str()))
        .then_with(|| a.0.value.cmp(&b.0.value))
}

/// ROI top-K + knee cutoff over a weight-sorted candidate round, releasing the
/// visited keys of everything it cuts.
///
/// The release is the load-bearing half: `visited` means "dispatched (or still
/// queued)", but a candidate cut here is *neither* — it was queued, then
/// dropped before any dispatch. Leaving its key in `visited` excluded the same
/// lead as `already_dispatched_this_scan` in every later round, so a lead whose
/// weight rises as corroboration accrues could never compete again — silently
/// lost for the rest of the scan. Releasing the key lets it re-enter a later
/// round's ranking on its new weight. Halting is unaffected: rounds are capped
/// by `depth`, each round dispatches at most the cutoff, and a re-queued
/// candidate either dispatches (entering `visited` for good) or is cut again.
pub(super) fn apply_roi_cutoff(
    next: &mut Vec<(Target, f64, String)>,
    visited: &mut HashSet<(TargetKind, String)>,
    max_concurrent: usize,
) {
    let weights: Vec<f64> = next.iter().map(|(_, w, _)| *w).collect();
    let keep = crate::core::roi::effective_cutoff(&weights, max_concurrent);
    if next.len() > keep {
        for (t, _, _) in &next[keep..] {
            visited.remove(&visit_key(t));
        }
        next.truncate(keep);
    }
}

/// Stop the expansion when an entity- or wall-time budget is hit. Pure over
/// `ScanOptions` + the round's start instant and current entity count.
pub(super) fn budget_check(
    opts: &ScanOptions,
    started: Instant,
    current_count: usize,
) -> Option<StopReason> {
    if let Some(max) = opts.max_entities
        && current_count >= max
    {
        return Some(StopReason::MaxEntities(max));
    }
    if let Some(max_secs) = opts.max_wall_time_secs
        && started.elapsed() >= Duration::from_secs(max_secs)
    {
        return Some(StopReason::MaxWallTime(max_secs));
    }
    None
}
