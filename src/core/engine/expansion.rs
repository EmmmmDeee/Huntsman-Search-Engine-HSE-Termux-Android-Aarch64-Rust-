//! Pure expansion/dedup bookkeeping helpers used by the round loop: stable
//! dedup keys for correlations and visited targets, and the deterministic total
//! order over expansion candidates. No engine state — split out so the loop reads
//! as control flow while the key/ordering policy lives in one place.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use crate::core::entity::{Entity, normalise};
use crate::core::scan::{ScanOptions, Target, TargetKind};

use super::StopReason;

/// The effective confidence used for EXPANSION decisions (the floor gate, the
/// ranking weight, and the wrong-identity/convex premiums): plain
/// [`Entity::c_effective`], or — under the opt-in `feature.depth_decay` policy —
/// that value discounted by the entity's generation (distance in pivots from
/// the seed). Pure. `decay_base` is `None` when the policy is off (the
/// default), giving behaviour byte-identical to a bare `entity.c_effective()`;
/// `Some(base)` discounts deeper leads so the recursion favours seed-adjacent
/// ones. Centralised here so the loop applies the SAME value to every downstream
/// expansion decision, and so the branch is unit-testable without touching the
/// global settings the engine reads the toggle from.
pub(super) fn expansion_confidence(entity: &Entity, decay_base: Option<f64>) -> f64 {
    match decay_base {
        Some(base) => entity.c_effective_depth_decayed(base),
        None => entity.c_effective(),
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::correlator::{Correlation, Severity};

    fn corr(rule: &str, uids: &[&str]) -> Correlation {
        Correlation::new(
            rule,
            "title",
            Severity::Medium,
            "desc".to_string(),
            uids.iter().map(|s| (*s).to_string()).collect(),
            "scan",
            0,
        )
    }

    #[test]
    fn correlation_key_is_order_independent_over_uids() {
        // Same rule + same uid SET in different orders → identical key.
        let a = correlation_key(&corr("AU-001", &["u3", "u1", "u2"]));
        let b = correlation_key(&corr("AU-001", &["u1", "u2", "u3"]));
        assert_eq!(a, b);
    }

    #[test]
    fn correlation_key_differs_on_rule_or_uid_set() {
        let base = correlation_key(&corr("AU-001", &["u1", "u2"]));
        // Different rule id → different finding.
        assert_ne!(base, correlation_key(&corr("AU-002", &["u1", "u2"])));
        // Different uid set → different finding.
        assert_ne!(base, correlation_key(&corr("AU-001", &["u1", "u3"])));
    }

    #[test]
    fn expansion_confidence_decays_only_when_the_policy_is_on() {
        use crate::core::confidence;
        use crate::core::entity::{Entity, EntityKind};
        let mut e = Entity::new(EntityKind::Email, "x@y.com", confidence::HIGH_PLUSPLUS, "s");
        e.generation = 2;

        // Policy OFF (None) ⇒ plain c_effective, byte-identical to today.
        assert_eq!(expansion_confidence(&e, None), e.c_effective());

        // Policy ON ⇒ the value the engine's floor/rank/gate see is the
        // generation-discounted one, strictly below the raw confidence.
        let decayed = expansion_confidence(&e, Some(0.75));
        assert!(decayed < e.c_effective());
        assert!((decayed - e.c_effective_depth_decayed(0.75)).abs() < 1e-12);

        // A gen-0 (seed-round) entity is never discounted even with the policy on.
        let mut seed = Entity::new(EntityKind::Email, "z@y.com", confidence::HIGH_PLUSPLUS, "s");
        seed.generation = 0;
        assert!((expansion_confidence(&seed, Some(0.75)) - seed.c_effective()).abs() < 1e-12);
    }
}
