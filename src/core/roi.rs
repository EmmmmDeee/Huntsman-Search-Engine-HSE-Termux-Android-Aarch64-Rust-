//! ROI-maximising expansion controls.
//!
//! Three orthogonal levers, all opt-in via [`ScanOptions::max_roi`]:
//!
//! 1. **Convergence-pruning** — an entity with ≥2 corroborating sources
//!    AND `c_eff ≥ 0.85` is considered "saturated" and is *not*
//!    re-expanded. Saves dispatch budget on entities that further
//!    queries would only re-confirm.
//!
//! 2. **Top-K candidate gate** — within an expansion round, keep only
//!    the top `2 × max_concurrent + 8` candidates by weight. Stops
//!    long-tail noise (e.g. 80 low-weight domains discovered through a
//!    single search engine) from consuming the round.
//!
//! 3. **Adaptive-depth termination** — when the prior round produced
//!    fewer than `min_marginal_yield` entities per dispatched target,
//!    stop recursing even if `--depth` would allow more rounds. The
//!    marginal yield collapses near convergence; this captures the
//!    `dE/dDispatch → 0` boundary.
//!
//! All three are pure-functions over the entity map; no I/O.

use crate::core::entity::Entity;

/// Threshold at which an entity is considered "saturated" — corroborated
/// by enough independent sources at high enough confidence that further
/// expansion would yield no new information.
pub const SATURATION_CORROBORATION: u32 = 2;
pub const SATURATION_CONFIDENCE: f64 = 0.85;

/// Default marginal-yield floor for adaptive-depth termination, expressed
/// as `new_entities / dispatched_targets` for the prior round. At rates
/// below this the next round is dominated by re-confirmation rather than
/// new discovery, so we cut recursion early.
pub const DEFAULT_MIN_MARGINAL_YIELD: f64 = 0.75;

/// True if an entity has reached the convergence threshold and should be
/// skipped from further expansion under `max_roi` mode.
pub fn is_saturated(entity: &Entity) -> bool {
    // Distinct corroborating SOURCES, not the summed `corroboration` magnitude.
    // An 8-row single-source hit (corroboration=8, source_count=1) must NOT be
    // treated as saturated and pruned from expansion — the rest of the engine
    // deliberately migrated off the inflated counter to `source_count()`
    // (see Entity::source_count), and this module's own doc says "≥2 sources".
    entity.source_count() >= SATURATION_CORROBORATION
        && entity.c_effective() >= SATURATION_CONFIDENCE
}

/// Top-K cap on expansion candidates per round. Scales with concurrency
/// so a 16-worker scan keeps a deeper pool than a 4-worker scan.
pub fn top_k_for_round(max_concurrent: usize) -> usize {
    2 * max_concurrent.max(1) + 8
}

/// Marginal yield = new entities discovered last round / targets dispatched.
/// Returns `f64::INFINITY` when no targets were dispatched (first round,
/// or empty queue) — never terminates recursion on insufficient data.
pub fn marginal_yield(new_entities: usize, dispatched_targets: usize) -> f64 {
    if dispatched_targets == 0 {
        f64::INFINITY
    } else {
        new_entities as f64 / dispatched_targets as f64
    }
}

/// True iff adaptive-depth termination should fire — i.e. marginal yield
/// is below floor AND we have meaningful data (at least one prior round).
pub fn should_terminate_adaptive(
    enabled: bool,
    new_entities: usize,
    dispatched_targets: usize,
    floor: f64,
) -> bool {
    if !enabled {
        return false;
    }
    // Don't terminate on the very first round (insufficient data).
    if dispatched_targets == 0 {
        return false;
    }
    marginal_yield(new_entities, dispatched_targets) < floor
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::entity::{Entity, EntityKind, Evidence};

    fn make(conf: f64, corrob: u32) -> Entity {
        let mut e = Entity::new(EntityKind::Email, "x@y.com", conf, "scan");
        e.corroboration = corrob;
        e
    }

    #[test]
    fn saturation_requires_both_corroboration_and_confidence() {
        // High conf, low corrob → not saturated
        assert!(!is_saturated(&make(0.95, 1)));
        // Low conf, high corrob → not saturated
        assert!(!is_saturated(&make(0.50, 5)));
        // Both above thresholds → saturated
        assert!(is_saturated(&make(0.90, 3)));
    }

    #[test]
    fn single_source_high_magnitude_is_not_saturated() {
        // 8 observations but all from ONE source (e.g. one hibp hit listing 8
        // breaches): source_count()==1 < 2, so it stays expandable even though
        // the summed corroboration magnitude is high. The pre-fix code read
        // `corroboration` and would have wrongly pruned this pivot under --max-roi.
        let mut e = Entity::new(EntityKind::Email, "x@y.com", 0.95, "scan");
        e.corroboration = 8;
        e.add_evidence(Evidence::new("hibp", "8 breaches"));
        assert_eq!(e.source_count(), 1);
        assert!(!is_saturated(&e), "one distinct source must not saturate");
        // A second DISTINCT source at the same confidence does saturate.
        e.add_evidence(Evidence::new("dehashed", "also seen"));
        assert_eq!(e.source_count(), 2);
        assert!(is_saturated(&e));
    }

    #[test]
    fn top_k_scales_with_concurrency() {
        assert_eq!(top_k_for_round(0), 10); // 2*1+8
        assert_eq!(top_k_for_round(4), 16);
        assert_eq!(top_k_for_round(16), 40);
    }

    #[test]
    fn marginal_yield_handles_zero_dispatches() {
        assert_eq!(marginal_yield(0, 0), f64::INFINITY);
        assert_eq!(marginal_yield(10, 5), 2.0);
        assert_eq!(marginal_yield(1, 4), 0.25);
    }

    #[test]
    fn adaptive_termination_only_fires_when_enabled_and_below_floor() {
        // Disabled → never terminates
        assert!(!should_terminate_adaptive(false, 0, 100, 1.0));
        // Enabled, no prior dispatches → no termination (insufficient data)
        assert!(!should_terminate_adaptive(true, 0, 0, 1.0));
        // Enabled, yield above floor → continue
        assert!(!should_terminate_adaptive(true, 10, 5, 1.0));
        // Enabled, yield below floor → terminate
        assert!(should_terminate_adaptive(true, 1, 10, 1.0));
    }
}
