//! ROI-maximising expansion controls.
//!
//! Three orthogonal levers, all opt-in via [`crate::core::scan::ScanOptions::max_roi`]:
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

/// Fraction of the leading candidate's weight below which a candidate is
/// treated as long-tail noise and dropped from the round — even if it would
/// fit under [`top_k_for_round`]. Conservative (5%) so it only bites genuine
/// bottom-feeders (dampened mega-domains, barely-above-floor leads) that sort
/// 20×+ below a strong geo/identity pivot, never the contested middle.
pub const KNEE_FRACTION: f64 = 0.05;

/// How many candidates to keep from a round's **weight-sorted-descending**
/// queue under `max_roi`: the smaller of the concurrency-scaled
/// [`top_k_for_round`] cap and a *relative knee* — the count of candidates
/// whose weight is within [`KNEE_FRACTION`] of the leader. Always keeps at
/// least the leader, so a round never starves. Pure over the sorted weights.
///
/// The knee complements top-K: top-K bounds breadth by a fixed budget, the
/// knee bounds it by *quality relative to this round's best lead*. A round
/// topped by a corroborated address (weight ~50) drops facebook.com-class
/// noise (weight ~5) that top-K alone would still dispatch; a flat round of
/// similar-weight leads keeps them all (up to top-K).
pub fn effective_cutoff(sorted_weights_desc: &[f64], max_concurrent: usize) -> usize {
    if sorted_weights_desc.is_empty() {
        return 0;
    }
    let cap = top_k_for_round(max_concurrent);
    let top = sorted_weights_desc[0];
    let knee = if top > 0.0 {
        let threshold = top * KNEE_FRACTION;
        sorted_weights_desc
            .iter()
            .take_while(|&&w| w >= threshold)
            .count()
            .max(1)
    } else {
        // Degenerate all-zero (or negative) round: no quality signal to knee
        // on, so fall back to the top-K budget alone.
        sorted_weights_desc.len()
    };
    knee.min(cap).max(1)
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
    include!("tests.rs");
}
