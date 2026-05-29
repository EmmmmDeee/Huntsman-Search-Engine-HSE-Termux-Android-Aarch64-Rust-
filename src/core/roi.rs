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
    entity.corroboration >= SATURATION_CORROBORATION
        && entity.c_effective() >= SATURATION_CONFIDENCE
}

/// True if an entity is **breach-dump noise that should never seed expansion**.
///
/// A high-recall breach query on a common name returns entire breach corpora —
/// hundreds of single-source emails/phones/persons/addresses that merely
/// co-occur with the query tokens. Pivoting on each of those wastes the bulk
/// of the expansion budget chasing unrelated identities (observed live: ~341
/// such entities from one common-name query). This gate is *always on* (unlike
/// the `max_roi` bundle): a breach/stealer-tagged PII entity that no
/// independent source corroborated (`corroboration < 2`) is not pivot-worthy.
/// The genuine subject — re-derived across modules — has `corroboration ≥ 2`
/// and is unaffected.
pub fn is_breach_dump_noise(entity: &Entity) -> bool {
    use crate::core::entity::EntityKind;
    let breach_sourced =
        entity.has_tag("breach") || entity.has_tag("oathnet-pro") || entity.has_tag("stealer-log");
    breach_sourced
        && entity.corroboration < SATURATION_CORROBORATION
        && matches!(
            entity.kind,
            EntityKind::Email | EntityKind::Phone | EntityKind::Person | EntityKind::Address
        )
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
    use crate::core::entity::{Entity, EntityKind};

    fn make(conf: f64, corrob: u32) -> Entity {
        let mut e = Entity::new(EntityKind::Email, "x@y.com", conf, "scan");
        e.corroboration = corrob;
        e
    }

    #[test]
    fn breach_dump_noise_is_single_source_breach_pii() {
        let mut dump = Entity::new(EntityKind::Email, "rando@bank.com", 0.7, "s");
        dump.tag("breach");
        dump.tag("oathnet-pro");
        assert!(is_breach_dump_noise(&dump)); // corroboration 1 + breach + email

        // Corroborated subject email — not noise.
        let mut real = Entity::new(EntityKind::Email, "subject@x.com", 0.7, "s");
        real.tag("breach");
        real.corroboration = 2;
        assert!(!is_breach_dump_noise(&real));

        // Non-PII kind (domain) — not gated as PII dump noise.
        let mut dom = Entity::new(EntityKind::Domain, "x.com", 0.7, "s");
        dom.tag("breach");
        assert!(!is_breach_dump_noise(&dom));

        // No breach provenance — never noise regardless of corroboration.
        let plain = Entity::new(EntityKind::Email, "a@b.com", 0.7, "s");
        assert!(!is_breach_dump_noise(&plain));
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
