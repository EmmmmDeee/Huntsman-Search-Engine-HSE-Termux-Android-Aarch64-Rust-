//! Pure expansion/dedup bookkeeping helpers used by the round loop: stable
//! dedup keys for correlations and visited targets, and the deterministic total
//! order over expansion candidates. No engine state — split out so the loop reads
//! as control flow while the key/ordering policy lives in one place.

use crate::core::entity::normalise;
use crate::core::scan::{Target, TargetKind};

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
