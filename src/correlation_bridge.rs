//! Deterministic adapter over the existing correlation rule registry.

use crate::correlator::{Correlation, RuleContext, confirmed_only, rank_and_sort, registry};
use crate::entity::Entity;

/// Run the existing entity-only correlators at an explicit timestamp.
///
/// The adapter deliberately supplies no invented relation model. Rules that require
/// domain relations remain silent until a relation-preserving bridge exists.
#[must_use]
pub fn correlate_entities_at(
    entities: &[Entity],
    scan_id: &str,
    now_unix: u64,
) -> Vec<Correlation> {
    let confirmed = confirmed_only(entities);
    let context = RuleContext::new(&confirmed, &[]);
    let mut correlations = Vec::new();
    for rule in registry() {
        correlations.extend(rule.run(&context, scan_id, now_unix));
    }
    rank_and_sort(&mut correlations, &confirmed);
    correlations
}
