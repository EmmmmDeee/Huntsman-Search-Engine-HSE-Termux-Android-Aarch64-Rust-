//! Whether a result set proves a name is held by more than one party.
//!
//! An entity whose *value* is a name — a `Person`, an `Organisation` — derives
//! its uid from that name, and `hse_core`'s `identity_fold` deliberately folds
//! case and whitespace for exactly those two kinds, so two different real
//! parties sharing a name fuse into one entity **by construction**.
//!
//! That fusion is not itself a defect: `Entity::absorb` joins conflicting
//! evidence attributes (`"AU; DE"`, `"ACTIVE; INACTIVE"`) rather than dropping
//! either side, so nothing observed is lost. The defect is *asserting* the
//! composite as one party, at a confidence that lets it pivot.
//!
//! The signal that makes the ambiguity provable is local and cheap: **one
//! provider's single answer already contains the same name twice**. That is not
//! a heuristic about how common a name is — it is the register contradicting
//! the assumption that the name identifies someone. No corpus, no name
//! frequency table, no second request.
//!
//! `ahpra` established the rule for practitioners (REQ-AHPRA-001): a name its
//! own result set holds more than once is scored lower and tagged
//! [`AMBIGUOUS_NAME`], "so the merged entity describes its own ambiguity
//! instead of fabricating a practitioner who does not exist." `gleif_lei` had
//! the identical situation — two companies holding one legal name in different
//! jurisdictions — and none of the mechanism (REQ-GLEIF-001). This module is
//! the one authority both consume, so the rule cannot drift between them.

use std::collections::{BTreeMap, BTreeSet};

use crate::core::confidence;
use crate::core::entity::{Entity, EntityKind, derive_uid, normalise};

/// The tag stamped on an entity whose name this provider's own answer shows is
/// held by more than one party.
///
/// Deliberately **not** `tags::CANDIDATE`: that tier means "this record does
/// not identify the subject" and is filtered out of every export. An ambiguous
/// name is the opposite problem — the records genuinely match, and there is
/// more than one of them. The operator must see them all, flagged.
pub const AMBIGUOUS_NAME: &str = "ambiguous-name";

/// The ceiling a proven-collision row's entities are capped at.
///
/// Below the noisy-OR expansion floor (`confidence::MEDIUM`), so nothing built
/// on an ambiguous name can pivot and seed new targets.
///
/// Deliberately the same tier a module gives a loose, non-matching candidate
/// rather than a bespoke number in between: the epistemic status is identical —
/// this row does not identify one party. *Why* it is sub-floor is carried by
/// [`AMBIGUOUS_NAME`] and an evidence caution, where an operator can read it,
/// not by a constant nobody can interpret.
pub const AMBIGUOUS_CEILING: f64 = confidence::LOW_MEDIUM;

/// Cap and flag one entity a proven-collision row produced.
///
/// Apply it to **every** entity the row yielded, not only the named one. A
/// company row's registration number, registered address and derived
/// coordinates all rest on the single claim "the subject is this party", so
/// they inherit that claim's ambiguity; demoting the `Organisation` while
/// leaving its `AbnAcn` at `confidence::EXPERT` moves the defect rather than
/// removing it, because the number still pivots.
///
/// Idempotent — the tag de-dupes and the cap is a `min`.
pub fn mark_ambiguous(entity: &mut Entity) {
    entity.tag(AMBIGUOUS_NAME);
    entity.confidence = entity.confidence.min(AMBIGUOUS_CEILING);
}

/// The names a single result set holds more than once.
///
/// # Keyed on the engine's own identity, not on a lookalike of it
///
/// The question this answers is precisely *"will the engine fuse these rows
/// into one entity?"*, so it is keyed on `derive_uid(kind, normalise(kind, …))`
/// — the same two functions `Entity::new` calls — rather than on a hand-rolled
/// case/whitespace fold that mirrors them. A mirror would be a second authority
/// for entity identity and would drift: `identity_fold` uses full Unicode
/// `to_lowercase`, so `"MÜLLER GMBH"` and `"Müller GmbH"` are one identity, and
/// an ASCII-only imitation would quietly miss that collision.
///
/// The `kind` matters: `identity_fold` folds case and whitespace for
/// `Person` and `Organisation` and for no other kind, which is exactly the set
/// of name-valued kinds this module is about.
///
/// Empty and whitespace-only names are ignored: they are not identities, and
/// treating two of them as a collision would flag rows carrying no name at all.
///
/// Pure, so the rule is testable without a network round trip.
///
/// ```
/// use huntsman_search_engine::core::entity::EntityKind;
/// use huntsman_search_engine::util::namesake::NameCollisions;
///
/// let seen = NameCollisions::of(&EntityKind::Organisation, ["Acme Ltd", "acme  LTD", "Other Pty"]);
/// assert!(seen.is_shared(&EntityKind::Organisation, "ACME LTD"));
/// assert!(!seen.is_shared(&EntityKind::Organisation, "Other Pty"));
/// assert!(seen.any());
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NameCollisions(BTreeSet<String>);

/// The engine's identity key for one name, or `None` when the name is blank.
fn identity(kind: &EntityKind, name: &str) -> Option<String> {
    let normalised = normalise(kind, name);
    if normalised.trim().is_empty() {
        return None;
    }
    Some(derive_uid(kind, &normalised))
}

impl NameCollisions {
    /// Count every name in `names` under `kind` and keep the ones seen more
    /// than once.
    #[must_use]
    pub fn of<'a, I>(kind: &EntityKind, names: I) -> Self
    where
        I: IntoIterator<Item = &'a str>,
    {
        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        for name in names {
            if let Some(key) = identity(kind, name) {
                *counts.entry(key).or_default() += 1;
            }
        }
        Self(
            counts
                .into_iter()
                .filter_map(|(key, n)| (n > 1).then_some(key))
                .collect(),
        )
    }

    /// Whether this result set proved `name` is held by more than one party.
    #[must_use]
    pub fn is_shared(&self, kind: &EntityKind, name: &str) -> bool {
        identity(kind, name).is_some_and(|key| self.0.contains(&key))
    }

    /// Whether any name collided at all — the cheap guard a caller uses to skip
    /// per-row work entirely on the overwhelmingly common unambiguous answer.
    #[must_use]
    pub fn any(&self) -> bool {
        !self.0.is_empty()
    }

    /// How many distinct names collided.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether no name collided.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(test)]
mod tests;
