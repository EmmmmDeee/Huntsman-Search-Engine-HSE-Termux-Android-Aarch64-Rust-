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
use crate::core::entity::{Entity, EntityKind, VerificationMethod, derive_uid, normalise};
use crate::core::tags;

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

/// Tags that assert a **determination about one specific party** — this person
/// holds public office, that company is designated — rather than describe the
/// record they came from.
///
/// On a proven-collision row such a tag cannot stand at the entity level. Tags
/// are entity-level and `Entity::absorb` unions them, so the row's tag lands
/// on the subject's same-named anchor through the merge exactly like the
/// confidence cap is lost through it (REQ-WIKIDATA-001) — but where the lost
/// cap only *overstates* a namesake, a surviving `pep` *asserts* the
/// namesake's office as the subject's, and AU-114 reports it against the
/// subject, gated on nothing but the tag and a confidence the anchor already
/// has. Scan 7258fc07 is that case: Wikidata's first "Ian Thorpe" hit was a
/// New Zealand soldier holding a P39 position, and the seed — the swimmer —
/// carried `pep` / `politically-exposed` in every export (REQ-NAMESAKE-002).
///
/// `"politically-exposed"` is the literal `wikidata` stamps beside
/// [`tags::PEP`]; it has no `tags` constant of its own, so it is named here
/// once rather than through a new wire-vocabulary constant.
pub const PARTY_DETERMINATION_TAGS: &[&str] = &[
    tags::PEP,
    "politically-exposed",
    tags::SANCTIONED,
    tags::DEBARRED,
    tags::SANCTIONS_LINKED,
];

/// The evidence attribute a stripped [`PARTY_DETERMINATION_TAGS`] entry is
/// recorded under: a sorted, comma-joined list of the flags the source raised
/// for *one of* the name's holders. Kept on the evidence, not dropped, so
/// nothing observed is lost — the record already reads
/// [`VerificationMethod::Unverified`], which is precisely the status of a flag
/// nobody has yet attributed to a party.
pub const UNRESOLVED_FLAGS_ATTR: &str = "unresolved_flags";

/// Cap, flag, and mark the ownership of one entity a proven-collision row
/// produced. **The one way an entity is marked ambiguous** —
/// `tests/architecture.rs` refuses [`AMBIGUOUS_NAME`] applied any other way,
/// because the partial copy `ahpra` kept scored a collision AT the expansion
/// floor instead of below it (REQ-NAMESAKE-001).
///
/// Apply it to **every** entity the row yielded, not only the named one. A
/// company row's registration number, registered address and derived
/// coordinates all rest on the single claim "the subject is this party", so
/// they inherit that claim's ambiguity; demoting the `Organisation` while
/// leaving its `AbnAcn` at `confidence::EXPERT` moves the defect rather than
/// removing it, because the number still pivots.
///
/// Call it **after** the entity's evidence is attached. The cap and the tag
/// are entity-level, and the engine's merge folds an entity into its
/// same-named twin — often the subject's own anchor — keeping the higher
/// confidence, so the cap does not survive the merge (REQ-WIKIDATA-001 is that
/// erasure). The third mark does: every evidence record without an ownership
/// status is stamped [`VerificationMethod::Unverified`], and records keep that
/// through the merge. It is what stops the row's attributes — a date of birth,
/// an identifier, a breach corpus — reading as the subject's own in the
/// exposure index. An ownership status the source already established (an
/// account linked by email) is about a different question and is kept.
///
/// The fourth mark is subtraction: a tag in [`PARTY_DETERMINATION_TAGS`] is a
/// verdict about one holder of the name, and an entity-level tag survives the
/// merge by union, so it is removed from the entity and recorded on every
/// evidence record under [`UNRESOLVED_FLAGS_ATTR`] instead (REQ-NAMESAKE-002).
/// A genuine designation of the subject is not lost by this: it arrives from a
/// source that resolved the party (`opensanctions`), on its own entity, and
/// the union restores it — which is also why AU-114 is deliberately **not**
/// taught to read [`AMBIGUOUS_NAME`] as a veto, since one module's collision
/// would then hide another module's real designation on the same anchor.
///
/// Idempotent — the tag de-dupes, the cap is a `min`, the mark fills only an
/// empty status, and a second call finds no determination tag left to strip,
/// so the recorded flags are left exactly as the first call wrote them.
pub fn mark_ambiguous(entity: &mut Entity) {
    strip_party_determinations(entity);
    entity.tag(AMBIGUOUS_NAME);
    entity.confidence = entity.confidence.min(AMBIGUOUS_CEILING);
    for ev in &mut entity.evidence {
        ev.verification
            .get_or_insert(VerificationMethod::Unverified);
    }
}

/// Move every [`PARTY_DETERMINATION_TAGS`] entry off `entity` and onto each of
/// its evidence records under [`UNRESOLVED_FLAGS_ATTR`].
///
/// The recorded list is the sorted union of what the record already held and
/// what was stripped now, so the output does not depend on tag order or on how
/// many times the entity was marked. A no-op when nothing is stripped.
fn strip_party_determinations(entity: &mut Entity) {
    let stripped: BTreeSet<String> = entity
        .tags
        .iter()
        .filter(|t| PARTY_DETERMINATION_TAGS.contains(&t.as_str()))
        .cloned()
        .collect();
    if stripped.is_empty() {
        return;
    }
    entity
        .tags
        .retain(|t| !PARTY_DETERMINATION_TAGS.contains(&t.as_str()));
    for ev in &mut entity.evidence {
        let mut flags = stripped.clone();
        if let Some(prior) = ev.attributes.get(UNRESOLVED_FLAGS_ATTR) {
            flags.extend(
                prior
                    .split(',')
                    .map(str::trim)
                    .filter(|f| !f.is_empty())
                    .map(str::to_owned),
            );
        }
        let joined = flags.into_iter().collect::<Vec<_>>().join(",");
        ev.attributes
            .insert(UNRESOLVED_FLAGS_ATTR.to_owned(), joined);
    }
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
