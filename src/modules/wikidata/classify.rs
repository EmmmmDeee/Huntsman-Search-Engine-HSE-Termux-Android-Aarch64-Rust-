use serde_json::Value;

use crate::core::{entity::EntityKind, scan::TargetKind};

use super::claims::claim_entity_ids;

/// Entity kind for the primary item: P31 `Q5` ⇒ Person; an explicit non-human
/// P31 ⇒ Organisation; absent P31 ⇒ fall back to the seed's kind — unless the
/// item has a coordinate location (P625).
///
/// A human item is never modelled with P625: coordinates belong to places,
/// buildings and organisations' sites. An untyped item that carries one is a
/// located thing, so it is not a person whatever the seed was. The fallback
/// minted the venue "Ian Thorpe Aquatic and Fitness Centre" as a `Person` on an
/// "Ian Thorpe" scan, and its pool's location became the subject's best
/// location fix at 0.97 (REQ-WIKIDATA-003).
pub(super) fn classify(entity: &Value, seed: TargetKind) -> EntityKind {
    let p31 = claim_entity_ids(entity, "P31");
    if p31.iter().any(|id| id == "Q5") {
        EntityKind::Person
    } else if p31.is_empty() && super::claims::claim_p625(entity).is_none() {
        seed_kind(seed)
    } else {
        EntityKind::Organisation
    }
}

pub(super) fn seed_kind(seed: TargetKind) -> EntityKind {
    match seed {
        TargetKind::Organisation => EntityKind::Organisation,
        _ => EntityKind::Person,
    }
}

/// True if `name` contains every token of the seed `query` as a whole word
/// (case-insensitive) — the same precision gate as `acnc_charities`/`gleif_lei`.
pub(super) fn name_matches_query(name: &str, query: &str) -> bool {
    crate::util::str_util::whole_word_token_match(name, query)
}
