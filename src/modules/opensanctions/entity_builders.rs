//! Pure entity-building functions for OpenSanctions sanctions/PEP screening.
//!
//! Free of HTTP transport so it is unit-tested directly against fixture JSON.

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    tags,
};

use super::{
    HIGH_CONFIDENCE_SCORE, MATCH_CONF, SRC,
    types::{MatchResult, QueryResponse},
};

/// OpenSanctions' own dataset id for DFAT's Australian Sanctions Consolidated
/// List — one of the ~400 source datasets folded into the `default` scope
/// this module queries. Tagged distinctly so an Australia-specific hit is
/// visible without an operator parsing the full `datasets` evidence string.
const AU_DFAT_DATASET: &str = "au_dfat_sanctions";

/// Build `Person` entities from an OpenSanctions `/match` response — one per
/// **definitive** match (`match: true`). A fuzzy candidate below the API's
/// own match threshold is not escalated into a sanctions/PEP claim about a
/// real person: falsely tagging someone as sanctioned is a serious,
/// reputationally consequential mistake, and this codebase's evidentiary
/// doctrine treats a false positive as worse than missing coverage. Pure.
pub(super) fn build_entities(query_name: &str, resp: &QueryResponse, scan_id: &str) -> Vec<Entity> {
    resp.results
        .iter()
        .filter(|r| r.is_match == Some(true))
        .map(|r| result_to_entity(query_name, r, scan_id))
        .collect()
}

fn result_to_entity(query_name: &str, result: &MatchResult, scan_id: &str) -> Entity {
    let caption = result.caption.as_deref().unwrap_or(query_name);
    let mut entity = Entity::new(EntityKind::Person, caption, MATCH_CONF, scan_id);
    entity.tag(SRC);

    for topic in &result.properties.topics {
        match topic.as_str() {
            "sanction" | "sanction.linked" => entity.tag(tags::SANCTIONED),
            t if t.starts_with("role.pep") => entity.tag(tags::PEP),
            "debarment" => entity.tag(tags::DEBARRED),
            _ => {}
        }
    }
    if result.datasets.iter().any(|d| d == AU_DFAT_DATASET) {
        entity.tag("au-sanctions");
    }
    if result.score.unwrap_or(0.0) >= HIGH_CONFIDENCE_SCORE {
        entity.tag("high-confidence-match");
    }

    let mut ev = Evidence::new(SRC, format!("OpenSanctions match for '{query_name}'"))
        .with_attr("opensanctions_id", result.id.as_str())
        .with_attr("match_score", format!("{:.2}", result.score.unwrap_or(0.0)));
    if !result.datasets.is_empty() {
        ev = ev.with_attr("datasets", result.datasets.join(", "));
    }
    if !result.properties.topics.is_empty() {
        ev = ev.with_attr("topics", result.properties.topics.join(", "));
    }
    if !result.properties.position.is_empty() {
        ev = ev.with_attr("position", result.properties.position.join(", "));
    }
    if !result.properties.birth_date.is_empty() {
        ev = ev.with_attr("birth_date", result.properties.birth_date.join(", "));
    }
    if !result.properties.nationality.is_empty() {
        ev = ev.with_attr("nationality", result.properties.nationality.join(", "));
    }
    if !result.properties.country.is_empty() {
        ev = ev.with_attr("country", result.properties.country.join(", "));
    }
    if !result.properties.program_id.is_empty() {
        ev = ev.with_attr("program_id", result.properties.program_id.join(", "));
    }
    entity.add_evidence(ev);
    entity
}
