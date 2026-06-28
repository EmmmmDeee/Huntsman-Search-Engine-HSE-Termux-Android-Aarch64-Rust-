//! Pure-data helpers: row → field access, seed name-matching, and the
//! transform that turns a matched DFAT Consolidated List row into a `Person`
//! (individual) or `Organisation` (entity) adverse-finding entity.

use std::collections::HashMap;

use crate::core::entity::{Entity, EntityKind, Evidence};

use super::{ORG_CONF, PERSON_CONF, SRC};

/// The DFAT export's column headers, lower-cased, that this module reads. Pinned
/// here (and exercised by the module's test fixtures) so a column rename in a
/// future re-export is a visible, testable change rather than a silent drop.
pub(super) const COL_NAME: &str = "name of individual or entity";
pub(super) const COL_TYPE: &str = "type of designation";
pub(super) const COL_NAME_TYPE: &str = "name type";
pub(super) const COL_REFERENCE: &str = "reference";
pub(super) const COL_DOB: &str = "date of birth";
pub(super) const COL_POB: &str = "place of birth";
pub(super) const COL_CITIZENSHIP: &str = "citizenship";
pub(super) const COL_ADDRESS: &str = "address";
pub(super) const COL_ADDITIONAL: &str = "additional information";
pub(super) const COL_LISTING: &str = "listing information";
pub(super) const COL_COMMITTEES: &str = "committees";

/// Read a row cell by (lower-cased) column name, trimmed; `None` when the column
/// is absent or the cell is empty / a literal `null` placeholder.
pub(super) fn cell<'a>(
    row: &'a [String],
    index: &HashMap<String, usize>,
    col: &str,
) -> Option<&'a str> {
    let v = index.get(col).and_then(|&i| row.get(i))?.trim();
    if v.is_empty() || v.eq_ignore_ascii_case("null") {
        None
    } else {
        Some(v)
    }
}

/// True if the listed name contains every token of the seed `query` as a *whole
/// word* (case-insensitive). Whole-word (not substring) so a seed token like
/// `"ali"` doesn't match inside `"Khalid"`. Tokenises on non-alphanumeric
/// boundaries; no per-token allocation.
pub(super) fn name_matches(name: &str, query: &str) -> bool {
    let words: Vec<&str> = name
        .split(|c: char| !c.is_alphanumeric())
        .filter(|s| !s.is_empty())
        .collect();
    let tokens: Vec<&str> = query
        .split(|c: char| !c.is_alphanumeric())
        .filter(|s| !s.is_empty())
        .collect();
    !tokens.is_empty()
        && tokens
            .iter()
            .all(|tok| words.iter().any(|w| w.eq_ignore_ascii_case(tok)))
}

/// Whether the row designates an entity (organisation) rather than an
/// individual. DFAT uses a `Type of designation` of "Entity" vs "Individual";
/// when the column is absent we fall back to the caller's seed kind.
pub(super) fn row_is_entity(row: &[String], index: &HashMap<String, usize>) -> Option<bool> {
    cell(row, index, COL_TYPE).map(|t| t.eq_ignore_ascii_case("Entity"))
}

/// Build the adverse-finding entity for one matched row. `seed_is_person`
/// disambiguates the entity kind only when the row's own `Type` column is
/// absent: a `FullName` seed defaults to `Person`, an `Organisation` seed to
/// `Organisation`. The full row rides in the evidence (no omission), and the
/// finding is tagged `sanctions` / `pep` / `dfat-consolidated-list` so the
/// adverse-screening correlator rules can key on it.
pub(super) fn row_to_entity(
    row: &[String],
    index: &HashMap<String, usize>,
    seed_is_person: bool,
    scan_id: &str,
) -> Option<Entity> {
    let name = cell(row, index, COL_NAME)?;
    let is_entity = row_is_entity(row, index).unwrap_or(!seed_is_person);

    let (kind, conf) = if is_entity {
        (EntityKind::Organisation, ORG_CONF)
    } else {
        (EntityKind::Person, PERSON_CONF)
    };

    let mut ev = Evidence::new(
        SRC,
        format!("DFAT Consolidated List (Australian autonomous sanctions): {name}"),
    )
    .with_attr("register", "DFAT Consolidated List")
    .with_attr("listed_name", name)
    .with_attr(
        "designation",
        if is_entity { "Entity" } else { "Individual" },
    );
    for (col, attr) in [
        (COL_REFERENCE, "reference"),
        (COL_NAME_TYPE, "name_type"),
        (COL_DOB, "date_of_birth"),
        (COL_POB, "place_of_birth"),
        (COL_CITIZENSHIP, "citizenship"),
        (COL_ADDRESS, "address"),
        (COL_COMMITTEES, "committees"),
        (COL_LISTING, "listing_information"),
        (COL_ADDITIONAL, "additional_information"),
    ] {
        if let Some(v) = cell(row, index, col) {
            ev = ev.with_attr(attr, v);
        }
    }

    let mut e = Entity::new(kind, name, conf, scan_id);
    e.tag(SRC);
    e.tag("dfat-consolidated-list");
    e.tag("sanctions");
    e.tag("pep");
    e.tag("adverse-media");
    e.tag("country:AU");
    e.add_evidence(ev);
    Some(e)
}
