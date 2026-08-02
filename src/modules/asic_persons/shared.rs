//! Plumbing shared by all three ASIC register emitters ([`super::banned`],
//! [`super::adviser`], [`super::credit`]): the CKAN query, name-token
//! matching, and the field/address/person-name helpers common to their
//! record parsing.

use serde_json::{Map, Value};

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{ModuleContext, ModuleResult},
};
use crate::util::ckan::field_str;

use super::{CKAN_BASE, MAX_HITS, SRC};

/// Query one CKAN datastore resource by free-text name, via the shared
/// [`crate::util::ckan::datastore_search`] (T2.118). Returns the matched
/// records, or a real `Error` when the register genuinely failed to answer —
/// a transport error, non-2xx status, unparseable body, or a CKAN
/// application error (`success: false`, which CKAN returns with HTTP 200 on
/// a bad resource id / offline datastore / rate-limit). Previously every one
/// of these collapsed into an empty `Vec` indistinguishable from a genuine
/// "not in this register"; `process()` now folds the three registers'
/// results so a real outage surfaces instead (see its `or_hard_failure`
/// fold).
pub(super) async fn ckan_query(
    ctx: &ModuleContext,
    resource_id: &str,
    name: &str,
) -> Result<Vec<Map<String, Value>>> {
    Ok(
        crate::util::ckan::datastore_search(&ctx.http, CKAN_BASE, resource_id, name, MAX_HITS, SRC)
            .await?
            .records,
    )
}

/// Lower-cased alphabetic name tokens (≥2 chars) of a full name.
pub(super) fn name_tokens(full: &str) -> Vec<String> {
    full.split(|c: char| !c.is_alphabetic())
        .filter(|t| t.len() >= 2)
        .map(str::to_ascii_lowercase)
        .collect()
}

/// True if a record's name field contains every target token (order-independent,
/// so `"Bill Abbott"` matches `"ABBOTT, BILL"`).
pub(super) fn record_name_matches(
    rec: &Map<String, Value>,
    name_field: &str,
    tokens: &[String],
) -> bool {
    let Some(name) = field(rec, name_field) else {
        return false;
    };
    let lower = name.to_ascii_lowercase();
    tokens.iter().all(|t| lower.contains(t.as_str()))
}

/// Compose `LOCAL STATE PCODE` into an Address entity, if any part is present.
#[allow(clippy::too_many_arguments)]
pub(super) fn push_address(
    rec: &Map<String, Value>,
    local_key: &str,
    state_key: &str,
    pcode_key: &str,
    person: &str,
    tag: &str,
    scan_id: &str,
    result: &mut ModuleResult,
) {
    let parts: Vec<String> = [local_key, state_key, pcode_key]
        .into_iter()
        .filter_map(|k| field(rec, k))
        .collect();
    if parts.is_empty() {
        return;
    }
    let addr = parts.join(" ");
    // The AU state of the register address, resolved once and reused for both the
    // Address and Coordinates tags so this register participates in the AU
    // geo/jurisdiction correlators like every other AU module.
    let sc = crate::util::address_au::state_code(&addr);
    let mut a = Entity::new(EntityKind::Address, &addr, confidence::MEDIUM_HIGH, scan_id);
    a.tag("au");
    a.tag("asic");
    a.tag(tag);
    a.tag("country:AU");
    if let Some(s) = sc {
        a.tag(format!("au-state:{s}"));
    }
    a.add_evidence(
        Evidence::new(SRC, format!("Registered address for {person}"))
            .with_attr("address", &addr)
            .with_attr("source", "asic-register"),
    );
    result.push(a);

    // Inline-geocode the register address to a Coordinates anchor (offline
    // gazetteer) so the registered locality enters the AU geo correlators
    // (AU-052/053) immediately, without waiting on a network forward-geocode —
    // exactly as the sibling AU register modules do.
    if let Some((lat, lon)) = crate::util::city_coords::city_coords(&addr) {
        let coord_val = format!("{lat:.4},{lon:.4}");
        let mut c = Entity::new(
            EntityKind::Coordinates,
            &coord_val,
            confidence::LOW_MEDIUM,
            scan_id,
        );
        c.tag("au");
        c.tag("asic");
        c.tag("addr-derived");
        c.tag("geoint");
        c.tag("country:AU");
        if let Some(s) = sc {
            c.tag(format!("au-state:{s}"));
        }
        c.add_evidence(
            Evidence::new(SRC, format!("Geocoded register address for {person}"))
                .with_attr("source_address", &addr),
        );
        result.push(c);
    }
}

/// A non-empty, non-`"null"` trimmed string field (JSON string or number).
/// A usable ASIC field value: the shared CKAN [`field_str`] stringification
/// (CONVENTIONS §4 — one stringifier, not a per-module copy) with this
/// register's `"null"` sentinel filter on top (`field_str` only drops JSON
/// null / empty, so the literal string `"null"` would otherwise pass through).
pub(super) fn field(rec: &Map<String, Value>, key: &str) -> Option<String> {
    field_str(rec, key).filter(|s| !s.eq_ignore_ascii_case("null"))
}

/// `"SURNAME, FIRSTNAME"` → `"Firstname Surname"` (title-cased); other forms are
/// title-cased as-is.
pub(super) fn humanise_name(s: &str) -> String {
    let reordered = match s.split_once(',') {
        Some((surname, first)) => format!("{} {}", first.trim(), surname.trim()),
        None => s.trim().to_string(),
    };
    crate::util::str_util::title_case(&reordered.to_ascii_lowercase())
}
