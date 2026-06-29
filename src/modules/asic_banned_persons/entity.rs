//! Pure-data helpers: datastore-resource selection, `"SURNAME, FIRSTNAME"`
//! name normalisation + whole-word matching, and the `records_to_entities`
//! transform that turns raw ASIC banned-person CKAN rows into adverse-finding
//! `Person` entities plus their locality pivot.

use serde_json::{Map, Value};

use crate::core::entity::{Entity, EntityKind, Evidence};
use crate::util::ckan::{Resource, field_str};

use super::{ADDR_CONF, MAX_RECORDS, PERSON_CANDIDATE, PERSON_EXACT, SRC};

/// Select the resource id to query: the datastore-active resource whose name
/// contains "Current" (case-insensitive — the dataset publishes a "...- Current"
/// resource that always carries the live records); failing that, the first
/// datastore-active resource. Returns `None` if nothing is datastore-active.
pub(super) fn pick_resource(resources: &[Resource]) -> Option<String> {
    let active: Vec<&Resource> = resources
        .iter()
        .filter(|r| r.datastore_active == Some(true))
        .collect();
    // Prefer a resource whose name advertises the live ("Current") records.
    let current = active.iter().find_map(|r| {
        let name = r.name.as_deref()?;
        if name.to_ascii_lowercase().contains("current") {
            r.id.clone()
        } else {
            None
        }
    });
    // Fall back to the first datastore-active resource with an id.
    current.or_else(|| active.iter().find_map(|r| r.id.clone()))
}

/// Build the geocodable locality string from the recorded address parts
/// ("Sydney, NSW 2000, Australia"). Assembles only the present parts; returns
/// `None` when there's nothing locating at all.
pub(super) fn person_locality(rec: &Map<String, Value>) -> Option<String> {
    let local = field_str(rec, "BD_PER_ADD_LOCAL");
    let state = field_str(rec, "BD_PER_ADD_STATE");
    let pcode = field_str(rec, "BD_PER_ADD_PCODE");
    let country = field_str(rec, "BD_PER_ADD_COUNTRY");
    if local.is_none() && state.is_none() && pcode.is_none() && country.is_none() {
        return None;
    }
    // Comma-joined parts, with state and postcode kept space-joined as one part.
    let mut parts: Vec<String> = Vec::new();
    if let Some(l) = local.as_deref() {
        parts.push(l.to_string());
    }
    match (state.as_deref(), pcode.as_deref()) {
        (Some(s), Some(p)) => parts.push(format!("{s} {p}")),
        (Some(s), None) => parts.push(s.to_string()),
        (None, Some(p)) => parts.push(p.to_string()),
        (None, None) => {}
    }
    if let Some(c) = country.as_deref() {
        parts.push(c.to_string());
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(", "))
    }
}

/// Attach every present register field to a banned-person's evidence so nothing
/// the API returned is dropped — true for exact hits and candidates alike.
pub(super) fn person_evidence(rec: &Map<String, Value>, name: &str, total: u64) -> Evidence {
    let ev = Evidence::new(SRC, format!("ASIC banned/disqualified person: {name}"))
        .with_attr("register", "ASIC Banned and Disqualified Persons")
        .with_attr("listed_name", name)
        .with_attr("total_matches", total.to_string());
    [
        ("REGISTER_NAME", "register_name"),
        ("BD_PER_TYPE", "ban_type"),
        ("BD_PER_DOC_NUM", "document_number"),
        ("BD_PER_START_DT", "ban_start"),
        ("BD_PER_END_DT", "ban_end"),
        ("BD_PER_ADD_LOCAL", "address_locality"),
        ("BD_PER_ADD_STATE", "address_state"),
        ("BD_PER_ADD_PCODE", "address_postcode"),
        ("BD_PER_ADD_COUNTRY", "address_country"),
        ("BD_PER_COMMENTS", "comments"),
    ]
    .into_iter()
    .filter_map(|(col, attr)| field_str(rec, col).map(|v| (attr, v)))
    .fold(ev, |ev, (attr, v)| ev.with_attr(attr, v))
}

/// Pure transform: CKAN ASIC banned-person rows → entities. Every row yields a
/// primary `Person` carrying the full record in evidence (no omission). A row
/// whose normalised name contains every seed token as a whole word is a
/// high-confidence adverse finding (tagged `asic-banned` / `disqualified` /
/// `adverse-record`) that fans out into an `Address` locality pivot; loose
/// full-text hits stay a single sub-floor `name-candidate` Person so a generic
/// name query can't pivot register noise into a false ban attribution.
pub(super) fn records_to_entities(
    records: &[Map<String, Value>],
    total: u64,
    query: &str,
    scan_id: &str,
) -> Vec<Entity> {
    let mut out = Vec::new();
    for rec in records.iter().take(MAX_RECORDS) {
        let Some(raw_name) = field_str(rec, "BD_PER_NAME") else {
            continue;
        };
        // ASIC stores some names with a non-breaking space; normalise for display.
        let name = raw_name.replace('\u{a0}', " ");
        let exact = crate::util::target_match::name_all_tokens_match(&name, query);
        let conf = if exact {
            PERSON_EXACT
        } else {
            PERSON_CANDIDATE
        };

        let mut person = Entity::new(EntityKind::Person, &name, conf, scan_id);
        person.tag(SRC);
        person.tag("asic");
        person.tag("country:AU");
        if exact {
            person.tag("asic-banned");
            person.tag("disqualified");
            person.tag("adverse-record");
            person.tag("regulatory-action");
            person.tag("exact-name-match");
        } else {
            person.tag("name-candidate");
        }
        person.add_evidence(person_evidence(rec, &name, total));
        out.push(person);

        // Locality pivot — exact hits only (a candidate's address is noise).
        if !exact {
            continue;
        }
        if let Some(addr) = person_locality(rec) {
            let mut e = Entity::new(EntityKind::Address, &addr, ADDR_CONF, scan_id);
            e.tag(SRC);
            e.tag("asic");
            e.tag("country:AU");
            e.tag("geoint");
            if let Some(sc) = crate::util::address_au::state_code(&addr) {
                e.tag(format!("au-state:{sc}"));
            }
            e.add_evidence(
                Evidence::new(SRC, format!("Recorded locality of banned person {name}"))
                    .with_attr("person", &name),
            );
            out.push(e);
        }
    }
    out
}
