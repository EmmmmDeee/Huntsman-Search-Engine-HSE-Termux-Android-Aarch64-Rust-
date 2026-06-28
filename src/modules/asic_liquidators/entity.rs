//! Pure-data helpers: datastore-resource selection, `"SURNAME, FIRSTNAME"`
//! name normalisation + whole-word matching, and the `records_to_entities`
//! transform that turns raw ASIC liquidator CKAN rows into a registered-person
//! `Person` plus its firm and locality pivots.

use serde_json::{Map, Value};

use crate::core::entity::{Entity, EntityKind, Evidence};
use crate::util::ckan::{Resource, field_str};

use super::{ADDR_CONF, FIRM_CONF, MAX_RECORDS, PERSON_CANDIDATE, PERSON_EXACT, SRC};

/// Select the resource id to query: the datastore-active resource whose name
/// contains "Current" (case-insensitive); failing that, the first
/// datastore-active resource. Returns `None` if nothing is datastore-active.
pub(super) fn pick_resource(resources: &[Resource]) -> Option<String> {
    let active: Vec<&Resource> = resources
        .iter()
        .filter(|r| r.datastore_active == Some(true))
        .collect();
    let current = active.iter().find_map(|r| {
        let name = r.name.as_deref()?;
        if name.to_ascii_lowercase().contains("current") {
            r.id.clone()
        } else {
            None
        }
    });
    current.or_else(|| active.iter().find_map(|r| r.id.clone()))
}

/// Split a value into its significant alphanumeric whole-word tokens
/// (case-preserved). Order-independent: a `"SURNAME, FIRSTNAME"` register name
/// and a `"Firstname Surname"` seed tokenise to the same (unordered) set.
fn tokens(s: &str) -> Vec<&str> {
    s.split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty())
        .collect()
}

/// True if `name` contains every token of the seed `query` as a *whole word*
/// (case-insensitive), comparing token-set-wise so the register's
/// `"SURNAME, FIRSTNAME"` format matches a `"Firstname Surname"` seed regardless
/// of order. Whole-word (not substring) so `"li"` doesn't match inside `"Ali"`.
pub(super) fn name_matches_query(name: &str, query: &str) -> bool {
    let words = tokens(name);
    let seed = tokens(query);
    !seed.is_empty()
        && seed
            .iter()
            .all(|tok| words.iter().any(|w| w.eq_ignore_ascii_case(tok)))
}

/// Build the geocodable locality string from the recorded address parts. Returns
/// `None` when nothing locates.
pub(super) fn liquidator_locality(rec: &Map<String, Value>) -> Option<String> {
    let local = field_str(rec, "LIQ_ADD_LOCAL");
    let state = field_str(rec, "LIQ_ADD_STATE");
    let pcode = field_str(rec, "LIQ_ADD_PCODE");
    let country = field_str(rec, "LIQ_ADD_COUNTRY");
    if local.is_none() && state.is_none() && pcode.is_none() && country.is_none() {
        return None;
    }
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

/// Attach every present register field to a liquidator's evidence so nothing the
/// API returned is dropped — true for exact hits and candidates alike.
pub(super) fn liquidator_evidence(rec: &Map<String, Value>, name: &str, total: u64) -> Evidence {
    let ev = Evidence::new(SRC, format!("ASIC registered liquidator: {name}"))
        .with_attr("register", "ASIC Liquidator")
        .with_attr("listed_name", name)
        .with_attr("total_matches", total.to_string());
    [
        ("REGISTER_NAME", "register_name"),
        ("LIQ_NUM", "liquidator_number"),
        ("OFF_LIQ_NUM", "official_liquidator_number"),
        ("LIQ_START_DT", "registration_start"),
        ("OFF_LIQ_START_DT", "official_registration_start"),
        ("LIQ_STATUS", "status"),
        ("LIQ_SUSP_DT", "suspension_date"),
        ("LIQ_ADD_LOCAL", "address_locality"),
        ("LIQ_ADD_STATE", "address_state"),
        ("LIQ_ADD_PCODE", "address_postcode"),
        ("LIQ_ADD_COUNTRY", "address_country"),
        ("LIQ_FIRM", "firm"),
    ]
    .into_iter()
    .filter_map(|(col, attr)| field_str(rec, col).map(|v| (attr, v)))
    .fold(ev, |ev, (attr, v)| ev.with_attr(attr, v))
}

/// Pure transform: CKAN ASIC liquidator rows → entities. Every row yields a
/// primary `Person` carrying the full record in evidence (no omission). A row
/// whose normalised name contains every seed token as a whole word is a
/// high-confidence finding (tagged `liquidator` / `insolvency-practitioner`) that
/// fans out into a firm `Organisation` and an `Address` locality pivot; loose
/// full-text hits stay a single sub-floor `name-candidate` Person.
pub(super) fn records_to_entities(
    records: &[Map<String, Value>],
    total: u64,
    query: &str,
    scan_id: &str,
) -> Vec<Entity> {
    let mut out = Vec::new();
    for rec in records.iter().take(MAX_RECORDS) {
        let Some(raw_name) = field_str(rec, "LIQ_NAME") else {
            continue;
        };
        let name = raw_name.replace('\u{a0}', " ");
        let exact = name_matches_query(&name, query);
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
            person.tag("liquidator");
            person.tag("insolvency-practitioner");
            person.tag("professional-record");
            person.tag("exact-name-match");
        } else {
            person.tag("name-candidate");
        }
        person.add_evidence(liquidator_evidence(rec, &name, total));
        out.push(person);

        // Cross-correlation pivots — exact hits only.
        if !exact {
            continue;
        }

        // Recorded firm → related Organisation (the practitioner's employer).
        if let Some(firm) = field_str(rec, "LIQ_FIRM") {
            let mut e = Entity::new(EntityKind::Organisation, &firm, FIRM_CONF, scan_id);
            e.tag(SRC);
            e.tag("asic");
            e.tag("country:AU");
            e.tag("insolvency-firm");
            e.add_evidence(
                Evidence::new(SRC, format!("Firm recorded for liquidator {name}"))
                    .with_attr("liquidator", &name),
            );
            out.push(e);
        }

        // Recorded locality → Address pivot.
        if let Some(addr) = liquidator_locality(rec) {
            let mut e = Entity::new(EntityKind::Address, &addr, ADDR_CONF, scan_id);
            e.tag(SRC);
            e.tag("asic");
            e.tag("country:AU");
            e.tag("geoint");
            if let Some(sc) = crate::util::address_au::state_code(&addr) {
                e.tag(format!("au-state:{sc}"));
            }
            e.add_evidence(
                Evidence::new(SRC, format!("Recorded locality of liquidator {name}"))
                    .with_attr("liquidator", &name),
            );
            out.push(e);
        }
    }
    out
}
