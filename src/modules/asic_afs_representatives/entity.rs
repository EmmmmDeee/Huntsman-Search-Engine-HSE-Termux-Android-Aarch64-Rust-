//! Pure-data helpers: datastore-resource selection, `"SURNAME, FIRSTNAME"`
//! name normalisation + whole-word / exact-ABN matching, and the
//! `records_to_entities` transform that turns raw ASIC AFS authorised-
//! representative CKAN rows into a `Person` anchor plus its ABN/ACN and locality
//! pivots.

use serde_json::{Map, Value};

use crate::core::entity::{Entity, EntityKind, Evidence};
use crate::util::ckan::{Resource, field_str};

use super::{ABN_CONF, ADDR_CONF, MAX_RECORDS, PERSON_CANDIDATE, PERSON_EXACT, SRC};

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

/// Keep only the ASCII digits of a value (ABN/ACN comparison is digit-only:
/// `"51 824 753 556"` and `"51824753556"` are the same identifier).
fn digits(s: &str) -> String {
    s.chars().filter(char::is_ascii_digit).collect()
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

/// True if the row's recorded ABN or ACN equals the seed's digits exactly (only
/// meaningful when the seed is an `AbnAcn`). A digit-only equality so spacing
/// never defeats the match; either `AFS_REP_ABN` or `AFS_REP_ACN` may carry it.
pub(super) fn abn_matches_query(rec: &Map<String, Value>, query: &str) -> bool {
    let seed = digits(query);
    if seed.len() < 9 {
        return false;
    }
    ["AFS_REP_ABN", "AFS_REP_ACN"]
        .into_iter()
        .filter_map(|col| field_str(rec, col))
        .any(|v| digits(&v) == seed)
}

/// Decide whether a row exactly identifies the seed: an `AbnAcn` seed matches
/// `AFS_REP_ABN`/`AFS_REP_ACN` digit-for-digit; any seed also matches when the
/// representative name contains every seed token as a whole word.
pub(super) fn record_is_exact(rec: &Map<String, Value>, query: &str, abn_query: bool) -> bool {
    if abn_query && abn_matches_query(rec, query) {
        return true;
    }
    field_str(rec, "AFS_REP_NAME").is_some_and(|n| name_matches_query(&n, query))
}

/// Build the geocodable locality string from the recorded address parts
/// ("Sydney, NSW 2000, Australia"). Returns `None` when nothing locates.
pub(super) fn rep_locality(rec: &Map<String, Value>) -> Option<String> {
    let local = field_str(rec, "AFS_REP_ADD_LOCAL");
    let state = field_str(rec, "AFS_REP_ADD_STATE");
    let pcode = field_str(rec, "AFS_REP_ADD_PCODE");
    let country = field_str(rec, "AFS_REP_ADD_COUNTRY");
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

/// Attach every present register field to a representative's evidence so nothing
/// the API returned is dropped — true for exact hits and candidates alike. The
/// `AFS_LIC_NUM` is noted as the licence the rep acts under (a pivot to the
/// licensee).
pub(super) fn rep_evidence(rec: &Map<String, Value>, name: &str, total: u64) -> Evidence {
    let mut ev = Evidence::new(SRC, format!("ASIC AFS authorised representative: {name}"))
        .with_attr(
            "register",
            "ASIC Australian Financial Services Authorised Representative",
        )
        .with_attr("representative_name", name)
        .with_attr("total_matches", total.to_string());
    if let Some(lic) = field_str(rec, "AFS_LIC_NUM") {
        ev = ev.with_attr("acts_under", format!("acts under AFS licence {lic}"));
    }
    [
        ("REGISTER_NAME", "register_name"),
        ("AFS_REP_NUM", "representative_number"),
        ("AFS_LIC_NUM", "afs_licence_number"),
        ("AFS_REP_ABN", "abn"),
        ("AFS_REP_ACN", "acn"),
        ("AFS_REP_OTHER_ROLE", "other_role"),
        ("AFS_REP_START_DT", "start_date"),
        ("AFS_REP_STATUS", "status"),
        ("AFS_REP_END_DT", "end_date"),
        ("AFS_REP_APPOINTED_BY", "appointed_by"),
        ("AFS_REP_ADD_LOCAL", "address_locality"),
        ("AFS_REP_ADD_STATE", "address_state"),
        ("AFS_REP_ADD_PCODE", "address_postcode"),
        ("AFS_REP_ADD_COUNTRY", "address_country"),
    ]
    .into_iter()
    .filter_map(|(col, attr)| field_str(rec, col).map(|v| (attr, v)))
    .fold(ev, |ev, (attr, v)| ev.with_attr(attr, v))
}

/// Pure transform: CKAN ASIC AFS authorised-representative rows → entities.
/// Every row yields a primary `Person` (the representative) carrying the full
/// record in evidence (no omission). A row whose normalised name contains every
/// seed token as a whole word — or whose ABN/ACN equals an `AbnAcn` seed exactly
/// — is a high-confidence finding (tagged `afs-representative` /
/// `financial-services`) that fans out into its ABN/ACN and `Address` pivots;
/// loose full-text hits stay a single sub-floor `name-candidate` Person.
pub(super) fn records_to_entities(
    records: &[Map<String, Value>],
    total: u64,
    query: &str,
    abn_query: bool,
    scan_id: &str,
) -> Vec<Entity> {
    let mut out = Vec::new();
    for rec in records.iter().take(MAX_RECORDS) {
        let Some(raw_name) = field_str(rec, "AFS_REP_NAME") else {
            continue;
        };
        let name = raw_name.replace('\u{a0}', " ");
        let exact = record_is_exact(rec, query, abn_query);
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
            person.tag("afs-representative");
            person.tag("financial-services");
            person.tag("professional-record");
            person.tag("exact-name-match");
        } else {
            person.tag("name-candidate");
        }
        person.add_evidence(rep_evidence(rec, &name, total));
        out.push(person);

        // Cross-correlation pivots — exact hits only.
        if !exact {
            continue;
        }

        // Recorded ABN → AbnAcn pivot (into au_business_id / abn_lookup / asic).
        if let Some(abn) = field_str(rec, "AFS_REP_ABN") {
            let abn = digits(&abn);
            if abn.len() >= 9 {
                let mut e = Entity::new(EntityKind::AbnAcn, &abn, ABN_CONF, scan_id);
                e.tag(SRC);
                e.tag("asic");
                e.tag("country:AU");
                e.add_evidence(Evidence::new(
                    SRC,
                    format!("AFS representative ABN {abn} → {name}"),
                ));
                out.push(e);
            }
        }

        // Recorded ACN → AbnAcn pivot (corporate representative); tagged `acn`.
        if let Some(acn) = field_str(rec, "AFS_REP_ACN") {
            let acn = digits(&acn);
            if acn.len() >= 9 {
                let mut e = Entity::new(EntityKind::AbnAcn, &acn, ABN_CONF, scan_id);
                e.tag(SRC);
                e.tag("asic");
                e.tag("country:AU");
                e.tag("acn");
                e.add_evidence(Evidence::new(
                    SRC,
                    format!("AFS representative ACN {acn} (corporate rep) → {name}"),
                ));
                out.push(e);
            }
        }

        // Recorded locality → Address pivot.
        if let Some(addr) = rep_locality(rec) {
            let mut e = Entity::new(EntityKind::Address, &addr, ADDR_CONF, scan_id);
            e.tag(SRC);
            e.tag("asic");
            e.tag("country:AU");
            e.tag("geoint");
            if let Some(sc) = crate::util::address_au::state_code(&addr) {
                e.tag(format!("au-state:{sc}"));
            }
            e.add_evidence(
                Evidence::new(
                    SRC,
                    format!("Recorded locality of AFS representative {name}"),
                )
                .with_attr("representative", &name),
            );
            out.push(e);
        }
    }
    out
}
