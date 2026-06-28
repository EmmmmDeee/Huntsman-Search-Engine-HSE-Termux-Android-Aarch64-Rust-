//! Pure-data helpers: datastore-resource selection, whole-word / exact-ACN
//! matching, and the `records_to_entities` transform that turns raw ASIC
//! registered-auditor CKAN rows into an anchor `Organisation` plus its ACN and
//! address pivots.

use serde_json::{Map, Value};

use crate::core::entity::{Entity, EntityKind, Evidence};
use crate::util::ckan::{Resource, field_str};

use super::{ACN_CONF, ADDR_CONF, MAX_RECORDS, ORG_CANDIDATE, ORG_EXACT, SRC};

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
/// (case-preserved).
fn tokens(s: &str) -> Vec<&str> {
    s.split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty())
        .collect()
}

/// Keep only the ASCII digits of a value (ACN comparison is digit-only).
fn digits(s: &str) -> String {
    s.chars().filter(char::is_ascii_digit).collect()
}

/// True if `name` contains every token of the seed `query` as a *whole word*
/// (case-insensitive). Whole-word (not substring) so a seed token like `"li"`
/// doesn't match inside `"Ali"`.
pub(super) fn name_matches_query(name: &str, query: &str) -> bool {
    let words = tokens(name);
    let seed = tokens(query);
    !seed.is_empty()
        && seed
            .iter()
            .all(|tok| words.iter().any(|w| w.eq_ignore_ascii_case(tok)))
}

/// True if the row's recorded ACN equals the seed's digits exactly (only
/// meaningful when the seed is an `AbnAcn`). A digit-only equality so spacing
/// never defeats the match.
pub(super) fn acn_matches_query(rec: &Map<String, Value>, query: &str) -> bool {
    let seed = digits(query);
    if seed.len() < 9 {
        return false;
    }
    field_str(rec, "REG_AUD_ACN").is_some_and(|v| digits(&v) == seed)
}

/// Decide whether a row exactly identifies the seed: an `AbnAcn` seed matches
/// `REG_AUD_ACN` digit-for-digit; any seed also matches when the auditor name
/// contains every seed token as a whole word.
pub(super) fn record_is_exact(rec: &Map<String, Value>, query: &str, abn_query: bool) -> bool {
    if abn_query && acn_matches_query(rec, query) {
        return true;
    }
    field_str(rec, "REG_AUD_NAME").is_some_and(|n| name_matches_query(&n, query))
}

/// Build the geocodable locality string from the recorded address parts
/// ("Sydney, NSW 2000, Australia"). Returns `None` when nothing locates.
pub(super) fn auditor_locality(rec: &Map<String, Value>) -> Option<String> {
    let local = field_str(rec, "REG_AUD_ADD_LOCAL");
    let state = field_str(rec, "REG_AUD_ADD_STATE");
    let pcode = field_str(rec, "REG_AUD_ADD_PCODE");
    let country = field_str(rec, "REG_AUD_ADD_COUNTRY");
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
    parts.push(country.unwrap_or_else(|| "Australia".to_string()));
    Some(parts.join(", "))
}

/// Attach every present register field to an auditor's evidence so nothing the
/// API returned is dropped — true for exact hits and candidates alike.
pub(super) fn auditor_evidence(rec: &Map<String, Value>, name: &str, total: u64) -> Evidence {
    let ev = Evidence::new(SRC, format!("ASIC registered auditor: {name}"))
        .with_attr("register", "ASIC Registered Auditor")
        .with_attr("auditor_name", name)
        .with_attr("total_matches", total.to_string());
    [
        ("REGISTER_NAME", "register_name"),
        ("REG_AUD_NUM", "registration_number"),
        ("REG_AUD_ACN", "acn"),
        ("REG_AUD_START_DT", "registration_start"),
        ("REG_AUD_STATUS", "status"),
        ("REG_AUD_SUSP_DT", "suspension_date"),
        ("REG_AUD_ADD_LOCAL", "address_locality"),
        ("REG_AUD_ADD_STATE", "address_state"),
        ("REG_AUD_ADD_PCODE", "address_postcode"),
        ("REG_AUD_ADD_COUNTRY", "address_country"),
    ]
    .into_iter()
    .filter_map(|(col, attr)| field_str(rec, col).map(|v| (attr, v)))
    .fold(ev, |ev, (attr, v)| ev.with_attr(attr, v))
}

/// Pure transform: CKAN ASIC registered-auditor rows → entities. Every row yields
/// a primary `Organisation` (the auditor) carrying the full record in evidence
/// (no omission). A row whose auditor name contains every seed token as a whole
/// word — or whose ACN equals an `AbnAcn` seed exactly — is a high-confidence
/// finding (tagged `registered-auditor` / `auditor`) that fans out into its
/// `AbnAcn` (an ACN) and `Address` pivots; loose full-text hits stay a single
/// sub-floor `name-candidate` Organisation.
pub(super) fn records_to_entities(
    records: &[Map<String, Value>],
    total: u64,
    query: &str,
    abn_query: bool,
    scan_id: &str,
) -> Vec<Entity> {
    let mut out = Vec::new();
    for rec in records.iter().take(MAX_RECORDS) {
        let Some(raw_name) = field_str(rec, "REG_AUD_NAME") else {
            continue;
        };
        let name = raw_name.replace('\u{a0}', " ");
        let exact = record_is_exact(rec, query, abn_query);
        let conf = if exact { ORG_EXACT } else { ORG_CANDIDATE };

        let mut org = Entity::new(EntityKind::Organisation, &name, conf, scan_id);
        org.tag(SRC);
        org.tag("asic");
        org.tag("country:AU");
        if exact {
            org.tag("registered-auditor");
            org.tag("auditor");
            org.tag("regulated-entity");
            org.tag("exact-name-match");
        } else {
            org.tag("name-candidate");
        }
        org.add_evidence(auditor_evidence(rec, &name, total));
        out.push(org);

        // Cross-correlation pivots — exact hits only.
        if !exact {
            continue;
        }

        // Recorded ACN → pivots into au_business_id / abn_lookup / asic stack.
        if let Some(acn) = field_str(rec, "REG_AUD_ACN") {
            let acn = digits(&acn);
            if acn.len() >= 9 {
                let mut e = Entity::new(EntityKind::AbnAcn, &acn, ACN_CONF, scan_id);
                e.tag(SRC);
                e.tag("asic");
                e.tag("country:AU");
                e.tag("acn");
                e.add_evidence(Evidence::new(
                    SRC,
                    format!("Registered auditor ACN {acn} → {name}"),
                ));
                out.push(e);
            }
        }

        // Recorded business locality → Address pivot.
        if let Some(addr) = auditor_locality(rec) {
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
                    format!("Recorded business address of registered auditor {name}"),
                )
                .with_attr("auditor", &name),
            );
            out.push(e);
        }
    }
    out
}
