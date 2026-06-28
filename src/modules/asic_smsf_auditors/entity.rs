//! Pure-data helpers: datastore-resource selection, plain `"First Last"`
//! whole-word / exact-ABN matching, and the `records_to_entities` transform that
//! turns raw ASIC SMSF-auditor CKAN rows into a `Person` anchor plus its firm
//! `Organisation`, ABN and locality pivots.

use serde_json::{Map, Value};

use crate::core::entity::{Entity, EntityKind, Evidence};
use crate::util::ckan::{Resource, field_str};

use super::{ABN_CONF, ADDR_CONF, MAX_RECORDS, ORG_CONF, PERSON_CANDIDATE, PERSON_EXACT, SRC};

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

/// Keep only the ASCII digits of a value (ABN comparison is digit-only:
/// `"51 824 753 556"` and `"51824753556"` are the same identifier).
fn digits(s: &str) -> String {
    s.chars().filter(char::is_ascii_digit).collect()
}

/// True if `name` contains every token of the seed `query` as a *whole word*
/// (case-insensitive). `SMSF_NAME` is plain `"First Last"`, so a `"First Last"`
/// seed matches token-set-wise. Whole-word (not substring) so `"Ben"` does not
/// match inside `"Benjamin"`.
pub(super) fn name_matches_query(name: &str, query: &str) -> bool {
    let words = tokens(name);
    let seed = tokens(query);
    !seed.is_empty()
        && seed
            .iter()
            .all(|tok| words.iter().any(|w| w.eq_ignore_ascii_case(tok)))
}

/// True if the row's recorded `SMSF_PERSON_ABN` equals the seed's digits exactly
/// (only meaningful when the seed is an `AbnAcn`). Digit-only equality so spacing
/// never defeats the match.
pub(super) fn abn_matches_query(rec: &Map<String, Value>, query: &str) -> bool {
    let seed = digits(query);
    if seed.len() < 9 {
        return false;
    }
    field_str(rec, "SMSF_PERSON_ABN").is_some_and(|v| digits(&v) == seed)
}

/// Decide whether a row exactly identifies the seed: an `AbnAcn` seed matches
/// `SMSF_PERSON_ABN` digit-for-digit; any seed also matches when the auditor name
/// contains every seed token as a whole word.
pub(super) fn record_is_exact(rec: &Map<String, Value>, query: &str, abn_query: bool) -> bool {
    if abn_query && abn_matches_query(rec, query) {
        return true;
    }
    field_str(rec, "SMSF_NAME").is_some_and(|n| name_matches_query(&n, query))
}

/// True if the recorded status denotes a suspension or cancellation (a
/// regulatory *condition*, not a ban). Used to tag the person `suspended`.
pub(super) fn status_is_suspended(status: &str) -> bool {
    let s = status.to_ascii_lowercase();
    s.contains("suspend") || s.contains("cancel")
}

/// Build the geocodable locality string from the recorded address parts
/// ("Sydney, NSW 2000, Australia"). Returns `None` when nothing locates.
pub(super) fn smsf_locality(rec: &Map<String, Value>) -> Option<String> {
    let local = field_str(rec, "SMSF_LOCALITY");
    let state = field_str(rec, "SMSF_STATE");
    let pcode = field_str(rec, "SMSF_POST_CODE");
    if local.is_none() && state.is_none() && pcode.is_none() {
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
    if parts.is_empty() {
        None
    } else {
        parts.push("Australia".to_string());
        Some(parts.join(", "))
    }
}

/// Attach every present register field to an auditor's evidence so nothing the
/// API returned is dropped — true for exact hits and candidates alike. One row
/// is one registration condition, so the condition fields are recorded per row.
pub(super) fn smsf_evidence(rec: &Map<String, Value>, name: &str, total: u64) -> Evidence {
    let ev = Evidence::new(SRC, format!("ASIC SMSF approved auditor: {name}"))
        .with_attr("register", "ASIC Self-Managed Super Fund Auditor")
        .with_attr("auditor_name", name)
        .with_attr("total_matches", total.to_string());
    [
        ("REGISTER_NAME", "register_name"),
        ("SMSF_NUM", "auditor_number"),
        ("SMSF_STATUS", "status"),
        ("SMSF_PERSON_ABN", "abn"),
        ("SMSF_REG_DT", "registration_date"),
        ("SMSF_SUSP_START_DT", "suspension_start_date"),
        ("SMSF_SUSP_END_DT", "suspension_end_date"),
        ("SMSF_CAPACITY_FIRM_NAME", "firm_name"),
        ("SMSF_CONDITION", "condition"),
        ("SMSF_CONDITION_DTL", "condition_detail"),
        ("SMSF_LOCALITY", "address_locality"),
        ("SMSF_STATE", "address_state"),
        ("SMSF_POST_CODE", "address_postcode"),
    ]
    .into_iter()
    .filter_map(|(col, attr)| field_str(rec, col).map(|v| (attr, v)))
    .fold(ev, |ev, (attr, v)| ev.with_attr(attr, v))
}

/// Pure transform: CKAN ASIC SMSF-auditor rows → entities. Every row yields a
/// primary `Person` (the auditor) carrying the full record in evidence (no
/// omission). A row whose name contains every seed token as a whole word — or
/// whose `SMSF_PERSON_ABN` equals an `AbnAcn` seed exactly — is a high-confidence
/// finding (tagged `smsf-auditor` / `auditor`, plus `suspended` when the status
/// denotes a suspension/cancellation) that fans out into its ABN, firm
/// `Organisation` and `Address` pivots; loose full-text hits stay a single
/// sub-floor `name-candidate` Person.
pub(super) fn records_to_entities(
    records: &[Map<String, Value>],
    total: u64,
    query: &str,
    abn_query: bool,
    scan_id: &str,
) -> Vec<Entity> {
    let mut out = Vec::new();
    for rec in records.iter().take(MAX_RECORDS) {
        let Some(raw_name) = field_str(rec, "SMSF_NAME") else {
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
            person.tag("smsf-auditor");
            person.tag("auditor");
            person.tag("professional-record");
            person.tag("exact-name-match");
            if field_str(rec, "SMSF_STATUS").is_some_and(|s| status_is_suspended(&s)) {
                // A registration condition (suspended/cancelled), NOT a ban —
                // surfaced for context, not treated as sanctioned.
                person.tag("suspended");
            }
        } else {
            person.tag("name-candidate");
        }
        person.add_evidence(smsf_evidence(rec, &name, total));
        out.push(person);

        // Cross-correlation pivots — exact hits only.
        if !exact {
            continue;
        }

        // Recorded ABN → AbnAcn pivot (into au_business_id / abn_lookup / asic).
        if let Some(abn) = field_str(rec, "SMSF_PERSON_ABN") {
            let abn = digits(&abn);
            if abn.len() >= 9 {
                let mut e = Entity::new(EntityKind::AbnAcn, &abn, ABN_CONF, scan_id);
                e.tag(SRC);
                e.tag("asic");
                e.tag("country:AU");
                e.add_evidence(Evidence::new(
                    SRC,
                    format!("SMSF auditor ABN {abn} → {name}"),
                ));
                out.push(e);
            }
        }

        // Recorded auditing firm → related Organisation pivot.
        if let Some(firm) = field_str(rec, "SMSF_CAPACITY_FIRM_NAME") {
            let mut e = Entity::new(EntityKind::Organisation, &firm, ORG_CONF, scan_id);
            e.tag(SRC);
            e.tag("asic");
            e.tag("country:AU");
            e.tag("auditor-firm");
            e.add_evidence(
                Evidence::new(SRC, format!("SMSF auditing firm of {name}: {firm}"))
                    .with_attr("auditor", &name),
            );
            out.push(e);
        }

        // Recorded locality → Address pivot.
        if let Some(addr) = smsf_locality(rec) {
            let mut e = Entity::new(EntityKind::Address, &addr, ADDR_CONF, scan_id);
            e.tag(SRC);
            e.tag("asic");
            e.tag("country:AU");
            e.tag("geoint");
            if let Some(sc) = crate::util::address_au::state_code(&addr) {
                e.tag(format!("au-state:{sc}"));
            }
            e.add_evidence(
                Evidence::new(SRC, format!("Recorded locality of SMSF auditor {name}"))
                    .with_attr("auditor", &name),
            );
            out.push(e);
        }
    }
    out
}
