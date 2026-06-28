//! Pure-data helpers: datastore-resource selection, whole-word / exact-ACN
//! matching, and the `records_to_entities` transform that turns raw ASIC
//! company CKAN rows into an anchor `Organisation` plus its ACN pivot.

use serde_json::{Map, Value};

use crate::core::entity::{Entity, EntityKind, Evidence};
use crate::util::ckan::{Resource, field_str};

use super::{ACN_CONF, MAX_RECORDS, ORG_CANDIDATE, ORG_EXACT, SRC};

/// Select the resource id to query: the datastore-active resource whose name
/// contains "Current" (case-insensitive); failing that, the first
/// datastore-active resource. Returns `None` if nothing is datastore-active.
///
/// Critical for this dataset: the package exposes **two** datastore-active
/// resources — the real "Company Dataset - Current" (4.4M-row CSV) and a
/// "Company Dataset - Help File" (a 27-row PDF help table). The "Current"
/// preference guarantees the help file is never selected.
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
/// doesn't match inside `"Ali"` — the conservative gate that stops a common
/// token promoting unrelated companies across the 4.4M-row register.
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
/// never defeats the match. An ACN is 9 digits.
pub(super) fn acn_matches_query(rec: &Map<String, Value>, query: &str) -> bool {
    let seed = digits(query);
    if seed.len() < 9 {
        return false;
    }
    field_str(rec, "ACN").is_some_and(|v| digits(&v) == seed)
}

/// Decide whether a row exactly identifies the seed: an `AbnAcn` seed matches
/// `ACN` digit-for-digit; any seed also matches when the company name contains
/// every seed token as a whole word.
pub(super) fn record_is_exact(rec: &Map<String, Value>, query: &str, abn_query: bool) -> bool {
    if abn_query && acn_matches_query(rec, query) {
        return true;
    }
    field_str(rec, "Company Name").is_some_and(|n| name_matches_query(&n, query))
}

/// Attach every present register field to a company's evidence so nothing the
/// API returned is dropped — true for exact hits and candidates alike.
pub(super) fn company_evidence(rec: &Map<String, Value>, name: &str, total: u64) -> Evidence {
    let ev = Evidence::new(SRC, format!("ASIC registered company: {name}"))
        .with_attr("register", "ASIC Company Dataset")
        .with_attr("company_name", name)
        .with_attr("total_matches", total.to_string());
    [
        ("ACN", "acn"),
        ("Type", "type"),
        ("Class", "class"),
        ("Sub Class", "sub_class"),
        ("Status", "status"),
        ("Date of Registration", "date_of_registration"),
        ("Date of Deregistration", "date_of_deregistration"),
        (
            "Previous State of Registration",
            "previous_state_of_registration",
        ),
        ("State Registration number", "state_registration_number"),
        ("Modified since last report", "modified_since_last_report"),
        ("Current Name Ind", "current_name_ind"),
    ]
    .into_iter()
    .filter_map(|(col, attr)| field_str(rec, col).map(|v| (attr, v)))
    .fold(ev, |ev, (attr, v)| ev.with_attr(attr, v))
}

/// Pure transform: CKAN ASIC company rows → entities. Every row yields a primary
/// `Organisation` (the company) carrying the full record in evidence (no
/// omission). A row whose company name contains every seed token as a whole word
/// — or whose ACN equals an `AbnAcn` seed exactly — is a high-confidence finding
/// (tagged `registered-company` / `asic`) that fans out into its `AbnAcn` (an
/// ACN); loose full-text hits stay a single sub-floor `name-candidate`
/// Organisation. This dataset has no address/coordinates, so no `Address` is
/// produced.
pub(super) fn records_to_entities(
    records: &[Map<String, Value>],
    total: u64,
    query: &str,
    abn_query: bool,
    scan_id: &str,
) -> Vec<Entity> {
    let mut out = Vec::new();
    for rec in records.iter().take(MAX_RECORDS) {
        let Some(raw_name) = field_str(rec, "Company Name") else {
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
            org.tag("registered-company");
            org.tag("exact-name-match");
        } else {
            org.tag("name-candidate");
        }
        org.add_evidence(company_evidence(rec, &name, total));
        out.push(org);

        // Cross-correlation pivot — exact hits only.
        if !exact {
            continue;
        }

        // Recorded ACN → pivots into abn_lookup / asic_director / opencorporates.
        if let Some(acn) = field_str(rec, "ACN") {
            let acn = digits(&acn);
            if acn.len() >= 9 {
                let mut e = Entity::new(EntityKind::AbnAcn, &acn, ACN_CONF, scan_id);
                e.tag(SRC);
                e.tag("asic");
                e.tag("country:AU");
                e.tag("acn");
                e.add_evidence(Evidence::new(
                    SRC,
                    format!("Registered company ACN {acn} → {name}"),
                ));
                out.push(e);
            }
        }
    }
    out
}
