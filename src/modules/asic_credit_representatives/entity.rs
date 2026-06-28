//! Pure-data helpers: datastore-resource selection, org/person shape detection
//! over the `CRED_REP_NAME` mix, `"SURNAME, FIRSTNAME"` name normalisation +
//! whole-word / exact-ABN matching, and the `records_to_entities` transform that
//! turns raw ASIC Credit Representative CKAN rows into a `Person` *or*
//! `Organisation` anchor plus its ABN/ACN and locality pivots.

use serde_json::{Map, Value};

use crate::core::entity::{Entity, EntityKind, Evidence};
use crate::util::ckan::{Resource, field_str};

use super::{ABN_CONF, ADDR_CONF, MAX_RECORDS, NAME_CANDIDATE, NAME_EXACT, SRC};

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

/// True if `name` looks like an organisation rather than a person. The
/// `CRED_REP_NAME` column is a mix of orgs (`"THINK TANK GROUP PTY LIMITED"`) and
/// persons (`"WEAVER, BRUCE"`); a company suffix as a whole word (PTY, LTD,
/// LIMITED, INC, CO, …) marks the org shape. Whole-word so `"CORPORATION"`
/// doesn't false-trigger on `"CO"` etc.
pub(super) fn looks_like_org(name: &str) -> bool {
    const SUFFIXES: &[&str] = &[
        "PTY",
        "LTD",
        "LIMITED",
        "INC",
        "INCORPORATED",
        "CO",
        "CORP",
        "CORPORATION",
        "LLC",
        "PLC",
        "GROUP",
        "COMPANY",
        "HOLDINGS",
        "TRUST",
        "ASSOCIATION",
        "SOCIETY",
        "FOUNDATION",
    ];
    tokens(name)
        .iter()
        .any(|w| SUFFIXES.iter().any(|s| w.eq_ignore_ascii_case(s)))
}

/// True if `name` contains every token of the seed `query` as a *whole word*
/// (case-insensitive), comparing token-set-wise so the register's
/// `"SURNAME, FIRSTNAME"` (person) or `"NAME PTY LTD"` (org) format matches a
/// seed regardless of order. Whole-word (not substring) so `"li"` doesn't match
/// inside `"Ali"`.
pub(super) fn name_matches_query(name: &str, query: &str) -> bool {
    let words = tokens(name);
    let seed = tokens(query);
    !seed.is_empty()
        && seed
            .iter()
            .all(|tok| words.iter().any(|w| w.eq_ignore_ascii_case(tok)))
}

/// True if the row's recorded ABN/ACN equals the seed's digits exactly (only
/// meaningful when the seed is an `AbnAcn`). A digit-only equality so spacing
/// never defeats the match.
pub(super) fn abn_matches_query(rec: &Map<String, Value>, query: &str) -> bool {
    let seed = digits(query);
    if seed.len() < 9 {
        return false;
    }
    field_str(rec, "CRED_REP_ABN_ACN").is_some_and(|v| digits(&v) == seed)
}

/// Decide whether a row exactly identifies the seed: an `AbnAcn` seed matches
/// `CRED_REP_ABN_ACN` digit-for-digit; any seed also matches when the
/// representative name contains every seed token as a whole word.
pub(super) fn record_is_exact(rec: &Map<String, Value>, query: &str, abn_query: bool) -> bool {
    if abn_query && abn_matches_query(rec, query) {
        return true;
    }
    field_str(rec, "CRED_REP_NAME").is_some_and(|n| name_matches_query(&n, query))
}

/// Build the geocodable locality string from the recorded address parts
/// ("Sydney, NSW 2000, Australia"). Returns `None` when nothing locates.
pub(super) fn rep_locality(rec: &Map<String, Value>) -> Option<String> {
    let local = field_str(rec, "CRED_REP_LOCALITY");
    let state = field_str(rec, "CRED_REP_STATE");
    let pcode = field_str(rec, "CRED_REP_PCODE");
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
    parts.push("Australia".to_string());
    Some(parts.join(", "))
}

/// Derive a human-readable status from the start/end dates: a representative with
/// a recorded end date is `Ceased`, otherwise `Current`. Returns `None` if no
/// date fields are present at all.
fn rep_status(rec: &Map<String, Value>) -> Option<&'static str> {
    let start = field_str(rec, "CRED_REP_START_DT");
    let end = field_str(rec, "CRED_REP_END_DT");
    if start.is_none() && end.is_none() {
        return None;
    }
    if end.as_deref().is_some_and(|e| !e.trim().is_empty()) {
        Some("Ceased")
    } else {
        Some("Current")
    }
}

/// Attach every present register field to a representative's evidence so nothing
/// the API returned is dropped — true for exact hits and candidates alike. The
/// `CRED_LIC_NUM` is noted as the credit licence the rep acts under (a pivot to
/// the licensee), and a derived status is included.
pub(super) fn rep_evidence(rec: &Map<String, Value>, name: &str, total: u64) -> Evidence {
    let mut ev = Evidence::new(SRC, format!("ASIC credit representative: {name}"))
        .with_attr("register", "ASIC Credit Representative")
        .with_attr("representative_name", name)
        .with_attr("total_matches", total.to_string());
    if let Some(lic) = field_str(rec, "CRED_LIC_NUM") {
        ev = ev.with_attr("acts_under", format!("acts under credit licence {lic}"));
    }
    if let Some(status) = rep_status(rec) {
        ev = ev.with_attr("status", status);
    }
    [
        ("REGISTER_NAME", "register_name"),
        ("CRED_REP_NUM", "representative_number"),
        ("CRED_LIC_NUM", "credit_licence_number"),
        ("CRED_REP_ABN_ACN", "abn_acn"),
        ("CRED_REP_START_DT", "start_date"),
        ("CRED_REP_END_DT", "end_date"),
        ("CRED_REP_LOCALITY", "address_locality"),
        ("CRED_REP_STATE", "address_state"),
        ("CRED_REP_PCODE", "address_postcode"),
        ("CRED_REP_EDRS", "edrs"),
        ("CRED_REP_AUTHORISATIONS", "authorisations"),
        ("CRED_REP_CROSS_ENDORSE", "cross_endorse"),
    ]
    .into_iter()
    .filter_map(|(col, attr)| field_str(rec, col).map(|v| (attr, v)))
    .fold(ev, |ev, (attr, v)| ev.with_attr(attr, v))
}

/// Pure transform: CKAN ASIC credit-representative rows → entities. Every row
/// yields a primary anchor carrying the full record in evidence (no omission) —
/// a `Person` for a `"SURNAME, FIRSTNAME"` shape, an `Organisation` when the
/// name carries a company suffix. A row whose normalised name contains every seed
/// token as a whole word — or whose ABN/ACN equals an `AbnAcn` seed exactly — is
/// a high-confidence finding (tagged `credit-representative` /
/// `financial-services`) that fans out into its ABN/ACN and `Address` pivots;
/// loose full-text hits stay a single sub-floor `name-candidate`.
pub(super) fn records_to_entities(
    records: &[Map<String, Value>],
    total: u64,
    query: &str,
    abn_query: bool,
    scan_id: &str,
) -> Vec<Entity> {
    let mut out = Vec::new();
    for rec in records.iter().take(MAX_RECORDS) {
        let Some(raw_name) = field_str(rec, "CRED_REP_NAME") else {
            continue;
        };
        let name = raw_name.replace('\u{a0}', " ");
        let is_org = looks_like_org(&name);
        let exact = record_is_exact(rec, query, abn_query);
        let conf = if exact { NAME_EXACT } else { NAME_CANDIDATE };

        let kind = if is_org {
            EntityKind::Organisation
        } else {
            EntityKind::Person
        };
        let mut anchor = Entity::new(kind, &name, conf, scan_id);
        anchor.tag(SRC);
        anchor.tag("asic");
        anchor.tag("country:AU");
        if exact {
            anchor.tag("credit-representative");
            anchor.tag("financial-services");
            anchor.tag("professional-record");
            anchor.tag("exact-name-match");
        } else {
            anchor.tag("name-candidate");
        }
        anchor.add_evidence(rep_evidence(rec, &name, total));
        out.push(anchor);

        // Cross-correlation pivots — exact hits only.
        if !exact {
            continue;
        }

        // Recorded ABN/ACN → AbnAcn pivot (into au_business_id / abn_lookup /
        // asic stack).
        if let Some(abn) = field_str(rec, "CRED_REP_ABN_ACN") {
            let abn = digits(&abn);
            if abn.len() >= 9 {
                let mut e = Entity::new(EntityKind::AbnAcn, &abn, ABN_CONF, scan_id);
                e.tag(SRC);
                e.tag("asic");
                e.tag("country:AU");
                e.add_evidence(Evidence::new(
                    SRC,
                    format!("Credit representative ABN/ACN {abn} → {name}"),
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
                    format!("Recorded locality of credit representative {name}"),
                )
                .with_attr("representative", &name),
            );
            out.push(e);
        }
    }
    out
}
