//! Pure-data helpers: field extraction, supplier-name matching, and the
//! `records_to_entities` transform that converts raw AusTender CKAN contract-
//! notice rows into cross-correlating graph entities.

use serde_json::{Map, Value};

use crate::core::entity::{Entity, EntityKind, Evidence};
use crate::util::ckan::field_str;

use super::{
    ABN_CONF, ADDR_CONF, AGENCY_CONF, MAX_RECORDS, ORG_CANDIDATE, ORG_EXACT, RESOURCE_ID, SRC,
};

/// The datastore_search URL for one full-text query.
pub(super) fn query_url(q: &str) -> String {
    crate::util::ckan::datastore_search_url(super::ACTION_BASE, RESOURCE_ID, q, MAX_RECORDS)
}

/// An 11-digit Australian Business Number (digits only) for the supplier of this
/// contract notice, else `None`. AusTender stores the ABN as text but a
/// numerically-typed datastore column would arrive as a JSON number, so we
/// normalise to digits and length-check.
pub(super) fn supplier_abn(rec: &Map<String, Value>) -> Option<String> {
    let raw = field_str(rec, "Supplier ABN")?;
    let digits = crate::util::str_util::ascii_digits(&raw);
    (digits.len() == 11).then_some(digits)
}

/// True if `name` contains every token of the seed `query` as a *whole word*
/// (case-insensitive). Whole-word (not substring) so a seed token like `"tel"`
/// doesn't match inside `"Intel"`. Tokenises on non-alphanumeric boundaries and
/// compares with `eq_ignore_ascii_case` (no per-token `String` allocation).
pub(super) fn name_matches_query(name: &str, query: &str) -> bool {
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

/// Whether this row is an exact match for the seed.
///
/// * ABN seed (`abn_query`): the supplier's ABN equals the seed's 11 digits —
///   an unambiguous identity match, so always exact.
/// * name / org seed: the supplier name contains every seed token as a whole
///   word.
pub(super) fn record_is_exact(rec: &Map<String, Value>, query: &str, abn_query: bool) -> bool {
    if abn_query {
        return supplier_abn(rec).as_deref() == Some(query);
    }
    field_str(rec, "Supplier Name")
        .as_deref()
        .is_some_and(|n| name_matches_query(n, query))
}

/// Build the geocodable supplier-locality string from the contract-notice
/// fields ("Sydney, NSW 2000, Australia"). The street line (`Supplier Address`)
/// is often a PO box or non-geocodable line, so it rides in the evidence; the
/// suburb/state/postcode is what the geocode chain pivots on. Returns `None`
/// when there's nothing locating at all.
pub(super) fn supplier_locality(rec: &Map<String, Value>) -> Option<String> {
    let suburb = field_str(rec, "Supplier Suburb");
    let state = field_str(rec, "Supplier State");
    let postcode = field_str(rec, "Supplier Postcode");
    let country = field_str(rec, "Supplier Country").unwrap_or_else(|| "Australia".to_string());
    if suburb.is_none() && state.is_none() && postcode.is_none() {
        return None;
    }
    let mut head = String::new();
    if let Some(s) = suburb.as_deref() {
        head.push_str(s);
    }
    match (state.as_deref(), postcode.as_deref()) {
        (Some(s), Some(p)) => {
            if !head.is_empty() {
                head.push_str(", ");
            }
            head.push_str(s);
            head.push(' ');
            head.push_str(p);
        }
        (Some(s), None) => {
            if !head.is_empty() {
                head.push_str(", ");
            }
            head.push_str(s);
        }
        (None, Some(p)) => {
            if !head.is_empty() {
                head.push_str(", ");
            }
            head.push_str(p);
        }
        (None, None) => {}
    }
    if head.is_empty() {
        return None;
    }
    Some(format!("{head}, {country}"))
}

/// Attach every present contract-notice field to the supplier's evidence so
/// nothing the API returned is dropped — true for exact hits and candidates
/// alike.
pub(super) fn contract_evidence(rec: &Map<String, Value>, total: u64) -> Evidence {
    let supplier = field_str(rec, "Supplier Name").unwrap_or_default();
    let ev = Evidence::new(
        SRC,
        format!("AusTender contract notice: supplier {supplier}"),
    )
    .with_attr(
        "register",
        "AusTender Australian Government contract notices",
    )
    .with_attr("total_matches", total.to_string());
    // Stable, useful columns — added only when present (no empty noise).
    [
        ("Agency Name", "agency"),
        ("Contract ID", "contract_id"),
        ("Contract Value", "contract_value"),
        ("Description", "description"),
        ("Publish Date", "publish_date"),
        ("Start Date", "start_date"),
        ("End Date", "end_date"),
        ("Procurement Method", "procurement_method"),
        ("Supplier ABN", "supplier_abn"),
        ("Supplier Address", "supplier_address"),
        ("Supplier Suburb", "supplier_suburb"),
        ("Supplier State", "supplier_state"),
        ("Supplier Postcode", "supplier_postcode"),
        ("Supplier Country", "supplier_country"),
        ("UNSPSC Title", "category"),
    ]
    .into_iter()
    .filter_map(|(col, attr)| field_str(rec, col).map(|v| (attr, v)))
    .fold(ev, |ev, (attr, v)| ev.with_attr(attr, v))
}

/// Pure transform: CKAN contract-notice records → entities. Every row yields a
/// primary `Organisation` (the supplier) carrying the full record in evidence
/// (no omission). Rows that match the seed exactly additionally fan out into the
/// cross-correlation pivots (supplier ABN, agency, supplier address → inline
/// coordinates); loose full-text candidates stay a single sub-floor
/// Organisation so generic queries don't pivot national contract-name noise.
pub(super) fn records_to_entities(
    records: &[Map<String, Value>],
    total: u64,
    query: &str,
    abn_query: bool,
    scan_id: &str,
) -> Vec<Entity> {
    let mut out = Vec::new();
    for rec in records.iter().take(MAX_RECORDS) {
        let Some(supplier) = field_str(rec, "Supplier Name") else {
            continue;
        };
        let exact = record_is_exact(rec, query, abn_query);
        let conf = if exact { ORG_EXACT } else { ORG_CANDIDATE };

        let mut org = Entity::new(EntityKind::Organisation, &supplier, conf, scan_id);
        org.tag(SRC);
        org.tag("austender");
        org.tag("government-contract");
        org.tag("country:AU");
        org.tag(if exact {
            "exact-name-match"
        } else {
            "name-candidate"
        });
        org.add_evidence(contract_evidence(rec, total));
        out.push(org);

        // Cross-correlation pivots — exact hits only.
        if !exact {
            continue;
        }

        // Supplier ABN → au_business_id / abn_lookup / opencorporates resolve the
        // full business registry (and the company → directors → people chain).
        if let Some(abn) = supplier_abn(rec) {
            let mut e = Entity::new(EntityKind::AbnAcn, &abn, ABN_CONF, scan_id);
            e.tag(SRC);
            e.tag("austender");
            e.tag("country:AU");
            e.add_evidence(Evidence::new(
                SRC,
                format!("Supplier ABN {abn} → {supplier}"),
            ));
            out.push(e);
        }

        // Awarding agency → a Business Relationship Organisation (the government
        // counterparty the supplier contracts with).
        if let Some(agency) = field_str(rec, "Agency Name") {
            let mut e = Entity::new(EntityKind::Organisation, &agency, AGENCY_CONF, scan_id);
            e.tag(SRC);
            e.tag("austender");
            e.tag("country:AU");
            e.tag("government-agency");
            e.add_evidence(
                Evidence::new(
                    SRC,
                    format!("Commonwealth agency awarding a contract to {supplier}"),
                )
                .with_attr("supplier", &supplier),
            );
            out.push(e);
        }

        // Supplier locality → geocode chains it into Coordinates.
        if let Some(addr) = supplier_locality(rec) {
            let mut e = Entity::new(EntityKind::Address, &addr, ADDR_CONF, scan_id);
            e.tag(SRC);
            e.tag("austender");
            e.tag("country:AU");
            e.tag("geoint");
            e.tag("supplier-address");
            if let Some(sc) = crate::util::address_au::state_code(&addr) {
                e.tag(format!("au-state:{sc}"));
            }
            let aev = ["Supplier Address", "Supplier Suburb"]
                .into_iter()
                .filter_map(|col| field_str(rec, col).map(|v| (col, v)))
                .fold(
                    Evidence::new(SRC, format!("Supplier address for {supplier}"))
                        .with_attr("supplier", &supplier),
                    |aev, (col, v)| aev.with_attr(col.to_lowercase().replace(' ', "_"), v),
                );
            e.add_evidence(aev);
            out.push(e);

            // Inline Coordinates for immediate geo participation.
            if let Some((lat, lon)) = crate::util::city_coords::city_coords(&addr) {
                let coord_val = format!("{lat:.4},{lon:.4}");
                let mut c = Entity::new(EntityKind::Coordinates, &coord_val, 0.60, scan_id);
                c.tag("addr-derived");
                c.tag("geoint");
                c.tag("austender");
                c.tag("country:AU");
                if let Some(sc) = crate::util::address_au::state_code(&addr) {
                    c.tag(format!("au-state:{sc}"));
                }
                c.add_evidence(Evidence::new(
                    SRC,
                    format!("Inline geocode of AusTender supplier address '{addr}' → {coord_val}"),
                ));
                out.push(c);
            }
        }
    }
    out
}
