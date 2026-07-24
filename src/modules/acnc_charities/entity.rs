//! Pure-data helpers: field extraction, name-matching, and the
//! `records_to_entities` transform that converts raw CKAN rows into
//! cross-correlating graph entities.

use serde_json::{Map, Value};

use crate::core::entity::{Entity, EntityKind, Evidence};
use crate::util::ckan::field_str;
use crate::util::url_util::host_from_url;

use super::{
    ABN_CONF, ADDR_CONF, DOMAIN_CONF, MAX_RECORDS, MAX_TRADING_NAMES, ORG_CANDIDATE, ORG_EXACT,
    SRC, TRADING_NAME_CONF,
};

/// An 11-digit Australian Business Number (digits only), else `None`. ACNC
/// stores the ABN as text but a numeric-typed datastore column would arrive as a
/// JSON number, so we normalise to digits and length-check.
pub(super) fn abn_digits(rec: &Map<String, Value>) -> Option<String> {
    let raw = field_str(rec, "ABN")?;
    let digits = crate::util::str_util::ascii_digits(&raw);
    (digits.len() == 11).then_some(digits)
}

/// Trading / other names, comma-separated in the register, split and trimmed.
/// `Address_Line_1` legitimately contains commas, but `Other_Organisation_Names`
/// is a flat comma list ("SUBS, Sydney University Business Society").
pub(super) fn other_names(rec: &Map<String, Value>) -> Vec<String> {
    field_str(rec, "Other_Organisation_Names")
        .map(|s| {
            s.split(',')
                .map(str::trim)
                .filter(|p| !p.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// True if `name` contains every token of the seed `query` as a *whole word*
/// (case-insensitive). Whole-word (not substring) so a seed token like `"red"`
/// doesn't match inside `"Mildred"`. Tokenises on non-alphanumeric boundaries
/// and compares with `eq_ignore_ascii_case` (no per-token `String` allocation).
pub(super) fn name_matches_query(name: &str, query: &str) -> bool {
    crate::util::str_util::whole_word_token_match(name, query)
}

/// True if the seed matches the charity's legal name or any of its other names.
pub(super) fn record_is_exact(rec: &Map<String, Value>, query: &str) -> bool {
    field_str(rec, "Charity_Legal_Name")
        .as_deref()
        .is_some_and(|n| name_matches_query(n, query))
        || other_names(rec)
            .iter()
            .any(|n| name_matches_query(n, query))
}

/// The datastore_search URL for one full-text query.
pub(super) fn query_url(q: &str) -> String {
    crate::util::ckan::datastore_search_url(super::ACTION_BASE, super::RESOURCE_ID, q, MAX_RECORDS)
}

/// Build the geocodable registered-address string from the locality fields
/// ("Sydney, NSW 2000, Australia"). The street line (`Address_Line_1`) often
/// can't be geocoded reliably (e.g. "Room 202, Codrington Building (H69)…") so it
/// rides in the evidence instead; the locality is what the geocode chain pivots
/// on. Returns `None` when there's nothing locating at all.
pub(super) fn locality_address(rec: &Map<String, Value>) -> Option<String> {
    let town = field_str(rec, "Town_City");
    let state = field_str(rec, "State");
    let postcode = field_str(rec, "Postcode");
    let country = field_str(rec, "Country").unwrap_or_else(|| "Australia".to_string());
    if town.is_none() && state.is_none() && postcode.is_none() {
        return None;
    }
    let mut head = String::new();
    if let Some(t) = town.as_deref() {
        head.push_str(t);
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

/// Attach every present register field to the charity's evidence so nothing the
/// API returned is dropped — true for exact hits and candidates alike.
pub(super) fn charity_evidence(rec: &Map<String, Value>, total: u64) -> Evidence {
    let legal = field_str(rec, "Charity_Legal_Name").unwrap_or_default();
    let ev = Evidence::new(SRC, format!("ACNC registered charity: {legal}"))
        .with_attr("register", "ACNC Register of Australian charities")
        .with_attr("total_matches", total.to_string());
    // Stable, useful columns — added only when present (no empty noise).
    [
        ("ABN", "abn"),
        ("Other_Organisation_Names", "other_names"),
        ("Address_Line_1", "address_line_1"),
        ("Address_Line_2", "address_line_2"),
        ("Address_Line_3", "address_line_3"),
        ("Town_City", "town_city"),
        ("State", "state"),
        ("Postcode", "postcode"),
        ("Country", "country"),
        ("Charity_Website", "website"),
        ("Registration_Date", "registration_date"),
        ("Date_Organisation_Established", "established"),
        ("Charity_Size", "charity_size"),
        ("Number_of_Responsible_Persons", "responsible_persons"),
    ]
    .into_iter()
    .filter_map(|(col, attr)| field_str(rec, col).map(|v| (attr, v)))
    .fold(ev, |ev, (attr, v)| ev.with_attr(attr, v))
}

/// Pure transform: CKAN records → entities. Every row yields a primary
/// `Organisation` carrying the full record in evidence (no omission). Rows whose
/// name matches the seed exactly additionally fan out into the cross-correlation
/// pivots (ABN, trading names, address, domain); loose full-text candidates stay
/// a single sub-floor Organisation so generic queries don't pivot name noise.
pub(super) fn records_to_entities(
    records: &[Map<String, Value>],
    total: u64,
    query: &str,
    scan_id: &str,
) -> Vec<Entity> {
    let mut out = Vec::new();
    for rec in records.iter().take(MAX_RECORDS) {
        let Some(legal) = field_str(rec, "Charity_Legal_Name") else {
            continue;
        };
        let exact = record_is_exact(rec, query);
        let conf = if exact { ORG_EXACT } else { ORG_CANDIDATE };

        let mut org = Entity::new(EntityKind::Organisation, &legal, conf, scan_id);
        org.tag(SRC);
        org.tag("acnc");
        org.tag("charity");
        org.tag("country:AU");
        org.tag(if exact {
            "exact-name-match"
        } else {
            "name-candidate"
        });
        org.add_evidence(charity_evidence(rec, total));
        out.push(org);

        // Cross-correlation pivots — exact hits only.
        if !exact {
            continue;
        }

        // ABN → abn_lookup / opencorporates resolve the full business registry.
        if let Some(abn) = abn_digits(rec) {
            let mut e = Entity::new(EntityKind::AbnAcn, &abn, ABN_CONF, scan_id);
            e.tag(SRC);
            e.tag("acnc");
            e.tag("country:AU");
            e.add_evidence(Evidence::new(SRC, format!("ABN {abn} → {legal}")));
            out.push(e);
        }

        // Other / trading names → resolvable Organisations.
        out.extend(
            other_names(rec)
                .into_iter()
                .take(MAX_TRADING_NAMES)
                .filter(|tn| !tn.eq_ignore_ascii_case(&legal))
                .map(|tn| {
                    let mut e =
                        Entity::new(EntityKind::Organisation, &tn, TRADING_NAME_CONF, scan_id);
                    e.tag(SRC);
                    e.tag("acnc");
                    e.tag("country:AU");
                    e.tag("business-name");
                    e.add_evidence(Evidence::new(
                        SRC,
                        format!("Other/trading name for {legal}"),
                    ));
                    e
                }),
        );

        // Registered locality → geocode chains it into Coordinates.
        if let Some(addr) = locality_address(rec) {
            let mut e = Entity::new(EntityKind::Address, &addr, ADDR_CONF, scan_id);
            e.tag(SRC);
            e.tag("acnc");
            e.tag("country:AU");
            e.tag("geoint");
            e.tag("registered-address");
            if let Some(sc) = crate::util::address_au::state_code(&addr) {
                e.tag(format!("au-state:{sc}"));
            }
            let aev = ["Address_Line_1", "Address_Line_2", "Address_Line_3"]
                .into_iter()
                .filter_map(|col| field_str(rec, col).map(|v| (col, v)))
                .fold(
                    Evidence::new(SRC, format!("Registered address for {legal}"))
                        .with_attr("org", &legal),
                    |aev, (col, v)| aev.with_attr(col.to_lowercase().replace(' ', "_"), v),
                );
            e.add_evidence(aev);
            out.push(e);

            // Inline Coordinates for immediate AU-052/053 participation.
            if let Some((lat, lon)) = crate::util::city_coords::city_coords(&addr) {
                let coord_val = format!("{lat:.4},{lon:.4}");
                let mut c = Entity::new(EntityKind::Coordinates, &coord_val, 0.62, scan_id);
                c.tag("addr-derived");
                c.tag("geoint");
                c.tag("acnc");
                c.tag("country:AU");
                if let Some(sc) = crate::util::address_au::state_code(&addr) {
                    c.tag(format!("au-state:{sc}"));
                }
                c.add_evidence(Evidence::new(
                    SRC,
                    format!("Inline geocode of ACNC address '{addr}' → {coord_val}"),
                ));
                out.push(c);
            }
        }

        // Website → DNS / web modules.
        if let Some(raw) = field_str(rec, "Charity_Website")
            && let Some(host) = host_from_url(&raw)
        {
            let mut e = Entity::new(EntityKind::Domain, &host, DOMAIN_CONF, scan_id);
            e.tag(SRC);
            e.tag("acnc");
            e.add_evidence(
                Evidence::new(SRC, format!("Charity website for {legal}")).with_attr("url", &raw),
            );
            out.push(e);
        }
    }
    out
}
