//! Pure-data helpers: datastore-resource selection, Title matching, and the
//! `records_to_entities` transform that converts raw AGOR CKAN body rows into
//! cross-correlating graph entities.

use serde_json::{Map, Value};

use crate::core::entity::{Entity, EntityKind, Evidence};
use crate::util::ckan::{Resource, field_str};
use crate::util::url_util::host_from_url;

use super::{
    ABN_CONF, ADDR_CONF, DOMAIN_CONF, MAX_RECORDS, ORG_CANDIDATE, ORG_EXACT, PARENT_CONF,
    PORTFOLIO_CONF, SRC,
};

/// Parse the date that AGOR encodes in a resource name (`"AGOR YYYY-MM-DD"`) into
/// a `(year, month, day)` tuple for ordering. Returns `None` if the name doesn't
/// carry a parseable trailing `YYYY-MM-DD`.
fn resource_date(name: &str) -> Option<(u32, u32, u32)> {
    // The date is the final whitespace-separated token (e.g. "AGOR 2025-04-01").
    let token = name.split_whitespace().next_back()?;
    let mut parts = token.split('-');
    let y = parts.next()?.parse().ok()?;
    let m = parts.next()?.parse().ok()?;
    let d = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((y, m, d))
}

/// Select the resource id to query: the datastore-active resource whose name
/// parses to the most recent `AGOR YYYY-MM-DD` date; if none parse, the first
/// datastore-active resource. Returns `None` if nothing is datastore-active.
pub(super) fn pick_resource(resources: &[Resource]) -> Option<String> {
    let active: Vec<&Resource> = resources
        .iter()
        .filter(|r| r.datastore_active == Some(true))
        .collect();
    // Prefer the most recent dated resource.
    let best_dated = active
        .iter()
        .filter_map(|r| {
            let name = r.name.as_deref()?;
            let date = resource_date(name)?;
            let id = r.id.as_deref()?;
            Some((date, id))
        })
        .max_by_key(|(date, _)| *date)
        .map(|(_, id)| id.to_string());
    // Fall back to the first datastore-active resource with an id.
    best_dated.or_else(|| active.iter().find_map(|r| r.id.clone()))
}

/// An 11-digit Australian Business Number (digits only) for this body, else
/// `None`. AGOR stores the ABN as text but a numerically-typed datastore column
/// would arrive as a JSON number, so we normalise to digits and length-check.
pub(super) fn body_abn(rec: &Map<String, Value>) -> Option<String> {
    let raw = field_str(rec, "ABN")?;
    let digits = crate::util::str_util::ascii_digits(&raw);
    (digits.len() == 11).then_some(digits)
}

/// True if `name` contains every token of the seed `query` as a *whole word*
/// (case-insensitive). Whole-word (not substring) so a seed token like `"tax"`
/// doesn't match inside `"taxation"`. Tokenises on non-alphanumeric boundaries
/// and compares with `eq_ignore_ascii_case` (no per-token `String` allocation).
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
/// * ABN seed (`abn_query`): the body's ABN equals the seed's 11 digits — an
///   unambiguous identity match, so always exact.
/// * name / org seed: the body's Title contains every seed token as a whole word.
pub(super) fn record_is_exact(rec: &Map<String, Value>, query: &str, abn_query: bool) -> bool {
    if abn_query {
        return body_abn(rec).as_deref() == Some(query);
    }
    field_str(rec, "Title")
        .as_deref()
        .is_some_and(|n| name_matches_query(n, query))
}

/// Build the geocodable head-office locality string from the address fields
/// ("Canberra, ACT 2600, Australia"). The street line is often non-geocodable,
/// so it rides in the evidence; the suburb/state/postcode is what the geocode
/// chain pivots on. Returns `None` when there's nothing locating at all.
pub(super) fn head_office_locality(rec: &Map<String, Value>) -> Option<String> {
    let suburb = field_str(rec, "Head Office Suburb");
    let state = field_str(rec, "Head Office State");
    let postcode = field_str(rec, "Head Office Postcode");
    let country = field_str(rec, "Head Office Country").unwrap_or_else(|| "Australia".to_string());
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

/// Attach every present register field to the body's evidence so nothing the API
/// returned is dropped — true for exact hits and candidates alike.
pub(super) fn body_evidence(rec: &Map<String, Value>, total: u64) -> Evidence {
    let title = field_str(rec, "Title").unwrap_or_default();
    let ev = Evidence::new(SRC, format!("AGOR register entry: {title}"))
        .with_attr("register", "Australian Government Organisations Register")
        .with_attr("total_matches", total.to_string());
    // Stable, useful columns — added only when present (no empty noise).
    [
        ("Portfolio", "portfolio"),
        ("Classification", "classification"),
        ("Type of Body", "type_of_body"),
        ("Description", "description"),
        ("Established By / Under", "established_by_under"),
        ("Established by/Under More Info", "established_more_info"),
        ("ABN", "abn"),
        ("Parent Organisation", "parent_organisation"),
        ("Head Office Street Address", "head_office_street"),
        ("Head Office Suburb", "head_office_suburb"),
        ("Head Office State", "head_office_state"),
        ("Head Office Postcode", "head_office_postcode"),
        ("Head Office Country", "head_office_country"),
        ("Website Address", "website"),
    ]
    .into_iter()
    .filter_map(|(col, attr)| field_str(rec, col).map(|v| (attr, v)))
    .fold(ev, |ev, (attr, v)| ev.with_attr(attr, v))
}

/// Pure transform: CKAN AGOR records → entities. Every row yields a primary
/// `Organisation` (the government body) carrying the full record in evidence (no
/// omission). Rows that match the seed exactly additionally fan out into the
/// cross-correlation pivots (ABN, head-office address → inline coordinates,
/// website domain, portfolio + parent organisations); loose full-text candidates
/// stay a single sub-floor Organisation so generic queries don't pivot
/// government-name noise.
pub(super) fn records_to_entities(
    records: &[Map<String, Value>],
    total: u64,
    query: &str,
    abn_query: bool,
    scan_id: &str,
) -> Vec<Entity> {
    let mut out = Vec::new();
    for rec in records.iter().take(MAX_RECORDS) {
        let Some(title) = field_str(rec, "Title") else {
            continue;
        };
        let exact = record_is_exact(rec, query, abn_query);
        let conf = if exact { ORG_EXACT } else { ORG_CANDIDATE };

        let mut org = Entity::new(EntityKind::Organisation, &title, conf, scan_id);
        org.tag(SRC);
        org.tag("gov-body");
        org.tag("commonwealth");
        org.tag("country:AU");
        org.tag(if exact {
            "exact-name-match"
        } else {
            "name-candidate"
        });
        org.add_evidence(body_evidence(rec, total));
        out.push(org);

        // Cross-correlation pivots — exact hits only.
        if !exact {
            continue;
        }

        // ABN → au_business_id / abn_lookup / opencorporates resolve the full
        // business registry (and the company → directors → people chain).
        if let Some(abn) = body_abn(rec) {
            let mut e = Entity::new(EntityKind::AbnAcn, &abn, ABN_CONF, scan_id);
            e.tag(SRC);
            e.tag("country:AU");
            e.add_evidence(Evidence::new(SRC, format!("ABN {abn} → {title}")));
            out.push(e);
        }

        // Portfolio department → a Business Relationship Organisation (the body
        // sits within this portfolio).
        if let Some(portfolio) = field_str(rec, "Portfolio") {
            let mut e = Entity::new(
                EntityKind::Organisation,
                &portfolio,
                PORTFOLIO_CONF,
                scan_id,
            );
            e.tag(SRC);
            e.tag("country:AU");
            e.tag("gov-body");
            e.tag("portfolio");
            e.add_evidence(
                Evidence::new(SRC, format!("Portfolio department of {title}"))
                    .with_attr("body", &title),
            );
            out.push(e);
        }

        // Parent organisation → a Business Relationship Organisation (the body's
        // place in the machinery-of-government hierarchy).
        if let Some(parent) = field_str(rec, "Parent Organisation") {
            let mut e = Entity::new(EntityKind::Organisation, &parent, PARENT_CONF, scan_id);
            e.tag(SRC);
            e.tag("country:AU");
            e.tag("gov-body");
            e.tag("parent-organisation");
            e.add_evidence(
                Evidence::new(SRC, format!("Parent organisation of {title}"))
                    .with_attr("body", &title),
            );
            out.push(e);
        }

        // Website → a Domain (a pivot into web intel). Normalised to a bare host.
        if let Some(raw) = field_str(rec, "Website Address")
            && let Some(host) = host_from_url(&raw)
        {
            let mut e = Entity::new(EntityKind::Domain, &host, DOMAIN_CONF, scan_id);
            e.tag(SRC);
            e.tag("gov-body");
            e.tag("country:AU");
            e.add_evidence(
                Evidence::new(SRC, format!("Website of {title}"))
                    .with_attr("body", &title)
                    .with_attr("website", &raw),
            );
            out.push(e);
        }

        // Head-office locality → geocode chains it into Coordinates.
        if let Some(addr) = head_office_locality(rec) {
            let mut e = Entity::new(EntityKind::Address, &addr, ADDR_CONF, scan_id);
            e.tag(SRC);
            e.tag("country:AU");
            e.tag("geoint");
            e.tag("head-office");
            if let Some(sc) = crate::util::address_au::state_code(&addr) {
                e.tag(format!("au-state:{sc}"));
            }
            let aev = ["Head Office Street Address", "Head Office Suburb"]
                .into_iter()
                .filter_map(|col| field_str(rec, col).map(|v| (col, v)))
                .fold(
                    Evidence::new(SRC, format!("Head office for {title}"))
                        .with_attr("body", &title),
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
                c.tag(SRC);
                c.tag("country:AU");
                if let Some(sc) = crate::util::address_au::state_code(&addr) {
                    c.tag(format!("au-state:{sc}"));
                }
                c.add_evidence(Evidence::new(
                    SRC,
                    format!("Inline geocode of AGOR head-office address '{addr}' → {coord_val}"),
                ));
                out.push(c);
            }
        }
    }
    out
}
