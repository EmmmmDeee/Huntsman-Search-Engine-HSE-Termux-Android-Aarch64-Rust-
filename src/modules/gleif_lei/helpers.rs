//! Pure helper functions used by the GLEIF transform.

use super::types::{GleifAddress, GleifEntity};
use crate::core::entity::Evidence;

use super::SRC;

/// Trims an `Option<&str>` to an owned
/// non-empty `String`, avoiding a clone of the source `Option<String>`.
pub(super) fn non_empty_ref(s: Option<&str>) -> Option<String> {
    s.map(str::trim).filter(|v| !v.is_empty()).map(str::to_owned)
}

/// True if `name` contains every token of the seed `query` as a whole word
/// (case-insensitive). Whole-word, not substring, so a short seed token can't
/// match inside an unrelated word. (Same precision rule as `acnc_charities`.)
pub(super) fn name_matches_query(name: &str, query: &str) -> bool {
    let words: Vec<&str> = name
        .split(|c: char| !c.is_alphanumeric())
        .filter(|s| !s.is_empty())
        .collect();
    let tokens: Vec<&str> = query
        .split(|c: char| !c.is_alphanumeric())
        .filter(|s| !s.is_empty())
        .collect();
    // At least one token, and every token present as a whole word.
    !tokens.is_empty()
        && tokens
            .iter()
            .all(|tok| words.iter().any(|w| w.eq_ignore_ascii_case(tok)))
}

/// The lei-records search URL for one legal-name query. JSON:API bracket params
/// are percent-encoded literally; the value is url-encoded.
pub(super) fn query_url(name: &str) -> String {
    use super::MAX_RECORDS;
    use crate::util::http::urlencode;
    format!(
        "{BASE_URL}?filter%5Bentity.legalName%5D={}&page%5Bsize%5D={MAX_RECORDS}",
        urlencode(name)
    )
}

const BASE_URL: &str = "https://api.gleif.org/api/v1/lei-records";

/// `registeredAs` digits when this AU entity's local registry id is a valid
/// ACN (9) or ABN (11). GLEIF stores it spaced ("004 028 077"); we strip to
/// digits. Only AU jurisdictions map cleanly to the ABN/ACN namespace — a UK
/// company number etc. must not masquerade as an `AbnAcn`.
pub(super) fn au_abn_acn(entity: &GleifEntity) -> Option<String> {
    if entity.jurisdiction.as_deref() != Some("AU") {
        return None;
    }
    let raw = entity.registered_as.as_deref()?;
    let digits = crate::util::str_util::ascii_digits(raw);
    matches!(digits.len(), 9 | 11).then_some(digits)
}

/// Build a geocodable locality string from a GLEIF address. The ISO-3166-2
/// region ("AU-VIC") is reduced to its subdivision ("VIC"); street lines ride in
/// evidence, not the geocode value. Returns `None` when there's nothing locating.
pub(super) fn locality(addr: &GleifAddress) -> Option<String> {
    let city = non_empty_ref(addr.city.as_deref());
    let region = non_empty_ref(addr.region.as_deref()).map(|r| {
        // "AU-VIC" -> "VIC"; leave plain regions untouched.
        r.rsplit('-').next().unwrap_or(&r).to_string()
    });
    let postal = non_empty_ref(addr.postal_code.as_deref());
    let country = non_empty_ref(addr.country.as_deref());
    if city.is_none() && region.is_none() && postal.is_none() {
        return None;
    }
    // Build "city, region postal, country" directly, skipping empty segments,
    // avoiding an intermediate Vec + join.
    let mut rp = String::new();
    if let Some(r) = &region {
        rp.push_str(r);
    }
    if let Some(p) = &postal {
        if !rp.is_empty() {
            rp.push(' ');
        }
        rp.push_str(p);
    }
    let mut out = String::new();
    for seg in [city.as_deref(), (!rp.is_empty()).then_some(rp.as_str()), country.as_deref()]
        .into_iter()
        .flatten()
    {
        if !out.is_empty() {
            out.push_str(", ");
        }
        out.push_str(seg);
    }
    (!out.is_empty()).then_some(out)
}

/// Attach the full record to evidence so nothing the API returned is dropped —
/// exact hits and candidates alike.
pub(super) fn record_evidence(lei: &str, entity: &GleifEntity, name: &str, total: u64) -> Evidence {
    let mut ev = Evidence::new(SRC, format!("GLEIF LEI record: {name}"))
        .with_attr("lei", lei)
        .with_attr("register", "GLEIF Global LEI Index")
        .with_attr("total_matches", total.to_string());
    if let Some(j) = entity.jurisdiction.as_deref() {
        ev = ev.with_attr("jurisdiction", j);
    }
    if let Some(s) = entity.status.as_deref() {
        ev = ev.with_attr("entity_status", s);
    }
    if let Some(r) = entity.registered_as.as_deref() {
        ev = ev.with_attr("registered_as", r);
    }
    for (label, addr) in [
        ("legal_address", &entity.legal_address),
        ("hq_address", &entity.hq_address),
    ] {
        if let Some(a) = addr {
            if !a.address_lines.is_empty() {
                ev = ev.with_attr(format!("{label}_street"), a.address_lines.join(", "));
            }
            if let Some(loc) = locality(a) {
                ev = ev.with_attr(label, loc);
            }
        }
    }
    ev
}
