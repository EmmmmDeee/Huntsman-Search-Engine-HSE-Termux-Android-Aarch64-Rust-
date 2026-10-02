use super::country::{au_state_norm, iso_for};

/// Parsed components of a free-form address string.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AddressComponents {
    pub street: Option<String>,
    pub city: Option<String>,
    pub state: Option<String>,
    pub postal_code: Option<String>,
    pub country: Option<String>,
    pub iso_country: Option<String>,
}

/// Parse a comma-separated address into structured components.
///
/// Handles common formats:
///   "Sydney, NSW, Australia"      → city=Sydney, state=NSW, country=Australia
///   "10 Smith St, Melbourne, VIC" → street=..., city=..., state=...
///   "SA, VIC"                     → state list (no city/country)
///   "Brisbane, QLD 4000"          → city + state + postal
pub fn parse_address(input: &str) -> AddressComponents {
    let mut out = AddressComponents::default();
    let parts: Vec<&str> = input
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if parts.is_empty() {
        return out;
    }

    // Country: last part if it matches a known ISO name.
    if let Some(last) = parts.last()
        && let Some(iso) = iso_for(last)
    {
        out.country = Some((*last).to_string());
        out.iso_country = Some(iso.to_string());
    }

    // Scan every part for state codes and postal patterns. A part like
    // "QLD 4000" carries both — split on space and try each token.
    // State codes: the first classified state wins, so scan FORWARD.
    // Match a state either as the WHOLE part ("New South Wales", "Queensland")
    // or as a token within it ("QLD 4000" → "QLD"). The whole-part check is
    // essential: a multi-word state name is never a single token, so the
    // previous token-only scan silently dropped every spelled-out multi-word
    // state ("New South Wales", "Western Australia") while still accepting the
    // abbreviations and single-word names ("NSW", "Queensland").
    for part in &parts {
        if out.state.is_none() {
            let matched =
                au_state_norm(part).or_else(|| part.split_whitespace().find_map(au_state_norm));
            if let Some(s) = matched {
                out.state = Some(s.to_string());
                if out.iso_country.is_none() {
                    out.iso_country = Some("AU".to_string());
                    out.country = Some("Australia".to_string());
                }
            }
        }
    }

    // Postal code (bare digits, 4-10 chars). Scan parts in REVERSE so the
    // address-TRAILING postcode wins over an earlier part whose last token is a
    // digit run — a PO-box or unit number ("PO Box 4321, …, NSW 2000" must yield
    // 2000, not 4321). Only the LAST token of a part is a candidate: a real
    // postcode trails its part ("QLD 4000", "4000"), whereas a leading digit run
    // like the street number in "1234 Smith St" is followed by the street name
    // and must NOT be captured.
    for part in parts.iter().rev() {
        if out.postal_code.is_none()
            && let Some(tok) = part.split_whitespace().last()
            && tok.chars().all(|c| c.is_ascii_digit())
            && (4..=10).contains(&tok.len())
        {
            out.postal_code = Some(tok.to_string());
        }
    }

    // Street detection BEFORE city: if parts.len() ≥ 3 and the first
    // part starts with a digit, it's a street address.
    let mut city_skip = 0usize;
    if parts.len() >= 3 && parts[0].chars().next().map(|c| c.is_ascii_digit()) == Some(true) {
        out.street = Some(parts[0].to_string());
        city_skip = 1;
    }

    // City: first non-classified part after any street.
    for part in parts.iter().skip(city_skip) {
        let p = part.trim();
        if p.is_empty() {
            continue;
        }
        if out.country.as_deref() == Some(p) {
            continue;
        }
        // Skip a part that is a state designation, so it is never mistaken for
        // the city: the whole part ("New South Wales") OR its leading token
        // ("QLD 4000" → "QLD"). Without the whole-part check a spelled-out
        // multi-word state would fall through and be captured as the city.
        let first_token = p.split_whitespace().next().unwrap_or("");
        if au_state_norm(p).is_some() || au_state_norm(first_token).is_some() {
            continue;
        }
        if iso_for(p).is_some() {
            continue;
        }
        if p.chars().all(|c| c.is_ascii_digit() || c.is_whitespace()) {
            continue;
        }
        // First valid candidate wins.
        out.city = Some(p.to_string());
        break;
    }

    out
}
