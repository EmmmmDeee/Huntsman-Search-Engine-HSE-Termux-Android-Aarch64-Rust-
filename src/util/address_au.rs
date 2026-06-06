//! Australian-format business address extraction.
//!
//! Parses strings like:
//!   "Level 11, 133 Mary Street, Brisbane City QLD 4000"
//!   "Suite 5/250 St Georges Tce, Perth WA 6000"
//!   "1 Haengabell Close, Bracken Ridge, QLD 4017"
//!
//! Returns structured components when at least street+suburb+state+postcode
//! are recognised, plus a confidence score.

use std::sync::OnceLock;

use regex::Regex;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuAddress {
    pub full: String,
    pub level: Option<String>,
    pub unit: Option<String>,
    pub street_number: String,
    pub street: String,
    pub suburb: String,
    pub state: String,
    pub postcode: String,
}

impl AuAddress {
    pub fn confidence(&self) -> f64 {
        // 0.70 baseline; +0.05 each for level/unit/street_number specificity
        let mut c = 0.70_f64;
        if self.level.is_some() {
            c += 0.10;
        }
        if self.unit.is_some() {
            c += 0.05;
        }
        if !self.street_number.is_empty() {
            c += 0.05;
        }
        c.min(0.95)
    }
}

const STATES: &[&str] = &["ACT", "NSW", "NT", "QLD", "SA", "TAS", "VIC", "WA"];

fn full_pattern() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r"(?ix)
            (?:                                              # optional level/suite/unit prefix
                (?P<lvl>Level\s+\d{1,3}|Lvl\s+\d{1,3}|L\d{1,3}|
                 Suite\s+\d{1,4}[A-Za-z]?|Ste\s+\d{1,4}[A-Za-z]?|
                 Unit\s+\d{1,4}[A-Za-z]?|U\s*\d{1,4}[A-Za-z]?|
                 Shop\s+\d{1,4}[A-Za-z]?|Office\s+\d{1,4}[A-Za-z]?)
                [\s,/]+
            )?
            (?:(?P<unit>\d{1,4}[A-Za-z]?)\s*/\s*)?           # optional unit/lot, must end with '/'
            (?P<num>\d{1,5}[A-Za-z]?)\s+                      # street number (required)
            (?P<street>[A-Z][A-Za-z'\.\-]+(?:\s+[A-Z][A-Za-z'\.\-]+){0,5}\s+
              (?:Street|St|Road|Rd|Avenue|Ave|Lane|Ln|Drive|Dr|Court|Ct|
                 Crescent|Cres|Place|Pl|Way|Highway|Hwy|Parade|Pde|Terrace|Tce|
                 Boulevard|Blvd|Circuit|Cct|Close|Cl|Esplanade|Esp|Square|Sq))
            ,?\s+
            (?P<suburb>[A-Z][A-Za-z'\-]+(?:\s+[A-Z][A-Za-z'\-]+){0,4})
            ,?\s+
            (?P<state>ACT|NSW|NT|QLD|SA|TAS|VIC|WA)\s+
            (?P<postcode>\d{4})
        ",
        )
        .expect("au-address regex")
    })
}

/// Find the first plausible Australian address in a free-text blob.
pub fn extract_first(text: &str) -> Option<AuAddress> {
    extract_all(text).into_iter().next()
}

/// Find all plausible Australian addresses in a free-text blob.
pub fn extract_all(text: &str) -> Vec<AuAddress> {
    let mut out = Vec::new();
    let re = full_pattern();
    for cap in re.captures_iter(text) {
        let full = cap
            .get(0)
            .map(|m| m.as_str().trim().to_string())
            .unwrap_or_default();
        let level = cap.name("lvl").map(|m| m.as_str().trim().to_string());
        let unit = cap.name("unit").map(|m| m.as_str().trim().to_string());
        let num = cap
            .name("num")
            .map(|m| m.as_str().trim().to_string())
            .unwrap_or_default();
        let street = cap
            .name("street")
            .map(|m| normalise_ws(m.as_str()))
            .unwrap_or_default();
        let suburb = cap
            .name("suburb")
            .map(|m| normalise_ws(m.as_str()))
            .unwrap_or_default();
        let state = cap
            .name("state")
            .map(|m| m.as_str().to_uppercase())
            .unwrap_or_default();
        let postcode = cap
            .name("postcode")
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();
        if !STATES.contains(&state.as_str()) {
            continue;
        }
        if !is_plausible_postcode(&state, &postcode) {
            continue;
        }
        out.push(AuAddress {
            full,
            level,
            unit,
            street_number: num,
            street,
            suburb,
            state,
            postcode,
        });
    }
    out
}

fn normalise_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Reject impossible state-postcode combos. Tight enough to filter
/// random four-digit numbers, loose enough to accept any real address.
fn is_plausible_postcode(state: &str, postcode: &str) -> bool {
    let Ok(pc) = postcode.parse::<u16>() else {
        return false;
    };
    match state {
        // 1000–1999 are NSW large-volume-receiver / PO-box ranges, 2000–2999
        // geographic — one contiguous span.
        "NSW" => (1000..=2999).contains(&pc),
        "ACT" => {
            (200..=299).contains(&pc) || (2600..=2618).contains(&pc) || (2900..=2920).contains(&pc)
        }
        "VIC" => (3000..=3999).contains(&pc) || (8000..=8999).contains(&pc),
        "QLD" => (4000..=4999).contains(&pc) || (9000..=9999).contains(&pc),
        "SA" => (5000..=5999).contains(&pc),
        "WA" => (6000..=6797).contains(&pc) || (6800..=6999).contains(&pc),
        "TAS" => (7000..=7999).contains(&pc),
        "NT" => (800..=999).contains(&pc),
        _ => false,
    }
}

/// AU phone-number normaliser: returns E.164 form (`+61…`) when the
/// input is a recognisable Australian number (08/02/03/04/07/13/1300/1800).
///
/// # Guarantees
/// - Strips spaces, brackets, and dashes, then maps the recognised AU forms
///   (`+61…`, `0061…`, a 10-digit `0…`, a 9-digit area/mobile, `1300`/`1800`) to
///   `+61…`; returns `None` for anything unrecognised. Never panics (operates on
///   an ASCII digit/`+` buffer).
///
/// ```
/// use huntsman_search_engine::util::address_au::normalise_phone;
///
/// assert_eq!(normalise_phone("0410 959 140").as_deref(), Some("+61410959140"));
/// assert_eq!(normalise_phone("(07) 3739 4511").as_deref(), Some("+61737394511"));
/// assert_eq!(normalise_phone("+61 2 9374 4000").as_deref(), Some("+61293744000"));
/// assert_eq!(normalise_phone("not a phone"), None);
/// ```
pub fn normalise_phone(s: &str) -> Option<String> {
    let digits: String = s
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == '+')
        .collect();
    if digits.starts_with("+61") {
        return Some(digits);
    }
    if digits.starts_with("0061") {
        return Some(format!("+{}", &digits[2..]));
    }
    if digits.starts_with('0') && digits.len() == 10 {
        return Some(format!("+61{}", &digits[1..]));
    }
    if digits.len() == 9
        && (digits.starts_with('2')
            || digits.starts_with('3')
            || digits.starts_with('4')
            || digits.starts_with('7')
            || digits.starts_with('8'))
    {
        return Some(format!("+61{}", digits));
    }
    if digits.starts_with("1300") || digits.starts_with("1800") {
        return Some(format!("+61{}", digits));
    }
    None
}

/// Crude AU phone scanner — pulls all plausible numbers out of a text
/// blob, returning normalised E.164 forms (deduplicated).
pub fn extract_phones(text: &str) -> Vec<String> {
    static R: OnceLock<Regex> = OnceLock::new();
    let re = R.get_or_init(|| {
        Regex::new(
            r"(?x)
            (?:\+?61[\s\-]?)?       # optional country code
            (?:\(?0?[2-478]\)?[\s\-]?)?  # optional area code (NSW/VIC/QLD/WA/SA/mobile)
            \d{2,4}[\s\-]?\d{2,4}[\s\-]?\d{2,4}   # digit groups
            ",
        )
        .expect("au-phone regex")
    });
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for m in re.find_iter(text) {
        if let Some(n) = normalise_phone(m.as_str())
            && seen.insert(n.clone())
        {
            out.push(n);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_level_address() {
        let s = "Our office is at Level 11, 133 Mary Street, Brisbane City QLD 4000";
        let a = extract_first(s).expect("should match");
        assert_eq!(a.level.as_deref(), Some("Level 11"));
        assert_eq!(a.street_number, "133");
        assert_eq!(a.street, "Mary Street");
        assert_eq!(a.suburb, "Brisbane City");
        assert_eq!(a.state, "QLD");
        assert_eq!(a.postcode, "4000");
        assert!(a.confidence() >= 0.80);
    }

    #[test]
    fn parses_plain_address() {
        let s = "Visit us at 1 Haengabell Close, Bracken Ridge, QLD 4017 for inspection.";
        let a = extract_first(s).expect("should match");
        assert_eq!(a.street_number, "1");
        assert!(a.street.contains("Haengabell"));
        assert_eq!(a.state, "QLD");
        assert_eq!(a.postcode, "4017");
    }

    #[test]
    fn rejects_wrong_state_postcode() {
        // NSW with VIC postcode → invalid
        let s = "5 Test Street, Sydney NSW 3000";
        assert!(extract_first(s).is_none());
    }

    #[test]
    fn accepts_valid_nsw_postcode_range() {
        // Positive coverage for the NSW arm (1000–2999, one contiguous span):
        // a geographic 2xxx and an LVR 1xxx both accept; 3000 (VIC) rejects.
        let geo = extract_first("1 George Street, Sydney NSW 2000").expect("2000 is NSW");
        assert_eq!(geo.state, "NSW");
        assert_eq!(geo.postcode, "2000");
        assert!(extract_first("1 George Street, Sydney NSW 1234").is_some()); // LVR range
        assert!(extract_first("1 George Street, Sydney NSW 3000").is_none()); // VIC range
    }

    #[test]
    fn normalises_phone_e164() {
        assert_eq!(
            normalise_phone("0410 959 140").as_deref(),
            Some("+61410959140")
        );
        assert_eq!(
            normalise_phone("(07) 3739 4511").as_deref(),
            Some("+61737394511")
        );
        assert_eq!(
            normalise_phone("+61 7 3739 4511").as_deref(),
            Some("+61737394511")
        );
        assert_eq!(
            normalise_phone("1300 846 637").as_deref(),
            Some("+611300846637")
        );
    }
}
