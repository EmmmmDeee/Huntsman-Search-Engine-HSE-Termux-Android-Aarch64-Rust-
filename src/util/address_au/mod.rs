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
    s.split_whitespace()
        .enumerate()
        .fold(String::with_capacity(s.len()), |mut acc, (i, w)| {
            if i > 0 {
                acc.push(' ');
            }
            acc.push_str(w);
            acc
        })
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

/// Map a 4-digit Australian postcode to its state/territory, or `None` when the
/// number falls in no assigned range. Iterates [`STATES`] in declared order so
/// the ACT (whose 2600–2618 / 2900–2920 ranges sit *inside* the NSW 2000–2999
/// span) is matched before NSW and isn't swallowed by it.
#[must_use]
pub fn state_for_postcode(postcode: &str) -> Option<&'static str> {
    STATES
        .iter()
        .copied()
        .find(|s| is_plausible_postcode(s, postcode))
}

/// Full state/territory names paired with their canonical abbreviation. Longest
/// names first so a substring scan matches "New South Wales" before the bare
/// "Wales" / "WA" could mislead.
const STATE_NAMES: &[(&str, &str)] = &[
    ("australian capital territory", "ACT"),
    ("new south wales", "NSW"),
    ("northern territory", "NT"),
    ("south australia", "SA"),
    ("western australia", "WA"),
    ("queensland", "QLD"),
    ("tasmania", "TAS"),
    ("victoria", "VIC"),
];

/// Best-effort canonical AU state/territory code for a free-text fragment
/// (`"Brisbane City, Queensland, Australia"`, `"… QLD 4000"`, `"4017"`).
///
/// Resolution order, most authoritative first: a whole-token state abbreviation
/// (`QLD`), then a full state name (`Queensland`), then a 4-digit postcode via
/// [`state_for_postcode`]. Returns `None` when nothing in the text names a
/// state. Whole-token / whole-word matching avoids the classic false positives
/// (the `WA` in "Walesby", the `SA` in "Sandgate"). Pure; no I/O.
#[must_use]
pub fn state_code(text: &str) -> Option<&'static str> {
    let lower = text.to_lowercase();
    // 1) Whole-token abbreviation (case-insensitive), split on non-alphanumerics.
    for tok in text.split(|c: char| !c.is_ascii_alphanumeric()) {
        if tok.len() == 2 || tok.len() == 3 {
            let up = tok.to_ascii_uppercase();
            if let Some(s) = STATES.iter().copied().find(|s| *s == up) {
                return Some(s);
            }
        }
    }
    // 2) Full state name as a substring (names are distinctive multi-word or
    //    long single words; ordered longest-first in STATE_NAMES).
    for (name, code) in STATE_NAMES {
        if lower.contains(name) {
            return Some(code);
        }
    }
    // 3) Any 4-digit run that maps to a postcode range.
    for tok in text.split(|c: char| !c.is_ascii_digit()) {
        if tok.len() == 4
            && let Some(s) = state_for_postcode(tok)
        {
            return Some(s);
        }
    }
    None
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

/// A **locality dedup key** for an address value: lowercased, punctuation
/// folded to spaces, a trailing 4-(AU)/5-(US) digit postcode dropped, whitespace
/// collapsed. So `"Murrumbateman, NSW"` and `"Murrumbateman, NSW 2582"` — one
/// place at two granularities — share a key and can be recognised as the same
/// locality regardless of which module or scan round produced each form.
///
/// AU state abbreviations are normalised to their full names as WHOLE tokens, so
/// `"Kuraby, QLD"` and `"Kuraby, Queensland"` (one place, two spellings) share a
/// key. Whole-token replacement is deliberate — a naive substring expansion
/// turns the `wa` inside `wales` into `western australia`.
///
/// The postcode is always *trailing*, so a leading street number (also numeric)
/// is never stripped — `"12 Main St, Brisbane QLD"` and `"99 Main St, Brisbane
/// QLD"` keep distinct keys. Pure; no I/O.
///
/// ```
/// use huntsman_search_engine::util::address_au::locality_key;
///
/// assert_eq!(locality_key("Murrumbateman, NSW"), locality_key("Murrumbateman, NSW 2582"));
/// assert_eq!(locality_key("Kuraby, QLD"), locality_key("Kuraby, Queensland"));
/// assert_ne!(locality_key("12 Main St, Brisbane QLD"), locality_key("99 Main St, Brisbane QLD"));
/// ```
#[must_use]
pub fn locality_key(addr: &str) -> String {
    let cleaned: String = addr
        .to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { ' ' })
        .collect();
    let mut tokens: Vec<&str> = cleaned.split_whitespace().collect();
    while tokens.len() > 1
        && tokens
            .last()
            .is_some_and(|t| (4..=5).contains(&t.len()) && t.bytes().all(|b| b.is_ascii_digit()))
    {
        tokens.pop();
    }
    // Normalise AU state abbreviations to their full names, token-wise (never
    // substring — so the `wa` in `wales` is left alone), so "QLD" and
    // "Queensland" produce the same key.
    let mut out: Vec<&str> = Vec::with_capacity(tokens.len() + 2);
    for t in tokens {
        match t {
            "nsw" => out.extend(["new", "south", "wales"]),
            "qld" => out.push("queensland"),
            "vic" => out.push("victoria"),
            "tas" => out.push("tasmania"),
            "act" => out.extend(["australian", "capital", "territory"]),
            "sa" => out.extend(["south", "australia"]),
            "wa" => out.extend(["western", "australia"]),
            "nt" => out.extend(["northern", "territory"]),
            other => out.push(other),
        }
    }
    out.join(" ")
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
    include!("tests.rs");
}
