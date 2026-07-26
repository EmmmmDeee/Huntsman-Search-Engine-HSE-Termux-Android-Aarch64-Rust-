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

use crate::util::scan::MatchSet;

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
        // 0.70 baseline; +0.10 for level, +0.05 each for unit/street_number specificity
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
        // The 6798/6799 gap is deliberate: 6798 (Christmas Island) and 6799
        // (Cocos (Keeling) Islands) are external territories ~2600 km offshore in
        // the Indian Ocean, administered separately from WA. They are postally
        // grouped under WA but are not the mainland state, so they map to no state
        // (None) rather than being mis-attributed to WA. (Contrast VIC's 8xxx and
        // QLD's 9xxx, which ARE in-state PO-box ranges and so are included.)
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

/// One-time compiled automaton over `STATE_NAMES` patterns (ASCII-CI).
/// Replaces the 8-way `lower.contains(name)` loop in [`state_code`] step 2
/// with a single Teddy/SIMD pass; `find_id` returns the pattern index so the
/// matching code is `STATE_NAMES[id].1` — no second table scan needed.
static STATE_NAMES_MATCHER: std::sync::LazyLock<MatchSet> =
    std::sync::LazyLock::new(|| MatchSet::new_ascii_ci(STATE_NAMES.iter().map(|(n, _)| *n)));

/// Best-effort canonical AU state/territory code for a free-text fragment
/// (`"Brisbane City, Queensland, Australia"`, `"… QLD 4000"`, `"4017"`).
///
/// Iterator over the AU state codes named as whole 2–3 letter tokens in `text`
/// (case-insensitive), in reading order, with repeats. Shared by [`state_code`]
/// (which takes the first) and [`single_state_code`] (which checks distinctness),
/// so the whole-token abbreviation scan lives in exactly one place.
/// `eq_ignore_ascii_case` tests membership without allocating an uppercased copy
/// of each token.
fn state_abbrev_tokens(text: &str) -> impl Iterator<Item = &'static str> + '_ {
    text.split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|t| t.len() == 2 || t.len() == 3)
        .filter_map(|t| STATES.iter().copied().find(|s| s.eq_ignore_ascii_case(t)))
}

/// Resolution order, most authoritative first: a whole-token state abbreviation
/// (`QLD`), then a full state name (`Queensland`), then a 4-digit postcode via
/// [`state_for_postcode`]. Returns `None` when nothing in the text names a
/// state. Whole-token / whole-word matching avoids the classic false positives
/// (the `WA` in "Walesby", the `SA` in "Sandgate"). Pure; no I/O.
#[must_use]
pub fn state_code(text: &str) -> Option<&'static str> {
    // 1) Whole-token abbreviation (case-insensitive) — first match wins.
    if let Some(s) = state_abbrev_tokens(text).next() {
        return Some(s);
    }
    // 2) Full state name as a substring (names are distinctive multi-word or
    //    long single words; ordered longest-first in STATE_NAMES). One
    //    aho-corasick pass replaces the former 8-way `to_lowercase().contains`
    //    loop; `find_id` returns the pattern index for O(1) code lookup.
    if let Some(id) = STATE_NAMES_MATCHER.find_id(text) {
        return Some(STATE_NAMES[id].1);
    }
    // 3) The TRAILING 4-digit run, when it maps to a postcode range. An AU address
    //    places its postcode LAST, so only the FINAL run of digits is a postcode
    //    candidate — never a LEADING 4-digit street number. Anchoring on the final
    //    run is what stops a foreign address from being mis-attributed to an AU
    //    state: "5528 North 73rd Avenue, Glendale, AZ, 85303" used to return "SA"
    //    because its real ZIP "85303" is 5 digits, leaving the street number "5528"
    //    as the only 4-digit token; now the final run is "85303" (rejected) and
    //    "5528" is never considered. (Steps 1–2 already short-circuit a genuine AU
    //    address via its explicit state code/name, so this last-resort path only
    //    ever sees state-less postcode text.)
    if let Some(last) = text
        .split(|c: char| !c.is_ascii_digit())
        .rfind(|t| !t.is_empty())
        && last.len() == 4
        && let Some(s) = state_for_postcode(last)
    {
        return Some(s);
    }
    None
}

/// The AU state named by `text`, but **only when exactly one** distinct state is
/// present — by 2–3 letter code as a whole token (`NSW`, `WA`, …) or by full
/// state name as a case-insensitive substring (`"western australia"`).
///
/// Ambiguous text that spans several states returns [`None`]. The motivating
/// case is a coarse phone area-code label such as `"Sydney / NSW / ACT"` or
/// `"Perth / SA / NT"`, where a single Australian area code (`02`, `08`) covers
/// more than one state/territory: [`state_code`] returns the *first* token it
/// sees (`NSW`, `SA`), fabricating one hard jurisdiction for a value that
/// genuinely spans several. This guard refuses to pick one.
///
/// Unlike [`state_code`], an EXPLICIT state mention is required — there is no
/// postcode fallback (a postcode always resolves to exactly one state, which
/// would defeat the "is it unambiguous?" question this answers). Pure.
#[must_use]
pub fn single_state_code(text: &str) -> Option<&'static str> {
    let lc = text.to_lowercase();
    // Whole-token abbreviations (shared with `state_code`) chained with full state
    // names as a substring, folded through ONE distinctness pass: the first state
    // seen is held; a second, DIFFERENT state proves the text spans several → None.
    // `STATE_NAMES_MATCHER` is deliberately NOT reused for the name step — its
    // `find_id` yields only the leftmost match, but detecting ambiguity needs EVERY
    // distinct name present.
    let names = STATE_NAMES
        .iter()
        .filter(|&&(n, _)| lc.contains(n))
        .map(|&(_, c)| c);

    let mut found: Option<&'static str> = None;
    for code in state_abbrev_tokens(text).chain(names) {
        match found {
            Some(prev) if prev != code => return None,
            _ => found = Some(code),
        }
    }
    found
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
    // Every branch below routes its candidate through the strict E.164 gate, so
    // this function can NEVER emit a syntactically invalid number (e.g. a bare
    // "+61", "0061" → "+61", or "1300" → "+611300"). The `+61…` / `0061…` early
    // returns used to pass their output back unvalidated, leaking malformed
    // too-short E.164 straight into correlation keys; the gate closes that.
    let validated = |e164: String| {
        crate::core::validation::validate_phone_e164(&e164)
            .valid
            .then_some(e164)
    };
    let digits: String = s
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == '+')
        .collect();
    if digits.starts_with("+61") {
        return validated(digits);
    }
    if digits.starts_with("0061") {
        return validated(format!("+{}", &digits[2..]));
    }
    // The second digit must be a real ACMA AU national-significant-number
    // lead (2/3/4/5/7/8), matching the gate the 9-digit branch below already
    // enforces. Without this, any 10-digit string starting with `0` —
    // including a foreign local-format number that happens to be 10 digits,
    // e.g. an Irish local mobile "087 123 4567" — was silently re-typed as a
    // fully-formed Australian number, fabricating a non-existent AU phone
    // that then leaks into generated search-query formats (`oathnet_batch`)
    // and the AU-102 phone-jurisdiction correlation key.
    if digits.starts_with('0')
        && digits.len() == 10
        && matches!(
            digits.as_bytes()[1],
            b'2' | b'3' | b'4' | b'5' | b'7' | b'8'
        )
    {
        return validated(format!("+61{}", &digits[1..]));
    }
    if digits.len() == 9
        && (digits.starts_with('2')
            || digits.starts_with('3')
            || digits.starts_with('4')
            || digits.starts_with('5')
            || digits.starts_with('7')
            || digits.starts_with('8'))
    {
        return validated(format!("+61{digits}"));
    }
    if digits.starts_with("1300") || digits.starts_with("1800") {
        return validated(format!("+61{digits}"));
    }
    None
}

/// The AU geographic region a fixed-line **area code** digit names: its slug,
/// human name, and the state/territory codes it spans. `None` for the
/// non-geographic leading digits (mobile `4`, VoIP `5`, the service prefixes
/// under `1`). The four geographic area codes are fixed by the ACMA Numbering
/// Plan and never reassigned. The single source of this mapping — `phone_au`
/// (module enrichment) and `core::correlator` (AU-085 jurisdiction cross-check)
/// both read it here so the two can't drift. Pure; no I/O.
#[must_use]
pub fn au_area_code_region(
    area_code: char,
) -> Option<(&'static str, &'static str, &'static [&'static str])> {
    match area_code {
        '2' => Some(("central-east", "Central East", &["NSW", "ACT"])),
        '3' => Some(("south-east", "South East", &["VIC", "TAS"])),
        '7' => Some(("north-east", "North East", &["QLD"])),
        '8' => Some(("central-west", "Central and West", &["SA", "WA", "NT"])),
        _ => None,
    }
}

/// The AU geographic region (slug, name, member states) implied by a phone
/// number's fixed-line area code, or `None` when the number is not an Australian
/// *geographic* fixed line — a mobile (`04`), a non-geographic service number
/// (`1300`/`1800`/…), a VoIP line (`05`) or a non-AU number. A geographic number
/// cannot port across regions, so its area code physically locates the line —
/// an independent jurisdiction signal. Derived from the value itself (via
/// [`normalise_phone`]), so it works on any AU phone, tagged or not. Pure; no I/O.
///
/// ```
/// use huntsman_search_engine::util::address_au::au_phone_region;
///
/// let (_slug, name, states) = au_phone_region("+61 2 9876 5432").expect("should succeed");
/// assert_eq!(name, "Central East");
/// assert_eq!(states, &["NSW", "ACT"]);
/// assert!(au_phone_region("+61 412 345 678").is_none()); // mobile — no region
/// assert!(au_phone_region("+1 555 123 4567").is_none()); // not Australian
/// ```
#[must_use]
pub fn au_phone_region(
    value: &str,
) -> Option<(&'static str, &'static str, &'static [&'static str])> {
    let e164 = normalise_phone(value)?;
    // Strip the country code, then a stray leading trunk `0` a malformed
    // `+610…` source might keep, leaving the bare national number.
    let national = e164.strip_prefix("+61")?.trim_start_matches('0');
    au_area_code_region(national.chars().next()?)
}

/// The contactability / network class an Australian phone number's leading
/// digits encode under the ACMA Numbering Plan — a robust signal that survives
/// number portability (the *type* of a number never ports, only the carrier).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AuLineType {
    /// A mobile service (`04…`) — a personal handset: a direct-contact and
    /// SMS/2FA pivot, and the line most strongly tied to one individual.
    Mobile,
    /// A geographic fixed line (`02/03/07/08…`) — physically anchored to its
    /// area-code region: a dwelling or premises location signal.
    GeographicFixed,
    /// A VoIP / digital service line (`05…`) — location-independent by design.
    Voip,
    /// A freephone number (`1800…`) — an inbound business/service line.
    Freephone,
    /// A local-rate number (`13` / `1300…`) — a business/service line.
    LocalRate,
    /// A premium-rate number (`190x`) — a charged service line.
    Premium,
}

impl AuLineType {
    /// A stable slug for tagging/serialisation (`mobile`, `geographic`, …).
    #[must_use]
    pub fn slug(self) -> &'static str {
        match self {
            Self::Mobile => "mobile",
            Self::GeographicFixed => "geographic",
            Self::Voip => "voip",
            Self::Freephone => "freephone",
            Self::LocalRate => "local-rate",
            Self::Premium => "premium-rate",
        }
    }

    /// True for an inbound business/service line (`1300`/`1800`/`13`/`190x`) —
    /// a number that ties its holder to an organisation rather than a person.
    #[must_use]
    pub fn is_business_service(self) -> bool {
        matches!(self, Self::Freephone | Self::LocalRate | Self::Premium)
    }
}

/// Classify an Australian phone number by **line type** — the contactability /
/// network class its leading digits encode (mobile, geographic fixed line, VoIP,
/// freephone, local-rate, premium), with a human label. `None` for a non-AU or
/// unrecognised number.
///
/// Complements [`au_phone_region`], which resolves only the *geographic* class
/// to a region: this resolves *every* AU number to its line type, so a mobile
/// (a personal device), a VoIP line, and the `1300`/`1800`/`190x` service lines
/// — which `au_phone_region` returns `None` for — each yield their own
/// people/network signal. The classification is by the ACMA-fixed leading
/// digits, so it is portability-proof (only the carrier ports, never the type).
/// The national significant number is read straight from the value's digits,
/// stripping an `0061`/`+61` country code and a trunk `0`, so it covers the
/// service forms (`190x`, the 6-digit `13xxxx`) the E.164 normaliser does not.
/// Pure; no I/O.
///
/// ```
/// use huntsman_search_engine::util::address_au::{au_phone_line_type, AuLineType};
///
/// assert_eq!(au_phone_line_type("0412 345 678").expect("should succeed").0, AuLineType::Mobile);
/// assert_eq!(au_phone_line_type("(07) 3739 4511").expect("should succeed").0, AuLineType::GeographicFixed);
/// assert_eq!(au_phone_line_type("1800 123 456").expect("should succeed").0, AuLineType::Freephone);
/// assert_eq!(au_phone_line_type("1300 975 707").expect("should succeed").0, AuLineType::LocalRate);
/// assert!(au_phone_line_type("+1 555 123 4567").is_none()); // not Australian
/// ```
#[must_use]
pub fn au_phone_line_type(value: &str) -> Option<(AuLineType, &'static str)> {
    // Read the national significant number directly: drop an `0061`/(`+`)`61`
    // country code and any trunk `0`. No valid AU national number begins with a
    // `6`, so a bare leading `61` is only stripped when a `+` marks it as a
    // country code — a plain `61…` foreign number is left intact (→ `None`).
    let plus = value.contains('+');
    let digits = crate::util::str_util::ascii_digits(value);
    let nat = if let Some(rest) = digits.strip_prefix("0061") {
        rest
    } else if plus && let Some(rest) = digits.strip_prefix("61") {
        rest
    } else {
        digits.as_str()
    }
    .trim_start_matches('0');
    if nat.starts_with("1800") {
        return Some((
            AuLineType::Freephone,
            "freephone (1800) — an inbound business/service line",
        ));
    }
    if nat.starts_with("1300") || (nat.len() == 6 && nat.starts_with("13")) {
        return Some((
            AuLineType::LocalRate,
            "local-rate (13/1300) — a business/service line",
        ));
    }
    if nat.starts_with("190") {
        return Some((
            AuLineType::Premium,
            "premium-rate (190x) — a charged service line",
        ));
    }
    match nat.chars().next()? {
        '4' => Some((
            AuLineType::Mobile,
            "mobile (04) — a personal handset and SMS/2FA pivot",
        )),
        '5' => Some((
            AuLineType::Voip,
            "VoIP / digital service (05) — location-independent",
        )),
        '2' | '3' | '7' | '8' => Some((
            AuLineType::GeographicFixed,
            "geographic fixed line — premises-anchored to its area-code region",
        )),
        _ => None,
    }
}

/// The Australian state/territory a `*.{state}.gov.au` government domain encodes,
/// as a canonical code (`NSW`/`VIC`/`QLD`/`WA`/`SA`/`TAS`/`ACT`/`NT`). The AU
/// government domain structure is official and fixed — every state-agency domain
/// is `agency.<state>.gov.au` (e.g. `transport.nsw.gov.au`, `health.vic.gov.au`)
/// — so the label immediately before `.gov.au` is an unambiguous jurisdiction
/// signal. Returns `None` for a federal `*.gov.au` domain (no single state, e.g.
/// `ato.gov.au`, `my.gov.au`) or any non-gov domain. Pure; no I/O.
///
/// ```
/// use huntsman_search_engine::util::address_au::au_gov_domain_state;
///
/// assert_eq!(au_gov_domain_state("health.nsw.gov.au"), Some("NSW"));
/// assert_eq!(au_gov_domain_state("TRANSPORT.VIC.GOV.AU"), Some("VIC"));
/// assert_eq!(au_gov_domain_state("ato.gov.au"), None);       // federal — no state
/// assert_eq!(au_gov_domain_state("acme.com.au"), None);      // not a gov domain
/// ```
#[must_use]
pub fn au_gov_domain_state(domain: &str) -> Option<&'static str> {
    let d = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    // The label immediately before the `.gov.au` suffix.
    au_state_label(d.strip_suffix(".gov.au")?.rsplit('.').next()?)
}

/// Map a canonical AU state/territory abbreviation label to its code (the single
/// source the `*.gov.au` / `*.edu.au` jurisdiction resolvers share).
fn au_state_label(label: &str) -> Option<&'static str> {
    match label {
        "nsw" => Some("NSW"),
        "vic" => Some("VIC"),
        "qld" => Some("QLD"),
        "wa" => Some("WA"),
        "sa" => Some("SA"),
        "tas" => Some("TAS"),
        "act" => Some("ACT"),
        "nt" => Some("NT"),
        _ => None,
    }
}

/// The Australian state/territory an `*.{state}.edu.au` education domain encodes
/// — the state school-system domains (`schools.nsw.edu.au`, `det.nsw.edu.au`,
/// `sa.edu.au`, `decd.tas.edu.au`, …) plus Education Queensland's `eq.edu.au`
/// (which carries no state label). Returns `None` for a university domain
/// (`uq.edu.au`, `anu.edu.au` — institution-named, no state code; those resolve
/// to their city via the `geo_domain_classifier` table) or any non-edu domain.
/// Pure; no I/O.
///
/// ```
/// use huntsman_search_engine::util::address_au::au_edu_domain_state;
///
/// assert_eq!(au_edu_domain_state("schools.nsw.edu.au"), Some("NSW"));
/// assert_eq!(au_edu_domain_state("eq.edu.au"), Some("QLD")); // Education Queensland
/// assert_eq!(au_edu_domain_state("uq.edu.au"), None);        // a university → city, not state
/// assert_eq!(au_edu_domain_state("acme.com.au"), None);      // not an edu domain
/// ```
#[must_use]
pub fn au_edu_domain_state(domain: &str) -> Option<&'static str> {
    let d = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let rest = d.strip_suffix(".edu.au")?;
    // Education Queensland's school domain is `eq.edu.au` (no state-code label).
    if rest == "eq" || rest.ends_with(".eq") {
        return Some("QLD");
    }
    au_state_label(rest.rsplit('.').next()?)
}

/// Classify an Australian domain by the **registrant category** its second-level
/// label encodes under the `.au` licensing rules, returning a stable tag value
/// and a human label. `None` for a non-`.au` domain, or a direct `.au`
/// registration (allowed since 2022) that carries no 2LD category.
///
/// Each 2LD is eligibility-bound, so the category is a real entity-type signal,
/// not a guess:
/// * `id.au` → an **individual** — a natural-person Australian registrant, the
///   single most people-centric domain signal there is.
/// * `com.au` / `net.au` → a **commercial** registrant (an Australian presence —
///   an ABN/ACN or registered trade mark — is required to hold one).
/// * `org.au` → a **non-profit** / charity.
/// * `asn.au` → an incorporated **association** / club.
/// * `gov.au` → an Australian **government** body.
/// * `edu.au` → an **education** institution.
///
/// Matching is on the registrable suffix, so a `www.` prefix or any number of
/// sub-labels is irrelevant (`mail.acme.com.au` → commercial). Pure; no I/O.
///
/// ```
/// use huntsman_search_engine::util::address_au::au_domain_registrant;
///
/// assert_eq!(au_domain_registrant("john.id.au").map(|c| c.0), Some("individual"));
/// assert_eq!(au_domain_registrant("ACME.COM.AU").map(|c| c.0), Some("commercial"));
/// assert_eq!(au_domain_registrant("club.asn.au").map(|c| c.0), Some("association"));
/// assert_eq!(au_domain_registrant("example.com"), None);   // not .au
/// assert_eq!(au_domain_registrant("direct.au"), None);     // direct rego, no 2LD category
/// ```
#[must_use]
pub fn au_domain_registrant(domain: &str) -> Option<(&'static str, &'static str)> {
    let d = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    // Ordered most-specific-first; suffixes are disjoint so order is not load-
    // bearing, only the longest-suffix intent.
    const REGISTRANTS: &[(&str, &str, &str)] = &[
        (
            ".id.au",
            "individual",
            "a natural-person Australian registrant (id.au)",
        ),
        (
            ".com.au",
            "commercial",
            "an Australian commercial registrant (com.au — Australian presence required)",
        ),
        (
            ".net.au",
            "commercial",
            "an Australian commercial registrant (net.au — Australian presence required)",
        ),
        (
            ".org.au",
            "non-profit",
            "an Australian non-profit / charity (org.au)",
        ),
        (
            ".asn.au",
            "association",
            "an Australian incorporated association / club (asn.au)",
        ),
        (
            ".gov.au",
            "government",
            "an Australian government body (gov.au)",
        ),
        (
            ".edu.au",
            "education",
            "an Australian education institution (edu.au)",
        ),
    ];
    REGISTRANTS
        .iter()
        .find(|(suffix, _, _)| d.ends_with(suffix))
        .map(|&(_, tag, label)| (tag, label))
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

/// Connection class of an Australian network operator. A consumer ISP places a
/// person on a domestic connection; AARNet is the academic & research network.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AuNetworkKind {
    /// A domestic consumer ISP / mobile carrier — a person on an AU connection.
    Consumer,
    /// AARNet — Australia's academic & research network (university/research/gov).
    Academic,
}

/// Australian network operator brand tokens (lowercase) → canonical name + class.
/// Only distinctive, unambiguously-Australian operator names are listed, so a
/// token in an `isp`/`org`/`as` value is a reliable AU signal, not a coincidence.
const AU_NETWORK_OPERATORS: &[(&str, &str, AuNetworkKind)] = &[
    ("telstra", "Telstra", AuNetworkKind::Consumer),
    ("optus", "Optus", AuNetworkKind::Consumer),
    ("tpg", "TPG", AuNetworkKind::Consumer),
    ("iinet", "iiNet", AuNetworkKind::Consumer),
    ("internode", "Internode", AuNetworkKind::Consumer),
    (
        "aussie broadband",
        "Aussie Broadband",
        AuNetworkKind::Consumer,
    ),
    ("aussiebb", "Aussie Broadband", AuNetworkKind::Consumer),
    ("vocus", "Vocus", AuNetworkKind::Consumer),
    ("dodo", "Dodo", AuNetworkKind::Consumer),
    ("iprimus", "iPrimus", AuNetworkKind::Consumer),
    ("belong", "Belong", AuNetworkKind::Consumer),
    ("superloop", "Superloop", AuNetworkKind::Consumer),
    ("launtel", "Launtel", AuNetworkKind::Consumer),
    ("exetel", "Exetel", AuNetworkKind::Consumer),
    ("myrepublic", "MyRepublic", AuNetworkKind::Consumer),
    ("spintel", "SpinTel", AuNetworkKind::Consumer),
    ("aapt", "AAPT", AuNetworkKind::Consumer),
    ("amaysim", "amaysim", AuNetworkKind::Consumer),
    ("tangerine", "Tangerine", AuNetworkKind::Consumer),
    ("aarnet", "AARNet", AuNetworkKind::Academic),
];

/// True if `token` occurs in `hay` (already lowercased) as a whole word — bounded
/// by a non-alphanumeric byte or a string edge on each side, so a short brand
/// (`tpg`) cannot match inside a longer word. Pure.
fn au_network_word_in(hay: &str, token: &str) -> bool {
    let bytes = hay.as_bytes();
    let mut from = 0;
    while let Some(rel) = hay[from..].find(token) {
        let at = from + rel;
        let end = at + token.len();
        let left_ok = at == 0 || !bytes[at - 1].is_ascii_alphanumeric();
        let right_ok = end == bytes.len() || !bytes[end].is_ascii_alphanumeric();
        if left_ok && right_ok {
            return true;
        }
        from = at + 1;
    }
    false
}

/// The Australian network operator named anywhere in `haystack` — typically an
/// IP/ASN entity's `isp`/`org`/`as`/`descr` text — with its connection class, or
/// `None`. Whole-word, case-insensitive, and limited to distinctive AU operator
/// brands, so a foreign ISP or an incidental token never matches. The shared
/// source of truth for AU-097 (network attribution) and AU-098 (which uses it as
/// a domestic-connection corroboration of the residency consensus). Pure; no I/O.
///
/// ```
/// use huntsman_search_engine::util::address_au::{au_network_operator, AuNetworkKind};
///
/// assert_eq!(au_network_operator("AS1221 Telstra"), Some(("Telstra", AuNetworkKind::Consumer)));
/// assert_eq!(au_network_operator("AARNET"), Some(("AARNet", AuNetworkKind::Academic)));
/// assert_eq!(au_network_operator("Google LLC"), None);          // foreign
/// assert_eq!(au_network_operator("ACMETPGENETICS LIMITED"), None); // not a word match
/// ```
#[must_use]
pub fn au_network_operator(haystack: &str) -> Option<(&'static str, AuNetworkKind)> {
    let hay = haystack.to_ascii_lowercase();
    AU_NETWORK_OPERATORS
        .iter()
        .find(|(tok, _, _)| au_network_word_in(&hay, tok))
        .map(|(_, canon, kind)| (*canon, *kind))
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
