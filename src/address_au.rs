//! Pure Australian address, postcode, domain, and phone helpers rebuilt from the monolith.

use std::collections::HashSet;

use crate::textnorm;

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
    #[must_use]
    pub fn confidence(&self) -> f64 {
        let mut confidence = 0.70_f64;
        if self.level.is_some() {
            confidence += 0.10;
        }
        if self.unit.is_some() {
            confidence += 0.05;
        }
        if !self.street_number.is_empty() {
            confidence += 0.05;
        }
        confidence.min(0.95)
    }
}

const STATES: &[&str] = &["ACT", "NSW", "NT", "QLD", "SA", "TAS", "VIC", "WA"];
const AU_DOMAIN_REGISTRANTS: &[(&str, &str, &str)] = &[
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
const STREET_SUFFIXES: &[&str] = &[
    "street",
    "st",
    "road",
    "rd",
    "avenue",
    "ave",
    "lane",
    "ln",
    "drive",
    "dr",
    "court",
    "ct",
    "crescent",
    "cres",
    "place",
    "pl",
    "way",
    "highway",
    "hwy",
    "parade",
    "pde",
    "terrace",
    "tce",
    "boulevard",
    "blvd",
    "circuit",
    "cct",
    "close",
    "cl",
    "esplanade",
    "esp",
    "square",
    "sq",
];

fn clean_word(word: &str) -> &str {
    word.trim_matches(|c: char| {
        c == ',' || c == ';' || c == ':' || c == '(' || c == ')' || c == '.'
    })
}

fn is_title_or_upper(word: &str) -> bool {
    let word = clean_word(word);
    let mut chars = word
        .chars()
        .filter(|c| c.is_alphabetic() || matches!(c, '\'' | '-'));
    let Some(first) = chars.next() else {
        return false;
    };
    if word.chars().all(|c| !c.is_alphabetic() || c.is_uppercase()) {
        return true;
    }
    first.is_uppercase() && chars.all(|c| !c.is_alphabetic() || c.is_lowercase())
}

fn street_suffix(word: &str) -> bool {
    let lowered = clean_word(word).to_ascii_lowercase();
    STREET_SUFFIXES.contains(&lowered.as_str())
}

fn parse_level(tokens: &[&str], num_idx: usize) -> Option<(usize, String)> {
    if num_idx == 0 {
        return None;
    }
    let one = clean_word(tokens[num_idx - 1]);
    if let Some(rest) = one
        .strip_prefix('L')
        .filter(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()))
    {
        return Some((num_idx - 1, format!("Level {rest}")));
    }
    if num_idx >= 2 {
        let prefix = clean_word(tokens[num_idx - 2]);
        let number = clean_word(tokens[num_idx - 1]);
        if number.bytes().all(|b| b.is_ascii_digit())
            && matches!(
                prefix.to_ascii_lowercase().as_str(),
                "level" | "lvl" | "suite" | "ste" | "shop" | "office"
            )
        {
            let label = match prefix.to_ascii_lowercase().as_str() {
                "lvl" => "Level",
                "ste" => "Suite",
                other => {
                    let mut chars = other.chars();
                    let mut out = String::new();
                    if let Some(first) = chars.next() {
                        out.push(first.to_ascii_uppercase());
                        out.extend(chars);
                    }
                    return Some((num_idx - 2, format!("{out} {number}")));
                }
            };
            return Some((num_idx - 2, format!("{label} {number}")));
        }
    }
    None
}

fn parse_number_and_unit(token: &str) -> Option<(Option<String>, String)> {
    let token = clean_word(token);
    if let Some((unit, number)) = token.split_once('/') {
        let valid = |s: &str| {
            !s.is_empty()
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || b.is_ascii_alphabetic())
                && s.bytes().any(|b| b.is_ascii_digit())
        };
        if valid(unit) && valid(number) {
            return Some((Some(unit.to_string()), number.to_string()));
        }
    }
    (!token.is_empty()
        && token
            .bytes()
            .all(|b| b.is_ascii_digit() || b.is_ascii_alphabetic())
        && token.bytes().any(|b| b.is_ascii_digit()))
    .then(|| (None, token.to_string()))
}

/// Find plausible Australian addresses in free text.
#[must_use]
pub fn extract_all(text: &str) -> Vec<AuAddress> {
    let tokens: Vec<&str> = text.split_whitespace().collect();
    let mut out = Vec::new();
    for postcode_idx in 0..tokens.len() {
        let postcode = clean_word(tokens[postcode_idx]);
        if postcode.len() != 4 || !postcode.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let Some(state_idx) = postcode_idx.checked_sub(1) else {
            continue;
        };
        let state = clean_word(tokens[state_idx]).to_ascii_uppercase();
        if !STATES.contains(&state.as_str()) || state_for_postcode(postcode) != Some(state.as_str())
        {
            continue;
        }
        let Some(street_suffix_idx) = (0..state_idx.saturating_sub(1))
            .rev()
            .find(|&idx| street_suffix(tokens[idx]))
        else {
            continue;
        };
        let suburb_start = street_suffix_idx + 1;
        if suburb_start >= state_idx
            || !tokens[suburb_start..state_idx]
                .iter()
                .all(|word| is_title_or_upper(word))
        {
            continue;
        }
        let Some(number_idx) = (0..street_suffix_idx)
            .rev()
            .find(|&idx| parse_number_and_unit(tokens[idx]).is_some())
        else {
            continue;
        };
        let Some((unit, street_number)) = parse_number_and_unit(tokens[number_idx]) else {
            continue;
        };
        if !tokens[number_idx + 1..=street_suffix_idx]
            .iter()
            .all(|word| is_title_or_upper(word))
        {
            continue;
        }
        let (start_idx, level) = parse_level(&tokens, number_idx)
            .map_or((number_idx, None), |(idx, level)| (idx, Some(level)));
        let street = tokens[number_idx + 1..=street_suffix_idx]
            .iter()
            .map(|word| clean_word(word))
            .collect::<Vec<_>>()
            .join(" ");
        let suburb = tokens[suburb_start..state_idx]
            .iter()
            .map(|word| clean_word(word))
            .collect::<Vec<_>>()
            .join(" ");
        let full = tokens[start_idx..=postcode_idx]
            .iter()
            .map(|word| clean_word(word))
            .collect::<Vec<_>>()
            .join(" ");
        out.push(AuAddress {
            full,
            level,
            unit,
            street_number,
            street,
            suburb,
            state,
            postcode: postcode.to_string(),
        });
    }
    out
}

#[must_use]
pub fn state_for_postcode(postcode: &str) -> Option<&'static str> {
    let value = postcode.parse::<u16>().ok()?;
    STATES.iter().copied().find(|state| match *state {
        "NSW" => (1000..=2999).contains(&value),
        "ACT" => {
            (200..=299).contains(&value)
                || (2600..=2618).contains(&value)
                || (2900..=2920).contains(&value)
        }
        "VIC" => (3000..=3999).contains(&value) || (8000..=8999).contains(&value),
        "QLD" => (4000..=4999).contains(&value) || (9000..=9999).contains(&value),
        "SA" => (5000..=5999).contains(&value),
        "WA" => (6000..=6797).contains(&value) || (6800..=6999).contains(&value),
        "TAS" => (7000..=7999).contains(&value),
        "NT" => (800..=999).contains(&value),
        _ => false,
    })
}

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

fn state_abbrev_tokens(text: &str) -> impl Iterator<Item = &'static str> + '_ {
    text.split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|token| token.len() == 2 || token.len() == 3)
        .filter_map(|token| {
            STATES
                .iter()
                .copied()
                .find(|state| state.eq_ignore_ascii_case(token))
        })
}

#[must_use]
pub fn state_code(text: &str) -> Option<&'static str> {
    if let Some(state) = state_abbrev_tokens(text).last() {
        return Some(state);
    }
    let lowered = text.to_ascii_lowercase();
    if let Some((_, code)) = STATE_NAMES.iter().find(|(name, _)| lowered.contains(name)) {
        return Some(*code);
    }
    let last_digits = text
        .split(|c: char| !c.is_ascii_digit())
        .rfind(|token| !token.is_empty());
    if let Some(last) = last_digits.filter(|last| last.len() == 4) {
        return state_for_postcode(last);
    }
    None
}

#[must_use]
pub fn normalise_phone(s: &str) -> Option<String> {
    crate::value_syntax::normalise_au_phone(s)
}

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

#[must_use]
pub fn au_phone_region(
    value: &str,
) -> Option<(&'static str, &'static str, &'static [&'static str])> {
    let e164 = normalise_phone(value)?;
    let national = e164.strip_prefix("+61")?.trim_start_matches('0');
    au_area_code_region(national.chars().next()?)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AuLineType {
    Mobile,
    GeographicFixed,
    Voip,
    Freephone,
    LocalRate,
    Premium,
}

impl AuLineType {
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
}

#[must_use]
pub fn au_phone_line_type(value: &str) -> Option<(AuLineType, &'static str)> {
    let plus = value.contains('+');
    let digits = textnorm::ascii_digits(value);
    let national = if let Some(rest) = digits.strip_prefix("0061") {
        rest
    } else if plus {
        digits.strip_prefix("61")?
    } else {
        digits.as_str()
    };
    let national = national.trim_start_matches('0');
    if national.len() == 10 && national.starts_with("1800") {
        return Some((
            AuLineType::Freephone,
            "freephone (1800) — an inbound business/service line",
        ));
    }
    if (national.len() == 10 && national.starts_with("1300"))
        || (national.len() == 6 && national.starts_with("13"))
    {
        return Some((
            AuLineType::LocalRate,
            "local-rate (13/1300) — a business/service line",
        ));
    }
    if national.len() == 10 && national.starts_with("190") {
        return Some((
            AuLineType::Premium,
            "premium-rate (190x) — a charged service line",
        ));
    }
    match national.chars().next()? {
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

#[must_use]
pub fn au_gov_domain_state(domain: &str) -> Option<&'static str> {
    let lowered = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let rest = lowered.strip_suffix(".gov.au")?;
    au_state_label(rest.rsplit('.').next()?)
}

#[must_use]
pub fn au_edu_domain_state(domain: &str) -> Option<&'static str> {
    let lowered = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let rest = lowered.strip_suffix(".edu.au")?;
    if rest == "eq"
        || rest
            .rsplit('.')
            .next()
            .is_some_and(|segment| segment == "eq")
    {
        return Some("QLD");
    }
    au_state_label(rest.rsplit('.').next()?)
}

#[must_use]
pub fn au_domain_registrant(domain: &str) -> Option<(&'static str, &'static str)> {
    let lowered = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    AU_DOMAIN_REGISTRANTS
        .iter()
        .find(|(suffix, _, _)| lowered.ends_with(suffix))
        .map(|&(_, tag, label)| (tag, label))
}

#[must_use]
pub fn locality_key(addr: &str) -> String {
    let cleaned: String = addr
        .to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { ' ' })
        .collect();
    let mut tokens: Vec<&str> = cleaned.split_whitespace().collect();
    while tokens.len() > 1
        && tokens.last().is_some_and(|token| {
            (4..=5).contains(&token.len()) && token.bytes().all(|b| b.is_ascii_digit())
        })
    {
        tokens.pop();
    }
    let mut out = Vec::with_capacity(tokens.len() + 2);
    for token in tokens {
        match token {
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

#[must_use]
pub fn extract_phones(text: &str) -> Vec<String> {
    let tokens: Vec<&str> = text.split_whitespace().collect();
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for start in 0..tokens.len() {
        for len in 1..=4 {
            if start + len > tokens.len() {
                break;
            }
            let candidate = tokens[start..start + len].join(" ");
            if let Some(normalised) = normalise_phone(&candidate) {
                let is_new = seen.insert(normalised.clone());
                if is_new {
                    out.push(normalised);
                }
            }
        }
    }
    out
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AuNetworkKind {
    Consumer,
    Academic,
}

const AU_NETWORK_OPERATORS: &[(&str, &str, AuNetworkKind, bool)] = &[
    ("telstra", "Telstra", AuNetworkKind::Consumer, false),
    ("optus", "Optus", AuNetworkKind::Consumer, false),
    ("tpg", "TPG", AuNetworkKind::Consumer, false),
    ("iinet", "iiNet", AuNetworkKind::Consumer, false),
    ("internode", "Internode", AuNetworkKind::Consumer, false),
    (
        "aussie broadband",
        "Aussie Broadband",
        AuNetworkKind::Consumer,
        false,
    ),
    (
        "aussiebb",
        "Aussie Broadband",
        AuNetworkKind::Consumer,
        false,
    ),
    ("vocus", "Vocus", AuNetworkKind::Consumer, false),
    ("dodo", "Dodo", AuNetworkKind::Consumer, true),
    ("iprimus", "iPrimus", AuNetworkKind::Consumer, false),
    ("belong", "Belong", AuNetworkKind::Consumer, true),
    ("superloop", "Superloop", AuNetworkKind::Consumer, false),
    ("launtel", "Launtel", AuNetworkKind::Consumer, false),
    ("exetel", "Exetel", AuNetworkKind::Consumer, false),
    ("myrepublic", "MyRepublic", AuNetworkKind::Consumer, false),
    ("spintel", "SpinTel", AuNetworkKind::Consumer, false),
    ("aapt", "AAPT", AuNetworkKind::Consumer, false),
    ("amaysim", "amaysim", AuNetworkKind::Consumer, false),
    ("tangerine", "Tangerine", AuNetworkKind::Consumer, true),
    ("aarnet", "AARNet", AuNetworkKind::Academic, false),
];

fn au_network_word_in(haystack: &str, token: &str) -> bool {
    let bytes = haystack.as_bytes();
    let mut from = 0usize;
    while let Some(relative) = haystack[from..].find(token) {
        let at = from + relative;
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

fn au_network_operator_in(
    haystack: &str,
    allow_ambiguous: bool,
) -> Option<(&'static str, AuNetworkKind)> {
    let lowered = haystack.to_ascii_lowercase();
    AU_NETWORK_OPERATORS
        .iter()
        .filter(|(_, _, _, ambiguous)| allow_ambiguous || !*ambiguous)
        .find(|(token, _, _, _)| au_network_word_in(&lowered, token))
        .map(|(_, canon, kind, _)| (*canon, *kind))
}

/// The Australian network operator a registry record names: `structured` is a handle such as
/// `RIPEstat`'s `ASN-TELSTRA`, where a common word such as `belong` can only be the operator's
/// name, and `descr` free text such as `Telstra Limited`, where such a word is not trusted.
#[must_use]
pub fn au_network_operator_split(
    structured: &str,
    descr: &str,
) -> Option<(&'static str, AuNetworkKind)> {
    au_network_operator_in(structured, true).or_else(|| au_network_operator_in(descr, false))
}

#[must_use]
pub fn is_standalone_postcode_at(bytes: &[u8], index: usize) -> bool {
    index + 3 < bytes.len()
        && bytes[index].is_ascii_digit()
        && bytes[index + 1].is_ascii_digit()
        && bytes[index + 2].is_ascii_digit()
        && bytes[index + 3].is_ascii_digit()
        && !bytes.get(index + 4).is_some_and(u8::is_ascii_digit)
        && (index == 0 || !bytes[index - 1].is_ascii_digit())
        && std::str::from_utf8(&bytes[index..index + 4])
            .ok()
            .and_then(state_for_postcode)
            .is_some()
}

/// One mobile number block of the ACMA numbering register (the Numbering System's
/// `EnhancedFullDownload.csv`, service type `Mobile`), as the regulator publishes it: who the
/// block was first allocated to and when, and its latest holder and transfer date. A block is
/// a *range allocation*, never the carrier that serves a number today — number portability lets a
/// number keep its block and change carrier in minutes — and never a subscriber. Names are kept
/// verbatim from the register.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuMobileBlock {
    /// First national number of the block without its trunk `0`, so `0405000000` is `405000000`.
    pub from: u32,
    /// Last national number of the block, in the same form.
    pub to: u32,
    /// Whether the register lists the block as spare (no holder; the number cannot be in
    /// service through an allocation).
    pub spare: bool,
    pub allocatee: &'static str,
    /// ISO date of the original allocation, empty for a spare block.
    pub allocated: &'static str,
    pub holder: &'static str,
    /// ISO date of the latest transfer, empty when the block was never transferred.
    pub transferred: &'static str,
}

impl AuMobileBlock {
    /// The block as the register writes it, `0405000000-0405999999`.
    #[must_use]
    pub fn range(&self) -> String {
        format!("0{}-0{}", self.from, self.to)
    }
}

/// When the register copy below was retrieved from the Numbering System's full download, and
/// the SHA-256 of that ZIP. The file carries no date of its own (its CSV was stamped 2026-11-02).
pub const AU_MOBILE_REGISTER_RETRIEVED: &str = "2026-11-03";
pub const AU_MOBILE_REGISTER_SHA256: &str =
    "a32a9cc0e43133c4f9f0f7c6d2cda4853887f33db04ce9f27ea3d7f109bffc49";
/// Where the register is published; the full download is public and keyless.
pub const AU_MOBILE_REGISTER_URL: &str =
    "https://www.thenumberingsystem.com.au/download/EnhancedFullDownload.zip";

/// Every `Mobile` block of the register, ascending and contiguous over `0400000000` to
/// `0499999999` (a test holds that). 175 blocks, 13 holders, 19 spare.
pub const AU_MOBILE_BLOCKS: &[AuMobileBlock] = &[
    AuMobileBlock {
        from: 400_000_000,
        to: 400_299_999,
        spare: false,
        allocatee: "ONE.TEL LIMITED",
        allocated: "1998-11-27",
        holder: "TELSTRA LIMITED",
        transferred: "2001-06-07",
    },
    AuMobileBlock {
        from: 400_300_000,
        to: 400_799_999,
        spare: false,
        allocatee: "ONE.TEL LIMITED",
        allocated: "1999-09-08",
        holder: "TELSTRA LIMITED",
        transferred: "2001-06-07",
    },
    AuMobileBlock {
        from: 400_800_000,
        to: 400_999_999,
        spare: false,
        allocatee: "ONE.TEL LIMITED",
        allocated: "1998-11-27",
        holder: "TELSTRA LIMITED",
        transferred: "2001-06-07",
    },
    AuMobileBlock {
        from: 401_000_000,
        to: 401_399_999,
        spare: false,
        allocatee: "SINGTEL OPTUS PTY LIMITED",
        allocated: "1999-05-24",
        holder: "OPTUS MOBILE PTY LIMITED",
        transferred: "2003-01-30",
    },
    AuMobileBlock {
        from: 401_400_000,
        to: 401_799_999,
        spare: false,
        allocatee: "SINGTEL OPTUS PTY LIMITED",
        allocated: "1999-09-20",
        holder: "OPTUS MOBILE PTY LIMITED",
        transferred: "2003-01-30",
    },
    AuMobileBlock {
        from: 401_800_000,
        to: 401_999_999,
        spare: false,
        allocatee: "SINGTEL OPTUS PTY LIMITED",
        allocated: "2000-03-09",
        holder: "OPTUS MOBILE PTY LIMITED",
        transferred: "2003-01-30",
    },
    AuMobileBlock {
        from: 402_000_000,
        to: 402_199_999,
        spare: false,
        allocatee: "SINGTEL OPTUS PTY LIMITED",
        allocated: "1999-05-24",
        holder: "OPTUS MOBILE PTY LIMITED",
        transferred: "2003-01-30",
    },
    AuMobileBlock {
        from: 402_200_000,
        to: 402_399_999,
        spare: false,
        allocatee: "SINGTEL OPTUS PTY LIMITED",
        allocated: "1999-09-20",
        holder: "OPTUS MOBILE PTY LIMITED",
        transferred: "2003-01-30",
    },
    AuMobileBlock {
        from: 402_400_000,
        to: 402_999_999,
        spare: false,
        allocatee: "SINGTEL OPTUS PTY LIMITED",
        allocated: "2000-03-09",
        holder: "OPTUS MOBILE PTY LIMITED",
        transferred: "2003-01-30",
    },
    AuMobileBlock {
        from: 403_000_000,
        to: 403_199_999,
        spare: false,
        allocatee: "SINGTEL OPTUS PTY LIMITED",
        allocated: "1999-05-24",
        holder: "OPTUS MOBILE PTY LIMITED",
        transferred: "2003-01-30",
    },
    AuMobileBlock {
        from: 403_200_000,
        to: 403_399_999,
        spare: false,
        allocatee: "SINGTEL OPTUS PTY LIMITED",
        allocated: "1999-09-20",
        holder: "OPTUS MOBILE PTY LIMITED",
        transferred: "2003-01-30",
    },
    AuMobileBlock {
        from: 403_400_000,
        to: 403_999_999,
        spare: false,
        allocatee: "SINGTEL OPTUS PTY LIMITED",
        allocated: "2000-03-09",
        holder: "OPTUS MOBILE PTY LIMITED",
        transferred: "2003-01-30",
    },
    AuMobileBlock {
        from: 404_000_000,
        to: 404_999_999,
        spare: false,
        allocatee: "VODAFONE AUSTRALIA PTY LIMITED",
        allocated: "2005-08-25",
        holder: "VODAFONE AUSTRALIA PTY LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 405_000_000,
        to: 405_999_999,
        spare: false,
        allocatee: "VODAFONE NETWORK PTY LIMITED",
        allocated: "1999-11-09",
        holder: "VODAFONE AUSTRALIA PTY LIMITED",
        transferred: "2007-02-07",
    },
    AuMobileBlock {
        from: 406_000_000,
        to: 406_799_999,
        spare: false,
        allocatee: "VODAFONE NETWORK PTY LIMITED",
        allocated: "2004-07-27",
        holder: "VODAFONE AUSTRALIA PTY LIMITED",
        transferred: "2007-02-07",
    },
    AuMobileBlock {
        from: 406_800_000,
        to: 406_999_999,
        spare: false,
        allocatee: "VODAFONE NETWORK PTY LIMITED",
        allocated: "2005-08-25",
        holder: "VODAFONE AUSTRALIA PTY LIMITED",
        transferred: "2007-02-07",
    },
    AuMobileBlock {
        from: 407_000_000,
        to: 409_999_999,
        spare: false,
        allocatee: "TELSTRA LIMITED",
        allocated: "1998-03-10",
        holder: "TELSTRA LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 410_000_000,
        to: 410_099_999,
        spare: false,
        allocatee: "VODAFONE AUSTRALIA PTY LIMITED",
        allocated: "2005-08-25",
        holder: "VODAFONE AUSTRALIA PTY LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 410_100_000,
        to: 410_299_999,
        spare: false,
        allocatee: "VODAFONE NETWORK PTY LIMITED",
        allocated: "2002-09-16",
        holder: "VODAFONE AUSTRALIA PTY LIMITED",
        transferred: "2007-02-07",
    },
    AuMobileBlock {
        from: 410_300_000,
        to: 410_999_999,
        spare: false,
        allocatee: "VODAFONE AUSTRALIA PTY LIMITED",
        allocated: "2005-08-25",
        holder: "VODAFONE AUSTRALIA PTY LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 411_000_000,
        to: 413_999_999,
        spare: false,
        allocatee: "SINGTEL OPTUS PTY LIMITED",
        allocated: "1992-07-10",
        holder: "OPTUS MOBILE PTY LIMITED",
        transferred: "2003-01-30",
    },
    AuMobileBlock {
        from: 414_000_000,
        to: 416_999_999,
        spare: false,
        allocatee: "VODAFONE AUSTRALIA PTY LIMITED",
        allocated: "2005-08-25",
        holder: "VODAFONE AUSTRALIA PTY LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 417_000_000,
        to: 419_999_999,
        spare: false,
        allocatee: "TELSTRA LIMITED",
        allocated: "1992-07-10",
        holder: "TELSTRA LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 420_000_000,
        to: 420_019_999,
        spare: false,
        allocatee: "SYDNEY TRAINS",
        allocated: "2008-09-26",
        holder: "SYDNEY TRAINS",
        transferred: "",
    },
    AuMobileBlock {
        from: 420_020_000,
        to: 420_029_999,
        spare: false,
        allocatee: "SINCH AUSTRALIA PTY LTD",
        allocated: "2012-09-04",
        holder: "SINCH AUSTRALIA PTY LTD",
        transferred: "",
    },
    AuMobileBlock {
        from: 420_030_000,
        to: 420_039_999,
        spare: true,
        allocatee: "",
        allocated: "",
        holder: "",
        transferred: "",
    },
    AuMobileBlock {
        from: 420_040_000,
        to: 420_049_999,
        spare: false,
        allocatee: "SYMBIO NETWORKS PTY LTD",
        allocated: "2017-04-20",
        holder: "SYMBIO NETWORKS PTY LTD",
        transferred: "",
    },
    AuMobileBlock {
        from: 420_050_000,
        to: 420_099_999,
        spare: true,
        allocatee: "",
        allocated: "",
        holder: "",
        transferred: "",
    },
    AuMobileBlock {
        from: 420_100_000,
        to: 420_109_999,
        spare: false,
        allocatee: "PIVOTEL SATELLITE PTY LIMITED",
        allocated: "2003-09-24",
        holder: "PIVOTEL SATELLITE PTY LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 420_110_000,
        to: 420_199_999,
        spare: false,
        allocatee: "PIVOTEL SATELLITE PTY LIMITED",
        allocated: "2026-05-28",
        holder: "PIVOTEL SATELLITE PTY LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 420_200_000,
        to: 420_999_999,
        spare: false,
        allocatee: "VODAFONE NETWORK PTY LIMITED",
        allocated: "2005-08-25",
        holder: "VODAFONE AUSTRALIA PTY LIMITED",
        transferred: "2007-02-07",
    },
    AuMobileBlock {
        from: 421_000_000,
        to: 422_999_999,
        spare: false,
        allocatee: "SINGTEL OPTUS PTY LIMITED",
        allocated: "2000-10-26",
        holder: "OPTUS MOBILE PTY LIMITED",
        transferred: "2003-01-30",
    },
    AuMobileBlock {
        from: 423_000_000,
        to: 423_999_999,
        spare: false,
        allocatee: "OPTUS NETWORKS PTY LIMITED",
        allocated: "2002-07-10",
        holder: "OPTUS MOBILE PTY LIMITED",
        transferred: "2003-02-10",
    },
    AuMobileBlock {
        from: 424_000_000,
        to: 424_299_999,
        spare: false,
        allocatee: "VODAFONE NETWORK PTY LIMITED",
        allocated: "2002-09-16",
        holder: "VODAFONE AUSTRALIA PTY LIMITED",
        transferred: "2007-02-07",
    },
    AuMobileBlock {
        from: 424_300_000,
        to: 424_799_999,
        spare: false,
        allocatee: "VODAFONE NETWORK PTY LIMITED",
        allocated: "2003-01-16",
        holder: "VODAFONE AUSTRALIA PTY LIMITED",
        transferred: "2007-02-07",
    },
    AuMobileBlock {
        from: 424_800_000,
        to: 424_999_999,
        spare: false,
        allocatee: "VODAFONE NETWORK PTY LIMITED",
        allocated: "2004-07-27",
        holder: "VODAFONE AUSTRALIA PTY LIMITED",
        transferred: "2007-02-07",
    },
    AuMobileBlock {
        from: 425_000_000,
        to: 425_099_999,
        spare: false,
        allocatee: "TPG TELECOM LIMITED",
        allocated: "2009-04-17",
        holder: "VODAFONE AUSTRALIA PTY LIMITED",
        transferred: "2014-07-10",
    },
    AuMobileBlock {
        from: 425_100_000,
        to: 425_199_999,
        spare: false,
        allocatee: "HUTCHISON TELECOMMUNICATIONS (AUSTRALIA) LIMITED",
        allocated: "2004-01-23",
        holder: "VODAFONE AUSTRALIA PTY LIMITED",
        transferred: "2014-07-10",
    },
    AuMobileBlock {
        from: 425_200_000,
        to: 425_299_999,
        spare: false,
        allocatee: "HUTCHISON TELECOMMUNICATIONS (AUSTRALIA) LIMITED",
        allocated: "1999-01-21",
        holder: "VODAFONE AUSTRALIA PTY LIMITED",
        transferred: "2014-07-10",
    },
    AuMobileBlock {
        from: 425_300_000,
        to: 425_399_999,
        spare: false,
        allocatee: "HUTCHISON TELECOMMUNICATIONS (AUSTRALIA) LIMITED",
        allocated: "2000-10-16",
        holder: "VODAFONE AUSTRALIA PTY LIMITED",
        transferred: "2014-07-10",
    },
    AuMobileBlock {
        from: 425_400_000,
        to: 425_599_999,
        spare: false,
        allocatee: "TPG TELECOM LIMITED",
        allocated: "2009-04-17",
        holder: "VODAFONE AUSTRALIA PTY LIMITED",
        transferred: "2014-07-10",
    },
    AuMobileBlock {
        from: 425_600_000,
        to: 425_699_999,
        spare: false,
        allocatee: "HUTCHISON TELECOMMUNICATIONS (AUSTRALIA) LIMITED",
        allocated: "2004-01-23",
        holder: "VODAFONE AUSTRALIA PTY LIMITED",
        transferred: "2014-07-10",
    },
    AuMobileBlock {
        from: 425_700_000,
        to: 425_799_999,
        spare: false,
        allocatee: "HUTCHISON TELECOMMUNICATIONS (AUSTRALIA) LIMITED",
        allocated: "1999-01-21",
        holder: "VODAFONE AUSTRALIA PTY LIMITED",
        transferred: "2014-07-10",
    },
    AuMobileBlock {
        from: 425_800_000,
        to: 425_899_999,
        spare: false,
        allocatee: "HUTCHISON TELECOMMUNICATIONS (AUSTRALIA) LIMITED",
        allocated: "2000-10-16",
        holder: "VODAFONE AUSTRALIA PTY LIMITED",
        transferred: "2014-07-10",
    },
    AuMobileBlock {
        from: 425_900_000,
        to: 425_999_999,
        spare: false,
        allocatee: "TPG TELECOM LIMITED",
        allocated: "2010-05-28",
        holder: "VODAFONE AUSTRALIA PTY LIMITED",
        transferred: "2014-07-10",
    },
    AuMobileBlock {
        from: 426_000_000,
        to: 426_999_999,
        spare: false,
        allocatee: "VODAFONE AUSTRALIA PTY LIMITED",
        allocated: "2010-05-28",
        holder: "VODAFONE AUSTRALIA PTY LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 427_000_000,
        to: 429_999_999,
        spare: false,
        allocatee: "TELSTRA LIMITED",
        allocated: "1998-09-18",
        holder: "TELSTRA LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 430_000_000,
        to: 430_099_999,
        spare: false,
        allocatee: "TPG TELECOM LIMITED",
        allocated: "2001-12-18",
        holder: "VODAFONE AUSTRALIA PTY LIMITED",
        transferred: "2014-07-10",
    },
    AuMobileBlock {
        from: 430_100_000,
        to: 430_599_999,
        spare: false,
        allocatee: "TPG TELECOM LIMITED",
        allocated: "2006-01-13",
        holder: "VODAFONE AUSTRALIA PTY LIMITED",
        transferred: "2014-07-10",
    },
    AuMobileBlock {
        from: 430_600_000,
        to: 430_999_999,
        spare: false,
        allocatee: "TPG TELECOM LIMITED",
        allocated: "2008-10-28",
        holder: "VODAFONE AUSTRALIA PTY LIMITED",
        transferred: "2014-07-10",
    },
    AuMobileBlock {
        from: 431_000_000,
        to: 431_999_999,
        spare: false,
        allocatee: "OPTUS MOBILE PTY LIMITED",
        allocated: "2003-06-30",
        holder: "OPTUS MOBILE PTY LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 432_000_000,
        to: 432_999_999,
        spare: false,
        allocatee: "OPTUS MOBILE PTY LIMITED",
        allocated: "2004-03-03",
        holder: "OPTUS MOBILE PTY LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 433_000_000,
        to: 433_099_999,
        spare: false,
        allocatee: "TPG TELECOM LIMITED",
        allocated: "2005-03-07",
        holder: "VODAFONE AUSTRALIA PTY LIMITED",
        transferred: "2014-07-10",
    },
    AuMobileBlock {
        from: 433_100_000,
        to: 433_399_999,
        spare: false,
        allocatee: "TPG TELECOM LIMITED",
        allocated: "2002-08-21",
        holder: "VODAFONE AUSTRALIA PTY LIMITED",
        transferred: "2014-07-10",
    },
    AuMobileBlock {
        from: 433_400_000,
        to: 433_599_999,
        spare: false,
        allocatee: "TPG TELECOM LIMITED",
        allocated: "2004-03-24",
        holder: "VODAFONE AUSTRALIA PTY LIMITED",
        transferred: "2014-07-10",
    },
    AuMobileBlock {
        from: 433_600_000,
        to: 433_899_999,
        spare: false,
        allocatee: "TPG TELECOM LIMITED",
        allocated: "2004-12-07",
        holder: "VODAFONE AUSTRALIA PTY LIMITED",
        transferred: "2014-07-10",
    },
    AuMobileBlock {
        from: 433_900_000,
        to: 433_999_999,
        spare: false,
        allocatee: "TPG TELECOM LIMITED",
        allocated: "2005-03-07",
        holder: "VODAFONE AUSTRALIA PTY LIMITED",
        transferred: "2014-07-10",
    },
    AuMobileBlock {
        from: 434_000_000,
        to: 434_999_999,
        spare: false,
        allocatee: "OPTUS NETWORKS PTY LIMITED",
        allocated: "2004-10-19",
        holder: "OPTUS MOBILE PTY LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 435_000_000,
        to: 435_099_999,
        spare: false,
        allocatee: "OPTUS MOBILE PTY LIMITED",
        allocated: "2005-04-21",
        holder: "OPTUS MOBILE PTY LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 435_100_000,
        to: 435_299_999,
        spare: false,
        allocatee: "OPTUS MOBILE PTY LIMITED",
        allocated: "2007-07-13",
        holder: "OPTUS MOBILE PTY LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 435_300_000,
        to: 435_699_999,
        spare: false,
        allocatee: "OPTUS MOBILE PTY LIMITED",
        allocated: "2008-09-26",
        holder: "OPTUS MOBILE PTY LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 435_700_000,
        to: 435_999_999,
        spare: false,
        allocatee: "OPTUS MOBILE PTY LIMITED",
        allocated: "2009-10-01",
        holder: "OPTUS MOBILE PTY LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 436_000_000,
        to: 436_499_999,
        spare: false,
        allocatee: "TELSTRA LIMITED",
        allocated: "2016-02-29",
        holder: "TELSTRA LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 436_500_000,
        to: 436_999_999,
        spare: false,
        allocatee: "TELSTRA LIMITED",
        allocated: "2016-10-11",
        holder: "TELSTRA LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 437_000_000,
        to: 437_299_999,
        spare: false,
        allocatee: "TELSTRA LIMITED",
        allocated: "2004-03-12",
        holder: "TELSTRA LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 437_300_000,
        to: 437_999_999,
        spare: false,
        allocatee: "TELSTRA LIMITED",
        allocated: "2004-05-06",
        holder: "TELSTRA LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 438_000_000,
        to: 439_999_999,
        spare: false,
        allocatee: "TELSTRA LIMITED",
        allocated: "1999-09-17",
        holder: "TELSTRA LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 440_000_000,
        to: 440_149_999,
        spare: false,
        allocatee: "OPTUS NETWORKS PTY LIMITED",
        allocated: "2024-04-30",
        holder: "OPTUS MOBILE PTY LIMITED",
        transferred: "2025-04-29",
    },
    AuMobileBlock {
        from: 440_150_000,
        to: 444_399_999,
        spare: true,
        allocatee: "",
        allocated: "",
        holder: "",
        transferred: "",
    },
    AuMobileBlock {
        from: 444_400_000,
        to: 444_499_999,
        spare: false,
        allocatee: "TELSTRA LIMITED",
        allocated: "2009-11-10",
        holder: "TELSTRA LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 444_500_000,
        to: 444_599_999,
        spare: false,
        allocatee: "TELSTRA LIMITED",
        allocated: "2017-09-08",
        holder: "TELSTRA LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 444_600_000,
        to: 446_999_999,
        spare: true,
        allocatee: "",
        allocated: "",
        holder: "",
        transferred: "",
    },
    AuMobileBlock {
        from: 447_000_000,
        to: 447_999_999,
        spare: false,
        allocatee: "TELSTRA LIMITED",
        allocated: "2006-12-12",
        holder: "TELSTRA LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 448_000_000,
        to: 448_999_999,
        spare: false,
        allocatee: "TELSTRA LIMITED",
        allocated: "2004-07-27",
        holder: "TELSTRA LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 449_000_000,
        to: 449_299_999,
        spare: false,
        allocatee: "VODAFONE NETWORK PTY LIMITED",
        allocated: "2006-07-28",
        holder: "VODAFONE AUSTRALIA PTY LIMITED",
        transferred: "2007-02-07",
    },
    AuMobileBlock {
        from: 449_300_000,
        to: 449_499_999,
        spare: true,
        allocatee: "",
        allocated: "",
        holder: "",
        transferred: "",
    },
    AuMobileBlock {
        from: 449_500_000,
        to: 449_999_999,
        spare: false,
        allocatee: "VODAFONE NETWORK PTY LIMITED",
        allocated: "2006-07-28",
        holder: "VODAFONE AUSTRALIA PTY LIMITED",
        transferred: "2007-02-07",
    },
    AuMobileBlock {
        from: 450_000_000,
        to: 450_999_999,
        spare: false,
        allocatee: "VODAFONE AUSTRALIA PTY LIMITED",
        allocated: "2007-06-22",
        holder: "VODAFONE AUSTRALIA PTY LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 451_000_000,
        to: 451_999_999,
        spare: false,
        allocatee: "VODAFONE AUSTRALIA PTY LIMITED",
        allocated: "2008-06-05",
        holder: "VODAFONE AUSTRALIA PTY LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 452_000_000,
        to: 452_699_999,
        spare: false,
        allocatee: "VODAFONE AUSTRALIA PTY LIMITED",
        allocated: "2010-08-11",
        holder: "VODAFONE AUSTRALIA PTY LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 452_700_000,
        to: 452_919_999,
        spare: true,
        allocatee: "",
        allocated: "",
        holder: "",
        transferred: "",
    },
    AuMobileBlock {
        from: 452_920_000,
        to: 452_929_999,
        spare: false,
        allocatee: "NETSIP PTY LTD",
        allocated: "2023-05-24",
        holder: "NETSIP PTY LTD",
        transferred: "",
    },
    AuMobileBlock {
        from: 452_930_000,
        to: 454_499_999,
        spare: true,
        allocatee: "",
        allocated: "",
        holder: "",
        transferred: "",
    },
    AuMobileBlock {
        from: 454_500_000,
        to: 454_999_999,
        spare: false,
        allocatee: "TELSTRA LIMITED",
        allocated: "2025-06-12",
        holder: "TELSTRA LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 455_000_000,
        to: 456_999_999,
        spare: false,
        allocatee: "TELSTRA LIMITED",
        allocated: "2012-06-18",
        holder: "TELSTRA LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 457_000_000,
        to: 457_999_999,
        spare: false,
        allocatee: "TELSTRA LIMITED",
        allocated: "2009-05-06",
        holder: "TELSTRA LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 458_000_000,
        to: 458_999_999,
        spare: false,
        allocatee: "TELSTRA LIMITED",
        allocated: "2007-09-11",
        holder: "TELSTRA LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 459_000_000,
        to: 459_299_999,
        spare: false,
        allocatee: "TELSTRA LIMITED",
        allocated: "2009-05-06",
        holder: "TELSTRA LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 459_300_000,
        to: 459_999_999,
        spare: false,
        allocatee: "TELSTRA LIMITED",
        allocated: "2010-02-11",
        holder: "TELSTRA LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 460_000_000,
        to: 460_999_999,
        spare: false,
        allocatee: "TELSTRA LIMITED",
        allocated: "2018-12-11",
        holder: "TELSTRA LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 461_000_000,
        to: 461_999_999,
        spare: false,
        allocatee: "TELSTRA LIMITED",
        allocated: "2022-08-16",
        holder: "TELSTRA LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 462_000_000,
        to: 462_999_999,
        spare: false,
        allocatee: "TELSTRA LIMITED",
        allocated: "2023-08-21",
        holder: "TELSTRA LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 463_000_000,
        to: 463_999_999,
        spare: false,
        allocatee: "TELSTRA LIMITED",
        allocated: "2023-12-20",
        holder: "TELSTRA LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 464_000_000,
        to: 465_999_999,
        spare: false,
        allocatee: "TELSTRA LIMITED",
        allocated: "2024-04-12",
        holder: "TELSTRA LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 466_000_000,
        to: 466_299_999,
        spare: false,
        allocatee: "OPTUS MOBILE PTY LIMITED",
        allocated: "2007-10-29",
        holder: "OPTUS MOBILE PTY LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 466_300_000,
        to: 466_699_999,
        spare: false,
        allocatee: "OPTUS MOBILE PTY LIMITED",
        allocated: "2008-02-14",
        holder: "OPTUS MOBILE PTY LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 466_700_000,
        to: 466_999_999,
        spare: false,
        allocatee: "OPTUS MOBILE PTY LIMITED",
        allocated: "2009-10-01",
        holder: "OPTUS MOBILE PTY LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 467_000_000,
        to: 467_999_999,
        spare: false,
        allocatee: "TELSTRA LIMITED",
        allocated: "2010-06-01",
        holder: "TELSTRA LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 468_000_000,
        to: 468_099_999,
        spare: false,
        allocatee: "OPTUS NETWORKS PTY LIMITED",
        allocated: "2025-02-07",
        holder: "OPTUS MOBILE PTY LIMITED",
        transferred: "2025-04-29",
    },
    AuMobileBlock {
        from: 468_100_000,
        to: 468_199_999,
        spare: false,
        allocatee: "PIVOTEL SATELLITE PTY LIMITED",
        allocated: "2025-06-26",
        holder: "PIVOTEL SATELLITE PTY LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 468_200_000,
        to: 468_299_999,
        spare: false,
        allocatee: "PIVOTEL SATELLITE PTY LIMITED",
        allocated: "2025-10-01",
        holder: "PIVOTEL SATELLITE PTY LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 468_300_000,
        to: 468_499_999,
        spare: false,
        allocatee: "OPTUS MOBILE PTY LIMITED",
        allocated: "2010-08-18",
        holder: "OPTUS MOBILE PTY LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 468_500_000,
        to: 468_999_999,
        spare: false,
        allocatee: "OPTUS MOBILE PTY LIMITED",
        allocated: "2009-07-15",
        holder: "OPTUS MOBILE PTY LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 469_000_000,
        to: 469_199_999,
        spare: false,
        allocatee: "LYCAMOBILE PTY LTD",
        allocated: "2010-03-01",
        holder: "LYCAMOBILE PTY LTD",
        transferred: "",
    },
    AuMobileBlock {
        from: 469_200_000,
        to: 469_449_999,
        spare: false,
        allocatee: "LYCAMOBILE PTY LTD",
        allocated: "2010-05-26",
        holder: "LYCAMOBILE PTY LTD",
        transferred: "",
    },
    AuMobileBlock {
        from: 469_450_000,
        to: 469_539_999,
        spare: true,
        allocatee: "",
        allocated: "",
        holder: "",
        transferred: "",
    },
    AuMobileBlock {
        from: 469_540_000,
        to: 469_999_999,
        spare: false,
        allocatee: "LYCAMOBILE PTY LTD",
        allocated: "2010-08-05",
        holder: "LYCAMOBILE PTY LTD",
        transferred: "",
    },
    AuMobileBlock {
        from: 470_000_000,
        to: 470_789_999,
        spare: false,
        allocatee: "LYCAMOBILE PTY LTD",
        allocated: "2011-02-09",
        holder: "LYCAMOBILE PTY LTD",
        transferred: "",
    },
    AuMobileBlock {
        from: 470_790_000,
        to: 472_499_999,
        spare: true,
        allocatee: "",
        allocated: "",
        holder: "",
        transferred: "",
    },
    AuMobileBlock {
        from: 472_500_000,
        to: 472_999_999,
        spare: false,
        allocatee: "TELSTRA LIMITED",
        allocated: "2015-07-01",
        holder: "TELSTRA LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 473_000_000,
        to: 473_999_999,
        spare: false,
        allocatee: "TELSTRA LIMITED",
        allocated: "2014-04-14",
        holder: "TELSTRA LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 474_000_000,
        to: 475_999_999,
        spare: false,
        allocatee: "TELSTRA LIMITED",
        allocated: "2013-05-10",
        holder: "TELSTRA LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 476_000_000,
        to: 476_999_999,
        spare: false,
        allocatee: "TELSTRA LIMITED",
        allocated: "2014-04-14",
        holder: "TELSTRA LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 477_000_000,
        to: 477_999_999,
        spare: false,
        allocatee: "TELSTRA LIMITED",
        allocated: "2011-02-11",
        holder: "TELSTRA LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 478_000_000,
        to: 479_199_999,
        spare: false,
        allocatee: "OPTUS MOBILE PTY LIMITED",
        allocated: "2010-08-19",
        holder: "OPTUS MOBILE PTY LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 479_200_000,
        to: 479_999_999,
        spare: true,
        allocatee: "",
        allocated: "",
        holder: "",
        transferred: "",
    },
    AuMobileBlock {
        from: 480_000_000,
        to: 480_099_999,
        spare: false,
        allocatee: "PIVOTEL SATELLITE PTY LIMITED",
        allocated: "2018-04-26",
        holder: "PIVOTEL SATELLITE PTY LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 480_100_000,
        to: 480_199_999,
        spare: false,
        allocatee: "TELSTRA LIMITED",
        allocated: "2018-08-14",
        holder: "TELSTRA LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 480_200_000,
        to: 480_299_999,
        spare: false,
        allocatee: "TELSTRA LIMITED",
        allocated: "2019-04-30",
        holder: "TELSTRA LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 480_300_000,
        to: 480_399_999,
        spare: false,
        allocatee: "TELSTRA LIMITED",
        allocated: "2020-11-18",
        holder: "TELSTRA LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 480_400_000,
        to: 480_499_999,
        spare: false,
        allocatee: "TELSTRA LIMITED",
        allocated: "2022-02-08",
        holder: "TELSTRA LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 480_500_000,
        to: 480_599_999,
        spare: false,
        allocatee: "TELSTRA LIMITED",
        allocated: "2022-12-06",
        holder: "TELSTRA LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 480_600_000,
        to: 480_799_999,
        spare: false,
        allocatee: "TELSTRA LIMITED",
        allocated: "2023-08-28",
        holder: "TELSTRA LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 480_800_000,
        to: 480_899_999,
        spare: false,
        allocatee: "PIVOTEL SATELLITE PTY LIMITED",
        allocated: "2018-02-20",
        holder: "PIVOTEL SATELLITE PTY LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 480_900_000,
        to: 480_999_999,
        spare: true,
        allocatee: "",
        allocated: "",
        holder: "",
        transferred: "",
    },
    AuMobileBlock {
        from: 481_000_000,
        to: 482_099_999,
        spare: false,
        allocatee: "OPTUS MOBILE PTY LIMITED",
        allocated: "2012-05-29",
        holder: "OPTUS MOBILE PTY LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 482_100_000,
        to: 482_199_999,
        spare: false,
        allocatee: "OPTUS NETWORKS PTY LIMITED",
        allocated: "2019-04-30",
        holder: "OPTUS MOBILE PTY LIMITED",
        transferred: "2021-03-18",
    },
    AuMobileBlock {
        from: 482_200_000,
        to: 482_399_999,
        spare: false,
        allocatee: "OPTUS MOBILE PTY LIMITED",
        allocated: "2023-04-03",
        holder: "OPTUS MOBILE PTY LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 482_400_000,
        to: 483_399_999,
        spare: false,
        allocatee: "TELSTRA LIMITED",
        allocated: "2019-06-11",
        holder: "TELSTRA LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 483_400_000,
        to: 483_599_999,
        spare: true,
        allocatee: "",
        allocated: "",
        holder: "",
        transferred: "",
    },
    AuMobileBlock {
        from: 483_600_000,
        to: 483_799_999,
        spare: false,
        allocatee: "TELSTRA LIMITED",
        allocated: "2025-09-15",
        holder: "TELSTRA LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 483_800_000,
        to: 483_899_999,
        spare: false,
        allocatee: "TELSTRA LIMITED",
        allocated: "2020-01-08",
        holder: "TELSTRA LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 483_900_000,
        to: 483_999_999,
        spare: false,
        allocatee: "OPTUS MOBILE PTY LIMITED",
        allocated: "2022-04-08",
        holder: "OPTUS MOBILE PTY LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 484_000_000,
        to: 484_999_999,
        spare: false,
        allocatee: "TELSTRA LIMITED",
        allocated: "2014-12-15",
        holder: "TELSTRA LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 485_000_000,
        to: 485_099_999,
        spare: false,
        allocatee: "OPTUS NETWORKS PTY LIMITED",
        allocated: "2025-03-03",
        holder: "OPTUS MOBILE PTY LIMITED",
        transferred: "2025-04-29",
    },
    AuMobileBlock {
        from: 485_100_000,
        to: 485_769_999,
        spare: false,
        allocatee: "OPTUS NETWORKS PTY LIMITED",
        allocated: "2025-04-17",
        holder: "OPTUS MOBILE PTY LIMITED",
        transferred: "2025-04-29",
    },
    AuMobileBlock {
        from: 485_770_000,
        to: 485_799_999,
        spare: true,
        allocatee: "",
        allocated: "",
        holder: "",
        transferred: "",
    },
    AuMobileBlock {
        from: 485_800_000,
        to: 485_899_999,
        spare: false,
        allocatee: "TRAVELSIM AUSTRALIA PTY LTD",
        allocated: "2017-02-14",
        holder: "PIVOTEL SATELLITE PTY LIMITED",
        transferred: "2017-02-16",
    },
    AuMobileBlock {
        from: 485_900_000,
        to: 485_999_999,
        spare: false,
        allocatee: "PIVOTEL SATELLITE PTY LIMITED",
        allocated: "2023-05-12",
        holder: "PIVOTEL SATELLITE PTY LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 486_000_000,
        to: 486_999_999,
        spare: false,
        allocatee: "TELSTRA LIMITED",
        allocated: "2020-04-07",
        holder: "TELSTRA LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 487_000_000,
        to: 487_999_999,
        spare: false,
        allocatee: "TELSTRA LIMITED",
        allocated: "2010-06-01",
        holder: "TELSTRA LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 488_000_000,
        to: 488_799_999,
        spare: false,
        allocatee: "TELSTRA LIMITED",
        allocated: "2006-12-12",
        holder: "TELSTRA LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 488_800_000,
        to: 488_899_999,
        spare: false,
        allocatee: "MY NUMBER PTY LTD",
        allocated: "2009-08-18",
        holder: "PIVOTEL SATELLITE PTY LIMITED",
        transferred: "2015-05-15",
    },
    AuMobileBlock {
        from: 488_900_000,
        to: 488_999_999,
        spare: false,
        allocatee: "TELSTRA LIMITED",
        allocated: "2006-12-12",
        holder: "TELSTRA LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 489_000_000,
        to: 489_349_999,
        spare: false,
        allocatee: "OPTUS NETWORKS PTY LIMITED",
        allocated: "2024-07-15",
        holder: "OPTUS MOBILE PTY LIMITED",
        transferred: "2025-04-29",
    },
    AuMobileBlock {
        from: 489_350_000,
        to: 489_839_999,
        spare: true,
        allocatee: "",
        allocated: "",
        holder: "",
        transferred: "",
    },
    AuMobileBlock {
        from: 489_840_000,
        to: 489_849_999,
        spare: false,
        allocatee: "VICTORIAN RAIL TRACK",
        allocated: "2009-07-07",
        holder: "VICTORIAN RAIL TRACK",
        transferred: "",
    },
    AuMobileBlock {
        from: 489_850_000,
        to: 489_899_999,
        spare: true,
        allocatee: "",
        allocated: "",
        holder: "",
        transferred: "",
    },
    AuMobileBlock {
        from: 489_900_000,
        to: 489_999_999,
        spare: false,
        allocatee: "TRAVELSIM AUSTRALIA PTY LTD",
        allocated: "2015-06-02",
        holder: "PIVOTEL SATELLITE PTY LIMITED",
        transferred: "2015-09-16",
    },
    AuMobileBlock {
        from: 490_000_000,
        to: 490_099_999,
        spare: false,
        allocatee: "TELSTRA LIMITED",
        allocated: "2012-05-29",
        holder: "TELSTRA LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 490_100_000,
        to: 490_399_999,
        spare: false,
        allocatee: "TELSTRA LIMITED",
        allocated: "2012-09-17",
        holder: "TELSTRA LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 490_400_000,
        to: 490_999_999,
        spare: false,
        allocatee: "TELSTRA LIMITED",
        allocated: "2013-04-11",
        holder: "TELSTRA LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 491_000_000,
        to: 491_499_999,
        spare: false,
        allocatee: "TELSTRA LIMITED",
        allocated: "2014-04-16",
        holder: "TELSTRA LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 491_500_000,
        to: 491_509_999,
        spare: false,
        allocatee: "BIRD.COM PTY LTD",
        allocated: "2018-06-28",
        holder: "BIRD.COM PTY LTD",
        transferred: "",
    },
    AuMobileBlock {
        from: 491_510_000,
        to: 491_519_999,
        spare: false,
        allocatee: "BIRD.COM PTY LTD",
        allocated: "2017-05-23",
        holder: "BIRD.COM PTY LTD",
        transferred: "",
    },
    AuMobileBlock {
        from: 491_520_000,
        to: 491_569_999,
        spare: true,
        allocatee: "",
        allocated: "",
        holder: "",
        transferred: "",
    },
    AuMobileBlock {
        from: 491_570_000,
        to: 491_579_999,
        spare: false,
        allocatee: "AUSTRALIAN COMMUNICATIONS AND MEDIA AUTHORITY",
        allocated: "2015-07-31",
        holder: "AUSTRALIAN COMMUNICATIONS AND MEDIA AUTHORITY",
        transferred: "",
    },
    AuMobileBlock {
        from: 491_580_000,
        to: 491_599_999,
        spare: true,
        allocatee: "",
        allocated: "",
        holder: "",
        transferred: "",
    },
    AuMobileBlock {
        from: 491_600_000,
        to: 491_799_999,
        spare: false,
        allocatee: "TELSTRA LIMITED",
        allocated: "2018-06-01",
        holder: "TELSTRA LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 491_800_000,
        to: 492_799_999,
        spare: false,
        allocatee: "TELSTRA LIMITED",
        allocated: "2019-08-02",
        holder: "TELSTRA LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 492_800_000,
        to: 492_999_999,
        spare: false,
        allocatee: "TELSTRA LIMITED",
        allocated: "2019-08-05",
        holder: "TELSTRA LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 493_000_000,
        to: 493_199_999,
        spare: false,
        allocatee: "TELSTRA LIMITED",
        allocated: "2020-02-03",
        holder: "TELSTRA LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 493_200_000,
        to: 493_499_999,
        spare: false,
        allocatee: "TELSTRA LIMITED",
        allocated: "2020-04-24",
        holder: "TELSTRA LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 493_500_000,
        to: 493_699_999,
        spare: false,
        allocatee: "TELSTRA LIMITED",
        allocated: "2021-08-31",
        holder: "TELSTRA LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 493_700_000,
        to: 493_899_999,
        spare: false,
        allocatee: "TELSTRA LIMITED",
        allocated: "2022-11-10",
        holder: "TELSTRA LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 493_900_000,
        to: 494_199_999,
        spare: false,
        allocatee: "TELSTRA LIMITED",
        allocated: "2023-04-18",
        holder: "TELSTRA LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 494_200_000,
        to: 494_499_999,
        spare: false,
        allocatee: "TELSTRA LIMITED",
        allocated: "2024-04-17",
        holder: "TELSTRA LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 494_500_000,
        to: 494_999_999,
        spare: false,
        allocatee: "TELSTRA LIMITED",
        allocated: "2025-05-06",
        holder: "TELSTRA LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 495_000_000,
        to: 495_079_999,
        spare: false,
        allocatee: "OPTUS MOBILE PTY LIMITED",
        allocated: "2025-10-29",
        holder: "OPTUS MOBILE PTY LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 495_080_000,
        to: 495_349_999,
        spare: false,
        allocatee: "OPTUS MOBILE PTY LIMITED",
        allocated: "2026-04-13",
        holder: "OPTUS MOBILE PTY LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 495_350_000,
        to: 495_999_999,
        spare: true,
        allocatee: "",
        allocated: "",
        holder: "",
        transferred: "",
    },
    AuMobileBlock {
        from: 496_000_000,
        to: 496_499_999,
        spare: false,
        allocatee: "TELSTRA LIMITED",
        allocated: "2026-10-08",
        holder: "TELSTRA LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 496_500_000,
        to: 496_999_999,
        spare: true,
        allocatee: "",
        allocated: "",
        holder: "",
        transferred: "",
    },
    AuMobileBlock {
        from: 497_000_000,
        to: 497_999_999,
        spare: false,
        allocatee: "TELSTRA LIMITED",
        allocated: "2012-06-18",
        holder: "TELSTRA LIMITED",
        transferred: "",
    },
    AuMobileBlock {
        from: 498_000_000,
        to: 499_999_999,
        spare: false,
        allocatee: "TELSTRA LIMITED",
        allocated: "2011-08-08",
        holder: "TELSTRA LIMITED",
        transferred: "",
    },
];

/// The register block holding an Australian mobile number, in any of the forms
/// [`au_phone_line_type`] reads (`0405 491 450`, `+61 405 491 450`, `0061…`), or `None` for a
/// number that is not a ten-digit `04` mobile. **Pure.**
#[must_use]
pub fn au_mobile_block(value: &str) -> Option<&'static AuMobileBlock> {
    let plus = value.contains('+');
    let digits = textnorm::ascii_digits(value);
    let national = if let Some(rest) = digits.strip_prefix("0061") {
        rest
    } else if plus {
        digits.strip_prefix("61")?
    } else {
        digits.as_str()
    };
    let national = national.trim_start_matches('0');
    if national.len() != 9 || !national.starts_with('4') {
        return None;
    }
    let number: u32 = national.parse().ok()?;
    let at = AU_MOBILE_BLOCKS.partition_point(|block| block.to < number);
    AU_MOBILE_BLOCKS
        .get(at)
        .filter(|block| block.from <= number && number <= block.to)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_mobile_register_is_contiguous_over_the_04_range_and_reads_every_form() {
        assert_eq!(AU_MOBILE_BLOCKS.first().map(|b| b.from), Some(400_000_000));
        assert_eq!(AU_MOBILE_BLOCKS.last().map(|b| b.to), Some(499_999_999));
        for pair in AU_MOBILE_BLOCKS.windows(2) {
            assert_eq!(pair[0].to + 1, pair[1].from, "{:?}", pair[0].range());
        }
        assert_eq!(AU_MOBILE_BLOCKS.iter().filter(|b| b.spare).count(), 19);
        for b in AU_MOBILE_BLOCKS {
            assert_eq!(
                b.spare,
                b.holder.is_empty() && b.allocatee.is_empty(),
                "{}",
                b.range()
            );
        }
        // The register row for 0405 491 450, as published: allocated to Vodafone Network on
        // 1999-11-09, held by Vodafone Australia since the 2007-02-07 transfer.
        for form in [
            "0405 491 450",
            "+61 405 491 450",
            "0061405491450",
            "0405491450",
        ] {
            let block = au_mobile_block(form).expect(form);
            assert_eq!(block.range(), "0405000000-0405999999");
            assert_eq!(block.allocatee, "VODAFONE NETWORK PTY LIMITED");
            assert_eq!(block.allocated, "1999-11-09");
            assert_eq!(block.holder, "VODAFONE AUSTRALIA PTY LIMITED");
            assert_eq!(block.transferred, "2007-02-07");
            assert!(!block.spare);
        }
        let spare = au_mobile_block("0444 000 000").expect("a spare block is still a block");
        assert!(spare.spare && spare.holder.is_empty());
        assert_eq!(
            au_mobile_block("0400000000").map(|b| b.holder),
            Some("TELSTRA LIMITED")
        );
        assert_eq!(
            au_mobile_block("0499999999").map(|b| b.holder),
            Some("TELSTRA LIMITED")
        );
        for not_mobile in [
            "02 9876 5432",
            "1800 123 456",
            "+1 416 555 0199",
            "040549145",
            "05 0549 1450",
        ] {
            assert!(au_mobile_block(not_mobile).is_none(), "{not_mobile}");
        }
    }

    fn extract_first(text: &str) -> Option<AuAddress> {
        extract_all(text).into_iter().next()
    }

    #[test]
    fn address_parser_keeps_structure_and_plausibility() {
        let addr =
            extract_first("Our office is at Level 11, 133 Mary Street, Brisbane City QLD 4000")
                .expect("address");
        assert_eq!(addr.level.as_deref(), Some("Level 11"));
        assert_eq!(addr.street_number, "133");
        assert_eq!(addr.street, "Mary Street");
        assert_eq!(addr.suburb, "Brisbane City");
        assert_eq!(addr.state, "QLD");
        assert_eq!(addr.postcode, "4000");
        assert!(addr.confidence() >= 0.80);
        assert!(extract_first("1 George Street, Sydney NSW 3000").is_none());
        assert!(
            extract_first(
                "please call me back in 42 minutes about the close matter brisbane qld 4000"
            )
            .is_none()
        );
    }

    #[test]
    fn state_and_locality_helpers_match_contract() {
        assert_eq!(state_for_postcode("2600"), Some("ACT"));
        assert_eq!(state_for_postcode("0800"), Some("NT"));
        assert_eq!(
            state_code("NT LOGISTICS PTY LTD, 100 COLLINS ST, MELBOURNE VIC 3000"),
            Some("VIC")
        );
        assert_eq!(
            state_code("5528 North 73rd Avenue, Glendale, AZ, 85303, US"),
            None
        );
        assert_eq!(
            locality_key("Kuraby, QLD"),
            locality_key("Kuraby, Queensland")
        );
        assert_ne!(
            locality_key("12 Main St, Brisbane QLD"),
            locality_key("99 Main St, Brisbane QLD")
        );
    }

    #[test]
    fn phone_helpers_cover_au_classes() {
        assert_eq!(
            normalise_phone("0410 959 140").as_deref(),
            Some("+61410959140")
        );
        assert_eq!(
            normalise_phone("61412345678").as_deref(),
            Some("+61412345678")
        );
        assert_eq!(normalise_phone("0612345678"), None);
        assert_eq!(
            au_phone_region("+61 2 9876 5432"),
            Some(("central-east", "Central East", &["NSW", "ACT"][..]))
        );
        assert_eq!(
            au_phone_line_type("13 11 14").expect("13xxxx").0,
            AuLineType::LocalRate
        );
        assert!(au_phone_line_type("+1 800 555 1234").is_none());
        assert!(
            extract_phones("Call 0410 959 140 or 1800 123 456")
                .contains(&"+61410959140".to_string())
        );
    }

    #[test]
    fn au_domain_and_network_helpers_work() {
        assert_eq!(au_gov_domain_state("transport.vic.gov.au"), Some("VIC"));
        assert_eq!(au_edu_domain_state("eq.edu.au"), Some("QLD"));
        assert_eq!(
            au_domain_registrant("mail.acme.net.au").map(|(kind, _)| kind),
            Some("commercial")
        );
        assert_eq!(
            au_network_operator_split("ASN-TELSTRA", "Telstra Limited"),
            Some(("Telstra", AuNetworkKind::Consumer))
        );
        assert_eq!(
            au_network_operator_split("", "AS1221 Telstra Corporation"),
            Some(("Telstra", AuNetworkKind::Consumer))
        );
        assert_eq!(
            au_network_operator_split("", "address space that used to belong to acme"),
            None
        );
        assert_eq!(
            au_network_operator_split("Belong Internet Pty Ltd", ""),
            Some(("Belong", AuNetworkKind::Consumer))
        );
    }

    #[test]
    fn postcode_boundary_predicate_uses_authoritative_ranges() {
        let any = |s: &str| {
            let bytes = s.as_bytes();
            (0..bytes.len().saturating_sub(3)).any(|idx| is_standalone_postcode_at(bytes, idx))
        };
        assert!(any("Bondi Beach 2026 NSW"));
        assert!(any("Canberra 0200"));
        assert!(any("Darwin NT 0800"));
        assert!(!any("20267"));
        assert!(!any("12026"));
    }
}
