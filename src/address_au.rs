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
pub fn single_state_code(text: &str) -> Option<&'static str> {
    let lowered = text.to_ascii_lowercase();
    let names = STATE_NAMES
        .iter()
        .filter(|(name, _)| lowered.contains(name))
        .map(|(_, code)| *code);
    let mut found = None;
    for code in state_abbrev_tokens(text).chain(names) {
        match found {
            Some(prev) if prev != code => return None,
            _ => found = Some(code),
        }
    }
    found
}

#[must_use]
pub fn normalise_phone(s: &str) -> Option<String> {
    let digits = textnorm::ascii_digits_and_plus(s);
    let validated = |candidate: String| {
        crate::value_syntax::phone_e164_error(&candidate)
            .is_none()
            .then_some(candidate)
    };
    if digits.starts_with("+61") {
        return validated(digits);
    }
    if digits.starts_with("0061") {
        return validated(format!("+{}", &digits[2..]));
    }
    if let Some(national) = digits.strip_prefix("61").filter(|national| {
        national.len() == 9
            && matches!(
                national.as_bytes()[0],
                b'2' | b'3' | b'4' | b'5' | b'7' | b'8'
            )
    }) {
        return validated(format!("+61{national}"));
    }
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
        && matches!(
            digits.as_bytes()[0],
            b'2' | b'3' | b'4' | b'5' | b'7' | b'8'
        )
    {
        return validated(format!("+61{digits}"));
    }
    if digits.len() == 10 && (digits.starts_with("1300") || digits.starts_with("1800")) {
        return validated(format!("+61{digits}"));
    }
    None
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

    #[must_use]
    pub fn is_business_service(self) -> bool {
        matches!(self, Self::Freephone | Self::LocalRate | Self::Premium)
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

#[must_use]
pub fn au_network_operator(haystack: &str) -> Option<(&'static str, AuNetworkKind)> {
    au_network_operator_in(haystack, true)
}

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

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(single_state_code("Sydney / NSW / ACT"), None);
        assert_eq!(single_state_code("Melbourne / VIC"), Some("VIC"));
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
            au_network_operator("AS1221 Telstra Corporation"),
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
