//! Pure validation helpers rebuilt from `core/validation` and related utility code.

use crate::textnorm::ascii_digits_and_plus;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ValidationReport {
    pub valid: bool,
    pub reason: &'static str,
    pub detail: String,
}

impl ValidationReport {
    #[must_use]
    pub fn ok() -> Self {
        Self {
            valid: true,
            reason: "",
            detail: String::new(),
        }
    }

    #[must_use]
    pub fn fail(reason: &'static str, detail: impl Into<String>) -> Self {
        Self {
            valid: false,
            reason,
            detail: detail.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueKind {
    Domain,
    Email,
    Url,
    Username,
    Person,
    Address,
    Password,
    ApiKey,
    Credential,
}

const RESERVED_PLACEHOLDER_TLDS: &[&str] = &["example", "invalid", "localhost", "local", "test"];

#[must_use]
pub fn validate_email_syntax(s: &str) -> ValidationReport {
    let Some((local, domain)) = s.split_once('@') else {
        return ValidationReport::fail("email.bad_at_count", "expected exactly one '@'");
    };
    if domain.contains('@') {
        return ValidationReport::fail("email.bad_at_count", "expected exactly one '@'");
    }
    let local_error = crate::value_syntax::email_local_error(local);
    if local_error == Some(crate::value_syntax::EmailLocalError::Length) {
        return ValidationReport::fail("email.local_length", "local part 1..=64 chars");
    }
    if domain.is_empty() || !domain.contains('.') {
        return ValidationReport::fail("email.domain_shape", "domain must contain '.'");
    }
    if local_error == Some(crate::value_syntax::EmailLocalError::DotEdge) {
        return ValidationReport::fail("email.local_dot_edge", "leading/trailing '.' in local");
    }
    if domain.starts_with('.') || domain.ends_with('.') {
        return ValidationReport::fail("email.domain_dot_edge", "leading/trailing '.' in domain");
    }
    if local_error == Some(crate::value_syntax::EmailLocalError::ConsecutiveDots)
        || domain.contains("..")
    {
        return ValidationReport::fail("email.consecutive_dots", "consecutive '.' forbidden");
    }
    ValidationReport::ok()
}

#[must_use]
pub fn validate_phone_e164(s: &str) -> ValidationReport {
    match crate::value_syntax::phone_e164_error(s) {
        None => ValidationReport::ok(),
        Some(crate::value_syntax::PhoneE164Error::MissingPlus) => {
            ValidationReport::fail("e164.missing_plus", "must start with '+'")
        }
        Some(crate::value_syntax::PhoneE164Error::NonDigit) => {
            ValidationReport::fail("e164.non_digit", "non-digit after '+'")
        }
        Some(crate::value_syntax::PhoneE164Error::CountryCodeLeadingZero) => {
            ValidationReport::fail("e164.cc_leading_zero", "country code cannot start with 0")
        }
        Some(crate::value_syntax::PhoneE164Error::Length(length)) => ValidationReport::fail(
            "e164.length",
            format!("expected 10..=15 digits, got {length}"),
        ),
    }
}

/// Scan a blob for E.164 numbers. Returns `true` when `cap` was reached.
pub fn scan_phones(text: &str, cap: usize, mut collect: impl FnMut(String)) -> bool {
    let bytes = text.as_bytes();
    let mut cursor = 0usize;
    let mut count = 0usize;
    while cursor < bytes.len() {
        if bytes[cursor] == b'+'
            && cursor + 10 < bytes.len()
            && matches!(bytes[cursor + 1], b'1'..=b'9')
        {
            let start = cursor;
            cursor += 1;
            let mut digits = 0u32;
            while cursor < bytes.len()
                && (bytes[cursor].is_ascii_digit()
                    || matches!(bytes[cursor], b'-' | b' ' | b'(' | b')'))
            {
                if bytes[cursor].is_ascii_digit() {
                    digits += 1;
                }
                cursor += 1;
            }
            if (10..=15).contains(&digits) {
                let cleaned = ascii_digits_and_plus(&text[start..cursor]);
                if validate_phone_e164(&cleaned).valid {
                    collect(cleaned);
                    count += 1;
                    if count >= cap {
                        return true;
                    }
                }
            }
        } else {
            cursor += 1;
        }
    }
    false
}

#[inline]
fn normalized_ascii_alnum_eq(input: &str, expected: &str) -> bool {
    input
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .eq(expected.chars())
}

#[must_use]
pub fn is_placeholder_domain(host: &str) -> bool {
    let lowered = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let host = lowered.strip_prefix("www.").unwrap_or(lowered.as_str());
    if host.is_empty() {
        return true;
    }
    if host
        .rsplit('.')
        .next()
        .is_some_and(|last| RESERVED_PLACEHOLDER_TLDS.contains(&last))
    {
        return true;
    }
    host.split('.').any(|label| label == "example")
        || matches!(
            host,
            "domain.tld" | "host.tld" | "yourdomain.com" | "yourdomain.tld" | "mydomain.com"
        )
        || host.rsplit('.').next().is_some_and(|tld| tld == "tld")
}

#[must_use]
pub fn is_whois_privacy_placeholder(s: &str) -> bool {
    crate::value_syntax::is_whois_privacy_placeholder(s)
}

#[must_use]
pub fn is_username_derived_name(name: &str) -> bool {
    let mut parts = name.split_whitespace();
    if matches!(
        (parts.next(), parts.next(), parts.next()),
        (Some(first), Some(second), None) if first.eq_ignore_ascii_case(second)
    ) {
        return true;
    }
    name.split_whitespace()
        .any(|token| token.contains('-') && token.bytes().any(|b| b.is_ascii_digit()))
}

fn is_placeholder_person(name: &str) -> bool {
    matches!(
        name.trim().to_ascii_lowercase().as_str(),
        "john doe"
            | "jane doe"
            | "john q. public"
            | "john q public"
            | "test user"
            | "first last"
            | "firstname lastname"
            | "first name last name"
            | "full name"
            | "your name"
            | "name surname"
    )
}

fn is_placeholder_email_local(local: &str) -> bool {
    const TEMPLATE: &[&str] = &[
        "firstname",
        "lastname",
        "firstnamelastname",
        "firstlast",
        "namesurname",
        "yourname",
        "fullname",
        "youremail",
        "emailaddress",
        "yourusername",
        "johndoe",
        "janedoe",
        "example",
        "sample",
        "test",
        "redacted",
        "placeholder",
    ];
    TEMPLATE.iter().any(|template| {
        local.eq_ignore_ascii_case(template) || normalized_ascii_alnum_eq(local, template)
    })
}

fn url_host_is_placeholder(url: &str) -> bool {
    let host = crate::value_syntax::host_only(url);
    !host.is_empty() && is_placeholder_domain(host)
}

#[must_use]
pub fn is_placeholder_entity(kind: &ValueKind, value: &str) -> bool {
    if matches!(
        kind,
        ValueKind::Password | ValueKind::ApiKey | ValueKind::Credential | ValueKind::Address
    ) {
        return false;
    }
    match kind {
        ValueKind::Domain => is_placeholder_domain(value),
        ValueKind::Email => value.rsplit_once('@').is_some_and(|(local, host)| {
            is_placeholder_domain(host) || is_placeholder_email_local(local)
        }),
        ValueKind::Url => url_host_is_placeholder(value),
        ValueKind::Username => {
            let v = value.trim().to_ascii_lowercase();
            matches!(
                v.as_str(),
                "example" | "redacted" | "placeholder" | "username"
            )
        }
        ValueKind::Person => is_placeholder_person(value),
        ValueKind::Address | ValueKind::Password | ValueKind::ApiKey | ValueKind::Credential => {
            false
        }
    }
}

#[must_use]
pub fn is_specific_residence(s: &str) -> bool {
    let compact: String = s
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect();
    if ["pobox", "gpobox", "lockedbag", "privatebag"]
        .iter()
        .any(|marker| compact.contains(marker))
    {
        return false;
    }
    let tokens = s
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|token| !token.is_empty())
        .count();
    tokens >= 3 && s.bytes().any(|b| b.is_ascii_digit()) && s.trim().len() >= 8
}

#[must_use]
pub fn is_fragment_value(kind: &ValueKind, value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return true;
    }
    if matches!(
        kind,
        ValueKind::Password | ValueKind::ApiKey | ValueKind::Credential
    ) {
        return false;
    }
    if trimmed.ends_with('…') || trimmed.ends_with("...") || trimmed.ends_with('@') {
        return true;
    }
    match kind {
        ValueKind::Email => match trimmed.split_once('@') {
            Some((local, domain)) => {
                local.is_empty() || !domain.contains('.') || domain.starts_with('.')
            }
            None => true,
        },
        ValueKind::Domain => trimmed.len() < 4 || !trimmed.contains('.'),
        ValueKind::Username => trimmed.starts_with('@'),
        ValueKind::Address => {
            !trimmed.chars().any(char::is_alphabetic)
                || (trimmed.len() == 2 && trimmed.bytes().all(|b| b.is_ascii_alphabetic()))
        }
        _ => false,
    }
}

#[allow(clippy::match_same_arms)]
fn skeleton_char(c: char) -> char {
    if ('\u{FF01}'..='\u{FF5E}').contains(&c) {
        let ascii = char::from_u32(c as u32 - 0xFEE0);
        if let Some(ascii) = ascii {
            return ascii;
        }
    }
    match c {
        'а' | 'α' | 'ɑ' => 'a',
        'е' | 'ё' => 'e',
        'о' | 'ο' => 'o',
        'р' | 'ρ' => 'p',
        'с' | 'ϲ' => 'c',
        'х' | 'χ' => 'x',
        'у' => 'y',
        'к' | 'κ' => 'k',
        'м' => 'm',
        'т' | 'τ' => 't',
        'н' => 'h',
        'в' => 'b',
        'і' | 'ι' | 'ⅰ' => 'i',
        'ѕ' => 's',
        'ј' => 'j',
        'ԁ' | 'ⅾ' => 'd',
        'г' => 'r',
        'п' => 'n',
        'ν' | 'ѵ' => 'v',
        'υ' => 'u',
        'ɡ' => 'g',
        'ⅼ' | 'ӏ' => 'l',
        _ => c,
    }
}

#[must_use]
pub fn skeleton(s: &str) -> String {
    s.chars()
        .map(skeleton_char)
        .flat_map(char::to_lowercase)
        .collect()
}

#[must_use]
pub fn homoglyph_skeleton(label: &str) -> String {
    let lowered = label.to_ascii_lowercase();
    let collapsed = lowered.replace("rn", "m").replace("vv", "w");
    collapsed
        .chars()
        .map(|c| match c {
            '0' => 'o',
            '1' | '|' => 'l',
            '3' => 'e',
            '4' | '@' => 'a',
            '5' | '$' => 's',
            '7' => 't',
            other => other,
        })
        .collect()
}

#[must_use]
pub fn levenshtein(a: &str, b: &str) -> usize {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.is_empty() {
        return b.len();
    }
    if b.is_empty() {
        return a.len();
    }
    let mut previous: Vec<usize> = (0..=b.len()).collect();
    let mut current = vec![0usize; b.len() + 1];
    for (i, &left) in a.iter().enumerate() {
        current[0] = i + 1;
        for (j, &right) in b.iter().enumerate() {
            let cost = usize::from(left != right);
            current[j + 1] = (previous[j] + cost)
                .min(previous[j + 1] + 1)
                .min(current[j] + 1);
        }
        std::mem::swap(&mut previous, &mut current);
    }
    previous[b.len()]
}

#[must_use]
pub fn is_lookalike(a: &str, b: &str) -> bool {
    const MIN_LABEL_LEN: usize = 4;
    let a = a.to_ascii_lowercase();
    let b = b.to_ascii_lowercase();
    if a == b || a.len() < MIN_LABEL_LEN || b.len() < MIN_LABEL_LEN {
        return false;
    }
    homoglyph_skeleton(&a) == homoglyph_skeleton(&b) || levenshtein(&a, &b) == 1
}

#[must_use]
pub fn is_confusable_mixed_script(value: &str) -> bool {
    let mut has_ascii_latin = false;
    let mut has_foreign_confusable = false;
    for ch in value.chars() {
        if ch.is_ascii_alphabetic() {
            has_ascii_latin = true;
        } else if !ch.is_ascii() {
            let folded = skeleton_char(ch);
            if folded.is_ascii_alphabetic() && folded != ch {
                has_foreign_confusable = true;
            }
        }
        if has_ascii_latin && has_foreign_confusable {
            return true;
        }
    }
    false
}

#[must_use]
pub fn looks_like_gibberish_name(value: &str) -> bool {
    fn breaks_run(c: char) -> bool {
        !c.is_ascii() || matches!(c.to_ascii_lowercase(), 'a' | 'e' | 'i' | 'o' | 'u' | 'y')
    }
    value.split_whitespace().any(|token| {
        let mut letters = 0usize;
        let mut run = 0usize;
        let mut max_run = 0usize;
        let mut any_break = false;
        for ch in token.chars().filter(|c| c.is_alphabetic()) {
            letters += 1;
            if breaks_run(ch) {
                any_break = true;
                run = 0;
            } else {
                run += 1;
                max_run = max_run.max(run);
            }
        }
        letters >= 6 && (!any_break || max_run >= 6)
    })
}

#[must_use]
pub fn is_onion_url(value: &str) -> bool {
    crate::value_syntax::host_from_url(value)
        .or_else(|| crate::value_syntax::canonical_domain_host(value))
        .is_some_and(|host| {
            host.rsplit('.')
                .next()
                .is_some_and(|suffix| suffix == "onion")
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_placeholder_uses_the_authority_host_only() {
        assert!(!is_placeholder_entity(
            &ValueKind::Url,
            "https://real.org/p?u=a@example.com"
        ));
        assert!(is_placeholder_entity(
            &ValueKind::Url,
            "https://example.com/@someone"
        ));
        assert!(is_placeholder_entity(
            &ValueKind::Url,
            "https://user@example.com/"
        ));
    }

    #[test]
    fn phone_and_email_validation_match_legacy_contract() {
        assert!(validate_phone_e164("+61410959140").valid);
        assert_eq!(
            validate_phone_e164("0410959140").reason,
            "e164.missing_plus"
        );
        assert_eq!(
            validate_phone_e164("+0123456789").reason,
            "e164.cc_leading_zero"
        );
        assert_eq!(
            crate::value_syntax::canonical_phone("0412 345 678").as_deref(),
            Some("+61412345678")
        );
        assert_eq!(
            crate::value_syntax::canonical_phone("+1 555 123 4567").as_deref(),
            Some("+15551234567")
        );
        assert!(validate_email_syntax("a.b+c@example.co.uk").valid);
        assert_eq!(validate_email_syntax("a@b").reason, "email.domain_shape");
        assert!(crate::value_syntax::is_role_localpart("No-Reply+ticket"));
    }

    #[test]
    fn phone_scan_extracts_valid_e164_only() {
        let mut found = Vec::new();
        let truncated = scan_phones(
            "Call +1 (415) 555-2671 or +61 412 345 678, ignore +1234",
            usize::MAX,
            |number| found.push(number),
        );
        assert!(!truncated);
        assert_eq!(found, ["+14155552671", "+61412345678"]);
    }

    #[test]
    fn placeholders_and_fragments_are_caught() {
        assert!(is_placeholder_domain("www.example.com"));
        assert!(is_whois_privacy_placeholder("Domains By Proxy, LLC"));
        assert!(is_username_derived_name("rhino-ryno23 rhino-ryno23"));
        assert!(is_placeholder_entity(
            &ValueKind::Email,
            "firstname@gmail.com"
        ));
        assert!(!is_placeholder_entity(&ValueKind::ApiKey, "sk-example-123"));
        assert!(is_specific_residence("123 Main St, Springfield, IL"));
        assert!(!is_specific_residence("PO Box 123, Sydney NSW 2000"));
        assert!(is_fragment_value(&ValueKind::Email, "x@.com"));
        assert!(is_fragment_value(&ValueKind::Address, "US"));
        assert!(!is_fragment_value(&ValueKind::Password, "@p"));
    }

    #[test]
    fn confusable_and_xml_adjacent_guards_work() {
        assert_eq!(skeleton("pаypal.com"), "paypal.com");
        assert_eq!(homoglyph_skeleton("paypa1"), homoglyph_skeleton("paypal"));
        assert_eq!(levenshtein("kitten", "sitting"), 3);
        assert!(is_lookalike("g00gle", "google"));
        assert!(is_confusable_mixed_script("pаypal.com"));
        assert!(!is_confusable_mixed_script("пример"));
        assert!(looks_like_gibberish_name("GvkJCJRWHWD"));
        assert!(!looks_like_gibberish_name("Nguyễn"));
        assert!(is_onion_url("http://example.onion/login"));
    }
}
