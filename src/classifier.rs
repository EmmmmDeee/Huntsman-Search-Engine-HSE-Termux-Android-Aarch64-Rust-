//! Lightweight offline entity classifier and extractor.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::au_id::{self, Identifier};
use crate::canonical::{
    canonical_domain, canonical_email, canonical_handle, canonical_phone, canonical_url,
};
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance};

pub const ACTIONABLE_FLOOR: f64 = 0.50;

/// Company words. A marker qualifies a name, so it counts only as a whole word, in a value
/// of two or more words.
const COMPANY_WORDS: &[&str] = &[
    "llc",
    "inc",
    "incorporated",
    "corp",
    "corporation",
    "corporate",
    "gmbh",
];

/// Street words, matched the same way as [`COMPANY_WORDS`].
const STREET_WORDS: &[&str] = &["street", "streets", "st", "road", "roads", "rd"];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Classified {
    pub kind: EntityKind,
    pub value: String,
    pub confidence: f64,
    pub signal: &'static str,
}

impl Classified {
    #[must_use]
    pub fn is_actionable(&self) -> bool {
        self.confidence >= ACTIONABLE_FLOOR && self.kind != EntityKind::Other
    }
}

#[must_use]
pub fn classify(raw: &str) -> Classified {
    let value = raw.trim();
    if value.is_empty() {
        return Classified {
            kind: EntityKind::Other,
            value: String::new(),
            confidence: 0.0,
            signal: "empty",
        };
    }
    if let Some(url) = canonical_url(value) {
        return classified(EntityKind::Url, &url, 0.90, "scheme");
    }
    if let Some(email) = canonical_email(value) {
        return classified(EntityKind::Email, &email, 0.85, "rfc-shape");
    }
    if parse_ipv4(value) {
        return classified(EntityKind::IpAddress, value, 0.92, "parsed");
    }
    if let Some(coordinates) = parse_decimal_coordinates(value) {
        return classified(EntityKind::Coordinates, &coordinates, 0.85, "lat-lon");
    }
    if let Some(domain) = canonical_domain(value) {
        return classified(EntityKind::Domain, &domain, 0.75, "domain-shape");
    }
    if let Some(phone) = canonical_phone(value) {
        return classified(EntityKind::Phone, &phone, 0.80, "dialable-shape");
    }
    if au_id::classify(value).is_ok() {
        return classified(EntityKind::AbnAcn, value, 0.95, "checksum");
    }
    if value.starts_with('@') {
        let handle = canonical_handle(value).unwrap_or_else(|| value.trim().to_owned());
        return classified(EntityKind::Username, &handle, 0.40, "handle");
    }
    // A single word is never a company, a street address or a person name.
    if value.split_whitespace().nth(1).is_none() {
        return classified(EntityKind::Other, value, 0.20, "residual");
    }
    let tokens = word_tokens(value);
    let has_word = |list: &[&str]| tokens.iter().any(|token| list.contains(&token.as_str()));
    let pty_ltd = tokens
        .windows(2)
        .any(|pair| pair[0] == "pty" && pair[1] == "ltd");
    if pty_ltd || has_word(COMPANY_WORDS) {
        return classified(EntityKind::Organisation, value, 0.60, "company-suffix");
    }
    // Digits alone are not an address: "12 345" has no letters and no street word.
    let has_digit = value.chars().any(|c| c.is_ascii_digit());
    let has_letter = value.chars().any(char::is_alphabetic);
    if has_word(STREET_WORDS) || (has_digit && has_letter) {
        return classified(EntityKind::Address, value, 0.60, "street-shape");
    }
    if has_letter && !has_digit {
        return classified(EntityKind::Person, value, 0.50, "multiword");
    }
    classified(EntityKind::Other, value, 0.20, "residual")
}

/// Lowercased alphanumeric runs of a value, so keyword markers match whole words only.
fn word_tokens(value: &str) -> Vec<String> {
    value
        .split(|c: char| !c.is_alphanumeric())
        .filter(|word| !word.is_empty())
        .map(str::to_lowercase)
        .collect()
}

#[must_use]
pub fn extract(text: &str) -> Vec<Classified> {
    let tokens = tokenize(text);
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    let mut index = 0;
    while index < tokens.len() {
        let (found, consumed) = span_at(&tokens[index..]);
        if found.kind != EntityKind::Other && seen.insert((found.kind.clone(), found.value.clone()))
        {
            out.push(found);
        }
        index += consumed;
    }
    out
}

#[must_use]
pub fn extract_entities(text: &str, scan_id: &str) -> Vec<Entity> {
    extract(text)
        .into_iter()
        .filter(Classified::is_actionable)
        .map(|classified| {
            Entity::builder(
                classified.kind,
                classified.value,
                classified.confidence,
                scan_id,
            )
            .tag("classified")
            .tag("auto-seed")
            .evidence(
                Evidence::new(
                    EvidenceProvenance::for_scan("classifier", scan_id),
                    format!("{} match in unstructured input", classified.signal),
                )
                .with_attr("signal", classified.signal),
            )
            .build()
        })
        .collect()
}

fn classified(kind: EntityKind, value: &str, confidence: f64, signal: &'static str) -> Classified {
    Classified {
        kind,
        value: value.trim().to_owned(),
        confidence,
        signal,
    }
}

/// Longest run of number fragments read as one phone number or ABN/ACN.
const NUMERIC_SPAN_MAX: usize = 4;
/// Longest gap, in tokens, between a street number and its street word (inclusive).
const ADDRESS_SPAN_MAX: usize = 4;

fn tokenize(text: &str) -> Vec<&str> {
    text.split_whitespace()
        .map(|token| {
            token.trim_matches(|c: char| {
                matches!(
                    c,
                    '"' | '\'' | '(' | ')' | '[' | ']' | '{' | '}' | ',' | ';' | '!'
                )
            })
        })
        .map(|token| token.trim_end_matches(['.', ':', '?']))
        .filter(|token| !token.is_empty())
        .collect()
}

/// Returns the entity that starts at the first token, and how many tokens it spans.
///
/// Multi-token spans are tried first so a phone number, ABN, or street address is never
/// split into its digit groups or words. Every path consumes at least one token, so the
/// caller's scan always advances.
fn span_at(tokens: &[&str]) -> (Classified, usize) {
    if let Some(span) = numeric_span(tokens) {
        return span;
    }
    if let Some(span) = address_span(tokens) {
        return span;
    }
    let head = tokens.first().copied().unwrap_or_default();
    (classify(head), 1)
}

/// Recognises a phone number or an ABN/ACN written as two to four digit groups.
fn numeric_span(tokens: &[&str]) -> Option<(Classified, usize)> {
    let fragments = tokens
        .iter()
        .take(NUMERIC_SPAN_MAX)
        .take_while(|token| is_number_fragment(token))
        .count();
    (2..=fragments).rev().find_map(|width| {
        let joined = tokens[..width].join(" ");
        if let Some(phone) = canonical_phone(&joined) {
            return Some((
                classified(EntityKind::Phone, &phone, 0.80, "dialable-shape"),
                width,
            ));
        }
        match au_id::classify(&joined) {
            Ok(Identifier::Abn { bare, .. } | Identifier::Acn { bare }) => Some((
                classified(EntityKind::AbnAcn, &bare, 0.95, "checksum"),
                width,
            )),
            _ => None,
        }
    })
}

/// Recognises `NUMBER [name words] STREET-WORD`, such as `12 Queen Street`.
///
/// Returns a span only when it starts at the first token. When a later number begins the
/// address (the `12` in `Unit 3, 12 Smith St`), the scan reaches that number on its own, so
/// leading noise is not absorbed into the address.
fn address_span(tokens: &[&str]) -> Option<(Classified, usize)> {
    let head = tokens.first()?;
    if !head.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    let mut end = None;
    for (offset, token) in tokens.iter().enumerate().skip(1).take(ADDRESS_SPAN_MAX) {
        if is_street_word(token) {
            end = Some(offset);
            break;
        }
        if !is_name_like(token) {
            return None;
        }
    }
    let end = end?;
    let last_number = tokens[..end]
        .iter()
        .rposition(|token| token.starts_with(|c: char| c.is_ascii_digit()))?;
    if last_number != 0 {
        return None;
    }
    let value = tokens[..=end].join(" ");
    Some((
        classified(EntityKind::Address, &value, 0.60, "street-shape"),
        end + 1,
    ))
}

/// A token made only of digits and phone punctuation, with at least one digit.
fn is_number_fragment(token: &str) -> bool {
    token.bytes().any(|b| b.is_ascii_digit())
        && token
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'+' | b'-' | b'(' | b')'))
}

/// A capitalised word or a token containing a digit, as found in street names.
fn is_name_like(token: &str) -> bool {
    token.starts_with(char::is_uppercase) || token.bytes().any(|b| b.is_ascii_digit())
}

/// A whitespace token that is exactly one street word, ignoring surrounding punctuation.
fn is_street_word(token: &str) -> bool {
    let word = token
        .trim_matches(|c: char| !c.is_alphanumeric())
        .to_ascii_lowercase();
    STREET_WORDS.contains(&word.as_str())
}

fn parse_ipv4(raw: &str) -> bool {
    let parts = raw.split('.').collect::<Vec<_>>();
    parts.len() == 4
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.parse::<u8>().is_ok())
}

/// Recognises a `LAT,LON` pair in decimal degrees and returns it as `lat,lon`.
///
/// Both components must be plain signed decimals with a fractional part, so
/// thousands-separated numbers (`1,000`) and decimal-comma values (`12,5`) are not
/// mistaken for coordinates. Latitude must lie in `-90..=90` and longitude in
/// `-180..=180`.
fn parse_decimal_coordinates(raw: &str) -> Option<String> {
    let (lat, lon) = raw.split_once(',')?;
    let lat = decimal_degree(lat, 2, 90.0)?;
    let lon = decimal_degree(lon, 3, 180.0)?;
    Some(format!("{lat},{lon}"))
}

fn decimal_degree(raw: &str, max_int_digits: usize, limit: f64) -> Option<&str> {
    let trimmed = raw.trim();
    let unsigned = trimmed
        .strip_prefix('-')
        .or_else(|| trimmed.strip_prefix('+'))
        .unwrap_or(trimmed);
    let (int, frac) = unsigned.split_once('.')?;
    if int.is_empty()
        || int.len() > max_int_digits
        || frac.is_empty()
        || !int.bytes().all(|b| b.is_ascii_digit())
        || !frac.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let degrees: f64 = unsigned.parse().ok()?;
    if degrees > limit {
        return None;
    }
    Some(trimmed.strip_prefix('+').unwrap_or(trimmed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actionable_entities_are_emitted() {
        let entities = extract_entities("see https://example.com and ada@example.com", "scan");
        assert_eq!(entities.len(), 2);
        assert!(entities.iter().all(|entity| entity.has_tag("classified")));
    }

    #[test]
    fn stored_value_is_canonical() {
        assert_eq!(classify("  Example.COM ").value, "example.com");
        assert_eq!(classify("  Ada@Example.COM ").value, "ada@example.com");
        assert_eq!(classify("@Ada").value, "ada");
    }

    #[test]
    fn classifies_structural_values() {
        assert_eq!(classify("https://example.com").kind, EntityKind::Url);
        assert_eq!(classify("Ada@Example.com").kind, EntityKind::Email);
        assert_eq!(classify("8.8.8.8").kind, EntityKind::IpAddress);
    }

    #[test]
    fn classifies_decimal_degree_coordinates() {
        let brisbane = classify("-27.4698,153.0251");
        assert_eq!(brisbane.kind, EntityKind::Coordinates);
        assert_eq!(brisbane.value, "-27.4698,153.0251");
        assert!(brisbane.is_actionable());

        let spaced = classify(" 37.7749, -122.4194 ");
        assert_eq!(spaced.kind, EntityKind::Coordinates);
        assert_eq!(spaced.value, "37.7749,-122.4194");

        let signed = classify("+0.0,+0.0");
        assert_eq!(signed.kind, EntityKind::Coordinates);
        assert_eq!(signed.value, "0.0,0.0");

        for bounds in ["90.0,180.0", "-90.0,-180.0"] {
            assert_eq!(classify(bounds).kind, EntityKind::Coordinates, "{bounds}");
        }
    }

    #[test]
    fn rejects_out_of_range_or_non_decimal_coordinates() {
        for raw in [
            "90.1,0.0",
            "-90.5,0.0",
            "0.0,180.1",
            "0.0,-181.0",
            "123.4,12.5",
            "12.5,1234.5",
            "1e1,2.0",
            "NaN,0.0",
            "1.5,inf",
            "12.,5.0",
            ".5,5.0",
            "1.5,2.5,3.5",
        ] {
            assert_ne!(classify(raw).kind, EntityKind::Coordinates, "{raw}");
        }
    }

    #[test]
    fn ordinary_numbers_and_addresses_are_not_coordinates() {
        for raw in ["1,000", "12,500", "12,100.50", "1.000,50", "12,5"] {
            assert_ne!(classify(raw).kind, EntityKind::Coordinates, "{raw}");
        }
        for raw in [
            "12 Smith Street",
            "Unit 3, 12 Smith St Brisbane",
            "1.5 Example Road, 2.5 km north",
        ] {
            assert_eq!(classify(raw).kind, EntityKind::Address, "{raw}");
        }
    }

    #[test]
    fn extracts_unique_entities_from_text() {
        let found = extract("mail ada@example.com and visit https://example.com, @Ada!");
        assert_eq!(found.len(), 3);
        assert!(found.iter().any(|item| item.kind == EntityKind::Email));
        assert!(found.iter().any(|item| item.kind == EntityKind::Url));
    }

    #[test]
    fn phone_numbers_in_free_text_are_single_entities() {
        let international = extract("call +61 412 345 678 today");
        assert_eq!(international.len(), 1, "{international:?}");
        assert_eq!(international[0].kind, EntityKind::Phone);
        assert_eq!(international[0].value, "+61412345678");

        let local = extract("call 0412 345 678 today");
        assert_eq!(local.len(), 1, "{local:?}");
        assert_eq!(local[0].kind, EntityKind::Phone);
    }

    #[test]
    fn abn_in_free_text_is_one_entity_without_address_fragments() {
        let found = extract("ABN 51 824 753 556 on file");
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].kind, EntityKind::AbnAcn);
        assert_eq!(found[0].value, "51824753556");
    }

    #[test]
    fn mixed_identifiers_and_address_each_yield_one_entity() {
        let found = extract("+61 412 345 678 and 51 824 753 556 at 12 Queen Street");
        let kinds: Vec<_> = found.iter().map(|item| item.kind.clone()).collect();
        assert_eq!(
            kinds,
            [EntityKind::Phone, EntityKind::AbnAcn, EntityKind::Address]
        );
        assert_eq!(found[2].value, "12 Queen Street");
    }

    #[test]
    fn street_address_in_prose_is_one_entity() {
        let shipped = extract("Ship to 12 Queen Street Brisbane");
        assert_eq!(shipped.len(), 1, "{shipped:?}");
        assert_eq!(shipped[0].kind, EntityKind::Address);
        assert_eq!(shipped[0].value, "12 Queen Street");

        let unit = extract("Unit 3, 12 Smith St Brisbane");
        assert_eq!(unit.len(), 1, "{unit:?}");
        assert_eq!(unit[0].value, "12 Smith St");
    }

    #[test]
    fn bare_digits_and_street_word_are_not_addresses() {
        for raw in ["12", "345", "12 345", "Street", "first place"] {
            assert_ne!(classify(raw).kind, EntityKind::Address, "{raw}");
        }
        assert_ne!(classify("12 345").kind, EntityKind::Person, "digit pair");
        for text in [
            "street 12 345",
            "I have 3 cats on Queen Street",
            "first place",
        ] {
            assert!(
                extract(text)
                    .iter()
                    .all(|item| item.kind != EntityKind::Address),
                "{text}"
            );
        }
    }

    #[test]
    fn company_suffixes_match_whole_words_only() {
        for raw in ["Vincent", "Princeton", "Lincoln"] {
            assert_ne!(classify(raw).kind, EntityKind::Organisation, "{raw}");
        }
        assert_eq!(classify("Acme Pty Ltd").kind, EntityKind::Organisation);
        assert_eq!(classify("Acme Inc.").kind, EntityKind::Organisation);
        assert_eq!(classify("Acme Corporation").kind, EntityKind::Organisation);
    }

    #[test]
    fn keyword_markers_match_whole_words_only() {
        // Hand-written regression set: each input and the kind it must receive. Names that
        // contain a marker inside a longer word keep their person kind.
        let cases = [
            ("Vincent Smith", EntityKind::Person),
            ("Lincoln Hill", EntityKind::Person),
            ("Mary Ward", EntityKind::Person),
            ("Mary Ward Smith", EntityKind::Person),
            ("John Hurst", EntityKind::Person),
            ("John Hurst Jones", EntityKind::Person),
            ("Broadbent Lee", EntityKind::Person),
            ("Justin Bell", EntityKind::Person),
            ("Ada Lovelace", EntityKind::Person),
            ("Acme Pty Ltd", EntityKind::Organisation),
            ("Foo Inc", EntityKind::Organisation),
            ("Bar Corp", EntityKind::Organisation),
            ("Acme Corporation", EntityKind::Organisation),
            ("Acme Incorporated", EntityKind::Organisation),
            ("Baz LLC", EntityKind::Organisation),
            ("Qux GmbH", EntityKind::Organisation),
            ("12 Smith Street", EntityKind::Address),
            ("5 Beach Rd", EntityKind::Address),
            ("Main St", EntityKind::Address),
            ("Ocean Road", EntityKind::Address),
        ];
        let wrong: Vec<String> = cases
            .iter()
            .filter_map(|(raw, want)| {
                let got = classify(raw).kind;
                (got != *want).then(|| format!("{raw:?}: want {want:?}, got {got:?}"))
            })
            .collect();
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    }

    #[test]
    fn single_words_in_prose_are_not_actionable() {
        // Each word is classified on its own. Keyword substrings inside ordinary words
        // ("since", "province", "broadcast") and digits in dates or times must not match.
        let prose = "Since 2026 the province kept its principle; Vincent broadcast 10:30 COVID-19";
        let actionable: Vec<String> = extract(prose)
            .into_iter()
            .filter(Classified::is_actionable)
            .map(|item| format!("{:?}={}", item.kind, item.value))
            .collect();
        assert!(actionable.is_empty(), "{actionable:?}");
    }

    #[test]
    fn single_words_are_residual_even_when_they_contain_markers() {
        // Company and street rules apply only to values of two or more words, so a single token
        // keeps the residual kind even when it would match a rule inside a longer value.
        for raw in ["Acme-Pty-Ltd", "Corporate", "Street", "Inc", "10:30"] {
            let found = classify(raw);
            assert_eq!(found.kind, EntityKind::Other, "{raw}");
            assert_eq!(found.signal, "residual", "{raw}");
        }
    }
}
