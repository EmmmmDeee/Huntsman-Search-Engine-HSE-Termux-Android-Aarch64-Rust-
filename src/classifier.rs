//! Lightweight offline entity classifier and extractor.

use std::collections::BTreeSet;

use crate::au_id::{self, Identifier};
use crate::canonical::{
    canonical_bitcoin_address, canonical_domain, canonical_email, canonical_handle, canonical_mac,
    canonical_phone, canonical_url,
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

/// Capitalised connectors that end a name in prose. "In 2024 The Main Road" is prose, so
/// "The" stops an address span before it can reach "Road".
const CONNECTOR_WORDS: &[&str] = &[
    "a", "an", "and", "at", "by", "for", "from", "in", "near", "of", "on", "or", "the", "to",
    "with",
];

#[derive(Debug, Clone, PartialEq)]
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
    // Stored compressed and lower-case, the form `canonical_ip` emits.
    if let Some(v6) = parse_ipv6(value) {
        return classified(EntityKind::IpAddress, &v6.to_string(), 0.92, "parsed");
    }
    if let Some(block) = crate::netblock::Netblock::parse(value) {
        return classified(EntityKind::Netblock, &block.to_string(), 0.90, "cidr");
    }
    if let Some(mac) = canonical_mac(value) {
        return classified(EntityKind::MacAddress, &mac, 0.90, "six-octet");
    }
    if let Some(asn) = parse_asn(value) {
        return classified(EntityKind::Asn, &asn, 0.85, "as-prefix");
    }
    if let Some(crypto) = parse_crypto_address(value) {
        return classified(EntityKind::CryptoAddress, &crypto, 0.90, "crypto-prefix");
    }
    if let Some(key) = parse_api_key(value) {
        return classified(EntityKind::ApiKey, &key, 0.92, "key-prefix");
    }
    if let Some(coordinates) = parse_decimal_coordinates(value) {
        return classified(EntityKind::Coordinates, &coordinates, 0.85, "lat-lon");
    }
    if let Some(domain) = canonical_domain(value) {
        return classified(EntityKind::Domain, &domain, 0.75, "domain-shape");
    }
    // `canonical_phone` keeps only the digits, so a token that merely holds enough of them (a
    // cookie's `GeoIP=US:VA:Ashburn:39.05:-77.49`, a hash, a version string) is a number, not a
    // phone, unless it is written with nothing but digits and dialling punctuation.
    if let Some(phone) = is_dialable(value).then(|| canonical_phone(value)).flatten() {
        return classified(EntityKind::Phone, &phone, 0.80, "dialable-shape");
    }
    if let Some(bare) = abn_acn(value) {
        return classified(EntityKind::AbnAcn, &bare, 0.95, "checksum");
    }
    if value.starts_with('@') {
        return match canonical_handle(value) {
            Some(handle) => classified(EntityKind::Username, &handle, 0.40, "handle"),
            None => classified(EntityKind::Other, value, 0.20, "residual"),
        };
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

/// The bare digits of a checksum-valid ABN or ACN. A BSB has no checksum, so six digits
/// alone are not one.
fn abn_acn(value: &str) -> Option<String> {
    match au_id::classify(value) {
        Ok(Identifier::Abn { bare, .. } | Identifier::Acn { bare }) => Some(bare),
        _ => None,
    }
}

/// An IPv6 address, unless every group is two hex digits. Such an address has eight groups
/// and no `::`, which is how an EUI-64, Fibre Channel WWN or IEEE 802.15.4 identifier is
/// written, not an address. The compressed form [`classify`] stores is checked as well as the
/// input, so `0010:0020:...` and `10:20:...` are refused alike and a stored value classifies
/// as it did. The rule reads how a value is written: the same 128 bits written with a
/// one-digit group (`50:6:1:60:3b:20:19:88`) are still an address.
fn parse_ipv6(value: &str) -> Option<std::net::Ipv6Addr> {
    let two_digit_groups = |text: &str| text.split(':').all(|group| group.len() == 2);
    if two_digit_groups(value) {
        return None;
    }
    let address: std::net::Ipv6Addr = value.parse().ok()?;
    (!two_digit_groups(&address.to_string())).then_some(address)
}

/// Recognises an autonomous-system number written `AS` or `ASN` followed by digits, such
/// as `AS13335`. Returned as `AS` plus the bare number, so the case of the prefix does not
/// split one network into two entities.
fn parse_asn(value: &str) -> Option<String> {
    let upper = value.to_ascii_uppercase();
    let digits = upper
        .strip_prefix("ASN")
        .or_else(|| upper.strip_prefix("AS"))?;
    // `u32` parsing takes a leading `+`, which an AS number never has.
    if !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    // AS numbers are 32-bit. Parsing also drops leading zeros, however many, so AS013335
    // is AS13335, as `canonical_asn` reads it.
    let number: u32 = digits.parse().ok()?;
    Some(format!("AS{number}"))
}

/// Recognises cryptocurrency addresses by their distinctive prefixes and character sets:
/// Bitcoin mainnet (1, 3, or bc1), Ethereum (0x + 40 hex), Monero (4 + 94 alnum).
fn parse_crypto_address(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.starts_with("0x") || trimmed.starts_with("0X") {
        let hex = &trimmed[2..];
        if hex.len() == 40 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Some(format!("0x{}", hex.to_ascii_lowercase()));
        }
    }
    if let Some(bitcoin) = canonical_bitcoin_address(trimmed) {
        return Some(bitcoin);
    }
    if trimmed.starts_with('4')
        && trimmed.len() == 95
        && trimmed.bytes().all(|b| b.is_ascii_alphanumeric())
    {
        return Some(trimmed.to_owned());
    }
    None
}

/// Recognises well-known API key prefixes: AWS access keys (AKIA/ASIA), GitHub tokens
/// (ghp_, gho_, ghs_, ghc_, ghr_), Slack tokens (xoxb-, xoxp-, xoxo-, xoxa-, xoxr-).
fn parse_api_key(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if (trimmed.starts_with("AKIA") || trimmed.starts_with("ASIA"))
        && trimmed.len() == 20
        && trimmed.bytes().all(|b| b.is_ascii_alphanumeric())
    {
        return Some(trimmed.to_owned());
    }
    for prefix in ["ghp_", "gho_", "ghs_", "ghc_", "ghr_"] {
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            if (36..=40).contains(&rest.len()) && rest.bytes().all(|b| b.is_ascii_alphanumeric()) {
                return Some(trimmed.to_owned());
            }
        }
    }
    for prefix in ["xoxb-", "xoxp-", "xoxo-", "xoxa-", "xoxr-"] {
        if trimmed.starts_with(prefix)
            && (40..=80).contains(&trimmed.len())
            && trimmed
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Some(trimmed.to_owned());
        }
    }
    None
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
                    '"' | '\'' | '(' | ')' | '[' | ']' | '{' | '}' | '<' | '>' | ',' | ';' | '!'
                )
            })
        })
        .map(|token| {
            let trimmed = token.trim_end_matches(['.', ':', '?']);
            // The colons that end `fe80::` are part of the address, so only a full stop or
            // question mark after it comes off. A bare `::`, as in `f :: Int`, is not one.
            let address = token.trim_end_matches(['.', '?']);
            if !trimmed.is_empty() && parse_ipv6(address).is_some() {
                address
            } else {
                trimmed
            }
        })
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
    let found = classify(head);
    // Free text is full of dotted tokens that are not host names: `document.cookie` in a
    // script, `2.699` in an SVG path. Extraction keeps a domain only under a delegated TLD;
    // a seed an operator types is still classified on syntax alone.
    if found.kind == EntityKind::Domain
        && !found
            .value
            .rsplit('.')
            .next()
            .is_some_and(crate::value_syntax::is_iana_tld)
    {
        return (classified(EntityKind::Other, head, 0.20, "unknown-tld"), 1);
    }
    (found, 1)
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
        abn_acn(&joined).map(|bare| {
            (
                classified(EntityKind::AbnAcn, &bare, 0.95, "checksum"),
                width,
            )
        })
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
    // The span runs over name-like tokens and ends on the last street word in that run, so
    // "12 St Kilda Road" keeps "Road" and "Ship to 12 Queen St Brisbane" stops at "St".
    let mut end = None;
    for (offset, token) in tokens.iter().enumerate().skip(1).take(ADDRESS_SPAN_MAX) {
        if !is_name_like(token) {
            break;
        }
        if is_street_word(token) {
            end = Some(offset);
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

/// A value written only with digits, spaces and the punctuation of a dialled number, with at
/// least one digit.
fn is_dialable(value: &str) -> bool {
    value.bytes().any(|b| b.is_ascii_digit())
        && value.chars().all(|c| {
            c.is_ascii_digit() || c.is_whitespace() || matches!(c, '+' | '-' | '(' | ')' | '.')
        })
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
    if token.bytes().any(|b| b.is_ascii_digit()) {
        return true;
    }
    let lowered = token.to_ascii_lowercase();
    token.starts_with(char::is_uppercase) && !CONNECTOR_WORDS.contains(&lowered.as_str())
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
    fn extraction_keeps_only_domains_under_a_delegated_tld() {
        let text = "if (navigator.useragent && document.cookie.split) line.trim(); \
                    <path d=\"M2.699 005.398 8.101\"/> see gravatar.com and mail.analytical.org.au";
        let domains: Vec<String> = extract(text)
            .into_iter()
            .filter(|c| c.kind == EntityKind::Domain)
            .map(|c| c.value)
            .collect();
        assert_eq!(domains, vec!["gravatar.com", "mail.analytical.org.au"]);
        assert_eq!(classify("intranet.corp").kind, EntityKind::Domain);
    }

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
    fn digits_inside_another_token_are_not_a_phone_number() {
        // A cookie's GeoIP coordinates once became the phone number +61390577494.
        let cookie = extract("set-cookie: GeoIP=US:VA:Ashburn:39.05:-77.49:v4; Path=/;");
        assert!(
            !cookie.iter().any(|item| item.kind == EntityKind::Phone),
            "{cookie:?}"
        );
        for raw in ["build-0412345678", "id=0412345678", "v0412345678"] {
            assert_ne!(classify(raw).kind, EntityKind::Phone, "{raw}");
        }
        for raw in ["(03) 9057 7494", "+61-491-570-006", "0491570006"] {
            assert_eq!(classify(raw).kind, EntityKind::Phone, "{raw}");
        }
    }

    #[test]
    fn abn_in_free_text_is_one_entity_without_address_fragments() {
        let found = extract("ABN 51 824 753 556 on file");
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].kind, EntityKind::AbnAcn);
        assert_eq!(found[0].value, "51824753556");
    }

    #[test]
    fn a_bsb_shape_is_not_an_abn_and_an_abn_or_acn_is_stored_bare() {
        // A BSB has no checksum, so any six digits would pass as one.
        for raw in ["123456", "062-000", "062 000"] {
            assert_eq!(classify(raw).kind, EntityKind::Other, "{raw}");
        }
        assert!(extract("order 123456 shipped").is_empty());
        let abn = classify("51 824 753 556");
        assert_eq!(abn.kind, EntityKind::AbnAcn);
        assert_eq!(abn.value, "51824753556");
        let acn = classify("004 085 616");
        assert_eq!(acn.kind, EntityKind::AbnAcn);
        assert_eq!(acn.value, "004085616");
        let found = extract("ACN 004 085 616 on file");
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].kind, EntityKind::AbnAcn);
        assert_eq!(found[0].value, "004085616");
    }

    #[test]
    fn an_ipv6_address_is_an_ip_address_in_compressed_form() {
        for raw in [
            "2606:4700:4700::1111",
            "2606:4700:4700:0000:0000:0000:0000:1111",
        ] {
            let found = classify(raw);
            assert_eq!(found.kind, EntityKind::IpAddress, "{raw}");
            assert_eq!(found.value, "2606:4700:4700::1111", "{raw}");
            assert_eq!(found.signal, "parsed", "{raw}");
        }
        assert_eq!(classify("2001:DB8::A").value, "2001:db8::a");
        assert_eq!(classify("00:1A:2B:3C:4D:5E").kind, EntityKind::MacAddress);
        let found = extract("resolver 2606:4700:4700::1111 answered");
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].kind, EntityKind::IpAddress);
        assert_eq!(found[0].value, "2606:4700:4700::1111");
    }

    #[test]
    fn eight_two_digit_groups_are_an_identifier_not_an_ipv6_address() {
        // A Fibre Channel WWN parses as IPv6, but no one writes an address that way.
        assert_eq!(classify("50:06:01:60:3b:20:19:88").kind, EntityKind::Other);
        assert!(extract("port 50:06:01:60:3b:20:19:88 is up").is_empty());
        let nat64 = classify("64:ff9b::808:808");
        assert_eq!(nat64.kind, EntityKind::IpAddress);
        assert_eq!(nat64.value, "64:ff9b::808:808");
        for raw in ["::1", "1::"] {
            assert_eq!(classify(raw).kind, EntityKind::IpAddress, "{raw}");
        }
        // Compressed, this is `10:20:30:40:50:60:70:80`, so it is refused too, and every value
        // classify stores classifies as the same kind again.
        assert_eq!(
            classify("0010:0020:0030:0040:0050:0060:0070:0080").kind,
            EntityKind::Other
        );
        for raw in [
            "0010:0020:0030:0040:0050:0060:0070:0080",
            "2606:4700:4700:0000:0000:0000:0000:1111",
            "64:ff9b::808:808",
            "::1",
        ] {
            let first = classify(raw);
            assert_eq!(classify(&first.value).kind, first.kind, "{raw}");
        }
    }

    #[test]
    fn extraction_keeps_an_ipv6_address_that_ends_in_a_double_colon() {
        for (text, value) in [
            ("prefix 2400:cb00:: announced", "2400:cb00::"),
            ("the link-local block is fe80::.", "fe80::"),
            ("is the block fe80::?", "fe80::"),
        ] {
            let found = extract(text);
            assert_eq!(found.len(), 1, "{text}: {found:?}");
            assert_eq!(found[0].kind, EntityKind::IpAddress, "{text}");
            assert_eq!(found[0].value, value, "{text}");
        }
        assert!(extract("f :: Int").is_empty());
    }

    #[test]
    fn extraction_reads_addresses_inside_angle_brackets() {
        let mail = extract("From: Ada Lovelace <ada@example.com>");
        assert_eq!(mail.len(), 1, "{mail:?}");
        assert_eq!(mail[0].kind, EntityKind::Email);
        assert_eq!(mail[0].value, "ada@example.com");
        let link = extract("see <https://example.com>");
        assert_eq!(link.len(), 1, "{link:?}");
        assert_eq!(link[0].kind, EntityKind::Url);
    }

    #[test]
    fn an_at_sign_value_that_is_not_a_handle_is_residual() {
        for raw in ["@", "@Ada Lovelace", "@josé"] {
            let found = classify(raw);
            assert_eq!(found.kind, EntityKind::Other, "{raw}");
            assert_eq!(found.signal, "residual", "{raw}");
        }
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
    fn address_span_keeps_road_after_an_st_name_part() {
        let found = extract("Meet at 12 St Kilda Road tomorrow");
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].kind, EntityKind::Address);
        assert_eq!(found[0].value, "12 St Kilda Road");
    }

    #[test]
    fn prose_with_a_connector_is_not_an_address() {
        let found = extract("In 2024 The Main Road was closed");
        assert!(
            found.iter().all(|item| item.kind != EntityKind::Address),
            "{found:?}"
        );
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

    #[test]
    fn mac_addresses_normalise_to_lowercase_colon_form() {
        for raw in ["00:1A:2B:3C:4D:5E", "00-1a-2b-3c-4d-5e"] {
            let found = classify(raw);
            assert_eq!(found.kind, EntityKind::MacAddress, "{raw}");
            assert_eq!(found.value, "00:1a:2b:3c:4d:5e", "{raw}");
        }
    }

    #[test]
    fn malformed_mac_addresses_are_not_mac_addresses() {
        for raw in [
            "00:1A:2B:3C:4D",
            "00:1A:2B:3C:4D:5G",
            "00:1A:2B:3C:4D:5E:6F",
        ] {
            assert_ne!(classify(raw).kind, EntityKind::MacAddress, "{raw}");
        }
    }

    #[test]
    fn asn_numbers_normalise_prefix_and_reject_non_digits() {
        for (raw, value) in [("AS13335", "AS13335"), ("asn64512", "AS64512")] {
            let found = classify(raw);
            assert_eq!(found.kind, EntityKind::Asn, "{raw}");
            assert_eq!(found.value, value, "{raw}");
        }
        for raw in ["ASIA", "AS", "AS12x", "AS+13335", "ASN12345678901"] {
            assert_ne!(classify(raw).kind, EntityKind::Asn, "{raw}");
        }
    }

    #[test]
    fn asn_numbers_drop_leading_zeros_and_stay_within_32_bits() {
        for (raw, value) in [
            ("AS013335", "AS13335"),
            ("AS00000013335", "AS13335"),
            ("AS4294967295", "AS4294967295"),
        ] {
            let found = classify(raw);
            assert_eq!(found.kind, EntityKind::Asn, "{raw}");
            assert_eq!(found.value, value, "{raw}");
        }
        assert_ne!(classify("AS4294967296").kind, EntityKind::Asn);
    }

    #[test]
    fn a_mac_address_with_mixed_separators_is_one_mac_address() {
        let found = classify("00:1A-2B:3C-4D:5E");
        assert_eq!(found.kind, EntityKind::MacAddress);
        assert_eq!(found.value, "00:1a:2b:3c:4d:5e");
    }

    #[test]
    fn a_cidr_block_is_a_netblock_written_as_its_first_address() {
        for (raw, value) in [
            ("192.0.2.77/24", "192.0.2.0/24"),
            ("2001:DB8::1/48", "2001:db8::/48"),
        ] {
            let found = classify(raw);
            assert_eq!(found.kind, EntityKind::Netblock, "{raw}");
            assert_eq!(found.value, value, "{raw}");
        }
        assert_ne!(classify("192.0.2.0/33").kind, EntityKind::Netblock);
    }

    #[test]
    fn extract_finds_mac_and_asn_inside_prose_without_duplicates() {
        let found = extract("device 00-1A-2B-3C-4D-5E on AS13335, again 00:1a:2b:3c:4d:5e");
        let kinds: Vec<_> = found.iter().map(|c| c.kind.clone()).collect();
        assert_eq!(kinds, vec![EntityKind::MacAddress, EntityKind::Asn]);
        assert_eq!(found[0].value, "00:1a:2b:3c:4d:5e");
    }

    #[test]
    fn ethereum_addresses_normalise_to_lowercase() {
        let found = classify("0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe");
        assert_eq!(found.kind, EntityKind::CryptoAddress);
        assert_eq!(found.value, "0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae");
    }

    #[test]
    fn bitcoin_bech32_addresses_are_detected() {
        let found = classify("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        assert_eq!(found.kind, EntityKind::CryptoAddress);
    }

    #[test]
    fn bitcoin_bech32_follows_the_canonical_case_rule() {
        let upper = classify("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4");
        assert_eq!(upper.kind, EntityKind::CryptoAddress);
        assert_eq!(upper.value, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        // b, i and o are outside the bech32 alphabet in either case.
        for letter in ['B', 'I', 'O'] {
            let raw = format!("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t{letter}");
            assert_ne!(classify(&raw).kind, EntityKind::CryptoAddress, "{raw}");
        }
    }

    #[test]
    fn bitcoin_legacy_addresses_are_detected() {
        let found = classify("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
        assert_eq!(found.kind, EntityKind::CryptoAddress);
    }

    #[test]
    fn malformed_crypto_addresses_are_rejected() {
        for raw in ["0xZZZZ", "0x1234", "bc1", "1short"] {
            assert_ne!(classify(raw).kind, EntityKind::CryptoAddress, "{raw}");
        }
    }

    #[test]
    fn aws_access_keys_are_detected() {
        let found = classify("AKIAIOSFODNN7EXAMPLE");
        assert_eq!(found.kind, EntityKind::ApiKey);
        assert_eq!(found.value, "AKIAIOSFODNN7EXAMPLE");
    }

    #[test]
    fn github_tokens_are_detected() {
        let token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh1234";
        let found = classify(token);
        assert_eq!(found.kind, EntityKind::ApiKey);
    }

    #[test]
    fn slack_tokens_are_detected() {
        let token = "xoxb-123456789012-1234567890123-ABCDEFGHIJKLMNOPQRSTUVWx";
        let found = classify(token);
        assert_eq!(found.kind, EntityKind::ApiKey);
    }

    #[test]
    fn malformed_api_keys_are_rejected() {
        for raw in ["AKIA", "AKIAIOSFOD", "ghp_short", "xoxb-short"] {
            assert_ne!(classify(raw).kind, EntityKind::ApiKey, "{raw}");
        }
    }

    #[test]
    fn extract_finds_crypto_and_api_keys_in_prose() {
        let text =
            "leaked key AKIAIOSFODNN7EXAMPLE and wallet 0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe";
        let found = extract(text);
        let kinds: Vec<_> = found.iter().map(|c| c.kind.clone()).collect();
        assert!(kinds.contains(&EntityKind::ApiKey), "{kinds:?}");
        assert!(kinds.contains(&EntityKind::CryptoAddress), "{kinds:?}");
    }
}
