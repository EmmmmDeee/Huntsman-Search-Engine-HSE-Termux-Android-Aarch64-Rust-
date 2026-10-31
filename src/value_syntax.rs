//! Dependency-free lexical and syntax primitives shared by L3 normalisation modules.
//!
//! This module exists to keep domain, mailbox, URL-host, E.164 and TXT-record tag syntax rules
//! in one place without forcing the higher-level normalisers to depend on one another.

const ROLE_LOCALPARTS: &[&str] = &[
    "admin",
    "administrator",
    "info",
    "support",
    "help",
    "helpdesk",
    "contact",
    "sales",
    "abuse",
    "postmaster",
    "hostmaster",
    "webmaster",
    "noreply",
    "donotreply",
    "dns",
    "root",
    "mail",
    "mailer",
    "mailerdaemon",
    "security",
    "privacy",
    "legal",
    "billing",
    "accounts",
    "marketing",
    "hello",
    "team",
    "office",
    "service",
    "services",
    "notifications",
    "notify",
    "news",
    "newsletter",
    "robot",
    "automated",
    "system",
    "daemon",
    "feedback",
    "enquiries",
    "enquiry",
    "generalenquiry",
    "generalenquiries",
    "inquiries",
    "inquiry",
    "careers",
    "jobs",
    "press",
    "media",
    "webmail",
    "namehost",
    "dmca",
    "domains",
    "domain",
    "registrar",
    "whois",
    "nic",
    "noc",
    "registry",
    "soa",
    "ssladmin",
    "sysadmin",
    "tech",
];

const SYSTEM_LOCALPART_SEGMENTS: &[&str] = &[
    "hostmaster",
    "postmaster",
    "webmaster",
    "namehost",
    "mailerdaemon",
    "noreply",
    "donotreply",
    "abuse",
    "dns",
];

const WHOIS_PRIVACY_MARKERS: &[&str] = &[
    "privacy",
    "redacted",
    "data protected",
    "not disclosed",
    "registration private",
    "private registration",
    "domains by proxy",
    "domainsbyproxy",
    "whoisguard",
    "identity protection",
    "statutory masking",
    "gdpr masked",
    "withheld",
    "unavailable",
    "non-public data",
    "domain protection services",
    "protecteddomainservices",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhoneE164Error {
    MissingPlus,
    NonDigit,
    CountryCodeLeadingZero,
    Length(usize),
}

#[must_use]
pub fn phone_e164_error(value: &str) -> Option<PhoneE164Error> {
    if !value.starts_with('+') {
        return Some(PhoneE164Error::MissingPlus);
    }
    let digits = &value[1..];
    if !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Some(PhoneE164Error::NonDigit);
    }
    if digits.starts_with('0') {
        return Some(PhoneE164Error::CountryCodeLeadingZero);
    }
    if !(10..=15).contains(&digits.len()) {
        return Some(PhoneE164Error::Length(digits.len()));
    }
    None
}

/// One DNS label: 1 to 63 ASCII letters, digits or hyphens, not starting or ending with a hyphen.
#[must_use]
pub fn is_domain_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '-')
}

/// One AU national-significant-number rule shared by every input shape:
/// nine digits with a geographic/mobile lead, or a 1300/1800 service number.
fn au_national_key(national: &str) -> Option<String> {
    let bytes = national.as_bytes();
    let ok = (bytes.len() == 9 && matches!(bytes[0], b'2' | b'3' | b'4' | b'5' | b'7' | b'8'))
        || (bytes.len() == 10 && (national.starts_with("1300") || national.starts_with("1800")));
    let candidate = format!("+61{national}");
    (ok && phone_e164_error(&candidate).is_none()).then_some(candidate)
}

#[must_use]
pub fn normalise_au_phone(raw: &str) -> Option<String> {
    let compact: String = raw
        .chars()
        .filter(|character| character.is_ascii_digit() || *character == '+')
        .collect();
    if let Some(rest) = compact
        .strip_prefix("+61")
        .or_else(|| compact.strip_prefix("0061"))
    {
        // "+61 (0)4..." keeps a trunk zero that is not part of the number.
        let national = match rest.strip_prefix('0') {
            Some(after) if au_national_key(after).is_some() => after,
            _ => rest,
        };
        return au_national_key(national);
    }
    if compact.contains('+') {
        return None;
    }
    if let Some(national) = compact.strip_prefix("61") {
        if national.len() == 9 {
            if let Some(key) = au_national_key(national) {
                return Some(key);
            }
        }
    }
    if let Some(national) = compact.strip_prefix('0') {
        if national.len() == 9 {
            return au_national_key(national);
        }
    }
    au_national_key(&compact)
}

/// The one canonical form of a phone number, which every phone value is read by (an entity, a
/// classified token, a selector, `phone_intl::canonicalize`): an explicit international number or
/// a recognised Australian national number in E.164, else `None`. **Pure.**
///
/// - The number starts at its first digit or `+`, so `tel:+1…` and `(+44)…` are read as written.
/// - A `00` or Australian `0011` international prefix is a `+` (`0044 20…`, `0011 44 20…` are
///   `+4420…`).
/// - A number with digits after an extension marker (`x12`, `ext 22`, `;ext=12`, `#12`) is
///   refused: dropping the marker would join the extension onto the number.
/// - A `+61` number is Australian or none, keeping no trunk zero (`+61 (0)4…` is `+614…`).
/// - A `+1` number written after an international prefix has the North American plan's ten
///   digits after the `1`. Any `+` number holds 10 to 15 digits, its country code not starting
///   with `0`, and one `+` only. The country of a bare non-Australian national number is never
///   guessed.
#[must_use]
pub fn canonical_phone(raw: &str) -> Option<String> {
    let number =
        raw.trim_start_matches(|character: char| !(character.is_ascii_digit() || character == '+'));
    if has_digits_after_a_marker(number) {
        return None;
    }
    // Every `+` is kept, so a second one (two numbers run together) is refused below.
    let dialled: String = number
        .chars()
        .filter(|character| character.is_ascii_digit() || *character == '+')
        .collect();
    let candidate = if dialled.starts_with('+') {
        dialled
    } else if let Some(international) = INTERNATIONAL_PREFIXES
        .iter()
        .find_map(|prefix| dialled.strip_prefix(prefix))
    {
        let candidate = format!("+{international}");
        // A run of digits that merely starts `00` (a zero-padded identifier) is no North
        // American number unless it has that plan's ten digits after the `1`. An explicit `+1`
        // number is left to the plan's own check, which says what it breaks.
        if candidate.starts_with("+1") && candidate.len() != NANP_E164_LEN {
            return None;
        }
        candidate
    } else {
        return normalise_au_phone(number);
    };
    if candidate.starts_with("+61") {
        return normalise_au_phone(&candidate);
    }
    phone_e164_error(&candidate).is_none().then_some(candidate)
}

/// The international dialling prefixes a number may be written after in place of `+`: Australia's
/// `0011` first, so its `11` is never read as a country code, then the common `00`.
const INTERNATIONAL_PREFIXES: [&str; 2] = ["0011", "00"];

/// A North American number in E.164: `+`, `1` and ten digits.
const NANP_E164_LEN: usize = 12;

/// Whether a letter, `#`, `;` or `,` stands between two of `raw`'s digits: an extension, a
/// dialling pause or a vanity word, after which the remaining digits are not the number's own.
/// Words after the last digit (`(office)`) are not. **Pure.**
fn has_digits_after_a_marker(raw: &str) -> bool {
    let mut seen_digit = false;
    let mut marker = false;
    for character in raw.chars() {
        if character.is_ascii_digit() {
            if marker {
                return true;
            }
            seen_digit = true;
        } else if seen_digit && (character.is_alphabetic() || matches!(character, '#' | ';' | ','))
        {
            marker = true;
        }
    }
    false
}

/// Shape defect in an email local part. One rule shared by
/// `canonical::canonical_email` and `validation::validate_email_syntax`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmailLocalError {
    Length,
    DotEdge,
    ConsecutiveDots,
}

#[must_use]
pub fn email_local_error(local: &str) -> Option<EmailLocalError> {
    if local.is_empty() || local.len() > 64 {
        Some(EmailLocalError::Length)
    } else if local.starts_with('.') || local.ends_with('.') {
        Some(EmailLocalError::DotEdge)
    } else if local.contains("..") {
        Some(EmailLocalError::ConsecutiveDots)
    } else {
        None
    }
}

/// The IANA root zone's top-level domains, one per line, upper case, sorted, after a
/// `# Version` header. Refresh it from <https://data.iana.org/TLD/tlds-alpha-by-domain.txt>.
const IANA_TLDS: &str = include_str!("tlds_iana.txt");

fn iana_tlds() -> &'static [&'static str] {
    static TLDS: std::sync::OnceLock<Vec<&'static str>> = std::sync::OnceLock::new();
    TLDS.get_or_init(|| {
        IANA_TLDS
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .collect()
    })
}

/// True when `label` is a top-level domain delegated in the IANA root zone, in any case.
#[must_use]
pub fn is_iana_tld(label: &str) -> bool {
    let upper = label.trim().trim_end_matches('.').to_ascii_uppercase();
    !upper.is_empty() && iana_tlds().binary_search(&upper.as_str()).is_ok()
}

/// `raw` as a domain name: lower-cased, outer dots trimmed, two or more valid labels. A top-level
/// label is never all digits (RFC 3696 §2), so a dotted IPv4 address (`93.184.216.34`, a
/// website's host) is no domain: a domain lookup of it would ask certificate logs, archives and
/// DNS about an address while the address's own lookup never ran.
#[must_use]
pub fn canonical_domain(raw: &str) -> Option<String> {
    let domain = raw.trim().trim_matches('.').to_ascii_lowercase();
    if domain.is_empty() || domain.len() > 253 {
        return None;
    }
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2
        || !labels.iter().all(|label| is_domain_label(label))
        || labels
            .last()
            .is_some_and(|tld| tld.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return None;
    }
    // No top-level domain is all digits, which is how a dotted-quad address is told from a name
    // (RFC 1123 section 2.1, RFC 3696 section 2): `10.0.0.5` is an address, never a domain.
    if labels
        .last()
        .is_some_and(|tld| tld.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return None;
    }
    Some(domain)
}

#[must_use]
pub fn canonical_domain_host(raw: &str) -> Option<String> {
    let domain = raw.trim().trim_matches('.').to_ascii_lowercase();
    let stripped = domain.strip_prefix("www.").unwrap_or(domain.as_str());
    canonical_domain(stripped)
}

#[must_use]
pub fn host_only(value: &str) -> &str {
    let trimmed = value.trim();
    let after_scheme = ["https://", "http://"]
        .iter()
        .find_map(|scheme| {
            trimmed
                .get(..scheme.len())
                .filter(|prefix| prefix.eq_ignore_ascii_case(scheme))
                .map(|_| &trimmed[scheme.len()..])
        })
        .unwrap_or(trimmed);
    let authority = after_scheme.split(['/', '?', '#']).next().unwrap_or("");
    // Userinfo (`user:pw@`) belongs to the authority only; an `@` in the path,
    // query or fragment never changes the host.
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    if let Some(close) = authority
        .strip_prefix('[')
        .and_then(|without_open| without_open.find(']'))
    {
        return &authority[..close + 2];
    }
    authority.split(':').next().unwrap_or("")
}

#[must_use]
pub fn host_from_url(url: &str) -> Option<String> {
    let host = host_only(url).to_ascii_lowercase();
    (!host.is_empty() && host.contains('.')).then_some(host)
}

#[must_use]
pub fn is_role_localpart(local: &str) -> bool {
    let detagged = local.split('+').next().unwrap_or(local);
    let base: String = detagged
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|character| character.to_ascii_lowercase())
        .collect();
    if ROLE_LOCALPARTS.contains(&base.as_str()) {
        return true;
    }
    detagged.split(['-', '.', '_']).any(|segment| {
        let folded: String = segment
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .map(|character| character.to_ascii_lowercase())
            .collect();
        SYSTEM_LOCALPART_SEGMENTS.contains(&folded.as_str())
    })
}

/// Byte offset of the first ASCII-case-insensitive match of `needle` in `haystack`: `Some(0)` for
/// an empty needle, `None` for one longer than the haystack. Bytes outside ASCII match only
/// themselves. **Pure.**
#[must_use]
pub fn find_ascii_ci_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack
        .windows(needle.len())
        .position(|window| window.eq_ignore_ascii_case(needle))
}

/// [`find_ascii_ci_bytes`] over text. A match starts where the needle's first character does, so
/// the offset is always a character boundary of `haystack`. **Pure.**
#[must_use]
pub fn find_ascii_ci(haystack: &str, needle: &str) -> Option<usize> {
    find_ascii_ci_bytes(haystack.as_bytes(), needle.as_bytes())
}

#[must_use]
pub fn is_whois_privacy_placeholder(value: &str) -> bool {
    WHOIS_PRIVACY_MARKERS
        .iter()
        .any(|marker| find_ascii_ci(value, marker).is_some())
}

/// `application/x-www-form-urlencoded` value decoding: `+` is a space and `%XX` a byte. `None`
/// for a malformed escape or bytes that are not UTF-8.
#[must_use]
pub fn form_decode(raw: &str) -> Option<String> {
    percent_decode(raw, true)
}

/// Strict `%XX` decoding. Unlike [`form_decode`], `+` stays a plus: it is legal in an address.
/// `None` for a malformed escape or bytes that are not UTF-8.
#[must_use]
pub fn percent_decode_strict(raw: &str) -> Option<String> {
    percent_decode(raw, false)
}

/// The one `%XX` decoder behind [`form_decode`] and [`percent_decode_strict`]: `plus_is_space`
/// is the only difference between them.
fn percent_decode(raw: &str, plus_is_space: bool) -> Option<String> {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' if plus_is_space => out.push(b' '),
            b'%' => {
                let hex = bytes.get(index + 1..index + 3)?;
                if !hex.iter().all(u8::is_ascii_hexdigit) {
                    return None;
                }
                out.push(u8::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()?);
                index += 2;
            }
            byte => out.push(byte),
        }
        index += 1;
    }
    String::from_utf8(out).ok()
}

/// The `key=value` pairs of a query string, each side form-decoded, empty pairs skipped.
/// `None` when any pair does not decode.
#[must_use]
pub fn form_pairs(query: &str) -> Option<Vec<(String, String)>> {
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            Some((form_decode(key)?, form_decode(value)?))
        })
        .collect()
}

/// One `name=value` tag of a TXT record, as SPF modifiers and DMARC tags are written: the
/// name trimmed and ASCII-lowercased, the value trimmed. `None` without an `=` or a name.
#[must_use]
pub(crate) fn record_tag(raw: &str) -> Option<(String, &str)> {
    let tag = raw.trim();
    let (name, value) = tag.split_once('=')?;
    let name = name.trim();
    (!name.is_empty()).then(|| (name.to_ascii_lowercase(), value.trim()))
}

/// The mailboxes of a comma-separated report URI list (`rua`, `ruf`, TLS-RPT's `rua`): each
/// case-insensitive `mailto:` scheme without its `!size` limit, kept when it holds an `@`
/// and is at least five bytes long. Other schemes are skipped; mailbox case is preserved.
pub(crate) fn parse_mailto_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .filter_map(|entry| {
            let trimmed = entry.trim();
            // RFC 3986: only the URI scheme is case-insensitive, not the mailbox.
            let scheme = trimmed.get(..7)?;
            if !scheme.eq_ignore_ascii_case("mailto:") {
                return None;
            }
            let addr = trimmed.get(7..)?;
            let addr = addr.split('!').next().unwrap_or(addr).trim();
            if addr.contains('@') && addr.len() >= 5 {
                Some(addr.to_string())
            } else {
                None
            }
        })
        .collect()
}

/// Router makers, carriers and platforms whose name in an SSID marks it as a factory or
/// shared default; matched as a substring.
pub const GENERIC_SSID_BRANDS: &[&str] = &[
    "android", "dlink", "eduroam", "galaxy", "hidden", "iphone", "linksys", "netgear", "optimum",
    "optus", "spectrum", "telstra", "tp-link", "tplink", "unnamed", "unknown", "vodafone",
    "xfinity",
];

/// Words that mark an SSID as a default, guest or public network; matched as a whole token.
pub const GENERIC_SSID_WORDS: &[&str] = &[
    "admin", "asus", "att", "config", "cox", "default", "free", "guest", "nbn", "open", "pixel",
    "public", "setup", "test",
];

/// Whether an SSID is one many unrelated networks broadcast (a factory default, a carrier's
/// hotspot, a guest or public network), so sharing it says nothing about who runs the network.
#[must_use]
pub fn is_generic_ssid(ssid: &str) -> bool {
    let lower = ssid.to_ascii_lowercase();
    if GENERIC_SSID_BRANDS
        .iter()
        .any(|brand| lower.contains(brand))
    {
        return true;
    }
    ssid_tokens(&lower).any(|token| GENERIC_SSID_WORDS.contains(&token))
}

fn ssid_tokens(lower: &str) -> impl Iterator<Item = &str> {
    lower
        .split(|c: char| !c.is_alphanumeric())
        .flat_map(|part| {
            let mut tokens = Vec::new();
            let mut start = 0usize;
            let mut prev: Option<char> = None;
            for (index, ch) in part.char_indices() {
                if let Some(prev_char) = prev {
                    if prev_char.is_ascii_digit() != ch.is_ascii_digit() {
                        tokens.push(&part[start..index]);
                        start = index;
                    }
                }
                prev = Some(ch);
            }
            if start < part.len() {
                tokens.push(&part[start..]);
            }
            tokens
        })
        .filter(|token| !token.is_empty())
}

#[cfg(test)]
mod form_tests {
    use super::*;

    #[test]
    fn form_values_decode_plus_and_escapes_and_refuse_bad_ones() {
        assert_eq!(form_decode("a+b%40c.d").as_deref(), Some("a b@c.d"));
        assert_eq!(form_decode("%e2%9c%93").as_deref(), Some("\u{2713}"));
        assert_eq!(form_decode("%zz"), None);
        assert_eq!(form_decode("%4"), None);
        assert_eq!(form_decode("%ff"), None);
        assert_eq!(
            form_pairs("target=example.com&&name=my+scan&flag"),
            Some(vec![
                ("target".into(), "example.com".into()),
                ("name".into(), "my scan".into()),
                ("flag".into(), String::new()),
            ])
        );
        assert_eq!(form_pairs("a=%zz"), None);
    }

    #[test]
    fn report_mailto_scheme_is_case_insensitive_without_changing_address_case() {
        assert_eq!(
            parse_mailto_list(
                "MAILTO:Reports@Example.org!10m, MaIlTo:Ops@Example.org, https://example.org/r, mailto:valid@example.org"
            ),
            [
                "Reports@Example.org",
                "Ops@Example.org",
                "valid@example.org"
            ]
        );
        assert!(parse_mailto_list("mailtox:wrong@example.org").is_empty());
    }

    #[test]
    fn record_tag_parser_normalises_name_and_trims_value() {
        assert_eq!(record_tag(" Pct = 75 "), Some(("pct".to_string(), "75")));
        assert_eq!(record_tag("missing"), None);
    }

    /// Both decoding modes over one table: `+` is the only byte they read differently, and a bad
    /// escape or bytes that are not UTF-8 refuse the whole value in either.
    #[test]
    fn form_and_strict_decoding_differ_only_in_the_plus() {
        let cases: [(&str, Option<&str>, Option<&str>); 8] = [
            ("a+b%40c", Some("a b@c"), Some("a+b@c")),
            ("%C3%A9", Some("\u{e9}"), Some("\u{e9}")),
            ("plain", Some("plain"), Some("plain")),
            ("%+1", None, None),
            ("%zz", None, None),
            ("%4", None, None),
            ("%", None, None),
            ("%FF", None, None),
        ];
        for (raw, form, strict) in cases {
            assert_eq!(form_decode(raw).as_deref(), form, "form {raw}");
            assert_eq!(
                percent_decode_strict(raw).as_deref(),
                strict,
                "strict {raw}"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_and_dotted_handles_follow_the_domain_rules() {
        assert!(is_domain_label("alice"));
        assert!(is_domain_label("a-b"));
        assert!(!is_domain_label("_alice"));
        assert!(!is_domain_label("-alice"));
        assert!(!is_domain_label("alice-"));
        assert!(!is_domain_label(""));
        assert!(!is_domain_label(&"a".repeat(64)));
        assert!(!is_domain_label("café"));
        assert!(canonical_domain("alice.dev").is_some());
        assert!(canonical_domain(" Example.COM. ").is_some());
        assert!(canonical_domain("a-b.example").is_some());
        assert!(canonical_domain("alice").is_none());
        assert!(canonical_domain("-bad.example").is_none());
        assert!(canonical_domain("bad-.example").is_none());
        assert!(canonical_domain("bad..example").is_none());
        assert!(canonical_domain("bad_example.com").is_none());
        // A dotted quad, or any name whose last label is all digits, is no domain.
        assert!(canonical_domain("10.0.0.5").is_none());
        assert!(canonical_domain("203.0.113.9.").is_none());
        assert!(canonical_domain("example.123").is_none());
        assert!(canonical_domain("123.example.com").is_some());
        assert!(canonical_domain("9.9.9.9.in-addr.arpa").is_some());
        assert!(canonical_domain("example.café").is_none());
        // A dotted IPv4 address is no domain: no top-level label is all digits.
        assert!(canonical_domain("93.184.216.34").is_none());
        assert!(canonical_domain("example.123").is_none());
        assert!(canonical_domain("1.2.3.example").is_some());
        assert!(canonical_domain("0412345678.com.au").is_some());
    }

    #[test]
    fn iana_tlds_are_sorted_and_recognised() {
        assert!(IANA_TLDS.starts_with("# Version "));
        let tlds = iana_tlds();
        assert!(tlds.len() > 1000, "{}", tlds.len());
        assert!(
            tlds.windows(2).all(|pair| pair[0] < pair[1]),
            "list must stay sorted"
        );
        for tld in ["com", "AU", "org.", "xn--p1ai", "app"] {
            assert!(is_iana_tld(tld), "{tld}");
        }
        for not_tld in ["cookie", "useragent", "trim", "699", "", "c0m"] {
            assert!(!is_iana_tld(not_tld), "{not_tld}");
        }
    }

    #[test]
    fn e164_errors_preserve_validation_precedence() {
        assert_eq!(
            phone_e164_error("0410959140"),
            Some(PhoneE164Error::MissingPlus)
        );
        assert_eq!(
            phone_e164_error("+61X12345678"),
            Some(PhoneE164Error::NonDigit)
        );
        assert_eq!(
            phone_e164_error("+0123456789"),
            Some(PhoneE164Error::CountryCodeLeadingZero)
        );
        assert_eq!(phone_e164_error("+123"), Some(PhoneE164Error::Length(3)));
        assert_eq!(phone_e164_error("+61412345678"), None);
    }

    #[test]
    fn shared_phone_rules_match_existing_contract() {
        assert_eq!(
            normalise_au_phone("0412 345 678"),
            Some("+61412345678".into())
        );
        assert_eq!(
            normalise_au_phone("0061 412 345 678"),
            Some("+61412345678".into())
        );
        assert_eq!(
            normalise_au_phone("412 345 678"),
            Some("+61412345678".into())
        );
        assert_eq!(
            normalise_au_phone("1300 123 456"),
            Some("+611300123456".into())
        );
        assert_eq!(
            normalise_au_phone("1800 123 456"),
            Some("+611800123456".into())
        );
        assert_eq!(normalise_au_phone("+1 415 555 2671"), None);
        assert_eq!(
            canonical_phone("+1 415 555 2671"),
            Some("+14155552671".into())
        );
        assert_eq!(canonical_phone("0412 345 678"), Some("+61412345678".into()));
    }

    #[test]
    fn host_only_scopes_userinfo_to_the_authority() {
        assert_eq!(host_only("https://user:pw@Real.org:8443/a"), "Real.org");
        assert_eq!(host_only("https://real.org/p?u=a@example.com"), "real.org");
        assert_eq!(host_only("https://example.com/@someone"), "example.com");
        assert_eq!(
            host_from_url("https://bob@Real.org/x"),
            Some("real.org".to_owned())
        );
    }

    #[test]
    fn shared_domain_and_host_rules_match_existing_contract() {
        assert_eq!(
            canonical_domain_host(" WWW.Example.COM. "),
            Some("example.com".into())
        );
        assert_eq!(
            canonical_domain("sub.example.org"),
            Some("sub.example.org".into())
        );
        assert!(canonical_domain("-bad.example").is_none());
        assert_eq!(host_only("https://Example.org:443/a"), "Example.org");
        assert_eq!(
            host_from_url("https://Example.org/a"),
            Some("example.org".into())
        );
    }

    #[test]
    fn ascii_case_search_finds_the_first_match_at_its_byte_offset() {
        assert_eq!(find_ascii_ci("Hello World", "WORLD"), Some(6));
        assert_eq!(find_ascii_ci("abc", ""), Some(0));
        assert_eq!(find_ascii_ci("", ""), Some(0));
        assert_eq!(find_ascii_ci("ab", "abc"), None);
        assert_eq!(find_ascii_ci("", "a"), None);
        assert_eq!(find_ascii_ci("\u{e9}</SCRIPT>", "</script"), Some(2));
        assert_eq!(find_ascii_ci("x\u{c9}y \u{e9}y", "\u{e9}Y"), Some(5));
        assert_eq!(
            find_ascii_ci_bytes(b"<a></Style></style>", b"</style"),
            Some(3)
        );
        assert_eq!(find_ascii_ci_bytes(b"no closer", b"</style"), None);
    }

    #[test]
    fn mailbox_and_privacy_markers_are_centralized() {
        assert!(is_role_localpart("support+case"));
        assert!(is_role_localpart("hostmaster-team"));
        assert!(!is_role_localpart("alice"));
        assert!(is_whois_privacy_placeholder("Domains By Proxy, LLC"));
        assert!(!is_whois_privacy_placeholder("Ada Lovelace"));
    }
}

#[cfg(test)]
mod au_phone_key_contract {
    use super::*;

    #[test]
    fn trunk_zero_after_country_code_is_one_key() {
        let want = Some("+61412345678".to_string());
        assert_eq!(normalise_au_phone("+61 (0)412 345 678"), want);
        assert_eq!(normalise_au_phone("0061 0412 345 678"), want);
        assert_eq!(canonical_phone("+61 (0)412 345 678"), want);
        assert_eq!(canonical_phone("0412 345 678"), want);
    }

    /// Every way a number reaches a key gives the key a scan of it gives: a `00` prefix is a
    /// `+`, and an extension is never joined onto the number.
    #[test]
    fn a_phone_has_one_key_however_it_is_written() {
        let want = Some("+442079460958".to_string());
        for written in [
            "+44 20 7946 0958",
            "0044 20 7946 0958",
            "tel:+44-20-7946-0958",
        ] {
            assert_eq!(canonical_phone(written), want, "{written}");
        }
        for extended in [
            "+1 415 555 2671 ext 22",
            "+44 20 7946 0958 x12",
            "0044 20 7946 0958;ext=3",
        ] {
            assert_eq!(canonical_phone(extended), None, "{extended}");
        }
        assert_eq!(
            canonical_phone("+1 415 555 2671 (office)").as_deref(),
            Some("+14155552671")
        );
        assert_eq!(canonical_phone("0011 44 20 7946 0958"), want);
        // Two numbers run together, and a zero-padded identifier, are no number.
        assert_eq!(canonical_phone("+44 +1 415 555 2671"), None);
        assert_eq!(canonical_phone("001234567890"), None);
        // An explicit `+1` number of the wrong length is still read, so the `phone` command's
        // own plan check can say what it breaks.
        assert_eq!(
            canonical_phone("+1202555010").as_deref(),
            Some("+1202555010")
        );
    }

    #[test]
    fn au_country_code_requires_au_national_length() {
        assert_eq!(normalise_au_phone("+61 4123 4567 8901"), None);
        assert_eq!(normalise_au_phone("+61 9 1234 5678"), None);
        assert_eq!(canonical_phone("+61 4123 4567 8901"), None);
        assert_eq!(canonical_phone("0061 4123 4567 8901"), None);
        assert_eq!(
            normalise_au_phone("+61 1300 123 456").as_deref(),
            Some("+611300123456")
        );
    }
}

#[cfg(test)]
mod ssid_tests {
    use super::*;

    #[test]
    fn generic_ssid_detection_uses_substrings_for_brands_and_tokens_for_words() {
        for ssid in [
            "linksys",
            "xfinitywifi",
            "NETGEAR-Guest",
            "Telstra-Home-123",
            "Free Public WiFi",
        ] {
            assert!(is_generic_ssid(ssid), "{ssid}");
        }
        for ssid in [
            "Freeman-Family",
            "Seattle-Cafe",
            "Testa-Household",
            "Openshaw-House",
            "Hancox-Home",
            "Attwood-Residence",
            "Nbnalla-House",
            "Smith-WiFi",
            "Johnson WLAN",
        ] {
            assert!(!is_generic_ssid(ssid), "{ssid}");
        }
    }
}
