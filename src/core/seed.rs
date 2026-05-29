//! `core::seed` — automatic seed classification.
//!
//! Turns a raw operator string ("Jordan Leigh Meyer Australia",
//! "john@acme.com", "8.8.8.8", "+61400123456") into a structured seed: the
//! [`TargetKind`], the normalised value, and an optional region prior peeled
//! from a trailing country token. This is the front door of the
//! Spiderfoot-style workflow — the operator types one box, the engine works
//! out what it is, like SpiderFoot's seed auto-detection but region-aware.
//!
//! # Architecture invariants
//! - Pure, deterministic, allocation-light. No I/O, no regex engine (cheap
//!   char scans only — matters on Termux).
//! - Depends only on `core::scan`, `core::geo`, `core::validation`.

use crate::core::geo;
use crate::core::scan::TargetKind;
use crate::core::validation;

/// A classified seed ready to drive a scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedSeed {
    pub kind: TargetKind,
    pub value: String,
    /// Region prior peeled from a trailing country token, ISO-2 (e.g. `"AU"`).
    pub region: Option<String>,
}

/// Classify a raw input string into a seed.
///
/// First peels a trailing region token ("… Australia" → region `AU`) when the
/// remainder is still a plausible multi-word value, then classifies what's
/// left by shape. Never fails: an unrecognisable single token falls back to
/// [`TargetKind::Username`], the broadest people-centric pivot.
pub fn detect(raw: &str) -> DetectedSeed {
    let trimmed = raw.trim();
    let (core, region) = split_trailing_region(trimmed);
    let value = core.trim();
    let kind = classify(value);
    DetectedSeed {
        kind,
        value: value.to_string(),
        region,
    }
}

/// Peel a trailing region/country token, returning `(remainder, region_iso)`.
///
/// Only fires when the input has ≥2 whitespace tokens and the remainder after
/// removing the region is non-empty — so "Australia" alone, or a single-token
/// email/domain, is never stripped. Tries the last token, then the last two
/// (for "New Zealand", "United States", "South Africa").
fn split_trailing_region(input: &str) -> (&str, Option<String>) {
    let tokens: Vec<&str> = input.split_whitespace().collect();
    if tokens.len() < 2 {
        return (input, None);
    }
    // Try last two tokens, then last one (longest match wins).
    for take in [2usize, 1] {
        if tokens.len() <= take {
            continue;
        }
        let tail = tokens[tokens.len() - take..].join(" ");
        if let Some(iso) = geo::normalize_region(&tail) {
            let head_tokens = &tokens[..tokens.len() - take];
            if !head_tokens.is_empty() {
                // Recover the head substring from the original input so we keep
                // the caller's spacing/casing for the value.
                let head = input.trim_end();
                let cut = rfind_token_boundary(head, head_tokens.len());
                let remainder = head[..cut].trim();
                if !remainder.is_empty() {
                    return (remainder, Some(iso.to_string()));
                }
            }
        }
    }
    (input, None)
}

/// Byte offset just past the `n`-th whitespace-delimited token in `s`.
fn rfind_token_boundary(s: &str, n: usize) -> usize {
    let mut count = 0;
    let mut in_tok = false;
    for (i, c) in s.char_indices() {
        if c.is_whitespace() {
            if in_tok {
                count += 1;
                if count == n {
                    return i;
                }
                in_tok = false;
            }
        } else {
            in_tok = true;
        }
    }
    // Last token runs to end of string.
    s.len()
}

/// Classify a region-stripped value by shape. Ordered most-specific first.
fn classify(v: &str) -> TargetKind {
    if v.is_empty() {
        return TargetKind::Username;
    }
    // Email — must contain '@' and pass light RFC check.
    if v.contains('@') && validation::validate_email_syntax(v).valid {
        return TargetKind::Email;
    }
    // URL.
    if v.starts_with("http://") || v.starts_with("https://") {
        return TargetKind::Url;
    }
    // IP address (v4 or v6).
    if v.parse::<std::net::IpAddr>().is_ok() {
        return TargetKind::IpAddress;
    }
    // MAC / BSSID: six 2-hex groups separated by ':' or '-'.
    if is_mac(v) {
        return TargetKind::MacAddress;
    }
    // Coordinates "lat,lon".
    if let Some((a, b)) = v.split_once(',')
        && a.trim().parse::<f64>().is_ok()
        && b.trim().parse::<f64>().is_ok()
    {
        return TargetKind::Coordinates;
    }
    // Phone: optional '+', then mostly digits (allow spaces/dashes/parens).
    if is_phone(v) {
        return TargetKind::Phone;
    }
    // Domain: single token, has a dot, valid shape, no spaces.
    if !v.contains(char::is_whitespace) && validation::validate_domain_shape(v).valid {
        return TargetKind::Domain;
    }
    // Multi-word alphabetic → person full name.
    let words: Vec<&str> = v.split_whitespace().collect();
    if (2..=5).contains(&words.len())
        && words.iter().all(|w| {
            w.chars()
                .all(|c| c.is_alphabetic() || c == '-' || c == '\'' || c == '.')
        })
    {
        return TargetKind::FullName;
    }
    // Single opaque token → username (broadest people pivot).
    TargetKind::Username
}

fn is_mac(v: &str) -> bool {
    let sep = if v.contains(':') {
        ':'
    } else if v.contains('-') {
        '-'
    } else {
        return false;
    };
    let parts: Vec<&str> = v.split(sep).collect();
    parts.len() == 6
        && parts
            .iter()
            .all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
}

fn is_phone(v: &str) -> bool {
    let stripped = v.trim_start_matches('+');
    let digits = stripped.chars().filter(|c| c.is_ascii_digit()).count();
    let only_phone_chars = stripped
        .chars()
        .all(|c| c.is_ascii_digit() || matches!(c, ' ' | '-' | '(' | ')' | '.'));
    only_phone_chars && (7..=15).contains(&digits)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(s: &str) -> DetectedSeed {
        detect(s)
    }

    #[test]
    fn name_with_trailing_region() {
        let s = d("Jordan Leigh Meyer Australia");
        assert_eq!(s.kind, TargetKind::FullName);
        assert_eq!(s.value, "Jordan Leigh Meyer");
        assert_eq!(s.region.as_deref(), Some("AU"));
    }

    #[test]
    fn name_with_iso_region() {
        let s = d("Jane Doe AU");
        assert_eq!(s.kind, TargetKind::FullName);
        assert_eq!(s.value, "Jane Doe");
        assert_eq!(s.region.as_deref(), Some("AU"));
    }

    #[test]
    fn two_word_region_new_zealand() {
        let s = d("John Smith New Zealand");
        assert_eq!(s.kind, TargetKind::FullName);
        assert_eq!(s.value, "John Smith");
        assert_eq!(s.region.as_deref(), Some("NZ"));
    }

    #[test]
    fn plain_name_no_region() {
        let s = d("Jordan Leigh Meyer");
        assert_eq!(s.kind, TargetKind::FullName);
        assert_eq!(s.value, "Jordan Leigh Meyer");
        assert_eq!(s.region, None);
    }

    #[test]
    fn region_only_input_is_not_stripped() {
        // "Australia" alone must not become an empty value.
        let s = d("Australia");
        assert!(!s.value.is_empty());
        assert_eq!(s.region, None);
    }

    #[test]
    fn email_detected_and_not_region_stripped() {
        let s = d("john.meyer@acme.com.au");
        assert_eq!(s.kind, TargetKind::Email);
        assert_eq!(s.value, "john.meyer@acme.com.au");
        assert_eq!(s.region, None);
    }

    #[test]
    fn ipv4_and_ipv6() {
        assert_eq!(d("8.8.8.8").kind, TargetKind::IpAddress);
        assert_eq!(d("2606:4700::1111").kind, TargetKind::IpAddress);
    }

    #[test]
    fn domain_detected() {
        assert_eq!(d("example.com.au").kind, TargetKind::Domain);
        assert_eq!(d("sub.example.org").kind, TargetKind::Domain);
    }

    #[test]
    fn url_detected() {
        assert_eq!(d("https://example.com/path").kind, TargetKind::Url);
    }

    #[test]
    fn phone_detected() {
        assert_eq!(d("+61 400 123 456").kind, TargetKind::Phone);
        assert_eq!(d("0412345678").kind, TargetKind::Phone);
    }

    #[test]
    fn mac_detected() {
        assert_eq!(d("02:fc:00:00:00:01").kind, TargetKind::MacAddress);
        assert_eq!(d("02-fc-00-00-00-01").kind, TargetKind::MacAddress);
    }

    #[test]
    fn coordinates_detected() {
        assert_eq!(d("-27.4698,153.0251").kind, TargetKind::Coordinates);
    }

    #[test]
    fn single_token_is_username() {
        assert_eq!(d("jordanleighmeyer").kind, TargetKind::Username);
        assert_eq!(d("ghost_42").kind, TargetKind::Username);
    }

    #[test]
    fn username_with_region() {
        let s = d("jmeyer Australia");
        assert_eq!(s.value, "jmeyer");
        assert_eq!(s.region.as_deref(), Some("AU"));
        assert_eq!(s.kind, TargetKind::Username);
    }
}
