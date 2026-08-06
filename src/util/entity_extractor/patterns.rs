//! Regex patterns for entity extraction + confidence boosters.
//!
//! EMAIL, IPv4, DOMAIN and URL patterns are re-exported from [`crate::core::classifier`]
//! so the document-ingestion pipeline and the scan engine share a single set of
//! canonical, lazily-compiled locators. Only two extraction locators live here:
//! the social-handle matcher and the hex-hash classifier — neither is part of the
//! core embedded-entity locator set.
//!
//! Extracted kinds: `Email`, `Ipv4`, `Ipv6`, `Domain`, `Url`, `SocialHandle`, and
//! `Hash` (MD5 / SHA-1 / SHA-256 / SHA-512, distinguished by hex length). IPv6 is
//! **validated** through [`std::net::Ipv6Addr`] rather than trusted from the
//! regex, so a deliberately loose candidate pattern can't leak `std::vector`-style
//! `::`, MAC addresses or `12:34:56` clock times. Phone, username, person-name and
//! license-ID locators stay removed: each matched almost any digit run or
//! capitalised word pair and — unlike IPv6 — has no cheap validating parser to
//! gate it, so it emitted far more noise than signal. `EntityKind` still models
//! those kinds; they reach the graph via caller hints and the core classifier, not
//! via free-text regex here.

use super::{EntityKind, ExtractedEntity};
use crate::util::str_util::char_window;
use regex::Regex;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::LazyLock;

// Canonical locators from `core::classifier`. Re-exported under the legacy names
// so existing call sites keep compiling after the duplicate regex definitions
// were removed.
pub use crate::core::classifier::DOMAIN_RE as DOMAIN_PATTERN;
pub use crate::core::classifier::EMAIL_RE as EMAIL_PATTERN;
pub use crate::core::classifier::IPV4_RE as IPV4_PATTERN;
pub use crate::core::classifier::URL_RE as URL_PATTERN;

// Social handle: @ + alphanumeric (Twitter, Instagram style)
pub static SOCIAL_HANDLE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"@[a-zA-Z0-9_]{1,30}").expect("valid social regex"));

// IPv6 CANDIDATE: any run of hex digits and colons. Deliberately loose — it
// only has to *find* candidates; `extract_by_patterns` then validates each one
// through `Ipv6Addr::from_str` and a boundary check, so the regex never has to
// judge whether a run is a real address. (Single char class, no alternation →
// linear time, no ReDoS.)
pub static IPV6_CANDIDATE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[0-9A-Fa-f:]+").expect("valid ipv6 candidate regex"));

// One MAXIMAL run of hex digits, bounded by word boundaries so a hex run
// embedded in a longer alphanumeric token is not carved out of it. The
// extractor classifies each run by its EXACT length (32/40/64/128) in
// `extract_by_patterns`, rather than running one length-specific regex per
// hash type. The old code ran independent {40} and {64} passes over the same
// text, so every 64-char SHA-256 additionally surfaced a bogus 40-char
// "SHA-1" — its own prefix — that dedup (keyed on `(kind, value)`) never
// caught because the two values differ.
pub static HEX_TOKEN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[0-9a-fA-F]+\b").expect("valid hex regex"));

/// Extract entities from text using pattern matching.
pub fn extract_by_patterns(text: &str) -> Vec<ExtractedEntity> {
    let mut entities = Vec::new();

    // Email extraction
    for cap in EMAIL_PATTERN.find_iter(text) {
        entities.push(ExtractedEntity {
            kind: EntityKind::Email,
            value: cap.as_str().to_lowercase(),
            confidence: 0.85, // RFC 5322 validation high confidence
            context: extract_context(text, cap.start()),
            source_pattern: "email_rfc5322".to_string(),
            boost_reason: Some("RFC 5322 compliant format".to_string()),
        });
    }

    // IPv4 extraction. The candidate regex `(\d{1,3}\.){3}\d{1,3}` is deliberately
    // loose and does NOT range-check octets, so it also matches `999.1.2.3` and
    // leading-zero forms like `192.168.01.1` (a parser-confusion / SSRF vector).
    // The old arm trusted the raw match after only a `255.`/`0.` prefix test and
    // stamped it "Valid IPv4 range" — emitting values that `Ipv4Addr::from_str`,
    // and therefore any downstream scanner, rejects, under a boost reason that was
    // untrue. Validate through `Ipv4Addr` exactly as the IPv6 arm does: parse
    // (rejecting out-of-range and leading-zero octets), drop the non-host ranges
    // the prefix test already excluded (0.0.0.0/8 and 255.0.0.0/8) plus multicast
    // (224.0.0.0/4 — the "not a broadcast or multicast" the old comment claimed
    // but never enforced), and emit the canonical dotted-quad so the value
    // re-parses stably.
    for cap in IPV4_PATTERN.find_iter(text) {
        let Ok(addr) = cap.as_str().parse::<Ipv4Addr>() else {
            continue;
        };
        let octets = addr.octets();
        if octets[0] == 0 || octets[0] == 255 || addr.is_multicast() {
            continue;
        }
        entities.push(ExtractedEntity {
            kind: EntityKind::Ipv4,
            value: addr.to_string(),
            confidence: 0.90,
            context: extract_context(text, cap.start()),
            source_pattern: "ipv4_quad_decimal".to_string(),
            boost_reason: Some("Valid IPv4 range (std-parsed)".to_string()),
        });
    }

    // IPv6 extraction. The candidate regex over-matches (hex + colons), so every
    // hit is gated hard before it is trusted:
    //   1. at least two colons — an IPv6 address always has them;
    //   2. no ALPHABETIC neighbour (any script, via `char::is_alphabetic`) — an
    //      adjacent letter means the run was carved out of a larger word (the
    //      `d::` inside `std::vector`, `::ba` in `foo::bar`, or an address glued
    //      to a multibyte word like `café2001:db8::1`); the maximal run already
    //      guarantees the neighbour is not hex/colon, so a letter is the giveaway;
    //   3. it must parse via `Ipv6Addr::from_str` — this rejects MAC addresses
    //      (`01:23:…`, 6 groups, no `::`), `12:34:56` clock times, and malformed
    //      groups outright;
    //   4. it must not be the loopback (`::1`) or unspecified (`::`) address —
    //      both are pure noise in prose (and `::` is rife in source code).
    // What survives is a real RFC 4291 address, emitted in canonical compressed
    // form so equivalent spellings deduplicate.
    for cap in IPV6_CANDIDATE.find_iter(text) {
        let value = cap.as_str();
        if value.bytes().filter(|&b| b == b':').count() < 2 {
            continue;
        }
        let before = text[..cap.start()].chars().next_back();
        let after = text[cap.end()..].chars().next();
        if matches!(before, Some(c) if c.is_alphabetic())
            || matches!(after, Some(c) if c.is_alphabetic())
        {
            continue;
        }
        let Ok(addr) = value.parse::<Ipv6Addr>() else {
            continue;
        };
        if addr.is_loopback() || addr.is_unspecified() {
            continue;
        }
        entities.push(ExtractedEntity {
            kind: EntityKind::Ipv6,
            value: addr.to_string(), // canonical, lower-case compressed form
            confidence: 0.88,
            context: extract_context(text, cap.start()),
            source_pattern: "ipv6_rfc4291".to_string(),
            boost_reason: Some("Valid IPv6 address (std-parsed)".to_string()),
        });
    }

    // Domain extraction
    for cap in DOMAIN_PATTERN.find_iter(text) {
        entities.push(ExtractedEntity {
            kind: EntityKind::Domain,
            value: cap.as_str().to_lowercase(),
            confidence: 0.75,
            context: extract_context(text, cap.start()),
            source_pattern: "domain_rfc1035".to_string(),
            boost_reason: None,
        });
    }

    // Hash extraction: ONE pass over maximal hex tokens, classified by length, so
    // a token is emitted at most once as exactly one hash kind. A SHA-256 is
    // therefore never also reported as the 40-char SHA-1 that is its own prefix.
    for cap in HEX_TOKEN.find_iter(text) {
        let value = cap.as_str();
        let (confidence, algo) = match value.len() {
            32 => (0.85, "md5"),
            40 => (0.90, "sha1"),
            64 => (0.95, "sha256"),
            128 => (0.97, "sha512"),
            // Not a recognised hash width (short hex, an IPv4 octet, a UUID
            // segment, a byte blob, …) — nothing to emit.
            _ => continue,
        };
        let bits = value.len() * 4;
        entities.push(ExtractedEntity {
            kind: EntityKind::Hash,
            value: value.to_lowercase(),
            confidence,
            context: extract_context(text, cap.start()),
            source_pattern: format!("hash_{algo}"),
            boost_reason: Some(format!("{bits}-bit hex hash")),
        });
    }

    // URL extraction
    for cap in URL_PATTERN.find_iter(text) {
        entities.push(ExtractedEntity {
            kind: EntityKind::Url,
            value: cap.as_str().to_string(),
            confidence: 0.80,
            context: extract_context(text, cap.start()),
            source_pattern: "url_http".to_string(),
            boost_reason: None,
        });
    }

    // Social handle extraction
    for cap in SOCIAL_HANDLE.find_iter(text) {
        entities.push(ExtractedEntity {
            kind: EntityKind::SocialHandle,
            value: cap.as_str()[1..].to_string(), // Remove @ prefix
            confidence: 0.60,                     // Speculative (could be mention, not identity)
            context: extract_context(text, cap.start()),
            source_pattern: "social_handle_twitter".to_string(),
            boost_reason: None,
        });
    }

    entities
}

/// Extract surrounding context for an entity (useful for validation).
///
/// The window is arithmetic (`pos - 20` … `pos + 40`) over a byte offset, so it
/// goes through [`char_window`], which rounds both ends to a UTF-8 boundary and
/// keeps `end >= start`. Slicing `text` directly panicked on any multibyte
/// character in the window — and unlike a module panic, this one is not
/// contained: `extract_by_patterns` is reached from `hse ingest` via
/// [`super::EntityExtractor::extract_from_text`], which dispatches outside every
/// `catch_unwind` in the engine, so the process died. Ingested documents carry
/// accented names, typographic quotes and emoji as a matter of course.
///
/// `char_window` also bounds `end` by `text.len()`, so the old `.min(text.len())`
/// is redundant. Same treatment as the sibling arithmetic windows in
/// `social_location`, `search_engines::helpers::text` and `web_crawler`.
fn extract_context(text: &str, pos: usize) -> Option<String> {
    Some(char_window(text, pos.saturating_sub(20), pos + 40).to_string())
}

/// Deduplicate entities by (kind, value).
pub fn deduplicate(entities: Vec<ExtractedEntity>) -> Vec<ExtractedEntity> {
    use std::collections::HashSet;
    let mut seen = HashSet::new();
    let mut deduped = Vec::new();

    for entity in entities {
        let key = (entity.kind.clone(), entity.value.clone());
        if seen.insert(key) {
            deduped.push(entity);
        }
    }

    deduped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_email() {
        let text = "Contact john.doe@example.com for info";
        let entities = extract_by_patterns(text);
        assert!(
            entities
                .iter()
                .any(|e| e.kind == EntityKind::Email && e.value == "john.doe@example.com")
        );
    }

    #[test]
    fn extract_ipv4() {
        let text = "Server at 192.168.1.1 running Linux";
        let entities = extract_by_patterns(text);
        assert!(
            entities
                .iter()
                .any(|e| e.kind == EntityKind::Ipv4 && e.value == "192.168.1.1")
        );
    }

    #[test]
    fn ipv4_extraction_rejects_non_addresses() {
        // The candidate regex `(\d{1,3}\.){3}\d{1,3}` does NOT range-check octets,
        // so it also matches `999.1.2.3` (out of range), `192.168.01.1` (leading
        // zeros — a parser-confusion / SSRF vector `Ipv4Addr` rejects), and
        // `224.0.0.1` (multicast, which the arm's own comment always claimed to
        // exclude). The old arm trusted the raw match after only a `255.`/`0.`
        // prefix test and stamped it "Valid IPv4 range", emitting values that
        // `Ipv4Addr::from_str` — and therefore any downstream scanner — rejects.
        // Only the single real host quad may survive.
        let text = "multicast 224.0.0.1, bad 999.1.2.3, ambiguous 192.168.01.1, good 192.168.1.42";
        let ipv4: Vec<String> = extract_by_patterns(text)
            .into_iter()
            .filter(|e| e.kind == EntityKind::Ipv4)
            .map(|e| e.value)
            .collect();
        assert_eq!(
            ipv4,
            ["192.168.1.42"],
            "only the valid host quad may survive"
        );
    }

    #[test]
    fn extract_sha256() {
        let text = "Hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let entities = extract_by_patterns(text);
        assert!(
            entities
                .iter()
                .any(|e| e.kind == EntityKind::Hash && e.confidence > 0.90)
        );
    }

    #[test]
    fn sha256_is_not_also_emitted_as_sha1() {
        // A 64-char SHA-256 contains a 40-char substring; the previous two-pass
        // extractor emitted BOTH a sha256 and a bogus 40-char "sha1". The single
        // length-classified pass must emit exactly one Hash for the token.
        let sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let hashes: Vec<_> = extract_by_patterns(sha256)
            .into_iter()
            .filter(|e| e.kind == EntityKind::Hash)
            .collect();
        assert_eq!(hashes.len(), 1, "expected exactly one hash, got {hashes:?}");
        assert_eq!(hashes[0].value, sha256);
        assert_eq!(hashes[0].source_pattern, "hash_sha256");
    }

    #[test]
    fn hashes_classified_by_hex_length() {
        // MD5 (32) and SHA-512 (128) were defined but never extracted before.
        let md5 = "5d41402abc4b2a76b9719d911017c592";
        let sha512 = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
                      47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
        assert_eq!(md5.len(), 32);
        assert_eq!(sha512.len(), 128);

        let md5_hits = extract_by_patterns(md5);
        assert!(
            md5_hits
                .iter()
                .any(|e| e.kind == EntityKind::Hash && e.source_pattern == "hash_md5"),
            "MD5 not classified: {md5_hits:?}"
        );

        let sha512_hits = extract_by_patterns(sha512);
        assert!(
            sha512_hits
                .iter()
                .any(|e| e.kind == EntityKind::Hash && e.source_pattern == "hash_sha512"),
            "SHA-512 not classified: {sha512_hits:?}"
        );
    }

    #[test]
    fn extract_ipv6_valid_forms() {
        // Compressed, fully-expanded (canonicalised on emit), and link-local.
        for (text, expected) in [
            ("Host 2001:db8::1 online", "2001:db8::1"),
            (
                "full 2001:0db8:85a3:0000:0000:8a2e:0370:7334 addr",
                "2001:db8:85a3::8a2e:370:7334",
            ),
            (
                "link fe80::1ff:fe23:4567:890a here",
                "fe80::1ff:fe23:4567:890a",
            ),
            // Bracketed, as in a URL authority.
            ("connect [2001:db8::dead:beef]:443", "2001:db8::dead:beef"),
        ] {
            let hits = extract_by_patterns(text);
            assert!(
                hits.iter()
                    .any(|e| e.kind == EntityKind::Ipv6 && e.value == expected),
                "expected IPv6 {expected} from {text:?}, got {hits:?}"
            );
        }
    }

    #[test]
    fn ipv6_extraction_rejects_noise() {
        // Rust/C++ path separators, a Haskell type signature, a MAC address, a
        // clock time, and the loopback/unspecified addresses must NOT surface as
        // IPv6 — the boundary check, the parser, and the loopback/unspecified
        // filter each kill a different class of false positive.
        for text in [
            "use std::vector; foo::bar::baz",
            "signature x :: Int -> Int",
            "mac 01:23:45:67:89:ab",
            "meeting at 12:34:56 today",
            "loop ::1 and :: unspecified",
            // Glued to a multibyte word — rejected by the Unicode-aware boundary.
            "café2001:db8::1",
        ] {
            let hits = extract_by_patterns(text);
            assert!(
                !hits.iter().any(|e| e.kind == EntityKind::Ipv6),
                "no IPv6 expected from {text:?}, got {hits:?}"
            );
        }
    }

    #[test]
    fn deduplicate_removes_duplicates() {
        let entities = vec![
            ExtractedEntity {
                kind: EntityKind::Email,
                value: "test@example.com".to_string(),
                confidence: 0.85,
                context: None,
                source_pattern: "test".to_string(),
                boost_reason: None,
            },
            ExtractedEntity {
                kind: EntityKind::Email,
                value: "test@example.com".to_string(),
                confidence: 0.85,
                context: None,
                source_pattern: "test".to_string(),
                boost_reason: None,
            },
        ];
        let deduped = deduplicate(entities);
        assert_eq!(deduped.len(), 1);
    }
}

#[cfg(test)]
mod multibyte_tests {
    use super::*;

    /// Non-ASCII document text must not panic the extractor.
    ///
    /// `extract_context` builds its window with raw byte arithmetic around the
    /// match (`pos - 20`, `pos + 40`). Neither end was clamped to a UTF-8
    /// boundary, so a multibyte character anywhere in the look-behind window, or
    /// straddling the look-ahead edge, split a code point and panicked.
    ///
    /// This path is NOT inside any `catch_unwind`: `extract_by_patterns` is
    /// reached from `hse ingest --file` via `EntityExtractor::extract_from_text`,
    /// and `Command::Ingest` dispatches outside every guard in the engine, so the
    /// panic terminated the process rather than degrading one module. Accented
    /// names, typographic quotes, NBSP and emoji are ordinary in ingested
    /// documents, which makes this routine input rather than a crafted edge case.
    ///
    /// The pre-existing tests in the sibling module are all pure ASCII, which is
    /// why this survived.
    #[test]
    fn multibyte_document_text_does_not_panic_the_extractor() {
        // 'é' occupies bytes 0..2, then 19 spaces, so the email match starts at
        // byte 21 and the look-behind lands on byte 1 — the continuation byte
        // inside 'é'. Spaces, not letters: the locator's leading `\b` will not
        // start a match between two word characters.
        let behind = format!("é{}john@example.com", " ".repeat(19));

        for text in [
            behind.as_str(),
            // Multibyte straddling the +40 look-ahead edge.
            "john@example.com                       é tail",
            // Multibyte on both sides of the match.
            "café                john@example.com café",
            // 3- and 4-byte code points.
            "日本語 test john@example.com 日本語",
            "😀😀😀 john@example.com 😀😀😀",
            // Multibyte adjacent to each other locator family.
            "señor 192.168.1.1 señor",
            "señor https://example.com/x señor",
            // Degenerate: text shorter than the window.
            "é",
            "éj@e.co",
        ] {
            let entities = extract_by_patterns(text);
            // Every emitted context must be real text from the document.
            for e in &entities {
                if let Some(ctx) = &e.context {
                    assert!(
                        text.contains(ctx.as_str()),
                        "context {ctx:?} is not a substring of {text:?}"
                    );
                }
            }
        }

        // The positive path still works beside multibyte text.
        let hit = extract_by_patterns(&behind);
        assert!(
            hit.iter()
                .any(|e| e.kind == EntityKind::Email && e.value == "john@example.com"),
            "the email must still be extracted: {hit:?}"
        );
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// `extract_by_patterns` is reached from `hse ingest --file` OUTSIDE every
        /// `catch_unwind` in the engine (see `extract_context`), so a panic on any
        /// document byte-sequence would terminate the whole process. The sibling
        /// `multibyte_tests` pin specific accented/emoji/CJK cases; this generalises
        /// them: over *arbitrary* Unicode text (any `char`, including control
        /// characters and newlines) the extractor must be TOTAL — never panic —
        /// every emitted `context` must be a real substring of the input (no
        /// fabricated provenance), and no entity may carry an empty value.
        #[test]
        fn extract_by_patterns_is_total_over_arbitrary_text(
            s in proptest::collection::vec(any::<char>(), 0..200)
                .prop_map(|cs| cs.into_iter().collect::<String>())
        ) {
            let entities = extract_by_patterns(&s);
            for e in &entities {
                prop_assert!(!e.value.is_empty(), "empty value emitted for {:?}", e.kind);
                if let Some(ctx) = &e.context {
                    prop_assert!(
                        s.contains(ctx.as_str()),
                        "context {ctx:?} is not a substring of the input"
                    );
                }
            }
        }

        /// Every IPv4 the arm emits must be a real, canonical address. Octets are
        /// drawn `0..=999`, so most generated quads carry an out-of-range octet:
        /// the loose candidate regex still MATCHES those, so this actively probes
        /// the `Ipv4Addr` gate rather than the happy path. Whatever survives must
        /// re-parse and equal its own canonical `to_string()` — the ingest→scan
        /// value contract a downstream scanner relies on.
        #[test]
        fn ipv4_arm_emits_only_parseable_canonical_quads(
            a in 0u16..=999,
            b in 0u16..=999,
            c in 0u16..=999,
            d in 0u16..=999,
        ) {
            let text = format!("addr {a}.{b}.{c}.{d} end");
            for e in extract_by_patterns(&text)
                .into_iter()
                .filter(|e| e.kind == EntityKind::Ipv4)
            {
                let parsed = e.value.parse::<Ipv4Addr>();
                prop_assert!(
                    parsed.is_ok(),
                    "emitted non-parseable Ipv4 {:?} from {text:?}",
                    e.value
                );
                prop_assert_eq!(
                    parsed.unwrap().to_string(),
                    e.value.clone(),
                    "Ipv4 value is not canonical"
                );
            }
        }

        /// A full eight-group IPv6 is always a valid address. Written in
        /// *uncompressed* form and embedded in prose, it must be extracted exactly
        /// once and emitted in the canonical compressed form `Ipv6Addr::to_string()`
        /// produces — so equivalent spellings collapse to one value downstream.
        #[test]
        fn ipv6_full_form_is_emitted_canonically(
            g in proptest::array::uniform8(any::<u16>()),
        ) {
            let addr = Ipv6Addr::new(g[0], g[1], g[2], g[3], g[4], g[5], g[6], g[7]);
            // The arm deliberately drops loopback/unspecified; skip those inputs.
            prop_assume!(!addr.is_loopback() && !addr.is_unspecified());
            let full = format!(
                "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                g[0], g[1], g[2], g[3], g[4], g[5], g[6], g[7]
            );
            let text = format!("v6 {full} end");
            let emitted: Vec<_> = extract_by_patterns(&text)
                .into_iter()
                .filter(|e| e.kind == EntityKind::Ipv6)
                .collect();
            prop_assert_eq!(emitted.len(), 1, "expected exactly one IPv6 from {:?}", text);
            prop_assert_eq!(&emitted[0].value, &addr.to_string());
        }
    }
}
