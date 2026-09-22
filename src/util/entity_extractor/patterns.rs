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

// Social handle: `@` + alphanumeric (Twitter, Instagram style). The `@` must
// be at a left boundary — start of text or a character that cannot be part of
// an email local part — so the `@domain` of an address (`jeremy@example.com`)
// is NOT mistaken for a mention. The Rust `regex` crate has no lookbehind, so
// the boundary is a leading alternation and the handle itself is capture 1;
// the call site reads group 1, not a `@`-stripped whole match.
pub static SOCIAL_HANDLE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|[^A-Za-z0-9._%+\-])@([A-Za-z0-9_]{1,30})").expect("valid social regex")
});

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

#[cfg(test)]
mod hash_validity_tests {
    use super::{EntityKind, ExtractedEntity, extract_by_patterns};

    fn hashes(text: &str) -> Vec<ExtractedEntity> {
        extract_by_patterns(text)
            .into_iter()
            .filter(|e| matches!(e.kind, EntityKind::Hash))
            .collect()
    }

    /// REQ-EXTRACTOR-002. Width was the entire classification, and `0-9` are
    /// hex digits, so a decimal run of the right length was certified a digest.
    /// Collected rather than asserted one at a time so a single failure names
    /// every width that slipped through.
    #[test]
    fn a_decimal_run_is_never_certified_a_cryptographic_hash() {
        let cases: Vec<(&str, String)> = vec![
            (
                "32-digit transaction id",
                "txn 12345678901234567890123456789012 ok".into(),
            ),
            (
                "40-digit account run",
                "acct 1234567890123456789012345678901234567890 ok".into(),
            ),
            (
                "64-digit numeric blob",
                format!("blob {} ok", "9".repeat(64)),
            ),
            (
                "128-digit numeric blob",
                format!("blob {} ok", "1".repeat(128)),
            ),
        ];
        let minted: Vec<String> = cases
            .iter()
            .flat_map(|(why, text)| {
                hashes(text)
                    .into_iter()
                    .map(move |e| format!("{why}: {} at {}", e.source_pattern, e.confidence))
            })
            .collect();
        assert!(
            minted.is_empty(),
            "a run of decimal digits is not a digest:\n  {}",
            minted.join("\n  ")
        );
    }

    /// Control — passes before the fix too. Every real digest of each supported
    /// width is still classified, at its own confidence, so the guard is a
    /// discriminator rather than a blanket refusal.
    #[test]
    fn every_real_digest_width_is_still_classified() {
        for (text, algo, conf) in [
            ("hash 5d41402abc4b2a76b9719d911017c592 x", "hash_md5", 0.85),
            (
                "hash aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d x",
                "hash_sha1",
                0.90,
            ),
            (
                "hash 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824 x",
                "hash_sha256",
                0.95,
            ),
        ] {
            let got = hashes(text);
            assert_eq!(got.len(), 1, "{algo}: {got:?}");
            assert_eq!(got[0].source_pattern, algo);
            assert!((got[0].confidence - conf).abs() < f64::EPSILON, "{algo}");
        }
    }

    /// Control — passes before the fix too. The guard is about the ALPHABET, not
    /// the width: a token of an unrecognised width was already declined, and a
    /// single hex letter is enough to make a run a candidate again.
    #[test]
    fn the_guard_is_about_the_alphabet_not_the_width() {
        assert!(
            hashes("x 1234567890123456789012345678901 ok").is_empty(),
            "31 chars is not a recognised digest width"
        );
        let mut one_letter = "a".to_string();
        one_letter.push_str(&"1".repeat(31));
        let got = hashes(&format!("h {one_letter} ok"));
        assert_eq!(
            got.len(),
            1,
            "a single hex letter makes a 32-char run a candidate again: {got:?}"
        );
    }
}

#[cfg(test)]
mod email_validity_tests {
    use super::{EntityKind, extract_by_patterns};

    fn emails(text: &str) -> Vec<String> {
        extract_by_patterns(text)
            .into_iter()
            .filter(|e| matches!(e.kind, EntityKind::Email))
            .map(|e| e.value)
            .collect()
    }

    /// REQ-EXTRACTOR-001. Every value carrying the `email_rfc5322` /
    /// "RFC 5322 compliant format" stamp must actually satisfy the crate's own
    /// syntactic authority. These three shapes were measured being admitted
    /// under that stamp before the arm validated anything; collected rather
    /// than asserted one at a time so one failure names all of them.
    #[test]
    fn nothing_carries_the_rfc_stamp_without_earning_it() {
        let overlong = format!("mail {}@example.com here", "a".repeat(69));
        let cases: Vec<(&str, String)> = vec![
            (
                "consecutive dots in local",
                "contact a..b@example.com now".into(),
            ),
            (
                "trailing dot in local",
                "write alice.@example.com ok".into(),
            ),
            ("local part over 64 chars", overlong),
        ];
        let admitted: Vec<String> = cases
            .iter()
            .flat_map(|(why, text)| {
                emails(text)
                    .into_iter()
                    .filter(|v| !crate::core::validation::validate_email_syntax(v).valid)
                    .map(move |v| format!("{why}: {v:?}"))
            })
            .collect();
        assert!(
            admitted.is_empty(),
            "stamped \"RFC 5322 compliant format\" without being valid:\n  {}",
            admitted.join("\n  ")
        );
    }

    /// The stamp itself, asserted rather than assumed — a future arm that
    /// validated but dropped the label would pass the test above vacuously.
    #[test]
    fn a_real_address_is_still_extracted_and_still_labelled() {
        let got = extract_by_patterns("good alice.smith+tag@example.com z");
        let email = got
            .iter()
            .find(|e| matches!(e.kind, EntityKind::Email))
            .expect("a well-formed address must still be extracted");
        assert_eq!(email.value, "alice.smith+tag@example.com");
        assert_eq!(email.source_pattern, "email_rfc5322");
        assert_eq!(
            email.boost_reason.as_deref(),
            Some("RFC 5322 compliant format")
        );
    }

    /// Control — passes before the fix too. The locator already trims a leading
    /// dot and a trailing domain dot out of the match, so those never reached
    /// the stamp and the fix is not credited with them.
    #[test]
    fn the_locator_already_trimmed_these_edges_before_the_fix() {
        assert_eq!(
            emails("mail .alice@example.com here"),
            ["alice@example.com"]
        );
        assert_eq!(emails("to alice@example.com. end"), ["alice@example.com"]);
    }
}

/// Extract entities from text using pattern matching.
pub fn extract_by_patterns(text: &str) -> Vec<ExtractedEntity> {
    let mut entities = Vec::new();

    // Email extraction. The locator is a SCANNER pattern, not a validator —
    // `util::extract`'s own header says so ("Pragmatic, ASCII-only,
    // scanner-grade — NOT an RFC 5322 validator"). This arm nonetheless stamped
    // every raw match `source_pattern: "email_rfc5322"` with the boost reason
    // "RFC 5322 compliant format" at 0.85, having checked nothing. Measured
    // against the crate's own `validate_email_syntax`, three shapes were
    // admitted under that untrue stamp:
    //
    //   "a..b@example.com"          consecutive dots in the local part
    //   "alice.@example.com"        trailing dot in the local part
    //   69-char local part          over RFC 5321's 64-octet limit
    //
    // This is the same defect the IPv4 arm below already carries the scar of —
    // its comment records an arm that "stamped it 'Valid IPv4 range' ... under a
    // boost reason that was untrue" until it was made to parse through
    // `Ipv4Addr`. Email was the remaining unbacked claim (REQ-EXTRACTOR-001).
    //
    // Validate through the ONE syntactic authority, exactly as the IPv4 and IPv6
    // arms validate through their parsers, and drop what does not conform — so
    // the stamp means what it says. Not a second local copy of the rules: the
    // admission gate (`core::validation::is_fragment_value`) delegates to the
    // same function, so the extractor and the gate cannot disagree about what an
    // email is.
    for cap in EMAIL_PATTERN.find_iter(text) {
        let value = cap.as_str().to_lowercase();
        if !crate::core::validation::validate_email_syntax(&value).valid {
            continue;
        }
        entities.push(ExtractedEntity {
            kind: EntityKind::Email,
            value,
            confidence: 0.85, // syntax-validated above, so the stamp is earned
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
        // Reject matches followed by `@`, which indicates the match is an email
        // local-part (e.g., `jeremy.stewart` in `jeremy.stewart@example.com`),
        // not a standalone domain.
        if cap.end() < text.len() && text.as_bytes()[cap.end()] == b'@' {
            continue;
        }
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
        // A run of DECIMAL digits is not a digest, however long it is. Width
        // alone was the whole classification, and `0-9` are hex digits, so
        // measured against this same arm:
        //
        //   "txn 1234…(32 digits)"  -> hash_md5    0.85  "128-bit hex hash"
        //   "acct 1234…(40 digits)" -> hash_sha1   0.90  "160-bit hex hash"
        //   "blob 999…(64 digits)"  -> hash_sha256 0.95  "256-bit hex hash"
        //   "blob 111…(128 digits)" -> hash_sha512 0.97  "512-bit hex hash"
        //
        // A transaction id, an account number, a concatenated timestamp or a
        // numeric column out of a breach dump landed in the graph as a
        // cryptographic hash at up to 0.97 (REQ-EXTRACTOR-002).
        //
        // Requiring at least one `a`-`f` is the discriminator, and its cost is
        // worth stating rather than glossing: a GENUINE digest whose every
        // nibble happens to fall in 0-9 has probability (10/16)^n — about
        // 1.2e-7 for a 32-char MD5, and 4e-27 for a 128-char SHA-512. Free text
        // contains decimal runs of these lengths far more often than that.
        //
        // Deliberately NOT pushed down into `util::hashcat::identify_hash`,
        // which shares the length-only shape. That function classifies a value
        // that arrived in a hash-typed FIELD (a breach row's `password_hash`),
        // where provenance already establishes the value is a digest and an
        // all-decimal one should still be read as one. This arm scans arbitrary
        // prose with no provenance at all, so the same string carries a
        // different prior. The guard belongs where the prior is weak.
        if !value.bytes().any(|b| b.is_ascii_alphabetic()) {
            continue;
        }
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
        // The locator over-matches trailing prose punctuation (`.`, `,`, `;`,
        // `:`, `!`, `?`); strip it via the shared `trim_url_punctuation` so a
        // document ingest never mints an unfetchable URL value.
        let link = crate::core::classifier::trim_url_punctuation(cap.as_str());
        if link.is_empty() {
            continue;
        }
        entities.push(ExtractedEntity {
            kind: EntityKind::Url,
            value: link.to_string(),
            confidence: 0.80,
            context: extract_context(text, cap.start()),
            source_pattern: "url_http".to_string(),
            boost_reason: None,
        });
    }

    // Social handle extraction. Group 1 is the handle (without the `@`); the
    // leading boundary that suppresses email `@domain` matches is outside it.
    for cap in SOCIAL_HANDLE.captures_iter(text) {
        let handle = cap.get(1).expect("group 1 present on every match");
        entities.push(ExtractedEntity {
            kind: EntityKind::SocialHandle,
            value: handle.as_str().to_string(),
            confidence: 0.60, // Speculative (could be mention, not identity)
            context: extract_context(text, handle.start()),
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
    fn email_domain_is_not_minted_as_a_social_handle() {
        // The `@` of an email address is not a Twitter/Instagram mention. The
        // SOCIAL_HANDLE regex had no left boundary, so `jeremy@example.com`
        // matched `@example` inside the address and emitted a bogus
        // `SocialHandle("example")` — a false-positive identity pivot on every
        // email the extractor sees.
        let text = "reach jeremy.stewart@example.com or dana@acme.io";
        let handles: Vec<String> = extract_by_patterns(text)
            .into_iter()
            .filter(|e| e.kind == EntityKind::SocialHandle)
            .map(|e| e.value)
            .collect();
        assert!(
            handles.is_empty(),
            "an email's @domain must not become a social handle, got: {handles:?}"
        );
    }

    #[test]
    fn a_real_mention_is_still_extracted_as_a_social_handle() {
        // A genuine mention — `@` at a word boundary, not preceded by email
        // local-part characters — must still be extracted (regression guard),
        // including one at the very start of the text.
        let text = "@jack ping and follow @openai_dev for updates";
        let handles: Vec<String> = extract_by_patterns(text)
            .into_iter()
            .filter(|e| e.kind == EntityKind::SocialHandle)
            .map(|e| e.value)
            .collect();
        assert!(handles.contains(&"jack".to_string()), "got: {handles:?}");
        assert!(
            handles.contains(&"openai_dev".to_string()),
            "got: {handles:?}"
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

    #[test]
    fn email_local_part_not_minted_as_domain() {
        // DOMAIN_PATTERN has no left-boundary constraint, so `jeremy.stewart`
        // in `jeremy.stewart@example.com` matches as a domain-like token
        // (label.label structure matches `\b\w+\.\w+\b`). This emits a
        // false-positive `Domain("jeremy.stewart")` every time the extractor
        // sees an email whose local part contains a dot.
        let text = "reach jeremy.stewart@example.com or alice.johnson@acme.io";
        let domains: Vec<String> = extract_by_patterns(text)
            .into_iter()
            .filter(|e| e.kind == EntityKind::Domain)
            .map(|e| e.value)
            .collect();
        assert!(
            !domains
                .iter()
                .any(|d| d == "jeremy.stewart" || d == "alice.johnson"),
            "email local-parts with dots must not be extracted as domains, got: {domains:?}"
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
