//! Regex patterns for entity extraction + confidence boosters.
//!
//! EMAIL, IPv4, DOMAIN and URL patterns are re-exported from [`crate::core::classifier`]
//! so the document-ingestion pipeline and the scan engine share a single set of
//! canonical, lazily-compiled locators. Only two extraction locators live here:
//! the social-handle matcher and the hex-hash classifier — neither is part of the
//! core embedded-entity locator set.
//!
//! Extracted kinds: `Email`, `Ipv4`, `Domain`, `Url`, `SocialHandle`, and `Hash`
//! (MD5 / SHA-1 / SHA-256 / SHA-512, distinguished by hex length). Phone, IPv6,
//! username, person-name and license-ID locators were removed: each matched
//! almost any digit run or capitalised word pair, so — without a validating
//! parser to gate them — they emitted far more noise than signal. `EntityKind`
//! still models those kinds; they reach the graph via caller hints and the core
//! classifier, not via free-text regex here.

use super::{EntityKind, ExtractedEntity};
use crate::util::str_util::char_window;
use lazy_static::lazy_static;
use regex::Regex;

// Canonical locators from `core::classifier`. Re-exported under the legacy names
// so existing call sites keep compiling after the duplicate regex definitions
// were removed.
pub use crate::core::classifier::DOMAIN_RE as DOMAIN_PATTERN;
pub use crate::core::classifier::EMAIL_RE as EMAIL_PATTERN;
pub use crate::core::classifier::IPV4_RE as IPV4_PATTERN;
pub use crate::core::classifier::URL_RE as URL_PATTERN;

lazy_static! {
    // Social handle: @ + alphanumeric (Twitter, Instagram style)
    pub static ref SOCIAL_HANDLE: Regex = Regex::new(r"@[a-zA-Z0-9_]{1,30}").expect("valid social regex");

    // One MAXIMAL run of hex digits, bounded by word boundaries so a hex run
    // embedded in a longer alphanumeric token is not carved out of it. The
    // extractor classifies each run by its EXACT length (32/40/64/128) in
    // `extract_by_patterns`, rather than running one length-specific regex per
    // hash type. The old code ran independent {40} and {64} passes over the same
    // text, so every 64-char SHA-256 additionally surfaced a bogus 40-char
    // "SHA-1" — its own prefix — that dedup (keyed on `(kind, value)`) never
    // caught because the two values differ.
    pub static ref HEX_TOKEN: Regex = Regex::new(r"\b[0-9a-fA-F]+\b").expect("valid hex regex");
}

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

    // IPv4 extraction
    for cap in IPV4_PATTERN.find_iter(text) {
        let value = cap.as_str();
        // Validate not a broadcast or multicast
        if !value.starts_with("255.") && !value.starts_with("0.") {
            entities.push(ExtractedEntity {
                kind: EntityKind::Ipv4,
                value: value.to_string(),
                confidence: 0.90,
                context: extract_context(text, cap.start()),
                source_pattern: "ipv4_quad_decimal".to_string(),
                boost_reason: Some("Valid IPv4 range".to_string()),
            });
        }
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
