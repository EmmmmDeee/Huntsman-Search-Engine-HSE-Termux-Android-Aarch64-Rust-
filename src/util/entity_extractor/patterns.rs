//! Regex patterns for entity extraction + confidence boosters.
//!
//! EMAIL, IPv4, DOMAIN and URL patterns are re-exported from [`crate::core::classifier`]
//! so the document-ingestion pipeline and the scan engine share a single set of
//! canonical, lazily-compiled locators. Phone, IPv6, hashes, usernames, social
//! handles, person names and license IDs remain here because they are not part of
//! the core embedded-entity locator set.

use super::{EntityKind, ExtractedEntity};
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
    // Phone: E.164 format (optional + prefix, 7-15 digits)
    pub static ref PHONE_E164: Regex = Regex::new(r"\+?[1-9]\d{6,14}").expect("valid phone regex");

    // IPv6: simplified (colons + hex groups)
    pub static ref IPV6_PATTERN: Regex = Regex::new(
        r"(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}"
    ).expect("valid ipv6 regex");

    // Hash: MD5 (32 hex), SHA1 (40), SHA256 (64), SHA512 (128)
    pub static ref MD5_HASH: Regex = Regex::new(r"[a-fA-F0-9]{32}").expect("valid md5 regex");
    pub static ref SHA1_HASH: Regex = Regex::new(r"[a-fA-F0-9]{40}").expect("valid sha1 regex");
    pub static ref SHA256_HASH: Regex = Regex::new(r"[a-fA-F0-9]{64}").expect("valid sha256 regex");
    pub static ref SHA512_HASH: Regex = Regex::new(r"[a-fA-F0-9]{128}").expect("valid sha512 regex");

    // Username: alphanumeric + underscore/dash (3-32 chars)
    pub static ref USERNAME_PATTERN: Regex = Regex::new(r"[a-zA-Z0-9_-]{3,32}").expect("valid username regex");

    // Social handle: @ + alphanumeric (Twitter, Instagram style)
    pub static ref SOCIAL_HANDLE: Regex = Regex::new(r"@[a-zA-Z0-9_]{1,30}").expect("valid social regex");

    // Person name: Title-cased words (heuristic: Name Surname)
    pub static ref PERSON_NAME: Regex = Regex::new(r"[A-Z][a-z]+\s+[A-Z][a-z]+").expect("valid person regex");

    // License/ID: Uppercase alphanumeric (8-20 chars, like "AB123CD456")
    pub static ref LICENSE_ID: Regex = Regex::new(r"[A-Z0-9]{6,20}").expect("valid license regex");
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

    // Hash extraction
    for cap in SHA256_HASH.find_iter(text) {
        entities.push(ExtractedEntity {
            kind: EntityKind::Hash,
            value: cap.as_str().to_lowercase(),
            confidence: 0.95, // 256-bit hashes almost always intentional
            context: extract_context(text, cap.start()),
            source_pattern: "hash_sha256".to_string(),
            boost_reason: Some("SHA256 (256-bit) high specificity".to_string()),
        });
    }

    for cap in SHA1_HASH.find_iter(text) {
        entities.push(ExtractedEntity {
            kind: EntityKind::Hash,
            value: cap.as_str().to_lowercase(),
            confidence: 0.90,
            context: extract_context(text, cap.start()),
            source_pattern: "hash_sha1".to_string(),
            boost_reason: Some("SHA1 (160-bit) high specificity".to_string()),
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
fn extract_context(text: &str, pos: usize) -> Option<String> {
    let start = pos.saturating_sub(20);
    let end = (pos + 40).min(text.len());
    Some(text[start..end].to_string())
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
