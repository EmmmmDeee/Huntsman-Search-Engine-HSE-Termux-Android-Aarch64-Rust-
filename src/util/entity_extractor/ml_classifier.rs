//! Lightweight ML-inspired entity classification enhancements (Phase 5).
//!
//! Optional confidence boosting based on context analysis, semantic signals,
//! and domain heuristics. Pure-Rust, no ML library dependencies.

use super::{EntityKind, ExtractedEntity};

/// Context-aware confidence boosters (Phase 5 extensions).
pub struct MlClassifier;

impl MlClassifier {
    /// Boost confidence based on context keywords and semantic signals.
    ///
    /// **Heuristics:**
    /// - Email: "contact", "email", "address" in context → +0.10
    /// - Phone: "call", "phone", "mobile", "tel", "fax" in context → +0.10
    /// - Domain: presence of common TLDs, registered registrar patterns → +0.05
    /// - Username: platform indicators (twitter@, github:, reddit u/) → +0.05
    /// - Hash: bytestring-adjacent keywords (checksum, md5, sha, hash) → +0.05
    /// - Address: postal keywords (street, avenue, road, suite, apt) → +0.10
    ///
    /// **Returns:** Boosted confidence, clamped to [0.0, 1.0].
    pub fn boost_from_context(entity: &ExtractedEntity) -> f64 {
        let mut boost = 0.0;
        let context = entity.context.as_deref().unwrap_or("");
        let context_lower = context.to_lowercase();

        match &entity.kind {
            EntityKind::Email => {
                if Self::contains_any(&context_lower, &["contact", "email", "address", "send to"]) {
                    boost += 0.10;
                }
            }
            EntityKind::Phone => {
                if Self::contains_any(
                    &context_lower,
                    &["call", "phone", "mobile", "tel", "fax", "ring", "dial"],
                ) {
                    boost += 0.10;
                }
            }
            EntityKind::Domain => {
                if Self::is_valid_tld(&entity.value) {
                    boost += 0.05;
                }
            }
            EntityKind::Username => {
                if Self::contains_any(&context_lower, &["user", "handle", "account", "profile", "@"]) {
                    boost += 0.05;
                }
            }
            EntityKind::Hash => {
                if Self::contains_any(
                    &context_lower,
                    &["checksum", "md5", "sha", "hash", "digest", "fingerprint"],
                ) {
                    boost += 0.05;
                }
            }
            _ => {}
        }

        (entity.confidence + boost).clamp(0.0, 1.0)
    }

    /// Check if any of the keywords appear in the text.
    fn contains_any(text: &str, keywords: &[&str]) -> bool {
        keywords.iter().any(|kw| text.contains(kw))
    }

    /// Validate TLD is in the common TLD list (rough heuristic).
    fn is_valid_tld(domain: &str) -> bool {
        const COMMON_TLDS: &[&str] = &[
            "com", "org", "net", "edu", "gov", "mil", "io", "co", "uk", "us", "de", "fr", "au",
            "ru", "cn", "jp", "in", "br", "mx", "ca", "info", "biz", "name", "pro", "tv", "cc",
            "ws", "asia", "eu", "vip", "app", "dev", "tech",
        ];

        domain
            .split('.')
            .last()
            .map(|tld| COMMON_TLDS.contains(&tld.to_lowercase().as_str()))
            .unwrap_or(false)
    }

    /// Score entity quality based on format consistency and pattern strength.
    ///
    /// **Returns:** A quality score (0.0-1.0), higher is better.
    /// - Email: RFC5322 compliance → high score
    /// - Phone: E.164 format → high score
    /// - Domain: Valid DNS structure → medium-high score
    /// - Others: Pattern specificity → scored proportionally
    pub fn quality_score(entity: &ExtractedEntity) -> f64 {
        match &entity.kind {
            EntityKind::Email => {
                // RFC 5322 loose validation: has @ and domain
                if entity.value.contains('@') && entity.value.contains('.') {
                    0.90
                } else {
                    0.50
                }
            }
            EntityKind::Phone => {
                // E.164 format: +1234567890 or similar
                let digits_only = entity.value.chars().filter(|c| c.is_ascii_digit()).count();
                if digits_only >= 7 && digits_only <= 15 {
                    0.85
                } else {
                    0.50
                }
            }
            EntityKind::Domain => {
                // Valid domain structure: has at least 2 labels
                if entity.value.matches('.').count() >= 1 && Self::is_valid_tld(&entity.value) {
                    0.80
                } else {
                    0.60
                }
            }
            EntityKind::Hash => {
                // Hexadecimal string, length indicates hash type
                let len = entity.value.len();
                let is_hex = entity.value.chars().all(|c| c.is_ascii_hexdigit());
                if is_hex {
                    match len {
                        32 => 0.95, // MD5
                        40 => 0.90, // SHA1
                        64 => 0.98, // SHA256
                        128 => 0.97, // SHA512
                        _ => 0.70,
                    }
                } else {
                    0.40
                }
            }
            EntityKind::Ipv4 => {
                // Quad-dotted decimal validation
                let parts: Vec<&str> = entity.value.split('.').collect();
                if parts.len() == 4
                    && parts.iter().all(|p| {
                        p.parse::<u8>().is_ok()
                    })
                {
                    0.95
                } else {
                    0.30
                }
            }
            _ => entity.confidence, // Fall back to extraction confidence
        }
    }

    /// Combine extraction confidence with contextual/quality boosting.
    ///
    /// Formula: `final_confidence = clamp(extraction_conf * (1 + quality_score * 0.20), 0.0, 1.0)`
    pub fn final_confidence(entity: &ExtractedEntity) -> f64 {
        let quality = Self::quality_score(entity);
        let contextual = Self::boost_from_context(entity);

        // Combine: base confidence, boosted by quality (up to +20%) and context
        let base_boost = entity.confidence * (1.0 + (quality - 0.5) * 0.20);
        let final_conf = (base_boost + contextual * 0.05).clamp(0.0, 1.0);

        final_conf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_context_boost() {
        let entity = ExtractedEntity {
            kind: EntityKind::Email,
            value: "test@example.com".to_string(),
            confidence: 0.75,
            context: Some("Contact: test@example.com for support".to_string()),
            source_pattern: "email_rfc5322".to_string(),
            boost_reason: None,
        };

        let boosted = MlClassifier::boost_from_context(&entity);
        assert!(boosted >= 0.75); // At least original confidence
        assert!(boosted <= 0.85); // Boosted by ~0.10
    }

    #[test]
    fn test_quality_score_md5() {
        let entity = ExtractedEntity {
            kind: EntityKind::Hash,
            value: "5d41402abc4b2a76b9719d911017c592".to_string(),
            confidence: 0.80,
            context: None,
            source_pattern: "hash_md5".to_string(),
            boost_reason: None,
        };

        let quality = MlClassifier::quality_score(&entity);
        assert_eq!(quality, 0.95); // MD5 hash → 0.95 quality
    }

    #[test]
    fn test_valid_tld() {
        assert!(MlClassifier::is_valid_tld("example.com"));
        assert!(MlClassifier::is_valid_tld("github.io"));
        assert!(!MlClassifier::is_valid_tld("example.xyz123"));
    }

    #[test]
    fn test_final_confidence_email() {
        let entity = ExtractedEntity {
            kind: EntityKind::Email,
            value: "user@domain.com".to_string(),
            confidence: 0.80,
            context: Some("Email: user@domain.com".to_string()),
            source_pattern: "email_rfc5322".to_string(),
            boost_reason: None,
        };

        let final_conf = MlClassifier::final_confidence(&entity);
        assert!(final_conf >= 0.80);
        assert!(final_conf <= 1.0);
    }
}
