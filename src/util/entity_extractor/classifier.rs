//! Entity kind classifier with heuristic-based detection + confidence boosting.

use super::{EntityKind, ExtractedEntity, ExtractionResult};
use regex::Regex;
use std::collections::HashMap;
use tracing::debug;

/// Classifier for assigning entity kinds + confidence scores.
pub struct EntityClassifier {
    // Heuristic rules for kind detection
    kind_patterns: HashMap<EntityKind, Vec<Regex>>,
}

impl EntityClassifier {
    /// Create a new classifier with built-in heuristics.
    pub fn new() -> ExtractionResult<Self> {
        let mut kind_patterns: HashMap<EntityKind, Vec<Regex>> = HashMap::new();

        // Email: must have @ and valid domain structure
        kind_patterns.insert(
            EntityKind::Email,
            vec![Regex::new(r"^[^@]+@[^@]+\.[a-z]{2,}$").unwrap()],
        );

        // Phone: 7-15 digits, optional +
        kind_patterns.insert(
            EntityKind::Phone,
            vec![Regex::new(r"^\+?[1-9]\d{6,14}$").unwrap()],
        );

        // IPv4: 4 octets
        kind_patterns.insert(
            EntityKind::Ipv4,
            vec![Regex::new(r"^(\d{1,3}\.){3}\d{1,3}$").unwrap()],
        );

        // Domain: labels + TLD
        kind_patterns.insert(
            EntityKind::Domain,
            vec![Regex::new(r"^([a-z0-9-]+\.)+[a-z]{2,}$").unwrap()],
        );

        Ok(Self { kind_patterns })
    }

    /// Classify an entity and assign kind + confidence.
    pub fn classify(&self, value: &str, hint_kind: Option<EntityKind>) -> EntityKind {
        // If hint provided, prefer it
        if let Some(kind) = hint_kind {
            return kind;
        }

        // Heuristic: Try to infer from value format
        if value.contains('@') && !value.contains(' ') {
            return EntityKind::Email;
        }

        if value.split('.').all(|part| part.parse::<u8>().is_ok()) {
            return EntityKind::Ipv4;
        }

        if value.contains(':') && value.len() > 10 {
            return EntityKind::Ipv6;
        }

        if value.starts_with("http://") || value.starts_with("https://") {
            return EntityKind::Url;
        }

        // Regex validation against patterns
        for (kind, patterns) in &self.kind_patterns {
            for pattern in patterns {
                if pattern.is_match(value) {
                    return kind.clone();
                }
            }
        }

        // Default to Unknown
        EntityKind::Unknown("unclassified".to_string())
    }

    /// Boost confidence based on contextual validation.
    pub fn boost_confidence(&self, entity: &mut ExtractedEntity, context: &str) {
        let base_confidence = entity.confidence;

        match entity.kind {
            EntityKind::Email => {
                // Boost if surrounded by email keywords
                if context.to_lowercase().contains("email")
                    || context.to_lowercase().contains("contact")
                {
                    entity.confidence = (base_confidence + 0.10).min(1.0);
                    entity.boost_reason = Some("Email context keywords found".to_string());
                }
            }
            EntityKind::Phone => {
                // Boost if surrounded by phone keywords
                if context.to_lowercase().contains("phone")
                    || context.to_lowercase().contains("call")
                {
                    entity.confidence = (base_confidence + 0.10).min(1.0);
                    entity.boost_reason = Some("Phone context keywords found".to_string());
                }
            }
            EntityKind::Domain => {
                // Boost if TLD is known (not exhaustive, just common ones)
                let common_tlds = [
                    "com", "org", "net", "gov", "edu", "io", "au", "uk", "de", "fr",
                ];
                if let Some(tld) = entity.value.split('.').last() {
                    if common_tlds.contains(&tld) {
                        entity.confidence = (base_confidence + 0.05).min(1.0);
                        entity.boost_reason = Some(format!("Known TLD: {}", tld));
                    }
                }
            }
            EntityKind::Ipv4 => {
                // Boost if not in private ranges
                if !is_private_ipv4(&entity.value) {
                    entity.confidence = (base_confidence + 0.05).min(1.0);
                    entity.boost_reason = Some("Public IPv4 range".to_string());
                }
            }
            _ => {}
        }
    }
}

impl Default for EntityClassifier {
    fn default() -> Self {
        Self::new().unwrap()
    }
}

/// Check if IPv4 is in private range (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).
fn is_private_ipv4(ip: &str) -> bool {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return false;
    }

    if let (Ok(a), Ok(b), _, _) = (
        parts[0].parse::<u8>(),
        parts[1].parse::<u8>(),
        parts[2].parse::<u8>(),
        parts[3].parse::<u8>(),
    ) {
        return a == 10 || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168);
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_email() {
        let classifier = EntityClassifier::new().unwrap();
        assert_eq!(
            classifier.classify("test@example.com", None),
            EntityKind::Email
        );
    }

    #[test]
    fn classify_ipv4() {
        let classifier = EntityClassifier::new().unwrap();
        assert_eq!(
            classifier.classify("192.168.1.1", None),
            EntityKind::Ipv4
        );
    }

    #[test]
    fn boost_email_confidence() {
        let classifier = EntityClassifier::new().unwrap();
        let mut entity = ExtractedEntity {
            kind: EntityKind::Email,
            value: "test@example.com".to_string(),
            confidence: 0.70,
            context: None,
            source_pattern: "test".to_string(),
            boost_reason: None,
        };
        classifier.boost_confidence(&mut entity, "Contact email: test@example.com");
        assert!(entity.confidence > 0.70);
    }

    #[test]
    fn private_ipv4_detection() {
        assert!(is_private_ipv4("10.0.0.1"));
        assert!(is_private_ipv4("172.16.0.1"));
        assert!(is_private_ipv4("192.168.1.1"));
        assert!(!is_private_ipv4("8.8.8.8"));
        assert!(!is_private_ipv4("1.1.1.1"));
    }
}
