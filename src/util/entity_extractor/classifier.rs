//! Entity kind classifier with heuristic-based detection + confidence boosting.
//!
//! This module now delegates canonical kind detection to [`crate::core::classifier`],
//! so there is a single source of truth for entity classification. The local
//! `EntityClassifier` keeps only the context-aware confidence-boosting logic used
//! by the document-ingestion pipeline.

use super::{EntityKind, ExtractedEntity, ExtractionResult};
use crate::core::classifier as core_classifier;
use crate::core::entity::EntityKind as CoreEntityKind;

/// Map a canonical core [`EntityKind`](crate::core::entity::EntityKind) back to the
/// extractor's local taxonomy.
fn core_kind_to_extractor(core: &CoreEntityKind, value: &str) -> EntityKind {
    match core {
        CoreEntityKind::Email => EntityKind::Email,
        CoreEntityKind::Phone => EntityKind::Phone,
        CoreEntityKind::IpAddress => {
            if value.contains(':') {
                EntityKind::Ipv6
            } else {
                EntityKind::Ipv4
            }
        }
        CoreEntityKind::Domain => EntityKind::Domain,
        CoreEntityKind::Url => EntityKind::Url,
        CoreEntityKind::Username => EntityKind::Username,
        CoreEntityKind::Person => EntityKind::Person,
        CoreEntityKind::Organisation => EntityKind::Organization,
        CoreEntityKind::Cidr => EntityKind::IpRange,
        CoreEntityKind::Other(s) if s == "hash" => EntityKind::Hash,
        CoreEntityKind::Other(s) => EntityKind::Unknown(s.clone()),
        // Core kinds not represented in the extractor taxonomy (Credential, ApiKey,
        // Password, Asn, Address, Coordinates, MacAddress, DeviceId, Ssid,
        // TrackingId, …) map to Unknown so the extractor never invents its own
        // type decision.
        _ => EntityKind::Unknown("unclassified".to_string()),
    }
}

/// Classifier for assigning entity kinds + confidence scores.
pub struct EntityClassifier;

impl EntityClassifier {
    /// Create a new classifier with built-in heuristics.
    ///
    /// The underlying regex patterns are compiled lazily on first access and
    /// shared across all classifier instances.
    pub fn new() -> ExtractionResult<Self> {
        Ok(Self)
    }

    /// Classify an entity and assign kind + confidence.
    ///
    /// Delegates to the canonical [`crate::core::classifier::classify`] so the
    /// extractor and the engine agree on type decisions. A caller-supplied hint
    /// still takes precedence.
    pub fn classify(&self, value: &str, hint_kind: Option<EntityKind>) -> EntityKind {
        // If hint provided, prefer it
        if let Some(kind) = hint_kind {
            return kind;
        }

        core_kind_to_extractor(&core_classifier::classify(value).kind, value)
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
                if let Some(tld) = entity.value.split('.').next_back()
                    && common_tlds.contains(&tld)
                {
                    entity.confidence = (base_confidence + 0.05).min(1.0);
                    entity.boost_reason = Some(format!("Known TLD: {tld}"));
                }
            }
            // Boost if not in private ranges
            EntityKind::Ipv4 if !is_private_ipv4(&entity.value) => {
                entity.confidence = (base_confidence + 0.05).min(1.0);
                entity.boost_reason = Some("Public IPv4 range".to_string());
            }
            _ => {}
        }
    }
}

impl Default for EntityClassifier {
    fn default() -> Self {
        Self::new().expect("should succeed")
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
        return a == 10 || (a == 172 && (16..=31).contains(&b)) || (a == 192 && b == 168);
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_email() {
        let classifier = EntityClassifier::new().expect("should succeed");
        assert_eq!(
            classifier.classify("test@example.com", None),
            EntityKind::Email
        );
    }

    #[test]
    fn classify_ipv4() {
        let classifier = EntityClassifier::new().expect("should succeed");
        assert_eq!(classifier.classify("192.168.1.1", None), EntityKind::Ipv4);
    }

    #[test]
    fn boost_email_confidence() {
        let classifier = EntityClassifier::new().expect("should succeed");
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
