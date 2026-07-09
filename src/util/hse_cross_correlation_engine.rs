/// HSE Cross-Correlation Engine
///
/// Advanced multi-source entity correlation with accuracy enhancement:
/// - Entity fingerprinting and canonical normalization
/// - Multi-pivot correlation (username → email → phone → IP → location)
/// - Confidence scoring based on source agreement
/// - Temporal consistency validation
/// - Infrastructure-level correlation (shared hosting, DNS, AS numbers)
/// - Graph-based relationship discovery
/// - False positive elimination through multi-source verification

use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;

/// Entity types that can be correlated
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EntityType {
    Username,      // Social media, gaming, developer profiles
    Email,         // Primary email address
    Phone,         // Telephone number (normalized)
    Domain,        // Domain name or website
    IpAddress,     // IPv4/IPv6 address
    Location,      // Geographic location (city, region)
    NamePerson,    // Full name of person
    Organization,  // Company/organization name
    SocialHandle,  // Platform-specific handle
    Credential,    // Username:password pair
    Hash,          // Password hash
    Infrastructure, // Hosting provider, ASN, etc
    FileHash,      // File hash (MD5, SHA1, SHA256)
    DomainEmail,   // Email on domain (admin@domain.com)
}

/// Correlation pivot (how entities are connected)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CorrelationPivot {
    SameUsername,           // Same username across platforms
    SameEmail,              // Same email in multiple sources
    SamePhone,              // Same phone number
    SameName,               // Same person name
    SameLocation,           // Same geographic location (within region)
    SameInfrastructure,     // Same hosting/ASN
    NameEmailMatch,         // Name + Email combination
    ProfileMetadata,        // Shared profile metadata (bio, avatar)
    RelatedUsernames,       // Username variants (rhino-ryno23 ≈ rhino_ryno23)
    BreachConnection,       // Same breach corpus
    CredentialMatch,        // Same username:password
    TimestampProximity,     // Events within same timeframe
    GeoProximity,           // Geographic clustering
    SocialRelation,         // Direct social connection
    InfrastructureShare,    // Shared server/IP block
    DnsRecord,              // Same DNS record
    WhoisData,              // Same WHOIS registrant
}

/// Correlation result
#[derive(Debug, Clone)]
pub struct Correlation {
    pub source_entity: Entity,
    pub target_entity: Entity,
    pub pivot: CorrelationPivot,
    pub confidence: f32,  // 0.0-1.0
    pub sources: Vec<String>,  // APIs that found this correlation
    pub evidence: Vec<String>,  // Specific matching fields
    pub temporal_span: Option<(u64, u64)>,  // First seen, last seen (Unix timestamps)
}

/// Entity representation
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Entity {
    pub entity_type: EntityType,
    pub value: String,
    pub canonical: String,  // Normalized form for correlation
    pub platform: Option<String>,
    pub metadata: HashMap<String, String>,
}

impl Hash for Entity {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.entity_type.hash(state);
        self.canonical.hash(state);
    }
}

impl Entity {
    /// Create normalized canonical form
    pub fn new(entity_type: EntityType, value: &str, platform: Option<&str>) -> Self {
        let canonical = Self::canonicalize(&entity_type, value);
        Self {
            entity_type,
            value: value.to_string(),
            canonical,
            platform: platform.map(|p| p.to_string()),
            metadata: HashMap::new(),
        }
    }

    /// Normalize entity for reliable correlation
    fn canonicalize(entity_type: &EntityType, value: &str) -> String {
        match entity_type {
            EntityType::Username => {
                value
                    .to_lowercase()
                    .chars()
                    .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
                    .collect()
            }
            EntityType::Email => value.to_lowercase().trim().to_string(),
            EntityType::Phone => {
                // Remove all non-digits
                value.chars().filter(|c| c.is_numeric()).collect()
            }
            EntityType::Domain => value.to_lowercase().trim_matches('.').to_string(),
            EntityType::IpAddress => value.to_string(), // Already normalized
            EntityType::NamePerson => {
                value
                    .to_lowercase()
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ")
            }
            EntityType::Location => value.to_lowercase(),
            _ => value.to_lowercase(),
        }
    }
}

/// Cross-correlation engine
pub struct CrossCorrelationEngine {
    entities: HashMap<Entity, Vec<Entity>>,  // Entity → correlated entities
    correlations: Vec<Correlation>,
    confidence_thresholds: ConfidenceThresholds,
}

/// Confidence thresholds for different correlation types
#[derive(Debug, Clone)]
pub struct ConfidenceThresholds {
    pub direct_match: f32,           // 0.95
    pub multi_source: f32,           // 0.85
    pub metadata_match: f32,         // 0.75
    pub temporal_proximity: f32,     // 0.70
    pub infrastructure_share: f32,   // 0.65
    pub minimum_acceptable: f32,     // 0.60
}

impl Default for ConfidenceThresholds {
    fn default() -> Self {
        Self {
            direct_match: 0.95,
            multi_source: 0.85,
            metadata_match: 0.75,
            temporal_proximity: 0.70,
            infrastructure_share: 0.65,
            minimum_acceptable: 0.60,
        }
    }
}

impl CrossCorrelationEngine {
    pub fn new() -> Self {
        Self {
            entities: HashMap::new(),
            correlations: Vec::new(),
            confidence_thresholds: ConfidenceThresholds::default(),
        }
    }

    /// Add entity to correlation graph
    pub fn add_entity(&mut self, entity: Entity) {
        self.entities.entry(entity.clone()).or_insert_with(Vec::new);
    }

    /// Correlate two entities with confidence scoring
    pub fn correlate(
        &mut self,
        source: Entity,
        target: Entity,
        pivot: CorrelationPivot,
        sources: Vec<String>,
        evidence: Vec<String>,
    ) -> Correlation {
        let confidence = self.calculate_correlation_confidence(&pivot, &sources, &evidence);

        let correlation = Correlation {
            source_entity: source.clone(),
            target_entity: target.clone(),
            pivot,
            confidence,
            sources,
            evidence,
            temporal_span: None,
        };

        self.entities
            .entry(source)
            .or_insert_with(Vec::new)
            .push(target);

        self.correlations.push(correlation.clone());
        correlation
    }

    /// Calculate confidence based on pivot type and evidence
    fn calculate_correlation_confidence(
        &self,
        pivot: &CorrelationPivot,
        sources: &[String],
        evidence: &[String],
    ) -> f32 {
        let mut confidence = match pivot {
            CorrelationPivot::SameUsername | CorrelationPivot::SameEmail | CorrelationPivot::SamePhone => {
                self.confidence_thresholds.direct_match
            }
            CorrelationPivot::NameEmailMatch | CorrelationPivot::CredentialMatch => {
                self.confidence_thresholds.multi_source
            }
            CorrelationPivot::ProfileMetadata | CorrelationPivot::NameEmailMatch => {
                self.confidence_thresholds.metadata_match
            }
            CorrelationPivot::TimestampProximity | CorrelationPivot::GeoProximity => {
                self.confidence_thresholds.temporal_proximity
            }
            CorrelationPivot::InfrastructureShare | CorrelationPivot::SameInfrastructure => {
                self.confidence_thresholds.infrastructure_share
            }
            _ => 0.7,
        };

        // Boost confidence with multiple sources
        if sources.len() >= 3 {
            confidence = (confidence + 0.10).min(0.99);
        } else if sources.len() >= 2 {
            confidence = (confidence + 0.05).min(0.99);
        }

        // Boost confidence with strong evidence
        if evidence.len() >= 5 {
            confidence = (confidence + 0.08).min(0.99);
        } else if evidence.len() >= 3 {
            confidence = (confidence + 0.04).min(0.99);
        }

        confidence
    }

    /// Find all entities correlated to a given entity
    pub fn find_correlations(&self, entity: &Entity) -> Vec<Correlation> {
        self.correlations
            .iter()
            .filter(|c| c.source_entity == *entity || c.target_entity == *entity)
            .cloned()
            .collect()
    }

    /// Get correlation graph depth (transitive correlations)
    pub fn find_transitive_correlations(&self, entity: &Entity, max_depth: u32) -> Vec<(Entity, u32, f32)> {
        let mut found = Vec::new();
        let mut queue = vec![(entity.clone(), 0u32, 1.0f32)];
        let mut visited = HashSet::new();

        while let Some((current, depth, cumulative_confidence)) = queue.pop() {
            if depth >= max_depth || visited.contains(&current) {
                continue;
            }
            visited.insert(current.clone());

            for correlation in self.find_correlations(&current) {
                let next_entity = if correlation.source_entity == current {
                    correlation.target_entity.clone()
                } else {
                    correlation.source_entity.clone()
                };

                let confidence = cumulative_confidence * correlation.confidence;
                found.push((next_entity.clone(), depth + 1, confidence));
                queue.push((next_entity, depth + 1, confidence));
            }
        }

        found
    }

    /// Validate correlations for false positives
    pub fn validate_correlation(&self, correlation: &Correlation) -> ValidationResult {
        let mut score = correlation.confidence;
        let mut flags = Vec::new();

        // Check for common false positive patterns
        if correlation.sources.len() == 1 {
            flags.push("Single source only".to_string());
            score -= 0.15;
        }

        if correlation.evidence.is_empty() {
            flags.push("No supporting evidence".to_string());
            score -= 0.25;
        }

        if correlation.evidence.len() == 1 {
            flags.push("Minimal evidence (1 field)".to_string());
            score -= 0.10;
        }

        // Check for infrastructure-level false positives
        if matches!(
            correlation.pivot,
            CorrelationPivot::SameInfrastructure | CorrelationPivot::InfrastructureShare
        ) && score < 0.75
        {
            flags.push("Infrastructure correlation below threshold".to_string());
        }

        let is_valid = score >= self.confidence_thresholds.minimum_acceptable && flags.is_empty();

        ValidationResult {
            is_valid,
            confidence_score: score.max(0.0),
            flags,
            recommendation: if is_valid {
                "ACCEPT".to_string()
            } else if score >= 0.65 {
                "REVIEW".to_string()
            } else {
                "REJECT".to_string()
            },
        }
    }

    /// Get correlation statistics
    pub fn get_statistics(&self) -> CorrelationStatistics {
        let total_correlations = self.correlations.len();
        let avg_confidence = if total_correlations > 0 {
            self.correlations.iter().map(|c| c.confidence).sum::<f32>() / total_correlations as f32
        } else {
            0.0
        };

        let high_confidence = self
            .correlations
            .iter()
            .filter(|c| c.confidence >= 0.85)
            .count();

        let multi_source = self
            .correlations
            .iter()
            .filter(|c| c.sources.len() >= 2)
            .count();

        let pivot_distribution = {
            let mut dist = HashMap::new();
            for corr in &self.correlations {
                *dist.entry(format!("{:?}", corr.pivot)).or_insert(0) += 1;
            }
            dist
        };

        CorrelationStatistics {
            total_entities: self.entities.len(),
            total_correlations,
            average_confidence: avg_confidence,
            high_confidence_count: high_confidence,
            multi_source_count: multi_source,
            pivot_distribution,
        }
    }
}

/// Validation result for correlation
#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub is_valid: bool,
    pub confidence_score: f32,
    pub flags: Vec<String>,
    pub recommendation: String,
}

/// Statistics about correlations
#[derive(Debug, Clone)]
pub struct CorrelationStatistics {
    pub total_entities: usize,
    pub total_correlations: usize,
    pub average_confidence: f32,
    pub high_confidence_count: usize,
    pub multi_source_count: usize,
    pub pivot_distribution: HashMap<String, usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entity_canonicalization() {
        let entity = Entity::new(EntityType::Username, "Rhino-RyNo23", None);
        assert_eq!(entity.canonical, "rhino-ryno23");

        let email = Entity::new(EntityType::Email, "  USER@EXAMPLE.COM  ", None);
        assert_eq!(email.canonical, "user@example.com");

        let phone = Entity::new(EntityType::Phone, "+1 (555) 123-4567", None);
        assert_eq!(phone.canonical, "15551234567");
    }

    #[test]
    fn test_direct_correlation() {
        let mut engine = CrossCorrelationEngine::new();

        let user1 = Entity::new(EntityType::Username, "rhino-ryno23", Some("twitter"));
        let user2 = Entity::new(EntityType::Username, "rhino-ryno23", Some("instagram"));

        engine.add_entity(user1.clone());
        engine.add_entity(user2.clone());

        let correlation = engine.correlate(
            user1.clone(),
            user2.clone(),
            CorrelationPivot::SameUsername,
            vec!["api1".to_string(), "api2".to_string()],
            vec!["username_match".to_string()],
        );

        assert!(correlation.confidence >= 0.90);
        assert_eq!(correlation.sources.len(), 2);
    }

    #[test]
    fn test_multi_source_confidence_boost() {
        let mut engine = CrossCorrelationEngine::new();

        let entity1 = Entity::new(EntityType::Email, "user@example.com", None);
        let entity2 = Entity::new(EntityType::Username, "user123", None);

        engine.add_entity(entity1.clone());
        engine.add_entity(entity2.clone());

        let correlation = engine.correlate(
            entity1.clone(),
            entity2.clone(),
            CorrelationPivot::NameEmailMatch,
            vec!["hibp".to_string(), "leakdb".to_string(), "dehashed".to_string()],
            vec!["name_match".to_string(), "email_match".to_string(), "registration_date".to_string()],
        );

        // Should be boosted by multi-source and strong evidence
        assert!(correlation.confidence >= 0.90);
    }

    #[test]
    fn test_correlation_validation() {
        let mut engine = CrossCorrelationEngine::new();

        let entity1 = Entity::new(EntityType::Username, "test1", None);
        let entity2 = Entity::new(EntityType::Username, "test2", None);

        engine.add_entity(entity1.clone());
        engine.add_entity(entity2.clone());

        let weak_correlation = engine.correlate(
            entity1.clone(),
            entity2.clone(),
            CorrelationPivot::SameInfrastructure,
            vec!["api1".to_string()],
            vec![],  // No evidence
        );

        let validation = engine.validate_correlation(&weak_correlation);
        assert!(!validation.is_valid);
        assert_eq!(validation.recommendation, "REJECT");
    }

    #[test]
    fn test_transitive_correlation() {
        let mut engine = CrossCorrelationEngine::new();

        let user1 = Entity::new(EntityType::Username, "user1", None);
        let email1 = Entity::new(EntityType::Email, "user1@example.com", None);
        let phone1 = Entity::new(EntityType::Phone, "5551234567", None);

        engine.add_entity(user1.clone());
        engine.add_entity(email1.clone());
        engine.add_entity(phone1.clone());

        engine.correlate(
            user1.clone(),
            email1.clone(),
            CorrelationPivot::SameEmail,
            vec!["api1".to_string()],
            vec!["email_match".to_string()],
        );

        engine.correlate(
            email1.clone(),
            phone1.clone(),
            CorrelationPivot::SamePhone,
            vec!["api2".to_string()],
            vec!["phone_match".to_string()],
        );

        let transitive = engine.find_transitive_correlations(&user1, 3);
        assert!(transitive.iter().any(|(e, _, _)| e == &phone1));
    }

    #[test]
    fn test_statistics() {
        let mut engine = CrossCorrelationEngine::new();

        let user1 = Entity::new(EntityType::Username, "user1", None);
        let user2 = Entity::new(EntityType::Username, "user2", None);
        let email1 = Entity::new(EntityType::Email, "user@example.com", None);

        engine.add_entity(user1.clone());
        engine.add_entity(user2.clone());
        engine.add_entity(email1.clone());

        engine.correlate(
            user1.clone(),
            email1.clone(),
            CorrelationPivot::SameEmail,
            vec!["api1".to_string(), "api2".to_string()],
            vec!["match".to_string()],
        );

        engine.correlate(
            user2.clone(),
            email1.clone(),
            CorrelationPivot::SameEmail,
            vec!["api1".to_string()],
            vec!["match".to_string()],
        );

        let stats = engine.get_statistics();
        assert_eq!(stats.total_entities, 3);
        assert_eq!(stats.total_correlations, 2);
        assert!(stats.average_confidence > 0.0);
    }
}
