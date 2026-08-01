//! Entity enrichment and merging across MPC parties.
//!
//! Merges raw entity datasets from multiple parties while preserving all data:
//! - No truncation or redaction
//! - Full evidence chains preserved
//! - Confidence only increases (GREATEST semantics)
//! - Provenance tracked for all enrichment

use crate::core::entity::{Entity, Evidence};
use crate::core::mpc::protocol::PartyId;
use crate::core::mpc::EnrichmentResult;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Enriches local entities with data from remote parties.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Enricher {
    /// Local party identifier
    pub local_party: PartyId,
    /// Deduplicate entities across parties
    pub deduplicate: bool,
    /// Merge evidence from corroborating sources
    pub merge_evidence: bool,
}

impl Enricher {
    /// Create a new enricher for the local party.
    pub fn new(local_party: PartyId) -> Self {
        Self {
            local_party,
            deduplicate: true,
            merge_evidence: true,
        }
    }

    /// Enrich local entities with data from remote parties.
    ///
    /// Merges entities by UID, preserving all data:
    /// - Combines evidence from all sources
    /// - Increases confidence via GREATEST semantics
    /// - Tracks provenance of enrichment
    ///
    /// # Arguments
    /// - `local_entities`: Local party's entity dataset
    /// - `remote_datasets`: Entity datasets from remote parties with their PartyId
    ///
    /// # Returns
    /// Enriched entity dataset and enrichment statistics
    pub fn enrich(
        &self,
        mut local_entities: Vec<Entity>,
        remote_datasets: Vec<(PartyId, Vec<Entity>)>,
    ) -> (Vec<Entity>, EnrichmentResult) {
        let original_count = local_entities.len();
        let mut enriched_by_uid: HashMap<String, Entity> =
            local_entities.into_iter().map(|e| (e.uid.clone(), e)).collect();

        let mut entities_enriched = 0;
        let mut entities_added = 0;
        let mut duplicates_merged = 0;

        for (remote_party, remote_entities) in remote_datasets {
            for remote_entity in remote_entities {
                if let Some(local_entity) = enriched_by_uid.get_mut(&remote_entity.uid) {
                    // Entity exists locally - enrich it
                    entities_enriched += 1;
                    duplicates_merged += 1;

                    // Merge confidence (GREATEST semantics)
                    if remote_entity.confidence > local_entity.confidence {
                        local_entity.confidence = remote_entity.confidence;
                    }

                    // Add remote entity's corroboration
                    local_entity.corroboration = local_entity.corroboration.saturating_add(
                        remote_entity.corroboration.saturating_sub(local_entity.corroboration)
                    );

                    // Add evidence from remote party
                    if self.merge_evidence {
                        self.merge_evidence_chains(local_entity, remote_entity, &remote_party);
                    }
                } else {
                    // New entity - add it with enrichment provenance
                    let mut enriched_entity = remote_entity.clone();
                    self.add_enrichment_evidence(&mut enriched_entity, &remote_party);
                    enriched_by_uid.insert(enriched_entity.uid.clone(), enriched_entity);
                    entities_added += 1;
                }
            }
        }

        let enriched_entities: Vec<Entity> = enriched_by_uid.into_values().collect();
        let enriched_count = enriched_entities.len();

        let result = EnrichmentResult {
            original_count,
            enriched_count,
            entities_enriched,
            entities_added,
            duplicates_merged,
            parties_count: remote_datasets.len() + 1, // +1 for local party
        };

        (enriched_entities, result)
    }

    /// Merge evidence chains from two entities.
    ///
    /// Preserves all evidence from both sources without redaction or truncation.
    fn merge_evidence_chains(&self, local: &mut Entity, remote: Entity, remote_party: &PartyId) {
        for mut remote_evidence in remote.evidence {
            // Mark evidence as coming from remote party
            remote_evidence = remote_evidence.with_attr(
                "mpc_source_party",
                remote_party.to_string(),
            );

            // Check if we already have identical evidence
            let exists = local.evidence.iter().any(|e| {
                e.source == remote_evidence.source
                    && e.summary == remote_evidence.summary
                    && e.attributes == remote_evidence.attributes
            });

            if !exists {
                local.evidence.push(remote_evidence);
            }
        }
    }

    /// Add evidence indicating this entity was enriched from a remote party.
    fn add_enrichment_evidence(&self, entity: &mut Entity, remote_party: &PartyId) {
        let mut evidence = Evidence::new(
            "mpc_enrichment",
            format!("Data enriched from party: {}", remote_party),
        )
        .with_attr("source_party", remote_party.to_string())
        .with_attr("enrichment_type", "remote_contribution")
        .with_attr("local_party", self.local_party.to_string());

        entity.evidence.push(evidence);
        entity.tags.push(format!("enriched_from:{}", remote_party));
    }

    /// Deduplicate entities by UID, keeping the highest-confidence version.
    pub fn deduplicate(entities: Vec<Entity>) -> Vec<Entity> {
        let mut by_uid: HashMap<String, Entity> = HashMap::new();

        for entity in entities {
            by_uid
                .entry(entity.uid.clone())
                .and_modify(|existing| {
                    // Keep highest confidence version
                    if entity.confidence > existing.confidence {
                        existing.confidence = entity.confidence;
                    }
                    // Accumulate corroboration
                    existing.corroboration = existing.corroboration.saturating_add(
                        entity.corroboration.saturating_sub(existing.corroboration)
                    );
                })
                .or_insert(entity);
        }

        by_uid.into_values().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::EntityKind;

    #[test]
    fn test_enricher_creation() {
        let enricher = Enricher::new(PartyId::new("local"));
        assert_eq!(enricher.local_party.0, "local");
        assert!(enricher.deduplicate);
        assert!(enricher.merge_evidence);
    }

    #[test]
    fn test_enrich_new_entities() {
        let enricher = Enricher::new(PartyId::new("local"));

        let local_entities = vec![Entity::new(
            EntityKind::Email,
            "alice@example.com",
            0.8,
            "scan_1",
        )];

        let remote_email = Entity::new(EntityKind::Email, "bob@example.com", 0.7, "scan_2");
        let remote_datasets = vec![(PartyId::new("party_a"), vec![remote_email])];

        let (enriched, result) = enricher.enrich(local_entities, remote_datasets);

        assert_eq!(result.original_count, 1);
        assert_eq!(result.enriched_count, 2); // 1 original + 1 new
        assert_eq!(result.entities_added, 1);
        assert_eq!(result.parties_count, 2);
    }

    #[test]
    fn test_enrich_existing_entity() {
        let enricher = Enricher::new(PartyId::new("local"));

        let mut local_entity =
            Entity::new(EntityKind::Email, "alice@example.com", 0.6, "scan_1");
        let uid = local_entity.uid.clone();

        let mut remote_entity =
            Entity::new(EntityKind::Email, "alice@example.com", 0.9, "scan_2");
        remote_entity.evidence.push(
            Evidence::new("remote_source", "Found in remote breach database")
                .with_attr("breach", "leaked_db_2024"),
        );

        let remote_datasets = vec![(PartyId::new("party_a"), vec![remote_entity])];

        let (enriched, result) = enricher.enrich(vec![local_entity], remote_datasets);

        assert_eq!(result.original_count, 1);
        assert_eq!(result.enriched_count, 1); // Same entity, just enriched
        assert_eq!(result.entities_enriched, 1);
        assert_eq!(result.duplicates_merged, 1);

        // Verify confidence was increased
        let merged = enriched.iter().find(|e| e.uid == uid).unwrap();
        assert_eq!(merged.confidence, 0.9);
    }

    #[test]
    fn test_deduplicate() {
        let entity_a =
            Entity::new(EntityKind::Email, "alice@example.com", 0.5, "scan_1");
        let entity_b =
            Entity::new(EntityKind::Email, "alice@example.com", 0.8, "scan_2");

        let entities = vec![entity_a, entity_b];
        let deduplicated = Enricher::deduplicate(entities);

        assert_eq!(deduplicated.len(), 1);
        assert_eq!(deduplicated[0].confidence, 0.8); // Keeps highest
    }

    #[test]
    fn test_evidence_preservation() {
        let enricher = Enricher::new(PartyId::new("local"));

        let mut local_entity = Entity::new(EntityKind::Email, "alice@example.com", 0.6, "scan_1");
        local_entity.evidence.push(
            Evidence::new("local_source", "Found locally")
                .with_attr("field1", "value1"),
        );

        let mut remote_entity =
            Entity::new(EntityKind::Email, "alice@example.com", 0.9, "scan_2");
        remote_entity.evidence.push(
            Evidence::new("remote_source", "Found remotely")
                .with_attr("field2", "value2"),
        );

        let remote_datasets = vec![(PartyId::new("party_a"), vec![remote_entity])];

        let (enriched, _) = enricher.enrich(vec![local_entity], remote_datasets);

        let merged = &enriched[0];
        // Should have both evidence records
        assert!(merged.evidence.iter().any(|e| e.source == "local_source"));
        assert!(merged.evidence.iter().any(|e| e.source == "remote_source"));
    }
}
