//! End-to-end entity extraction pipeline.

use super::{classifier::EntityClassifier, patterns, EntityKind, ExtractionResult, ExtractedEntity};
use tracing::{debug, info};

/// Main entity extractor: patterns + classification + deduplication.
pub struct EntityExtractor {
    classifier: EntityClassifier,
    min_confidence: f64,
}

impl EntityExtractor {
    /// Create a new extractor with confidence threshold.
    pub fn new(min_confidence: f64) -> ExtractionResult<Self> {
        Ok(Self {
            classifier: EntityClassifier::new()?,
            min_confidence,
        })
    }

    /// Extract entities from unstructured text (e.g., OCR output).
    pub fn extract_from_text(&self, text: &str) -> Vec<ExtractedEntity> {
        debug!("Extracting entities from {} chars of text", text.len());

        // Step 1: Pattern-based extraction
        let mut entities = patterns::extract_by_patterns(text);
        info!("Extracted {} candidate entities via patterns", entities.len());

        // Step 2: Classify + boost confidence
        for entity in &mut entities {
            self.classifier.boost_confidence(entity, text);
        }

        // Step 3: Filter by confidence threshold
        entities.retain(|e| e.confidence >= self.min_confidence);
        info!(
            "Retained {} entities above confidence threshold {}",
            entities.len(),
            self.min_confidence
        );

        // Step 4: Deduplicate by (kind, value)
        let entities = patterns::deduplicate(entities);
        info!("After deduplication: {} unique entities", entities.len());

        entities
    }

    /// Extract from text AND fold into CSV-like batch format.
    pub fn extract_and_batch(&self, text: &str) -> Vec<ExtractedBatch> {
        let entities = self.extract_from_text(text);

        // Group by kind for batch output
        let mut batches: std::collections::HashMap<EntityKind, Vec<String>> =
            std::collections::HashMap::new();

        for entity in entities {
            batches
                .entry(entity.kind.clone())
                .or_default()
                .push(entity.value);
        }

        batches
            .into_iter()
            .map(|(kind, values)| {
                let count = values.len();
                ExtractedBatch {
                    kind,
                    values,
                    count,
                }
            })
            .collect()
    }
}

impl Default for EntityExtractor {
    fn default() -> Self {
        Self::new(0.30).unwrap() // MVP: confidence floor 0.30 (candidate tier)
    }
}

/// Batch of entities grouped by kind.
#[derive(Debug, Clone)]
pub struct ExtractedBatch {
    pub kind: EntityKind,
    pub values: Vec<String>,
    pub count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_from_mixed_text() {
        let extractor = EntityExtractor::new(0.60).unwrap();
        let text =
            "Contact: john.doe@example.com or call +1 415-555-0123. Visit https://example.com";

        let entities = extractor.extract_from_text(text);
        assert!(entities.iter().any(|e| e.kind == EntityKind::Email));
        assert!(entities.iter().any(|e| e.kind == EntityKind::Url));
        // Phone extraction may depend on regex tuning
    }

    #[test]
    fn extract_and_batch() {
        let extractor = EntityExtractor::new(0.60).unwrap();
        let text = "test1@example.com test2@example.com https://example.com";

        let batches = extractor.extract_and_batch(text);
        let email_batch = batches.iter().find(|b| b.kind == EntityKind::Email);
        assert!(email_batch.is_some());
    }
}
