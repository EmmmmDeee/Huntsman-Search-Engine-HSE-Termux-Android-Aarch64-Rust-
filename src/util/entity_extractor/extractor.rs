//! End-to-end entity extraction pipeline.

use super::{ExtractedEntity, ExtractionResult, classifier::EntityClassifier, patterns};
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
        info!(
            "Extracted {} candidate entities via patterns",
            entities.len()
        );

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
}

impl Default for EntityExtractor {
    fn default() -> Self {
        Self::new(0.30).expect("should succeed") // MVP: confidence floor 0.30 (candidate tier)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::entity_extractor::EntityKind;

    #[test]
    fn extract_from_mixed_text() {
        let extractor = EntityExtractor::new(0.60).expect("should succeed");
        let text =
            "Contact: john.doe@example.com or call +1 415-555-0123. Visit https://example.com";

        let entities = extractor.extract_from_text(text);
        assert!(entities.iter().any(|e| e.kind == EntityKind::Email));
        assert!(entities.iter().any(|e| e.kind == EntityKind::Url));
        // Phone extraction may depend on regex tuning
    }
}
