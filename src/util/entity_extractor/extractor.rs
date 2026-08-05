//! End-to-end entity extraction pipeline.

use super::{
    EntityKind, ExtractedEntity, ExtractionError, ExtractionResult, classifier::EntityClassifier,
    patterns,
};
use tracing::{debug, info};

/// Default confidence floor: the "candidate" tier.
///
/// Named so [`EntityExtractor::default`] can build from a value this module
/// knows is in range, instead of unwrapping a fallible call.
pub const DEFAULT_MIN_CONFIDENCE: f64 = 0.30;

/// Main entity extractor: patterns + classification + deduplication.
#[derive(Debug, Clone, Copy)]
pub struct EntityExtractor {
    classifier: EntityClassifier,
    /// Validated by [`EntityExtractor::new`] to be finite and within
    /// `0.0..=1.0`; [`Self::extract_from_text`] compares against it directly.
    min_confidence: f64,
}

impl EntityExtractor {
    /// Create a new extractor with confidence threshold.
    ///
    /// # Errors
    ///
    /// [`ExtractionError::InvalidConfidenceFloor`] if `min_confidence` is not
    /// finite or falls outside `0.0..=1.0`.
    ///
    /// Rejecting here rather than clamping is deliberate: the filter in
    /// [`Self::extract_from_text`] is `confidence >= min_confidence`, and a NaN
    /// floor makes that comparison false for *every* entity — the extractor
    /// then returns an empty set and reports success, so the caller cannot tell
    /// "this document contained nothing" from "your threshold discarded
    /// everything". Silently clamping NaN to a default would hide the operator's
    /// mistake just as thoroughly. `hse ingest --min-confidence nan` did exactly
    /// this: exit 0, empty output, three entities dropped without a word.
    ///
    /// The scan path guards the same hazard at
    /// [`crate::core::scan::ScanOptions::effective_min_confidence`] and its two
    /// siblings, each filtering on `is_finite()`; this is the one floor that
    /// reaches a comparison straight from the CLI, so it validates at the door.
    pub fn new(min_confidence: f64) -> ExtractionResult<Self> {
        if !min_confidence.is_finite() || !(0.0..=1.0).contains(&min_confidence) {
            return Err(ExtractionError::InvalidConfidenceFloor(min_confidence));
        }
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
    /// Built by struct literal from [`DEFAULT_MIN_CONFIDENCE`] rather than by
    /// unwrapping `Self::new`, so `Default` is *structurally* incapable of
    /// panicking — there is no fallible call left to unwrap. (`new`'s only
    /// failure is an out-of-range floor, and this floor is a constant this
    /// module owns.)
    fn default() -> Self {
        // Built from its fields rather than through `new().expect(...)`:
        // `EntityExtractor::new` is fallible only because it propagates
        // `EntityClassifier::new`, which cannot fail, so the `Err` arm was
        // unreachable and the `expect` was a panic path that could never fire.
        // Constructing directly removes it. The floor comes from
        // `DEFAULT_MIN_CONFIDENCE` so the constant `new` validates against and
        // the one `Default` uses cannot drift apart.
        Self {
            // The unit struct itself, not `EntityClassifier::default()`:
            // clippy::default_constructed_unit_struct rejects the latter.
            classifier: EntityClassifier,
            min_confidence: DEFAULT_MIN_CONFIDENCE,
        }
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
    fn new_rejects_a_non_finite_confidence_floor() {
        // The library-level half of the CLI guard: a NaN floor makes
        // `confidence >= floor` false for every entity, so extraction would
        // return an empty set and report success. Reject rather than clamp, so
        // the caller learns its threshold was unusable.
        for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let err = EntityExtractor::new(bad).expect_err("non-finite floor must be rejected");
            assert!(
                matches!(err, ExtractionError::InvalidConfidenceFloor(_)),
                "expected the typed variant, got {err:?}"
            );
        }
    }

    #[test]
    fn new_rejects_a_floor_outside_zero_to_one() {
        for bad in [-0.1, 1.1, 5.0, -1e9] {
            assert!(
                matches!(
                    EntityExtractor::new(bad),
                    Err(ExtractionError::InvalidConfidenceFloor(_))
                ),
                "{bad} is outside 0.0..=1.0 and must be rejected"
            );
        }
    }

    #[test]
    fn new_accepts_the_inclusive_boundaries() {
        for good in [0.0, DEFAULT_MIN_CONFIDENCE, 1.0] {
            assert!(
                EntityExtractor::new(good).is_ok(),
                "{good} is a usable floor"
            );
        }
    }

    #[test]
    fn default_is_panic_free_and_uses_the_documented_floor() {
        let d = EntityExtractor::default();
        assert!(
            (d.min_confidence - DEFAULT_MIN_CONFIDENCE).abs() < f64::EPSILON,
            "Default must use the candidate-tier floor"
        );
    }

    #[test]
    fn a_valid_floor_still_filters_by_confidence() {
        // Guards the fix from over-correcting: rejecting bad floors must not
        // disturb the ordinary filtering behaviour a good floor selects.
        let low = EntityExtractor::new(0.0).expect("0.0 is valid");
        let high = EntityExtractor::new(1.0).expect("1.0 is valid");
        let text = "reach me at test@example.com";
        assert!(
            low.extract_from_text(text).len() >= high.extract_from_text(text).len(),
            "a higher floor must never retain more than a lower one"
        );
    }

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

    #[test]
    fn extract_and_batch() {
        let extractor = EntityExtractor::new(0.60).expect("should succeed");
        let text = "test1@example.com test2@example.com https://example.com";

        let batches = extractor.extract_and_batch(text);
        let email_batch = batches.iter().find(|b| b.kind == EntityKind::Email);
        assert!(email_batch.is_some());
    }
}
