//! Classifier adapter that emits entities from unstructured text.

use crate::classifier;
use crate::entity::{Entity, Evidence, EvidenceProvenance};

#[derive(Debug, Default, Clone, Copy)]
pub struct ClassifyModule;

impl ClassifyModule {
    #[must_use]
    pub fn process_text(self, text: &str, scan_id: &str) -> Vec<Entity> {
        classifier::extract(text)
            .into_iter()
            .filter(classifier::Classified::is_actionable)
            .map(|classified| {
                Entity::builder(
                    classified.kind,
                    classified.value,
                    classified.confidence,
                    scan_id,
                )
                .tag("classified")
                .tag("auto-seed")
                .evidence(
                    Evidence::new(
                        EvidenceProvenance::for_scan("classifier", scan_id),
                        format!("{} match in unstructured input", classified.signal),
                    )
                    .with_attr("signal", classified.signal),
                )
                .build()
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actionable_entities_are_emitted() {
        let entities =
            ClassifyModule.process_text("see https://example.com and ada@example.com", "scan");
        assert_eq!(entities.len(), 2);
        assert!(entities.iter().all(|entity| entity.has_tag("classified")));
    }
}
