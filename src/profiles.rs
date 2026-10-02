//! Per-entity profile summaries.

use serde::{Deserialize, Serialize};

use crate::confidence::Classification;
use crate::entity::Entity;
use crate::exposure::compute_exposure;
use crate::timeline::reconstruct;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EntityProfile {
    pub uid: String,
    pub value: String,
    pub kind: String,
    pub classification: Classification,
    pub confidence: f64,
    pub effective_confidence: f64,
    pub evidence_count: usize,
    pub source_count: u32,
    pub exposure_score: u32,
    pub first_event_iso: Option<String>,
    pub last_event_iso: Option<String>,
}

#[must_use]
pub fn build_profiles(entities: &[Entity]) -> Vec<EntityProfile> {
    let exposure = compute_exposure(entities)
        .findings
        .into_iter()
        .map(|finding| (finding.uid, finding.score))
        .collect::<std::collections::HashMap<_, _>>();
    let timeline = reconstruct(entities);
    let mut by_uid = std::collections::HashMap::<String, Vec<&str>>::new();
    for event in &timeline {
        by_uid
            .entry(event.entity_uid.clone())
            .or_default()
            .push(event.iso.as_str());
    }
    let mut profiles = entities
        .iter()
        .map(|entity| {
            let span = by_uid.get(&entity.uid);
            EntityProfile {
                uid: entity.uid.clone(),
                value: entity.value.clone(),
                kind: entity.kind.to_string(),
                classification: entity.classify(),
                confidence: entity.confidence,
                effective_confidence: entity.c_effective(),
                evidence_count: entity.evidence.len(),
                source_count: entity.source_count(),
                exposure_score: exposure.get(&entity.uid).copied().unwrap_or(0),
                first_event_iso: span.and_then(|events| events.first().map(ToString::to_string)),
                last_event_iso: span.and_then(|events| events.last().map(ToString::to_string)),
            }
        })
        .collect::<Vec<_>>();
    profiles.sort_by(|left, right| {
        right
            .classification
            .rank()
            .cmp(&left.classification.rank())
            .then_with(|| right.exposure_score.cmp(&left.exposure_score))
            .then_with(|| left.uid.cmp(&right.uid))
    });
    profiles
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance};

    #[test]
    fn profile_carries_timeline_span_and_exposure() {
        let entity = Entity::builder(EntityKind::Email, "ada@example.com", 0.8, "scan")
            .tag(crate::tags::BREACH)
            .evidence(
                Evidence::new(EvidenceProvenance::new("hibp"), "breach")
                    .with_attr("breach_date", "2019-01-02"),
            )
            .build();
        let profiles = build_profiles(&[entity]);
        assert_eq!(profiles[0].exposure_score, 30);
        assert_eq!(profiles[0].first_event_iso.as_deref(), Some("2019-01-02"));
    }
}
