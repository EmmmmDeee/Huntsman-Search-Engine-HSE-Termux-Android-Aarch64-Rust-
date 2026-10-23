//! Per-entity profile summaries.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::confidence::{Classification, effective};
use crate::entity::Entity;
use crate::exposure::ExposureFinding;
use crate::timeline::TimelineEvent;

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

/// One profile per entity, most trusted first, then most exposed, then by uid. `exposures` and
/// `timeline` are what `compute_exposure` and `timeline::reconstruct` gave for `entities`; a
/// profile's first and last events are the first and last of its entity's in timeline order.
#[must_use]
pub fn build_profiles(
    entities: &[Entity],
    exposures: &[ExposureFinding],
    timeline: &[TimelineEvent],
) -> Vec<EntityProfile> {
    let exposure = exposures
        .iter()
        .map(|finding| (finding.uid.as_str(), finding.score))
        .collect::<HashMap<_, _>>();
    let mut spans = HashMap::<&str, (&str, &str)>::new();
    for event in timeline {
        spans
            .entry(event.entity_uid.as_str())
            .and_modify(|(_, last)| *last = event.iso.as_str())
            .or_insert((event.iso.as_str(), event.iso.as_str()));
    }
    let mut profiles = entities
        .iter()
        .map(|entity| {
            let sources = entity.source_count();
            let effective_confidence = effective(entity.confidence, sources);
            let span = spans.get(entity.uid.as_str());
            EntityProfile {
                uid: entity.uid.clone(),
                value: entity.value.clone(),
                kind: entity.kind.to_string(),
                classification: Classification::from_effective(effective_confidence),
                confidence: entity.confidence,
                effective_confidence,
                evidence_count: entity.evidence.len(),
                source_count: sources,
                exposure_score: exposure.get(entity.uid.as_str()).copied().unwrap_or(0),
                first_event_iso: span.map(|(first, _)| (*first).to_owned()),
                last_event_iso: span.map(|(_, last)| (*last).to_owned()),
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
    use crate::exposure::compute_exposure;
    use crate::timeline::reconstruct;

    #[test]
    fn profile_carries_timeline_span_and_exposure() {
        let entity = Entity::builder(EntityKind::Email, "ada@example.com", 0.8, "scan")
            .tag(crate::tags::BREACH)
            .evidence(
                Evidence::new(EvidenceProvenance::new("hibp"), "breach")
                    .with_attr("breach_date", "2019-01-02"),
            )
            .build();
        let entities = [entity];
        let profiles = build_profiles(
            &entities,
            &compute_exposure(&entities),
            &reconstruct(&entities),
        );
        assert_eq!(profiles[0].exposure_score, 30);
        assert_eq!(profiles[0].first_event_iso.as_deref(), Some("2019-01-02"));
    }
}
