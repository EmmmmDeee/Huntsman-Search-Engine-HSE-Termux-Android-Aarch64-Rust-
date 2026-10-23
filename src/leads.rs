//! Lead ranking over entity profiles.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::confidence::{Classification, effective};
use crate::entity::Entity;
use crate::exposure::ExposureFinding;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Lead {
    pub uid: String,
    pub value: String,
    pub classification: Classification,
    pub score: f64,
}

/// The entities not yet verified, best lead first: effective confidence, corroborating sources
/// and the entity's score in `exposures` (the findings `compute_exposure` gave for `entities`).
#[must_use]
pub fn rank_leads(entities: &[Entity], exposures: &[ExposureFinding]) -> Vec<Lead> {
    let exposure = exposures
        .iter()
        .map(|finding| (finding.uid.as_str(), f64::from(finding.score)))
        .collect::<HashMap<_, _>>();
    let mut leads = entities
        .iter()
        .filter_map(|entity| {
            let sources = entity.source_count();
            let c_effective = effective(entity.confidence, sources);
            let classification = Classification::from_effective(c_effective);
            (classification != Classification::Verified).then(|| Lead {
                uid: entity.uid.clone(),
                value: entity.value.clone(),
                classification,
                score: c_effective * 100.0
                    + f64::from(sources) * 10.0
                    + exposure.get(entity.uid.as_str()).copied().unwrap_or(0.0),
            })
        })
        .collect::<Vec<_>>();
    leads.sort_by(|left, right| {
        right
            .score
            .total_cmp(&left.score)
            .then_with(|| left.uid.cmp(&right.uid))
    });
    leads
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::{Entity, EntityKind};
    use crate::exposure::compute_exposure;

    #[test]
    fn highest_scoring_non_verified_entity_ranks_first() {
        let candidate = Entity::builder(EntityKind::Email, "c@example.com", 0.3, "scan")
            .tag(crate::tags::BREACH)
            .build();
        let probable = Entity::new(EntityKind::Email, "p@example.com", 0.6, "scan");
        let entities = [candidate, probable];
        let leads = rank_leads(&entities, &compute_exposure(&entities));
        assert_eq!(leads[0].classification, Classification::Probable);
    }
}
