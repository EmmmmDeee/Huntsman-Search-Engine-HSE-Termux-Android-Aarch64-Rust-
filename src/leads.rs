//! Lead ranking over entity profiles.

use serde::{Deserialize, Serialize};

use crate::confidence::Classification;
use crate::entity::Entity;
use crate::exposure::compute_exposure;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Lead {
    pub uid: String,
    pub value: String,
    pub classification: Classification,
    pub score: f64,
}

#[must_use]
pub fn rank_leads(entities: &[Entity]) -> Vec<Lead> {
    let exposure = compute_exposure(entities)
        .findings
        .into_iter()
        .map(|finding| (finding.uid, f64::from(finding.score)))
        .collect::<std::collections::HashMap<_, _>>();
    let mut leads = entities
        .iter()
        .filter(|entity| entity.classify() != Classification::Verified)
        .map(|entity| Lead {
            uid: entity.uid.clone(),
            value: entity.value.clone(),
            classification: entity.classify(),
            score: entity.c_effective() * 100.0
                + f64::from(entity.source_count()) * 10.0
                + exposure.get(&entity.uid).copied().unwrap_or(0.0),
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

    #[test]
    fn highest_scoring_non_verified_entity_ranks_first() {
        let candidate = Entity::builder(EntityKind::Email, "c@example.com", 0.3, "scan")
            .tag(crate::tags::BREACH)
            .build();
        let probable = Entity::new(EntityKind::Email, "p@example.com", 0.6, "scan");
        let leads = rank_leads(&[candidate, probable]);
        assert_eq!(leads[0].classification, Classification::Probable);
    }
}
