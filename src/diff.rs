//! Entity and relation diffing.

use serde::{Deserialize, Serialize};

use crate::entity::Entity;
use crate::graph::EntityRelation;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EntityChange {
    pub uid: String,
    pub before_confidence: f64,
    pub after_confidence: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanDiff {
    pub added_entities: Vec<String>,
    pub removed_entities: Vec<String>,
    pub strengthened_entities: Vec<EntityChange>,
    pub weakened_entities: Vec<EntityChange>,
    pub added_relations: Vec<String>,
    pub removed_relations: Vec<String>,
}

#[must_use]
pub fn diff_entities(
    before_entities: &[Entity],
    after_entities: &[Entity],
    before_relations: &[EntityRelation],
    after_relations: &[EntityRelation],
) -> ScanDiff {
    let before = before_entities
        .iter()
        .map(|entity| (entity.uid.clone(), entity))
        .collect::<std::collections::BTreeMap<_, _>>();
    let after = after_entities
        .iter()
        .map(|entity| (entity.uid.clone(), entity))
        .collect::<std::collections::BTreeMap<_, _>>();
    let added_entities = after
        .keys()
        .filter(|uid| !before.contains_key(*uid))
        .cloned()
        .collect();
    let removed_entities = before
        .keys()
        .filter(|uid| !after.contains_key(*uid))
        .cloned()
        .collect();
    let mut strengthened_entities = Vec::new();
    let mut weakened_entities = Vec::new();
    for (uid, old_entity) in &before {
        if let Some(new_entity) = after.get(uid) {
            let delta = new_entity.confidence - old_entity.confidence;
            if delta > 1e-12 {
                strengthened_entities.push(EntityChange {
                    uid: uid.clone(),
                    before_confidence: old_entity.confidence,
                    after_confidence: new_entity.confidence,
                });
            } else if delta < -1e-12 {
                weakened_entities.push(EntityChange {
                    uid: uid.clone(),
                    before_confidence: old_entity.confidence,
                    after_confidence: new_entity.confidence,
                });
            }
        }
    }
    let relation_key = |relation: &EntityRelation| {
        format!(
            "{}:{}:{}",
            relation.from_uid, relation.kind, relation.to_uid
        )
    };
    let before_rel = before_relations
        .iter()
        .map(relation_key)
        .collect::<std::collections::BTreeSet<_>>();
    let after_rel = after_relations
        .iter()
        .map(relation_key)
        .collect::<std::collections::BTreeSet<_>>();
    ScanDiff {
        added_entities,
        removed_entities,
        strengthened_entities,
        weakened_entities,
        added_relations: after_rel.difference(&before_rel).cloned().collect(),
        removed_relations: before_rel.difference(&after_rel).cloned().collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::{Entity, EntityKind};
    use crate::graph::RelationKind;

    #[test]
    fn reports_added_removed_and_changed_items() {
        let before = vec![Entity::new(EntityKind::Email, "a@b.com", 0.4, "scan")];
        let after = vec![
            Entity::new(EntityKind::Email, "a@b.com", 0.8, "scan"),
            Entity::new(EntityKind::Email, "c@d.com", 0.5, "scan"),
        ];
        let diff = diff_entities(
            &before,
            &after,
            &[],
            &[EntityRelation::new(
                after[0].uid.clone(),
                after[1].uid.clone(),
                RelationKind::AssociatedWith,
                0.6,
            )],
        );
        assert_eq!(diff.added_entities.len(), 1);
        assert_eq!(diff.strengthened_entities.len(), 1);
        assert_eq!(diff.added_relations.len(), 1);
    }
}
