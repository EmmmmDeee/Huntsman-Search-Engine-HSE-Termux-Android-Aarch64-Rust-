//! Deterministic co-reference clustering by canonical identity key.

use serde::{Deserialize, Serialize};

use crate::entity::{Entity, EntityKind};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorefCluster {
    pub kind: EntityKind,
    pub canonical_value: String,
    pub members: Vec<String>,
}

#[must_use]
pub fn cluster_entities(entities: &[Entity]) -> Vec<CorefCluster> {
    let mut buckets = std::collections::BTreeMap::<(EntityKind, String), Vec<String>>::new();
    for entity in entities {
        buckets
            .entry((entity.kind.clone(), entity.value.clone()))
            .or_default()
            .push(entity.uid.clone());
    }
    buckets
        .into_iter()
        .map(|((kind, canonical_value), members)| CorefCluster {
            kind,
            canonical_value,
            members,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::{Entity, EntityKind};

    #[test]
    fn equivalent_values_share_a_cluster() {
        let entities = vec![
            Entity::new(EntityKind::Email, "Ada@Example.com", 0.6, "scan"),
            Entity::new(EntityKind::Email, "ada@example.com", 0.8, "scan"),
        ];
        let clusters = cluster_entities(&entities);
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].members.len(), 2);
    }
}
