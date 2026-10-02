use std::collections::BTreeMap;

use serde::Serialize;

use crate::entity::Entity;
use crate::graph::EntityRelation;

pub const DAMPING: f64 = 0.85;
pub const MAX_ROUNDS: usize = 20;
pub const EPSILON: f64 = 1e-6;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TrustScore {
    pub uid: String,
    pub score: f64,
}

#[must_use]
pub fn propagate(entities: &[Entity], relations: &[EntityRelation]) -> Vec<TrustScore> {
    let mut index = BTreeMap::new();
    for entity in entities {
        index.insert(entity.uid.as_str(), 0_usize);
    }
    let len = index.len();
    if len == 0 {
        return Vec::new();
    }
    let mut uids = Vec::with_capacity(len);
    for (slot, (uid, value)) in index.iter_mut().enumerate() {
        *value = slot;
        uids.push(*uid);
    }
    let by_uid: BTreeMap<&str, &Entity> = entities
        .iter()
        .map(|entity| (entity.uid.as_str(), entity))
        .collect();
    let seed: Vec<f64> = uids
        .iter()
        .map(|uid| by_uid[uid].c_effective().clamp(0.0, 1.0))
        .collect();

    let mut edge_weight: BTreeMap<(usize, usize), f64> = BTreeMap::new();
    for relation in relations {
        let Some(&left) = index.get(relation.from_uid.as_str()) else {
            continue;
        };
        let Some(&right) = index.get(relation.to_uid.as_str()) else {
            continue;
        };
        if left == right {
            continue;
        }
        let pair = if left < right {
            (left, right)
        } else {
            (right, left)
        };
        let weight = relation.confidence.clamp(0.0, 1.0);
        edge_weight
            .entry(pair)
            .and_modify(|current| *current = current.max(weight))
            .or_insert(weight);
    }

    let mut neighbours = vec![Vec::new(); len];
    for (&(left, right), &weight) in &edge_weight {
        neighbours[left].push((right, weight));
        neighbours[right].push((left, weight));
    }
    for list in &mut neighbours {
        list.sort_by_key(|item| item.0);
    }

    let mut current = seed.clone();
    let mut next = vec![0.0; len];
    for _ in 0..MAX_ROUNDS {
        let mut max_delta = 0.0_f64;
        for node in 0..len {
            let value = if neighbours[node].is_empty() {
                seed[node]
            } else {
                let mut weight_sum = 0.0;
                let mut weighted = 0.0;
                for &(neighbour, weight) in &neighbours[node] {
                    weight_sum += weight;
                    weighted += weight * current[neighbour];
                }
                if weight_sum > 0.0 {
                    let average = weighted / weight_sum;
                    DAMPING.mul_add(average, (1.0 - DAMPING) * seed[node])
                } else {
                    seed[node]
                }
            }
            .clamp(0.0, 1.0);
            max_delta = max_delta.max((value - current[node]).abs());
            next[node] = value;
        }
        std::mem::swap(&mut current, &mut next);
        if max_delta < EPSILON {
            break;
        }
    }

    let mut out: Vec<TrustScore> = uids
        .iter()
        .enumerate()
        .map(|(index, uid)| TrustScore {
            uid: (*uid).to_string(),
            score: current[index],
        })
        .collect();
    out.sort_by(|left, right| {
        right
            .score
            .total_cmp(&left.score)
            .then_with(|| left.uid.cmp(&right.uid))
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::EntityKind;
    use crate::graph::{EntityRelation, RelationKind};

    fn ent(kind: EntityKind, value: &str, confidence: f64) -> Entity {
        Entity::new(kind, value, confidence, "trust-scan")
    }

    fn rel(from: &Entity, to: &Entity, kind: RelationKind, confidence: f64) -> EntityRelation {
        EntityRelation::new(from.uid.as_str(), to.uid.as_str(), kind, confidence)
    }

    fn score_of(scores: &[TrustScore], uid: &str) -> f64 {
        scores.iter().find(|score| score.uid == uid).unwrap().score
    }

    #[test]
    fn star_anchor_lifts_leaves() {
        let anchor = ent(EntityKind::Person, "Anchor", 0.95);
        let leaf_a = ent(EntityKind::Username, "leaf_a", 0.20);
        let leaf_b = ent(EntityKind::Username, "leaf_b", 0.20);
        let leaf_c = ent(EntityKind::Email, "leaf_c@example.com", 0.20);
        let relations = vec![
            rel(&anchor, &leaf_a, RelationKind::AssociatedWith, 0.9),
            rel(&anchor, &leaf_b, RelationKind::AssociatedWith, 0.9),
            rel(&anchor, &leaf_c, RelationKind::AssociatedWith, 0.9),
        ];
        let scores = propagate(
            &[
                anchor.clone(),
                leaf_a.clone(),
                leaf_b.clone(),
                leaf_c.clone(),
            ],
            &relations,
        );
        assert_eq!(scores[0].uid, anchor.uid);
        for leaf in [&leaf_a, &leaf_b, &leaf_c] {
            let score = score_of(&scores, &leaf.uid);
            assert!(score > 0.20);
            assert!(score < score_of(&scores, &anchor.uid));
        }
    }

    #[test]
    fn trust_attenuates_with_distance() {
        let anchor = ent(EntityKind::Person, "Deep Anchor", 0.95);
        let middle = ent(EntityKind::Username, "middle", 0.10);
        let far = ent(EntityKind::Username, "far", 0.10);
        let relations = vec![
            rel(&anchor, &middle, RelationKind::AssociatedWith, 0.9),
            rel(&middle, &far, RelationKind::AliasOf, 0.9),
        ];
        let scores = propagate(&[anchor.clone(), middle.clone(), far.clone()], &relations);
        let middle_score = score_of(&scores, &middle.uid);
        let far_score = score_of(&scores, &far.uid);
        assert!(middle_score > far_score);
        assert!(far_score > 0.10);
    }

    #[test]
    fn propagation_is_order_independent() {
        let a = ent(EntityKind::Person, "Person A", 0.9);
        let b = ent(EntityKind::Email, "b@example.com", 0.6);
        let c = ent(EntityKind::Username, "cccc", 0.4);
        let d = ent(EntityKind::Username, "dddd", 0.3);
        let first_entities = vec![a.clone(), b.clone(), c.clone(), d.clone()];
        let first_relations = vec![
            rel(&a, &b, RelationKind::AssociatedWith, 0.8),
            rel(&b, &c, RelationKind::AliasOf, 0.5),
            rel(&a, &d, RelationKind::AssociatedWith, 0.7),
        ];
        let second_entities = vec![d.clone(), c.clone(), b.clone(), a.clone()];
        let second_relations = vec![
            rel(&a, &d, RelationKind::AssociatedWith, 0.7),
            rel(&c, &b, RelationKind::AliasOf, 0.5),
            rel(&b, &a, RelationKind::AssociatedWith, 0.8),
            rel(&b, &c, RelationKind::AliasOf, 0.2),
        ];
        assert_eq!(
            propagate(&first_entities, &first_relations),
            propagate(&second_entities, &second_relations)
        );
    }

    #[test]
    fn isolated_nodes_keep_their_seed() {
        let hub = ent(EntityKind::Person, "Connected", 0.9);
        let friend = ent(EntityKind::Username, "friend", 0.5);
        let lonely = ent(EntityKind::Email, "lonely@example.com", 0.42);
        let relations = vec![rel(&hub, &friend, RelationKind::AssociatedWith, 0.8)];
        let scores = propagate(&[hub, friend, lonely.clone()], &relations);
        let lonely_score = score_of(&scores, &lonely.uid);
        assert!((lonely_score - lonely.c_effective()).abs() < 1e-12);
    }

    #[test]
    fn bad_input_and_ties_are_handled() {
        let only = ent(EntityKind::Person, "Lonely", 0.8);
        let ghost = ent(EntityKind::Person, "Ghost", 0.5);
        let relations = vec![
            rel(&only, &ghost, RelationKind::AssociatedWith, 0.5),
            rel(&only, &only, RelationKind::AliasOf, 0.9),
        ];
        let scores = propagate(std::slice::from_ref(&only), &relations);
        assert_eq!(scores.len(), 1);
        assert!((scores[0].score - only.c_effective()).abs() < 1e-12);

        let p = ent(EntityKind::Username, "zzzz", 0.5);
        let q = ent(EntityKind::Username, "aaaa", 0.5);
        let tied = propagate(
            &[p.clone(), q.clone()],
            &[rel(&p, &q, RelationKind::AliasOf, 0.7)],
        );
        assert!((tied[0].score - tied[1].score).abs() < 1e-12);
        assert!(tied[0].uid < tied[1].uid);
    }
}
