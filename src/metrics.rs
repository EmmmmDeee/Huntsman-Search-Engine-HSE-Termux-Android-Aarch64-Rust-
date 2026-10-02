use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::confidence::Classification;
use crate::entity::{Entity, Evidence, EvidenceProvenance};
use crate::eval::stats::mean;
use crate::graph::{EntityRelation, Graph, UNREACHABLE};
use crate::tags;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TierCounts {
    pub verified: usize,
    pub probable: usize,
    pub candidate: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SeedReach {
    pub anchored: bool,
    pub max_depth: usize,
    pub reached_at_hop: Vec<usize>,
    pub reachable_total: usize,
    pub reachable_fraction: f64,
}

impl SeedReach {
    fn unanchored() -> Self {
        Self {
            anchored: false,
            max_depth: 0,
            reached_at_hop: Vec::new(),
            reachable_total: 0,
            reachable_fraction: 0.0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ScanMetrics {
    pub total_entities: usize,
    pub entities_by_kind: Vec<(String, usize)>,
    pub tier_counts: TierCounts,
    pub mean_confidence: f64,
    pub median_confidence: f64,
    pub corroborated_fraction: f64,
    pub total_relations: usize,
    pub relations_by_kind: Vec<(String, usize)>,
    pub linked_entity_fraction: f64,
    pub graph_density: f64,
    pub graph_degeneracy: usize,
    pub main_core_size: usize,
    pub cross_scan_bridges: usize,
    pub distinct_evidence_sources: usize,
    pub seed_reach: SeedReach,
}

const CROSS_SCAN_TAGS: [&str; 3] = [
    "cross-scan",
    "cross-scan-cooccurrence",
    "cross-scan-relation",
];
const MAX_REACH_DEPTH: usize = 24;

#[must_use]
pub fn subject_uid(entities: &[Entity]) -> Option<&str> {
    entities
        .iter()
        .find(|entity| entity.has_tag("subject"))
        .or_else(|| entities.iter().find(|entity| entity.has_tag("seed")))
        .map(|entity| entity.uid.as_str())
}

#[must_use]
pub fn reachability(
    entities: &[Entity],
    relations: &[EntityRelation],
    anchor_uid: &str,
) -> SeedReach {
    reachability_on(
        &Graph::build(entities, relations),
        entities.len(),
        anchor_uid,
    )
}

fn reachability_on(graph: &Graph, total: usize, anchor_uid: &str) -> SeedReach {
    let Some(src) = graph.index_of(anchor_uid) else {
        return SeedReach::unanchored();
    };
    let distances = graph.bfs_levels(src);
    let mut reached_at_hop = vec![1];
    let mut max_depth = 0;
    let mut reachable_total = 1;
    for (index, &hop) in distances.iter().enumerate() {
        if index == src || hop == UNREACHABLE || hop > MAX_REACH_DEPTH {
            continue;
        }
        if reached_at_hop.len() <= hop {
            reached_at_hop.resize(hop + 1, 0);
        }
        reached_at_hop[hop] += 1;
        max_depth = max_depth.max(hop);
        reachable_total += 1;
    }
    SeedReach {
        anchored: true,
        max_depth,
        reached_at_hop,
        reachable_total,
        reachable_fraction: fraction(reachable_total, total),
    }
}

#[must_use]
pub fn compute(entities: &[Entity], relations: &[EntityRelation]) -> ScanMetrics {
    let total_entities = entities.len();
    let total_relations = relations.len();

    let mut by_kind = BTreeMap::new();
    for entity in entities {
        *by_kind.entry(entity.kind.to_string()).or_insert(0) += 1;
    }
    let entities_by_kind = by_kind.into_iter().collect();

    let mut relation_kinds = BTreeMap::new();
    for relation in relations {
        *relation_kinds.entry(relation.kind.to_string()).or_insert(0) += 1;
    }
    let relations_by_kind = relation_kinds.into_iter().collect();

    let mut tier_counts = TierCounts {
        verified: 0,
        probable: 0,
        candidate: 0,
    };
    let mut corroborated = 0;
    for entity in entities {
        match entity.classify() {
            Classification::Verified => tier_counts.verified += 1,
            Classification::Probable => tier_counts.probable += 1,
            Classification::Candidate => tier_counts.candidate += 1,
        }
        if entity.source_count() >= 2 {
            corroborated += 1;
        }
    }

    let mut confidences: Vec<f64> = entities.iter().map(Entity::c_effective).collect();
    confidences.sort_by(f64::total_cmp);
    let mean_confidence = mean(&confidences);
    let median_confidence = median(&confidences);

    let mut endpoints = BTreeSet::new();
    for relation in relations {
        endpoints.insert(relation.from_uid.as_str());
        endpoints.insert(relation.to_uid.as_str());
    }
    let linked = entities
        .iter()
        .filter(|entity| endpoints.contains(entity.uid.as_str()))
        .count();
    let linked_entity_fraction = fraction(linked, total_entities);
    let graph_density = density(total_relations, total_entities);

    let graph = Graph::build(entities, relations);
    let coreness = graph.coreness();
    let graph_degeneracy = coreness.iter().copied().max().unwrap_or(0);
    let main_core_size = if graph_degeneracy == 0 {
        0
    } else {
        coreness
            .iter()
            .filter(|&&value| value == graph_degeneracy)
            .count()
    };

    let cross_scan_bridges = entities
        .iter()
        .filter(|entity| CROSS_SCAN_TAGS.iter().any(|tag| entity.has_tag(tag)))
        .count();

    let mut sources = BTreeSet::new();
    for entity in entities {
        for evidence in &entity.evidence {
            sources.insert(evidence.provenance.source.as_str());
        }
    }
    let distinct_evidence_sources = sources.len();

    let seed_reach = match subject_uid(entities) {
        Some(anchor) => reachability_on(&graph, total_entities, anchor),
        None => SeedReach::unanchored(),
    };

    ScanMetrics {
        total_entities,
        entities_by_kind,
        tier_counts,
        mean_confidence,
        median_confidence,
        corroborated_fraction: fraction(corroborated, total_entities),
        total_relations,
        relations_by_kind,
        linked_entity_fraction,
        graph_density,
        graph_degeneracy,
        main_core_size,
        cross_scan_bridges,
        distinct_evidence_sources,
        seed_reach,
    }
}

fn median(sorted: &[f64]) -> f64 {
    let len = sorted.len();
    if len == 0 {
        return 0.0;
    }
    let mid = len / 2;
    if len % 2 == 1 {
        sorted[mid]
    } else {
        f64::midpoint(sorted[mid - 1], sorted[mid])
    }
}

#[allow(clippy::cast_precision_loss)]
pub(crate) fn fraction(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

#[allow(clippy::cast_precision_loss)]
fn density(edges: usize, n: usize) -> f64 {
    if n < 2 {
        return 0.0;
    }
    let possible = n as f64 * (n - 1) as f64 / 2.0;
    (edges as f64 / possible).clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::EntityKind;
    use crate::graph::{EntityRelation, RelationKind};

    fn ent(kind: EntityKind, value: &str, confidence: f64) -> Entity {
        Entity::new(kind, value, confidence, "scan")
    }

    fn with_sources(mut entity: Entity, sources: &[&str]) -> Entity {
        for source in sources {
            entity.add_evidence(Evidence::new(EvidenceProvenance::new(*source), "seen"));
        }
        entity
    }

    #[test]
    fn empty_input_is_all_zero() {
        let metrics = compute(&[], &[]);
        assert_eq!(metrics.total_entities, 0);
        assert_eq!(metrics.total_relations, 0);
        assert!(metrics.entities_by_kind.is_empty());
        assert!(metrics.relations_by_kind.is_empty());
        assert!(metrics.mean_confidence.abs() < f64::EPSILON);
        assert!(metrics.median_confidence.abs() < f64::EPSILON);
        assert!(metrics.corroborated_fraction.abs() < f64::EPSILON);
        assert!(metrics.linked_entity_fraction.abs() < f64::EPSILON);
        assert!(metrics.graph_density.abs() < f64::EPSILON);
        assert_eq!(metrics.graph_degeneracy, 0);
        assert_eq!(metrics.main_core_size, 0);
        assert_eq!(metrics.cross_scan_bridges, 0);
        assert_eq!(metrics.distinct_evidence_sources, 0);
    }

    #[test]
    fn mixed_scan_produces_expected_counts() {
        let entities = vec![
            ent(EntityKind::Person, "jane", 0.90),
            ent(EntityKind::Email, "jane@example.com", 0.80),
            ent(EntityKind::Domain, "example.com", 0.50),
            ent(EntityKind::Domain, "cdn.example.com", 0.20),
        ];
        let metrics = compute(&entities, &[]);
        assert_eq!(metrics.total_entities, 4);
        assert_eq!(
            metrics.entities_by_kind,
            vec![
                ("domain".to_string(), 2),
                ("email".to_string(), 1),
                ("person".to_string(), 1),
            ]
        );
        assert_eq!(
            metrics.tier_counts,
            TierCounts {
                verified: 2,
                probable: 1,
                candidate: 1,
            }
        );
        assert!((metrics.mean_confidence - 0.60).abs() < 1e-9);
        assert!((metrics.median_confidence - 0.65).abs() < 1e-9);
    }

    #[test]
    fn corroborated_fraction_counts_multi_source_entities() {
        let entities = vec![
            with_sources(
                ent(EntityKind::Email, "a@x.com", 0.6),
                &["hibp", "dehashed"],
            ),
            with_sources(
                ent(EntityKind::Email, "b@x.com", 0.6),
                &["hibp", "search", "whois"],
            ),
            with_sources(ent(EntityKind::Email, "c@x.com", 0.6), &["hibp"]),
            ent(EntityKind::Email, "d@x.com", 0.6),
        ];
        let metrics = compute(&entities, &[]);
        assert_eq!(metrics.distinct_evidence_sources, 4);
        assert!((metrics.corroborated_fraction - 0.5).abs() < 1e-9);
    }

    #[test]
    fn graph_metrics_match_known_graphs() {
        let email = ent(EntityKind::Email, "a@x.com", 0.6);
        let person = ent(EntityKind::Person, "b", 0.6);
        let phone = ent(EntityKind::Phone, "+15551230000", 0.6);
        let orphan = ent(EntityKind::Domain, "orphan.example.com", 0.6);
        let relations = vec![
            EntityRelation::new(
                email.uid.clone(),
                person.uid.clone(),
                RelationKind::AssociatedWith,
                0.6,
            ),
            EntityRelation::new(
                person.uid.clone(),
                phone.uid.clone(),
                RelationKind::AssociatedWith,
                0.6,
            ),
        ];
        let metrics = compute(&[email, person, phone, orphan], &relations);
        assert!((metrics.graph_density - (2.0 / 6.0)).abs() < 1e-9);
        assert!((metrics.linked_entity_fraction - 0.75).abs() < 1e-9);
        assert_eq!(metrics.graph_degeneracy, 1);
        assert_eq!(metrics.main_core_size, 3);
    }

    #[test]
    fn dense_core_is_reported_separately_from_periphery() {
        let alpha = ent(EntityKind::Person, "a", 0.6);
        let bravo = ent(EntityKind::Person, "b", 0.6);
        let charlie = ent(EntityKind::Person, "c", 0.6);
        let delta = ent(EntityKind::Person, "d", 0.6);
        let echo = ent(EntityKind::Person, "e", 0.6);
        let link = |left: &Entity, right: &Entity| {
            EntityRelation::new(
                left.uid.clone(),
                right.uid.clone(),
                RelationKind::AssociatedWith,
                0.6,
            )
        };
        let relations = vec![
            link(&alpha, &bravo),
            link(&bravo, &charlie),
            link(&alpha, &charlie),
            link(&charlie, &delta),
        ];
        let metrics = compute(&[alpha, bravo, charlie, delta, echo], &relations);
        assert_eq!(metrics.graph_degeneracy, 2);
        assert_eq!(metrics.main_core_size, 3);
    }

    #[test]
    fn metrics_are_order_independent() {
        let a = with_sources(ent(EntityKind::Person, "jane", 0.90), &["search", "whois"]);
        let b = ent(EntityKind::Email, "jane@example.com", 0.80);
        let c = ent(EntityKind::Domain, "example.com", 0.50);
        let mut d = ent(EntityKind::Domain, "cdn.example.com", 0.20);
        d.tag(tags::SEARCH_DISCOVERED);
        d.tag("cross-scan");
        let relations = vec![
            EntityRelation::new(
                b.uid.clone(),
                c.uid.clone(),
                RelationKind::AssociatedWith,
                0.5,
            ),
            EntityRelation::new(
                a.uid.clone(),
                b.uid.clone(),
                RelationKind::AssociatedWith,
                0.8,
            ),
        ];
        let entities = vec![a, b, c, d];
        let first = compute(&entities, &relations);
        let mut reversed_entities = entities.clone();
        reversed_entities.reverse();
        let mut reversed_relations = relations.clone();
        reversed_relations.reverse();
        let second = compute(&reversed_entities, &reversed_relations);
        assert_eq!(first, second);
    }

    #[test]
    fn reachability_profiles_from_subject() {
        let mut subject = ent(EntityKind::Person, "subject", 0.85);
        subject.tag("subject");
        let email = ent(EntityKind::Email, "a@x.com", 0.6);
        let phone = ent(EntityKind::Phone, "+1555", 0.6);
        let domain = ent(EntityKind::Domain, "d.example.com", 0.6);
        let relations = vec![
            EntityRelation::new(
                subject.uid.clone(),
                email.uid.clone(),
                RelationKind::AssociatedWith,
                0.6,
            ),
            EntityRelation::new(
                email.uid.clone(),
                phone.uid.clone(),
                RelationKind::AssociatedWith,
                0.6,
            ),
            EntityRelation::new(
                phone.uid.clone(),
                domain.uid.clone(),
                RelationKind::AssociatedWith,
                0.6,
            ),
        ];
        let entities = vec![subject.clone(), email, phone, domain];
        let reach = reachability(&entities, &relations, &subject.uid);
        assert!(reach.anchored);
        assert_eq!(reach.reached_at_hop, vec![1, 1, 1, 1]);
        let metrics = compute(&entities, &relations);
        assert!(metrics.seed_reach.anchored);
        assert_eq!(metrics.seed_reach.max_depth, 3);
        assert_eq!(metrics.seed_reach.reachable_total, 4);
    }
}
