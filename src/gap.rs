use std::collections::BTreeSet;

use serde::Serialize;

use crate::dependency::TargetKind;
use crate::entity::Entity;
use crate::graph::{EntityRelation, Graph};
use crate::metrics::fraction;

pub const EXPAND_FLOOR: f64 = 0.50;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Isolation {
    Unexpanded,
    BelowExpandFloor,
    Terminal,
}

impl Isolation {
    fn rank(self) -> u8 {
        match self {
            Self::Unexpanded => 0,
            Self::BelowExpandFloor => 1,
            Self::Terminal => 2,
        }
    }

    fn action(self) -> &'static str {
        match self {
            Self::Unexpanded => {
                "no trace/index coverage — re-inject as a seed and run the modules that accept its kind"
            }
            Self::BelowExpandFloor => {
                "below the expansion floor — corroborate to raise confidence, or force a re-scan, to expand it"
            }
            Self::Terminal => {
                "terminal leaf — kind is not independently scannable; no corrective scan"
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct OrphanSeed {
    pub uid: String,
    pub kind: String,
    pub value: String,
    pub confidence: f64,
    pub isolation: Isolation,
    pub reinjection_target: Option<String>,
    pub action: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IsolationCounts {
    pub unexpanded: usize,
    pub below_expand_floor: usize,
    pub terminal: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GapReport {
    pub null_state: bool,
    pub total_seeds: usize,
    pub linked_seeds: usize,
    pub isolated_seeds: usize,
    pub linked_fraction: f64,
    pub isolation: IsolationCounts,
    pub orphans: Vec<OrphanSeed>,
}

#[must_use]
pub fn analyze(entities: &[Entity], relations: &[EntityRelation]) -> GapReport {
    let graph = Graph::build(entities, relations);
    let mut linked_seeds = 0;
    let mut total_seeds = 0;
    let mut isolation = IsolationCounts {
        unexpanded: 0,
        below_expand_floor: 0,
        terminal: 0,
    };
    let mut orphans = Vec::new();
    let mut seen = BTreeSet::new();

    for entity in entities {
        if !seen.insert(entity.uid.as_str()) {
            continue;
        }
        total_seeds += 1;
        let degree = graph
            .index_of(&entity.uid)
            .map_or(0, |idx| graph.degree(idx));
        if degree > 0 {
            linked_seeds += 1;
            continue;
        }
        let reinjection_target = TargetKind::from_entity_kind(&entity.kind);
        let classification = if reinjection_target.is_none() {
            isolation.terminal += 1;
            Isolation::Terminal
        } else if entity.c_effective() < EXPAND_FLOOR {
            isolation.below_expand_floor += 1;
            Isolation::BelowExpandFloor
        } else {
            isolation.unexpanded += 1;
            Isolation::Unexpanded
        };
        orphans.push(OrphanSeed {
            uid: entity.uid.clone(),
            kind: entity.kind.to_string(),
            value: entity.value.clone(),
            confidence: entity.c_effective(),
            isolation: classification,
            reinjection_target: reinjection_target.map(|kind| kind.canonical_str().to_string()),
            action: classification.action(),
        });
    }

    orphans.sort_by(|left, right| {
        left.isolation
            .rank()
            .cmp(&right.isolation.rank())
            .then_with(|| right.confidence.total_cmp(&left.confidence))
            .then_with(|| left.uid.cmp(&right.uid))
    });

    GapReport {
        null_state: total_seeds == 0,
        total_seeds,
        linked_seeds,
        isolated_seeds: orphans.len(),
        linked_fraction: fraction(linked_seeds, total_seeds),
        isolation,
        orphans,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::EntityKind;
    use crate::graph::{EntityRelation, RelationKind};

    fn ent(kind: EntityKind, value: &str, confidence: f64) -> Entity {
        Entity::new(kind, value, confidence, "gap-scan")
    }

    #[test]
    fn empty_scan_is_explicit_null_state() {
        let report = analyze(&[], &[]);
        assert!(report.null_state);
        assert_eq!(report.total_seeds, 0);
        assert_eq!(report.linked_seeds, 0);
        assert_eq!(report.isolated_seeds, 0);
        assert!(report.linked_fraction.abs() < f64::EPSILON);
        assert!(report.orphans.is_empty(), "{:?}", report.orphans);
    }

    #[test]
    fn linked_pair_has_no_orphans() {
        let a = ent(EntityKind::Email, "a@example.test", 0.8);
        let b = ent(EntityKind::Domain, "example.test", 0.8);
        let relations = vec![EntityRelation::new(
            a.uid.as_str(),
            b.uid.as_str(),
            RelationKind::AssociatedWith,
            0.7,
        )];
        let report = analyze(&[a, b], &relations);
        assert!(!report.null_state);
        assert_eq!(report.total_seeds, 2);
        assert_eq!(report.linked_seeds, 2);
        assert_eq!(report.isolated_seeds, 0);
        assert!((report.linked_fraction - 1.0).abs() < 1e-9);
    }

    #[test]
    fn orphans_are_classified_by_expandability() {
        let email = ent(EntityKind::Email, "lonely@example.test", 0.9);
        let low = ent(EntityKind::Domain, "weak.example.test", 0.30);
        let credential = ent(EntityKind::Credential, "hunter2", 0.9);
        let report = analyze(&[credential.clone(), low.clone(), email.clone()], &[]);
        assert_eq!(report.orphans[0].isolation, Isolation::Unexpanded);
        assert_eq!(report.orphans[1].isolation, Isolation::BelowExpandFloor);
        assert_eq!(report.orphans[2].isolation, Isolation::Terminal);
        assert_eq!(
            report.orphans[0].reinjection_target.as_deref(),
            Some("email")
        );
        assert_eq!(report.orphans[2].reinjection_target, None);
    }

    #[test]
    fn self_loops_and_dangling_edges_do_not_count_as_links() {
        let entity = ent(EntityKind::Username, "solo", 0.8);
        let relations = vec![
            EntityRelation::new(
                entity.uid.as_str(),
                entity.uid.as_str(),
                RelationKind::AliasOf,
                0.6,
            ),
            EntityRelation::new(
                entity.uid.as_str(),
                "uid:absent",
                RelationKind::AssociatedWith,
                0.6,
            ),
        ];
        let report = analyze(std::slice::from_ref(&entity), &relations);
        assert_eq!(report.linked_seeds, 0);
        assert_eq!(report.isolated_seeds, 1);
    }

    #[test]
    fn linked_fraction_reflects_partial_connectivity() {
        let a = ent(EntityKind::Email, "a@example.test", 0.8);
        let b = ent(EntityKind::Domain, "example.test", 0.8);
        let c = ent(EntityKind::Phone, "+15551230000", 0.8);
        let relations = vec![EntityRelation::new(
            a.uid.as_str(),
            b.uid.as_str(),
            RelationKind::AssociatedWith,
            0.7,
        )];
        let report = analyze(&[a, b, c], &relations);
        assert_eq!(report.linked_seeds, 2);
        assert_eq!(report.isolated_seeds, 1);
        assert!((report.linked_fraction - (2.0 / 3.0)).abs() < 1e-9);
    }
}
