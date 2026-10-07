use serde::Serialize;

use crate::coverage::{CoverageVerdict, Event, coverage_verdict, provider_coverage_from_events};
use crate::dependency::Target;
use crate::entity::Entity;
use crate::evidence_ancestry::EvidenceAncestryGraph;
use crate::graph::{EntityRelation, Graph};
use crate::metrics::{ScanMetrics, compute};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanStatus {
    Pending,
    Running,
    Complete,
    Failed,
    Cancelled,
}

impl ScanStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::Complete => "complete",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScanRecord {
    pub id: String,
    pub target: Target,
    pub status: ScanStatus,
    pub started_at: u64,
    pub finished_at: Option<u64>,
    pub modules_run: usize,
    pub modules_errored: usize,
    pub modules_timed_out: usize,
}

impl ScanRecord {
    #[must_use]
    pub fn new(id: impl Into<String>, target: Target) -> Self {
        Self {
            id: id.into(),
            target,
            status: ScanStatus::Pending,
            started_at: 0,
            finished_at: None,
            modules_run: 0,
            modules_errored: 0,
            modules_timed_out: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Scorecard {
    pub multi_hop_depth: usize,
    pub graph_coverage: f64,
    pub corroborated_fraction: f64,
    pub graph_density: f64,
    pub cut_vertex_count: usize,
    pub bridge_count: usize,
    pub degeneracy: usize,
    pub main_core_size: usize,
    pub total_entities: usize,
    pub total_relations: usize,
    pub cross_scan_bridges: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct BenchmarkReport {
    pub scan_id: String,
    pub seed: String,
    pub seed_kind: String,
    pub status: String,
    pub duration_secs: Option<u64>,
    pub entities_per_sec: f64,
    pub modules_run: usize,
    pub modules_errored: usize,
    pub modules_timed_out: usize,
    pub pivot_count: usize,
    pub top_pivot_uid: Option<String>,
    pub scorecard: Scorecard,
    pub metrics: ScanMetrics,
    pub coverage: Option<CoverageVerdict>,
    pub comparability_caveat: Option<String>,
}

impl BenchmarkReport {
    #[must_use]
    pub fn comparability_caveat(&self) -> Option<String> {
        let Some(coverage) = self.coverage else {
            return Some(
                "provider coverage for this run is unknown (no dispatch events retained), so a yield difference cannot be attributed to the configuration under test".to_string(),
            );
        };
        if coverage.unavailable_count > 0 {
            return Some(format!(
                "{} of {} provider(s) could not be used during this run; a lower yield here may reflect that rather than the configuration under test",
                coverage.unavailable_count, coverage.provider_count
            ));
        }
        if coverage.out_of_scope_count > 0 {
            return Some(format!(
                "{} of {} provider(s) were out of scope for this run; compare only against a run with the same scope",
                coverage.out_of_scope_count, coverage.provider_count
            ));
        }
        None
    }
}

fn pivot_profile(graph: &Graph) -> (usize, Option<String>) {
    let mut scored: Vec<(usize, &str)> = (0..graph.node_count())
        .map(|index| (graph.degree(index), graph.uid(index)))
        .filter(|(degree, _)| *degree >= 2)
        .collect();
    scored.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(right.1)));
    (
        scored.len(),
        scored.first().map(|(_, uid)| (*uid).to_string()),
    )
}

#[must_use]
pub fn report(
    scan: &ScanRecord,
    entities: &[Entity],
    relations: &[EntityRelation],
    events: &[Event],
) -> BenchmarkReport {
    let metrics = compute(entities, relations);
    let graph = Graph::build(entities, relations);
    let (pivot_count, top_pivot_uid) = pivot_profile(&graph);
    let (cuts, bridges) = graph.cut_vertices_and_bridges();
    let cut_vertex_count = cuts.len();
    let bridge_count = bridges.len();
    let duration_secs = scan
        .finished_at
        .map(|finished| finished.saturating_sub(scan.started_at));
    let entities_per_sec = match duration_secs {
        Some(duration) if duration > 0 => {
            #[allow(clippy::cast_precision_loss)]
            {
                entities.len() as f64 / duration as f64
            }
        }
        _ => 0.0,
    };
    let scorecard = Scorecard {
        multi_hop_depth: metrics.seed_reach.max_depth,
        graph_coverage: metrics.seed_reach.reachable_fraction,
        corroborated_fraction: metrics.corroborated_fraction,
        graph_density: metrics.graph_density,
        cut_vertex_count,
        bridge_count,
        degeneracy: metrics.graph_degeneracy,
        main_core_size: metrics.main_core_size,
        total_entities: metrics.total_entities,
        total_relations: metrics.total_relations,
        cross_scan_bridges: metrics.cross_scan_bridges,
    };
    let rows = provider_coverage_from_events(events);
    let coverage = (!rows.is_empty()).then(|| coverage_verdict(&rows));
    let mut report = BenchmarkReport {
        scan_id: scan.id.clone(),
        seed: scan.target.value.clone(),
        seed_kind: scan.target.kind.canonical_str().to_string(),
        status: scan.status.as_str().to_string(),
        duration_secs,
        entities_per_sec,
        modules_run: scan.modules_run,
        modules_errored: scan.modules_errored,
        modules_timed_out: scan.modules_timed_out,
        pivot_count,
        top_pivot_uid,
        scorecard,
        metrics,
        coverage,
        comparability_caveat: None,
    };
    report.comparability_caveat = report.comparability_caveat();
    report
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ExpectedPublicFact {
    pub entity_kind: crate::entity::EntityKind,
    pub value: String,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ForbiddenPublicFact {
    pub entity_kind: crate::entity::EntityKind,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CoverageRatio {
    pub numerator: usize,
    pub denominator: usize,
}

impl CoverageRatio {
    #[must_use]
    pub const fn new(numerator: usize, denominator: usize) -> Self {
        if denominator == 0 {
            Self {
                numerator: 1,
                denominator: 1,
            }
        } else {
            Self {
                numerator,
                denominator,
            }
        }
    }

    #[must_use]
    pub const fn is_complete(self) -> bool {
        self.numerator == self.denominator
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PersonResolutionScore {
    pub expected_facts: usize,
    pub matched_facts: usize,
    pub recall: CoverageRatio,
    pub supported_entities: usize,
    pub emitted_entities: usize,
    pub precision: CoverageRatio,
    pub entities_with_evidence: usize,
    pub entities_without_evidence: usize,
    pub provenance_coverage: CoverageRatio,
    pub unsupported_person_entities: usize,
    pub forbidden_facts: usize,
    pub forbidden_facts_emitted: usize,
    pub required_independent_person_support: usize,
    pub proven_independent_person_support: usize,
    pub independence_check_complete: bool,
    pub accepted: bool,
}

#[must_use]
pub fn score_person_resolution(
    entities: &[Entity],
    expected: &[ExpectedPublicFact],
    forbidden: &[ForbiddenPublicFact],
) -> PersonResolutionScore {
    score_person_resolution_with_ancestry(entities, expected, forbidden, None, 0)
}

#[must_use]
pub fn score_person_resolution_with_ancestry(
    entities: &[Entity],
    expected: &[ExpectedPublicFact],
    forbidden: &[ForbiddenPublicFact],
    ancestry: Option<&EvidenceAncestryGraph>,
    required_independent_person_support: usize,
) -> PersonResolutionScore {
    use std::collections::BTreeSet;

    let expected: BTreeSet<_> = expected
        .iter()
        .map(|fact| {
            (
                fact.entity_kind.clone(),
                crate::entity::normalise(&fact.entity_kind, &fact.value),
                fact.source.as_str(),
            )
        })
        .collect();
    let forbidden: BTreeSet<_> = forbidden
        .iter()
        .map(|fact| {
            (
                fact.entity_kind.clone(),
                crate::entity::normalise(&fact.entity_kind, &fact.value),
            )
        })
        .collect();

    let matched_facts = expected
        .iter()
        .filter(|(kind, value, source)| {
            entities.iter().any(|entity| {
                entity.kind == *kind
                    && entity.value == *value
                    && entity
                        .evidence
                        .iter()
                        .any(|evidence| evidence.provenance.source == **source)
            })
        })
        .count();
    let supported_entities = entities
        .iter()
        .filter(|entity| {
            expected.iter().any(|(kind, value, source)| {
                entity.kind == *kind
                    && entity.value == *value
                    && entity
                        .evidence
                        .iter()
                        .any(|evidence| evidence.provenance.source == *source)
            })
        })
        .count();
    let entities_with_evidence = entities
        .iter()
        .filter(|entity| !entity.evidence.is_empty())
        .count();
    let entities_without_evidence = entities.len().saturating_sub(entities_with_evidence);
    let unsupported_person_entities = entities
        .iter()
        .filter(|entity| {
            entity.kind == crate::entity::EntityKind::Person
                && !expected
                    .iter()
                    .any(|(kind, value, _)| entity.kind == *kind && entity.value == *value)
        })
        .count();
    let forbidden_facts_emitted = forbidden
        .iter()
        .filter(|(kind, value)| {
            entities
                .iter()
                .any(|entity| entity.kind == *kind && entity.value == *value)
        })
        .count();

    let person_ancestry_nodes: BTreeSet<_> = entities
        .iter()
        .filter(|entity| {
            entity.kind == crate::entity::EntityKind::Person
                && expected
                    .iter()
                    .any(|(kind, value, _)| entity.kind == *kind && entity.value == *value)
        })
        .flat_map(|entity| {
            entity
                .evidence
                .iter()
                .filter_map(|evidence| evidence.ancestry_node.as_ref())
        })
        .collect();
    let independence = if required_independent_person_support == 0 {
        Some(crate::evidence_ancestry::IndependenceRouteCount {
            proven: 0,
            incomplete: false,
        })
    } else {
        ancestry.and_then(|graph| {
            graph
                .proven_independent_route_count(
                    person_ancestry_nodes.iter().copied(),
                    required_independent_person_support,
                    100_000,
                )
                .ok()
        })
    };
    let proven_independent_person_support = independence.map_or(0, |count| count.proven);
    let independence_check_complete = independence.is_some_and(|count| !count.incomplete);
    let independence_accepted = required_independent_person_support == 0
        || (independence_check_complete
            && proven_independent_person_support >= required_independent_person_support);

    let recall = CoverageRatio::new(matched_facts, expected.len());
    let precision = CoverageRatio::new(supported_entities, entities.len());
    let provenance_coverage = CoverageRatio::new(entities_with_evidence, entities.len());
    let accepted = recall.is_complete()
        && precision.is_complete()
        && provenance_coverage.is_complete()
        && unsupported_person_entities == 0
        && forbidden_facts_emitted == 0
        && independence_accepted;

    PersonResolutionScore {
        expected_facts: expected.len(),
        matched_facts,
        recall,
        supported_entities,
        emitted_entities: entities.len(),
        precision,
        entities_with_evidence,
        entities_without_evidence,
        provenance_coverage,
        unsupported_person_entities,
        forbidden_facts: forbidden.len(),
        forbidden_facts_emitted,
        required_independent_person_support,
        proven_independent_person_support,
        independence_check_complete,
        accepted,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coverage::{EventKind, SkipClass};
    use crate::dependency::TargetKind;
    use crate::entity::EntityKind;
    use crate::graph::{EntityRelation, RelationKind};

    fn module_event(kind: EventKind) -> Event {
        Event {
            scan_id: "s1".to_string(),
            ts: 0,
            kind,
        }
    }

    #[test]
    fn report_consolidates_metrics_timing_and_pivots() {
        let mut subject = Entity::new(EntityKind::Person, "Subject Person", 0.85, "s1");
        subject.tag("subject");
        let address = Entity::new(EntityKind::Address, "1 Main St, Town", 0.6, "s1");
        let relative = Entity::new(EntityKind::Person, "Relative Person", 0.5, "s1");
        let relations = vec![
            EntityRelation::new(
                subject.uid.as_str(),
                address.uid.as_str(),
                RelationKind::LocatedAt,
                0.6,
            ),
            EntityRelation::new(
                relative.uid.as_str(),
                address.uid.as_str(),
                RelationKind::LocatedAt,
                0.6,
            ),
        ];
        let entities = vec![subject, address.clone(), relative];
        let mut scan = ScanRecord::new("s1", Target::new(TargetKind::FullName, "Subject Person"));
        scan.status = ScanStatus::Complete;
        scan.started_at = 1000;
        scan.finished_at = Some(1010);
        scan.modules_run = 8;
        scan.modules_errored = 1;
        let report = report(&scan, &entities, &relations, &[]);
        assert_eq!(report.scan_id, "s1");
        assert_eq!(report.seed_kind, "full_name");
        assert_eq!(report.status, "complete");
        assert_eq!(report.duration_secs, Some(10));
        assert!((report.entities_per_sec - 0.3).abs() < 1e-9);
        assert_eq!(report.scorecard.multi_hop_depth, 2);
        assert!((report.scorecard.graph_coverage - 1.0).abs() < 1e-9);
        assert_eq!(report.scorecard.cut_vertex_count, 1);
        assert_eq!(report.scorecard.bridge_count, 2);
        assert_eq!(report.scorecard.degeneracy, 1);
        assert_eq!(report.scorecard.main_core_size, 3);
        assert_eq!(report.top_pivot_uid.as_deref(), Some(address.uid.as_str()));
    }

    #[test]
    fn cut_vertex_count_uses_full_graph_not_truncated_headline() {
        let nodes: Vec<Entity> = (0..30)
            .map(|idx| Entity::new(EntityKind::Username, format!("n{idx:02}"), 0.6, "s1"))
            .collect();
        let relations: Vec<EntityRelation> = nodes
            .windows(2)
            .map(|window| {
                EntityRelation::new(
                    window[0].uid.as_str(),
                    window[1].uid.as_str(),
                    RelationKind::AssociatedWith,
                    0.6,
                )
            })
            .collect();
        let mut scan = ScanRecord::new("s1", Target::new(TargetKind::Username, "n00"));
        scan.status = ScanStatus::Complete;
        let report = report(&scan, &nodes, &relations, &[]);
        assert_eq!(report.scorecard.cut_vertex_count, 28);
    }

    #[test]
    fn comparability_caveats_track_missing_degraded_and_clean_coverage() {
        let scan = ScanRecord::new("s1", Target::new(TargetKind::FullName, "Subject Person"));
        let entities = vec![Entity::new(
            EntityKind::Person,
            "Subject Person",
            0.85,
            "s1",
        )];
        let blind = report(&scan, &entities, &[], &[]);
        assert!(blind.coverage.is_none());
        assert!(
            blind
                .comparability_caveat
                .as_deref()
                .unwrap()
                .contains("unknown")
        );

        let degraded = report(
            &scan,
            &entities,
            &[],
            &[
                module_event(EventKind::ModuleDone {
                    module: "answered".to_string(),
                    found: 1,
                }),
                module_event(EventKind::ModuleSkipped {
                    module: "unkeyed".to_string(),
                    reason: "needs API key".to_string(),
                    class: Some(SkipClass::Unavailable),
                }),
            ],
        );
        assert_eq!(degraded.coverage.unwrap().unavailable_count, 1);
        assert!(
            degraded
                .comparability_caveat
                .as_deref()
                .unwrap()
                .contains("could not be used")
        );

        let clean = report(
            &scan,
            &entities,
            &[],
            &[module_event(EventKind::ModuleDone {
                module: "answered".to_string(),
                found: 1,
            })],
        );
        assert!(clean.coverage.unwrap().is_exhaustive());
        assert_eq!(clean.comparability_caveat, None);
    }
}
