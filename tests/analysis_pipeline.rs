use std::collections::BTreeMap;

use huntsman_recon::analysis::{analyze_snapshot, analyze_snapshot_with_cross_scan};
use huntsman_recon::cross_scan::{CrossScanCategory, CrossScanStore};
use huntsman_recon::entity::{Entity, EntityKind, Evidence, EvidenceProvenance};
use huntsman_recon::error::Error;
use huntsman_recon::evidence_ancestry::EvidenceAncestryGraph;
use huntsman_recon::graph::{EntityRelation, RelationKind};
use huntsman_recon::pipeline::{AnalysisSnapshot, PipelineLimits};
use huntsman_recon::termination::TerminationReason;

struct HistoryStore {
    scan_entities: BTreeMap<String, Vec<Entity>>,
    entity_scans: BTreeMap<String, Vec<String>>,
}

impl CrossScanStore for HistoryStore {
    fn entities_for_scan(&self, scan_id: &str) -> Result<Vec<Entity>, Error> {
        Ok(self.scan_entities.get(scan_id).cloned().unwrap_or_default())
    }

    fn scan_ids_for_entity(&self, entity_uid: &str) -> Result<Vec<String>, Error> {
        Ok(self
            .entity_scans
            .get(entity_uid)
            .cloned()
            .unwrap_or_default())
    }
}

fn snapshot(truncated: bool) -> AnalysisSnapshot {
    let left = Entity::new(EntityKind::Email, "ada@example.com", 0.8, "current");
    let right = Entity::new(EntityKind::Domain, "example.com", 0.7, "current");
    AnalysisSnapshot {
        entities: vec![left.clone(), right.clone()],
        relations: vec![EntityRelation::new(
            left.uid,
            right.uid,
            RelationKind::AssociatedWith,
            0.8,
        )],
        coverage: vec![],
        ancestry: EvidenceAncestryGraph::default(),
        truncated,
    }
}

#[test]
fn one_snapshot_drives_intelligence_metrics_gaps_pivots_and_termination() {
    let report = analyze_snapshot(&snapshot(false));
    assert_eq!(report.intelligence.graph.node_count, 2);
    assert_eq!(report.metrics.total_entities, 2);
    assert_eq!(report.metrics.total_relations, 1);
    assert_eq!(report.gaps.linked_seeds, 2);
    assert_eq!(report.attack.leaf_techniques_covered, 0);
    assert_eq!(report.pivots.len(), 2);
    assert_eq!(report.termination, TerminationReason::FixedPoint);
    assert!(!report.truncated);
}

#[test]
fn observed_evidence_drives_attack_projection_without_scoring_seed_assertions() {
    let mut seed = Entity::new(EntityKind::Email, "seed@example.com", 1.0, "current");
    seed.add_evidence(
        Evidence::new(
            EvidenceProvenance::for_scan("operator_input", "current"),
            "operator seed",
        )
        .with_attr("evidence_role", "seed_not_external_verification"),
    );

    let mut observed = Entity::new(EntityKind::Email, "ada@example.com", 0.8, "current");
    observed.add_evidence(Evidence::new(
        EvidenceProvenance::for_scan("public_profile", "current"),
        "provider observation",
    ));

    let snapshot = AnalysisSnapshot {
        entities: vec![seed, observed],
        relations: vec![],
        coverage: vec![],
        ancestry: EvidenceAncestryGraph::default(),
        truncated: false,
    };
    let report = analyze_snapshot(&snapshot);
    let covered: Vec<&str> = report
        .attack
        .covered_leaves
        .iter()
        .map(|item| item.id)
        .collect();

    assert!(covered.contains(&"T1589.002"));
    assert_eq!(report.attack.leaf_techniques_covered, 1);
}

#[test]
fn truncated_snapshot_reports_resource_limit_not_fixed_point() {
    let report = analyze_snapshot(&snapshot(true));
    assert_eq!(report.termination, TerminationReason::ResourceLimit);
    assert!(report.truncated);
}

#[test]
fn cross_scan_analysis_uses_pipeline_limits() {
    let snapshot = snapshot(false);
    let email = snapshot.entities[0].clone();
    let store = HistoryStore {
        scan_entities: BTreeMap::from([("prior".to_string(), vec![email.clone()])]),
        entity_scans: BTreeMap::from([(email.uid.clone(), vec!["prior".to_string()])]),
    };
    let limits = PipelineLimits {
        max_cross_scan_frontier: 1,
        max_cross_scan_visited: 2,
        ..PipelineLimits::default()
    };
    let report = analyze_snapshot_with_cross_scan(&snapshot, "current", &store, &limits)
        .expect("cross-scan report");
    assert!(matches!(
        report.cross_scan,
        Some(
            CrossScanCategory::Historical { .. }
                | CrossScanCategory::Relation { .. }
                | CrossScanCategory::Transitive { .. },
        )
    ));
}
