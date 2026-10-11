use std::collections::BTreeMap;

use huntsman_recon::analysis::{analyze_snapshot, analyze_snapshot_with_cross_scan};
use huntsman_recon::archive::{ArchiveCapture, ArchiveSource, merge_captures, parse_archive_url};
use huntsman_recon::archive_bridge::records_to_observation_batch;
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

#[test]
fn archive_records_enter_collection_pipeline_with_provenance_and_metadata() {
    let url = "https://example.com/admin/backup.zip?version=1";
    let key = parse_archive_url(url).expect("archive URL");
    let records = merge_captures(vec![ArchiveCapture {
        source: ArchiveSource::Wayback,
        dataset: "cdx".to_string(),
        collection: Some("2025".to_string()),
        original_url: url.to_string(),
        key,
        captured_at: "20250101000000".to_string(),
        status: Some(200),
        mime: Some("application/zip".to_string()),
        digest: Some("sha1:fixture".to_string()),
        source_url: Some("https://web.archive.org/fixture".to_string()),
    }]);
    let batch = records_to_observation_batch(&records, "scan", &PipelineLimits::default());
    assert_eq!(batch.observations.len(), 1);
    let observation = &batch.observations[0];
    assert_eq!(observation.provider_id, "wayback");
    assert_eq!(
        observation
            .upstream
            .as_ref()
            .and_then(|origin| origin.dataset.as_deref()),
        Some("cdx")
    );
    let interests = observation
        .attributes
        .get("archive_interests")
        .expect("interest metadata");
    assert!(interests.contains("archive_or_backup"));
    assert!(interests.contains("admin_auth_api_like"));
    assert!(interests.contains("parameterized"));
}

#[test]
fn archive_cap_surfaces_truncation() {
    let records = (0..3)
        .map(|index| {
            let url = format!("https://example.com/file{index}.pdf");
            let key = parse_archive_url(&url).expect("archive URL");
            ArchiveCapture {
                source: ArchiveSource::CommonCrawl,
                dataset: format!("CC-MAIN-{index}"),
                collection: None,
                original_url: url,
                key,
                captured_at: "20250101000000".to_string(),
                status: Some(200),
                mime: Some("application/pdf".to_string()),
                digest: None,
                source_url: None,
            }
        })
        .collect::<Vec<_>>();
    let merged = merge_captures(records);
    let limits = PipelineLimits {
        max_archive_captures: 2,
        ..PipelineLimits::default()
    };
    let batch = records_to_observation_batch(&merged, "scan", &limits);
    assert_eq!(batch.observations.len(), 2);
    assert!(batch.truncated);
    assert!(batch.events.iter().all(|event| event.truncated));
}
