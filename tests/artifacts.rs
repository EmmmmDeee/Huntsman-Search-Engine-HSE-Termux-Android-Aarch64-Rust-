use huntsman_recon::analysis::analyze_snapshot;
use huntsman_recon::artifacts::{ArtifactPayload, render_artifacts};
use huntsman_recon::entity::{Entity, EntityKind};
use huntsman_recon::evidence_ancestry::EvidenceAncestryGraph;
use huntsman_recon::graph::{EntityRelation, RelationKind};
use huntsman_recon::ledger::{Claim, seal};
use huntsman_recon::pipeline::{AnalysisSnapshot, PipelineLimits};
use huntsman_recon::stage::{EvidenceLevel, Status};

fn snapshot() -> AnalysisSnapshot {
    let left = Entity::new(EntityKind::Email, "ada@example.com", 0.8, "scan");
    let right = Entity::new(EntityKind::Domain, "example.com", 0.7, "scan");
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
        truncated: false,
    }
}

#[test]
fn repeated_rendering_is_deterministic() {
    let snapshot = snapshot();
    let report = analyze_snapshot(&snapshot);
    let left =
        render_artifacts(&snapshot, &report, &[], &PipelineLimits::default()).expect("artifacts");
    let right =
        render_artifacts(&snapshot, &report, &[], &PipelineLimits::default()).expect("artifacts");
    assert_eq!(left, right);
}

#[test]
fn all_graph_artifacts_come_from_the_same_snapshot() {
    let snapshot = snapshot();
    let report = analyze_snapshot(&snapshot);
    let artifacts =
        render_artifacts(&snapshot, &report, &[], &PipelineLimits::default()).expect("artifacts");
    let ArtifactPayload::Ready(report_json) = &artifacts.report_json else {
        panic!("report omitted")
    };
    let report_text = String::from_utf8_lossy(report_json);
    assert!(report_text.contains("\"node_count\":2"));
    let ArtifactPayload::Ready(gexf) = &artifacts.gexf else {
        panic!("gexf omitted")
    };
    assert!(String::from_utf8_lossy(gexf).contains("<nodes>"));
    let ArtifactPayload::Ready(snake) = &artifacts.snake_graph else {
        panic!("snake omitted")
    };
    assert!(!snake.is_empty(), "{snake:?}");
}

#[test]
fn stix_and_navigator_do_not_invent_admitted_claims() {
    let snapshot = snapshot();
    let report = analyze_snapshot(&snapshot);
    let entry = seal(&Claim {
        claim: "candidate only".to_string(),
        source: "fixture".to_string(),
        component: "tests/artifacts.rs".to_string(),
        technique_id: Some("T1591".to_string()),
        status: Status::Unverified,
        evidence_level: EvidenceLevel::Assertion,
        does_not_show: "not verified".to_string(),
    });
    let artifacts = render_artifacts(&snapshot, &report, &[entry], &PipelineLimits::default())
        .expect("artifacts");
    let ArtifactPayload::Ready(stix) = &artifacts.stix else {
        panic!("stix omitted")
    };
    assert!(String::from_utf8_lossy(stix).contains("\"objects\":[]"));
    let ArtifactPayload::Ready(navigator) = &artifacts.navigator else {
        panic!("navigator omitted")
    };
    assert!(String::from_utf8_lossy(navigator).contains("\"techniques\":[]"));
}

#[test]
fn oversized_artifacts_are_omitted_not_truncated_into_invalid_data() {
    let snapshot = snapshot();
    let report = analyze_snapshot(&snapshot);
    let limits = PipelineLimits {
        max_export_bytes: 16,
        ..PipelineLimits::default()
    };
    let artifacts = render_artifacts(&snapshot, &report, &[], &limits).expect("artifacts");
    assert!(artifacts.truncated);
    assert!(matches!(
        artifacts.report_json,
        ArtifactPayload::OmittedTooLarge { .. }
    ));
    assert!(matches!(
        artifacts.gexf,
        ArtifactPayload::OmittedTooLarge { .. }
    ));
}

#[test]
fn bounded_entity_tree_reports_exact_required_bytes_without_partial_output() {
    let snapshot = snapshot();
    let report = analyze_snapshot(&snapshot);
    let baseline = render_artifacts(&snapshot, &report, &[], &PipelineLimits::default())
        .expect("baseline artifacts");
    let ArtifactPayload::Ready(tree) = baseline.snake_graph else {
        panic!("baseline tree omitted")
    };
    let limit = tree.len() - 1;
    let limits = PipelineLimits {
        max_export_bytes: limit,
        ..PipelineLimits::default()
    };
    let capped = render_artifacts(&snapshot, &report, &[], &limits).expect("capped artifacts");
    assert_eq!(
        capped.snake_graph,
        ArtifactPayload::OmittedTooLarge {
            required_bytes: tree.len(),
            limit,
        }
    );
    assert!(capped.truncated);
}

#[test]
fn bounded_gexf_reports_exact_required_bytes_without_partial_xml() {
    let snapshot = snapshot();
    let report = analyze_snapshot(&snapshot);
    let baseline = render_artifacts(&snapshot, &report, &[], &PipelineLimits::default())
        .expect("baseline artifacts");
    let ArtifactPayload::Ready(xml) = baseline.gexf else {
        panic!("baseline GEXF omitted")
    };
    let limit = xml.len() - 1;
    let limits = PipelineLimits {
        max_export_bytes: limit,
        ..PipelineLimits::default()
    };
    let capped = render_artifacts(&snapshot, &report, &[], &limits).expect("capped artifacts");
    assert_eq!(
        capped.gexf,
        ArtifactPayload::OmittedTooLarge {
            required_bytes: xml.len(),
            limit,
        }
    );
    assert!(capped.truncated);
}

#[test]
fn bounded_report_json_reports_exact_required_bytes_without_partial_document() {
    let snapshot = snapshot();
    let report = analyze_snapshot(&snapshot);
    let baseline = render_artifacts(&snapshot, &report, &[], &PipelineLimits::default())
        .expect("baseline artifacts");
    let ArtifactPayload::Ready(json) = baseline.report_json else {
        panic!("baseline report JSON omitted")
    };
    let limit = json.len() - 1;
    let limits = PipelineLimits {
        max_export_bytes: limit,
        ..PipelineLimits::default()
    };
    let capped = render_artifacts(&snapshot, &report, &[], &limits).expect("capped artifacts");
    assert_eq!(
        capped.report_json,
        ArtifactPayload::OmittedTooLarge {
            required_bytes: json.len(),
            limit,
        }
    );
    assert!(capped.truncated);
}
