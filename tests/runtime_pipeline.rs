use huntsman_recon::artifacts::ArtifactPayload;
use huntsman_recon::pipeline::{InvestigationInput, InvestigationMode, PipelineLimits};
use huntsman_recon::planner::PlannerPolicy;
use huntsman_recon::runtime::{investigate_offline, session_for_outcome};

fn input() -> InvestigationInput {
    InvestigationInput {
        scan_id: "scan-runtime".to_string(),
        seeds: vec!["ada@example.com".to_string(), "example.com".to_string()],
        mode: InvestigationMode::Offline,
    }
}

#[test]
fn offline_runtime_executes_the_shared_spine_end_to_end() {
    let outcome = investigate_offline(
        &[],
        &input(),
        &PipelineLimits::default(),
        &PlannerPolicy::default(),
        &[],
    )
    .expect("outcome");
    assert_eq!(outcome.normalization.accepted.len(), 2);
    assert_eq!(outcome.snapshot.entities.len(), 2);
    assert_eq!(outcome.report.metrics.total_entities, 2);
    assert!(!outcome.plan.selected.is_empty());
    assert!(matches!(
        outcome.artifacts.report_json,
        ArtifactPayload::Ready(_)
    ));
}

#[test]
fn offline_runtime_is_deterministic_for_fixed_inputs() {
    let left = investigate_offline(
        &[],
        &input(),
        &PipelineLimits::default(),
        &PlannerPolicy::default(),
        &[],
    )
    .expect("left");
    let right = investigate_offline(
        &[],
        &input(),
        &PipelineLimits::default(),
        &PlannerPolicy::default(),
        &[],
    )
    .expect("right");
    assert_eq!(left, right);
}

#[test]
fn session_records_execution_without_claiming_live_collection() {
    let outcome = investigate_offline(
        &[],
        &input(),
        &PipelineLimits::default(),
        &PlannerPolicy::default(),
        &[],
    )
    .expect("outcome");
    let session = session_for_outcome(&input(), &outcome).expect("session");
    assert!(!session.executions.is_empty());
    assert!(!session.verifications.is_empty());
    assert!(
        session
            .termination
            .as_ref()
            .is_some_and(|term| term.partial)
    );
    assert!(
        session
            .termination
            .as_ref()
            .is_some_and(|term| term.residual_uncertainty.contains("offline"))
    );
}
