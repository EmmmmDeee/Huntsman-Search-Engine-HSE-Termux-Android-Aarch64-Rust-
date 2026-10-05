//! High-level composition root. Domain modules remain authoritative for their invariants.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::analysis::{InvestigationReport, analyze_snapshot};
use crate::artifacts::{PipelineArtifacts, render_artifacts};
use crate::collection::{CollectionEvent, ObservationBatch, RawObservation, UpstreamOrigin};
use crate::dependency::{Module, Target, TargetKind};
use crate::error::Error;
use crate::ledger::LedgerEntry;
use crate::pipeline::{
    AnalysisSnapshot, InvestigationInput, PipelineLimits, SeedNormalization, normalize_observations,
    normalize_seeds,
};
use crate::planner::{DispatchPlan, PlannerPolicy, build_dispatch_plan};
use crate::session::{Candidate, ExecuteRecord, FalsifyRecord, Session, VerifyRecord};
use crate::source_outcome::SourceOutcomeKind;
use crate::stage::{EvidenceLevel, Status};
use crate::store::Store;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PipelineOutcome {
    pub normalization: SeedNormalization,
    #[serde(skip)]
    pub plan: DispatchPlan,
    #[serde(skip)]
    pub snapshot: AnalysisSnapshot,
    pub report: InvestigationReport,
    pub artifacts: PipelineArtifacts,
}

fn seed_batch(normalization: &SeedNormalization, scan_id: &str) -> ObservationBatch {
    let mut events = Vec::new();
    let mut observations = Vec::new();
    for seed in &normalization.accepted {
        let Some(kind) = TargetKind::from_entity_kind(&seed.kind) else {
            continue;
        };
        let target = Target::new(kind, seed.value.clone());
        let upstream = UpstreamOrigin {
            provider: Some("operator_input".to_string()),
            dataset: Some("explicit_seed".to_string()),
            artifact: None,
        };
        events.push(CollectionEvent {
            scan_id: scan_id.to_string(),
            provider_id: "operator_input".to_string(),
            target: target.clone(),
            outcome: SourceOutcomeKind::Success,
            finding_count: 1,
            truncated: false,
            started_at_unix: 0,
            finished_at_unix: 0,
            credential_fingerprint: None,
            upstream: Some(upstream.clone()),
        });
        observations.push(RawObservation {
            provider_id: "operator_input".to_string(),
            upstream: Some(upstream),
            target,
            kind: seed.kind.clone(),
            value: seed.value.clone(),
            summary: "operator-supplied investigation seed".to_string(),
            attributes: std::collections::BTreeMap::from([(
                "evidence_role".to_string(),
                "seed_not_external_verification".to_string(),
            )]),
            observed_at_unix: Some(0),
        });
    }
    ObservationBatch {
        events,
        observations,
        truncated: normalization.truncated,
    }
}

/// Execute the full deterministic offline spine. Dispatches are planned but not executed.
///
/// # Errors
/// Returns ancestry or artifact serialization failures.
pub fn investigate_offline(
    modules: &[Arc<dyn Module>],
    input: &InvestigationInput,
    limits: &PipelineLimits,
    policy: &PlannerPolicy,
    ledger: &[LedgerEntry],
) -> Result<PipelineOutcome, Error> {
    let normalization = normalize_seeds(input, limits);
    let plan = build_dispatch_plan(modules, &normalization.accepted, limits, policy);
    let snapshot = normalize_observations(seed_batch(&normalization, &input.scan_id), limits)
        .map_err(|error| Error::Invalid(error.to_string()))?;
    let report = analyze_snapshot(&snapshot);
    let artifacts = render_artifacts(&snapshot, &report, ledger, limits)?;
    Ok(PipelineOutcome {
        normalization,
        plan,
        snapshot,
        report,
        artifacts,
    })
}

/// Build an auditable execution session for an offline pipeline result.
///
/// This records that the software path executed; it does not claim external providers
/// were queried or that seed assertions were independently verified.
///
/// # Errors
/// Returns session validation failures.
pub fn session_for_outcome(
    input: &InvestigationInput,
    outcome: &PipelineOutcome,
) -> Result<Session, Error> {
    let mut session = Session::new(format!("investigate {}", input.scan_id));
    session.apply_recover(
        "run one bounded Huntsman investigation pipeline",
        "normalize, plan, analyze, and render one shared state",
        "offline mode does not execute planned external source routes",
        "all accepted seeds reach the shared analysis state or truncation is explicit",
    );
    session.add_candidate(Candidate {
        statement: "the shared runtime spine preserves one consistent investigation state".into(),
        alternatives: vec!["independent per-export reconstruction".into()],
        reverse_observation: "artifact counts disagree with the shared analysis report".into(),
    })?;
    session.add_falsify(FalsifyRecord {
        attack: "force bounded or incomplete input".into(),
        test: "inspect report/artifact truncation and termination reason".into(),
        result: format!(
            "truncated={} termination={:?}",
            outcome.report.truncated, outcome.report.termination
        ),
    })?;
    session.add_execute(ExecuteRecord {
        action: "offline investigation spine".into(),
        observed: format!(
            "accepted={} entities={} relations={} planned={}",
            outcome.normalization.accepted.len(),
            outcome.snapshot.entities.len(),
            outcome.snapshot.relations.len(),
            outcome.plan.selected.len()
        ),
        component: "src/runtime.rs".into(),
    })?;
    session.add_verify(VerifyRecord {
        claim: "offline pipeline completed through shared analysis/artifact state".into(),
        status: Status::Verified,
        evidence_level: EvidenceLevel::Reproduction,
        does_not_show: "does not show that planned network providers were queried".into(),
    })?;
    session.terminate(
        "offline execution leaves planned external collection unexecuted".into(),
        true,
        "",
    )?;
    Ok(session)
}

/// Persist a runtime session through the existing bounded atomic session store.
///
/// # Errors
/// Returns store/path validation failures.
pub fn persist_session(root: &Path, session: &Session) -> Result<PathBuf, Error> {
    Store::new(root).save(session)
}
