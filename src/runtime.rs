//! High-level composition root. Domain modules remain authoritative for their invariants.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::analysis::{InvestigationReport, analyze_snapshot};
use crate::artifacts::{PipelineArtifacts, render_artifacts};
use crate::collection::{CollectionEvent, ObservationBatch, RawObservation, UpstreamOrigin};
use crate::dependency::{Module, Target, TargetKind};
use crate::error::Error;
use crate::ledger::LedgerEntry;
use crate::pipeline::{
    AnalysisSnapshot, InvestigationInput, PipelineLimits, SeedNormalization,
    normalize_observations, normalize_seeds,
};
use crate::meta_plan::{MetaPlan, PlanReject};
use crate::planner::{DispatchPlan, PlannerPolicy, build_dispatch_plan};
use crate::session::{Candidate, ExecuteRecord, FalsifyRecord, Session, VerifyRecord};
use crate::source_outcome::SourceOutcomeKind;
use crate::stage::{EvidenceLevel, Status};
use crate::store::Store;

#[derive(Debug, Clone, PartialEq)]
pub struct PipelineOutcome {
    pub normalization: SeedNormalization,
    pub plan: DispatchPlan,
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
        independence_assertions: Vec::new(),
        truncated: normalization.truncated,
    }
}


/// Admit one round plan. Refusal is the result when the plan is inherited or incomplete.
///
/// # Errors
/// Returns [`Error::Invalid`] for every [`PlanReject`]. Does not fall back to `planner`.
pub fn admit_round(plan: MetaPlan) -> Result<MetaPlan, Error> {
    plan.admit().map_err(|reject| Error::Invalid(reject_message(reject)))
}

fn reject_message(reject: PlanReject) -> String {
    match reject {
        PlanReject::EmptySeed => "meta-plan refused: empty seed".to_string(),
        PlanReject::MissingField(field) => format!("meta-plan refused: missing {field}"),
        PlanReject::InheritedFallback => "meta-plan refused: inherited fallback".to_string(),
        PlanReject::VerificationClaim => "meta-plan refused: verification claim".to_string(),
        PlanReject::EmptyDispatch => "meta-plan refused: empty dispatch".to_string(),
        PlanReject::NoReversalObservation => {
            "meta-plan refused: no reversal observation".to_string()
        }
    }
}


/// One admitted round. `planner` is not called.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatedRound {
    pub admitted: MetaPlan,
}

/// Refuse an inherited or incomplete plan before any dispatch.
///
/// # Errors
/// Returns the [`admit_round`] refusal. Does not call `build_dispatch_plan`.
pub fn investigate_gated(plan: MetaPlan) -> Result<GatedRound, Error> {
    Ok(GatedRound {
        admitted: admit_round(plan)?,
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caller_refuses_inherited_plan() {
        let plan = MetaPlan {
            seed: "example.com".into(),
            hypotheses: vec!["domain".into()],
            determination_method: "fallback to static source table".into(),
            method_reversal: "a fetched body contradicts the method".into(),
            actions: vec![crate::meta_plan::PlanAction {
                source_id: "crtsh".into(),
                query: "example.com".into(),
                why: "structured names before html".into(),
                reversal_observation: "quarantine or valid zero".into(),
                requires_key: false,
                lead_only: true,
            }],
            stop_rule: "stop on two independent admitted origins".into(),
            next_pivot: "none until a body is admitted".into(),
        };
        let error = admit_round(plan.clone()).expect_err("inherited plan must be refused");
        assert!(error.to_string().contains("inherited fallback"));
        let gated = investigate_gated(plan).expect_err("gated path must refuse");
        assert!(gated.to_string().contains("inherited fallback"));
    }

    #[test]
    fn gated_path_returns_the_admitted_plan_only() {
        let plan = MetaPlan {
            seed: " Example.COM ".into(),
            hypotheses: vec!["domain".into()],
            determination_method: "reversal-tested case construction".into(),
            method_reversal: "a fetched body contradicts the method".into(),
            actions: vec![crate::meta_plan::PlanAction {
                source_id: " CrtSh ".into(),
                query: " Example.COM ".into(),
                why: "structured names before html".into(),
                reversal_observation: "quarantine or valid zero".into(),
                requires_key: false,
                lead_only: true,
            }],
            stop_rule: "stop on two independent admitted origins".into(),
            next_pivot: "none until a body is admitted".into(),
        };
        let gated = investigate_gated(plan).expect("admitted round");
        assert_eq!(gated.admitted.seed, "example.com");
        assert_eq!(gated.admitted.actions[0].source_id, "crtsh");
        assert_eq!(gated.admitted.actions[0].query, "example.com");
    }
}
