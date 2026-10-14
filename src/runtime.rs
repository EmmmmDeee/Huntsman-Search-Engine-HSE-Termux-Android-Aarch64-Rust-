//! High-level composition root. Domain modules remain authoritative for their invariants.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Serialize;

use crate::analysis::{InvestigationReport, analyze_snapshot};
use crate::artifacts::{PipelineArtifacts, render_artifacts};
use crate::collection::{CollectionEvent, ObservationBatch, RawObservation, UpstreamOrigin};
use crate::correlator::Correlation;
use crate::dependency::{Module, Target, TargetKind};
use crate::entity::Entity;
use crate::error::Error;
use crate::gap::GapReport;
use crate::graph::EntityRelation;
use crate::ledger::LedgerEntry;
use crate::meta_plan::{MetaPlan, PlanReject};
use crate::pipeline::{
    AnalysisSnapshot, InvestigationInput, InvestigationMode, NormalizedSeed, PipelineLimits,
    SeedNormalization, SeedRejection, normalize_observations, normalize_seeds,
};
use crate::pivot::PivotScore;
use crate::planner::{DispatchAction, DispatchPlan, PlannerPolicy, build_dispatch_plan};
use crate::session::{Candidate, ExecuteRecord, FalsifyRecord, Session, VerifyRecord};
use crate::source_outcome::SourceOutcomeKind;
use crate::stage::{EvidenceLevel, Status};
use crate::store::Store;
use crate::termination::TerminationReason;

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
    plan.admit()
        .map_err(|reject| Error::Invalid(reject_message(&reject)))
}

fn reject_message(reject: &PlanReject) -> String {
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

/// The multi-hop result of an offline investigation, as `GET /api/analyze` returns it: the
/// entities, the links between them, the next pivots, the correlations, the gaps and the planned
/// sources. `plan` prints these only as counts.
#[derive(Debug, Serialize)]
pub struct AnalysisView<'a> {
    pub accepted: &'a [NormalizedSeed],
    pub rejected: Vec<RejectedSeed<'a>>,
    pub entities: &'a [Entity],
    pub relations: &'a [EntityRelation],
    pub pivots: &'a [PivotScore],
    pub correlations: &'a [Correlation],
    pub gaps: &'a GapReport,
    pub planned: Vec<PlannedSource<'a>>,
    pub termination: TerminationReason,
    pub truncated: bool,
}

/// A seed the spine refused, and why.
#[derive(Debug, Serialize)]
pub struct RejectedSeed<'a> {
    pub seed: &'a str,
    pub reason: String,
}

/// A source the planner would query next for one target. Offline it is planned, never fetched.
#[derive(Debug, Serialize)]
pub struct PlannedSource<'a> {
    pub kind: TargetKind,
    pub value: &'a str,
    pub source: String,
    pub url: Option<&'a str>,
    pub utility: Option<f64>,
}

impl PipelineOutcome {
    /// The multi-hop view of this outcome.
    #[must_use]
    pub fn analysis_view(&self) -> AnalysisView<'_> {
        AnalysisView {
            accepted: &self.normalization.accepted,
            rejected: self
                .normalization
                .rejected
                .iter()
                .map(|(seed, rejection)| RejectedSeed {
                    seed,
                    reason: match rejection {
                        SeedRejection::Empty => "empty".to_owned(),
                        SeedRejection::Unsupported => {
                            "not a kind of seed the spine takes".to_owned()
                        }
                        SeedRejection::Invalid(message) => message.clone(),
                    },
                })
                .collect(),
            entities: &self.snapshot.entities,
            relations: &self.snapshot.relations,
            pivots: &self.report.pivots,
            correlations: &self.report.correlations,
            gaps: &self.report.gaps,
            planned: self
                .plan
                .selected
                .iter()
                .map(|dispatch| {
                    let (source, url) = match &dispatch.action {
                        DispatchAction::Module { module_index } => {
                            (format!("module {module_index}"), None)
                        }
                        DispatchAction::Route { source_id, url } => {
                            ((*source_id).to_owned(), Some(url.as_str()))
                        }
                        DispatchAction::ServiceProbe { service } => ((*service).to_owned(), None),
                    };
                    PlannedSource {
                        kind: dispatch.target.kind,
                        value: &dispatch.target.value,
                        source,
                        url,
                        utility: dispatch
                            .utility
                            .as_ref()
                            .map(|utility| utility.final_utility),
                    }
                })
                .collect(),
            termination: self.report.termination,
            truncated: self.report.truncated || self.artifacts.truncated,
        }
    }
}

/// Run the offline spine on `seeds`, as `plan` does, and return its multi-hop view as JSON.
/// Planned sources are not fetched: nothing here makes a network request.
///
/// # Errors
/// Returns the spine's error, or a failure to encode the view.
pub fn analyze_offline(seeds: &[String]) -> Result<serde_json::Value, Error> {
    let input = InvestigationInput {
        scan_id: "analyze".to_owned(),
        seeds: seeds.to_vec(),
        mode: InvestigationMode::Offline,
    };
    let outcome = investigate_offline(
        &[],
        &input,
        &PipelineLimits::default(),
        &PlannerPolicy::default(),
        &[],
    )?;
    serde_json::to_value(outcome.analysis_view())
        .map_err(|error| Error::Invalid(format!("analysis view: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_offline_analysis_links_the_seeds_ranks_the_pivot_and_names_the_orphan() {
        let seeds = [
            "alex.demo@example.org",
            "@alexdemo",
            "example.org",
            "+15555550123",
        ]
        .map(str::to_owned);
        let view = analyze_offline(&seeds).unwrap();
        assert_eq!(view["accepted"].as_array().unwrap().len(), 4);
        assert_eq!(view["rejected"], serde_json::json!([]));
        let uid_of = |kind: &str| {
            let entity = view["entities"]
                .as_array()
                .unwrap()
                .iter()
                .find(|entity| entity["kind"] == kind)
                .unwrap_or_else(|| panic!("no {kind} entity in {view}"));
            entity["uid"].clone()
        };
        let linked = |left: &serde_json::Value, right: &serde_json::Value| {
            view["relations"]
                .as_array()
                .unwrap()
                .iter()
                .any(|relation| {
                    (relation["from_uid"] == *left && relation["to_uid"] == *right)
                        || (relation["from_uid"] == *right && relation["to_uid"] == *left)
                })
        };
        let email = uid_of("email");
        // Two hops from one seed: the email reaches its local part's username and its domain.
        assert!(linked(&email, &uid_of("username")), "{view}");
        assert!(linked(&email, &uid_of("domain")), "{view}");
        // So the email is the pivot that holds the cluster together.
        assert_eq!(view["pivots"][0]["uid"], email);
        assert_eq!(view["pivots"][0]["articulation"], true);
        // The phone links to nothing, and the gaps name it.
        assert_eq!(view["gaps"]["linked_seeds"], 3);
        assert_eq!(view["gaps"]["total_seeds"], 4);
        assert_eq!(view["gaps"]["orphans"][0]["kind"], "phone");
        assert!(!view["planned"].as_array().unwrap().is_empty(), "{view}");
        assert_eq!(view["termination"], "fixed_point");
        // The email and the username are one identity joined by a single path, so that pair
        // carries a corroboration gap (AU-063). The domain only hosts the address: it is not part
        // of the identity, so no identity rule names it and no three-entity cluster (AU-060)
        // forms.
        let correlations = view["correlations"].as_array().unwrap();
        let fired: Vec<&str> = correlations
            .iter()
            .filter_map(|correlation| correlation["rule_id"].as_str())
            .collect();
        assert!(!fired.contains(&"AU-060"), "{fired:?}");
        let gap = correlations
            .iter()
            .find(|correlation| correlation["rule_id"] == "AU-063")
            .unwrap_or_else(|| panic!("no AU-063 in {fired:?}"));
        let mut pair = [email.clone(), uid_of("username")];
        pair.sort_by(|left, right| left.as_str().cmp(&right.as_str()));
        assert_eq!(gap["entity_uids"], serde_json::json!(pair), "{gap}");
        let domain = uid_of("domain");
        for correlation in correlations.iter().filter(|correlation| {
            ["AU-060", "AU-062", "AU-063", "AU-070", "AU-071"]
                .contains(&correlation["rule_id"].as_str().unwrap_or_default())
        }) {
            let named = correlation["entity_uids"].as_array().unwrap();
            assert!(!named.contains(&domain), "{correlation}");
        }
    }

    #[test]
    fn the_offline_analysis_names_each_rejected_seed() {
        let seeds = ["example.org", "alexdemo"].map(str::to_owned);
        let view = analyze_offline(&seeds).unwrap();
        let rejected = view["rejected"].as_array().unwrap();
        assert_eq!(rejected.len(), 1, "{rejected:?}");
        assert_eq!(rejected[0]["seed"], "alexdemo");
        assert!(
            rejected[0]["reason"]
                .as_str()
                .is_some_and(|reason| !reason.is_empty())
        );
    }

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

    #[test]
    fn an_offline_run_persists_a_session_that_reloads_byte_for_byte() {
        use crate::pipeline::{InvestigationInput, InvestigationMode, PipelineLimits};
        use crate::planner::PlannerPolicy;
        use crate::store::Store;

        let input = InvestigationInput {
            scan_id: "persist-roundtrip".into(),
            seeds: vec!["alice@example.org".into()],
            mode: InvestigationMode::Offline,
        };
        let outcome = investigate_offline(
            &[],
            &input,
            &PipelineLimits::default(),
            &PlannerPolicy::default(),
            &[],
        )
        .expect("offline investigation");

        let session = session_for_outcome(&input, &outcome).expect("session");
        assert!(session.termination.is_some());

        let root =
            std::env::temp_dir().join(format!("huntsman-session-roundtrip-{}", std::process::id()));
        let saved = persist_session(&root, &session).expect("persist");
        assert!(saved.exists());

        // The dormant read path is now reachable: a saved session reloads to the
        // exact document that was written.
        let reloaded = Store::new(&root).load(&session.id).expect("reload");
        assert_eq!(reloaded, session);

        std::fs::remove_dir_all(&root).ok();
    }
}
