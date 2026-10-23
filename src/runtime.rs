//! High-level composition root. Domain modules remain authoritative for their invariants.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Serialize;

use crate::analysis::{InvestigationReport, analyze_snapshot, analyze_snapshot_with_cross_scan};
use crate::artifacts::{PipelineArtifacts, render_artifacts};
use crate::collection::{CollectionEvent, ObservationBatch, RawObservation, UpstreamOrigin};
use crate::correlator::Correlation;
use crate::cross_scan::CrossScanCategory;
use crate::dependency::{Module, Target, TargetKind};
use crate::entity::{Entity, EntityKind, SEED_EVIDENCE_ROLE};
use crate::error::Error;
use crate::gap::GapReport;
use crate::graph::EntityRelation;
use crate::ledger::LedgerEntry;
use crate::meta_plan::MetaPlan;
use crate::pipeline::{
    AnalysisSnapshot, InvestigationInput, InvestigationMode, NormalizedSeed, PipelineLimits,
    SeedNormalization, SeedRejection, normalize_observations, normalize_seeds,
};
use crate::pivot::PivotScore;
use crate::planner::{DispatchAction, DispatchPlan, PlannerPolicy, build_dispatch_plan};
use crate::scan_artifact::ArtifactHistory;
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
                SEED_EVIDENCE_ROLE.to_string(),
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
/// Returns [`Error::Invalid`] for every [`crate::meta_plan::PlanReject`]. Does not fall back
/// to `planner`.
pub fn admit_round(plan: MetaPlan) -> Result<MetaPlan, Error> {
    plan.admit()
        .map_err(|reject| Error::Invalid(format!("meta-plan refused: {reject}")))
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
    investigate_offline_with_history(modules, input, limits, policy, ledger, None)
}

/// As [`investigate_offline`], and when `history` is given, bridges the snapshot's entities to the
/// saved scans in it, which the report then carries as `cross_scan`.
///
/// # Errors
/// Returns cross-scan storage failures, ancestry or artifact serialization failures.
pub fn investigate_offline_with_history(
    modules: &[Arc<dyn Module>],
    input: &InvestigationInput,
    limits: &PipelineLimits,
    policy: &PlannerPolicy,
    ledger: &[LedgerEntry],
    history: Option<&ArtifactHistory>,
) -> Result<PipelineOutcome, Error> {
    let normalization = normalize_seeds(input, limits);
    let plan = build_dispatch_plan(modules, &normalization.accepted, limits, policy);
    let snapshot = normalize_observations(seed_batch(&normalization, &input.scan_id), limits)
        .map_err(|error| Error::Invalid(error.to_string()))?;
    let report = match history {
        Some(history) => {
            analyze_snapshot_with_cross_scan(&snapshot, &input.scan_id, history, limits)?
        }
        None => analyze_snapshot(&snapshot),
    };
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
            "truncated={} termination={}",
            outcome.report.truncated,
            outcome.report.termination.as_str()
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
/// A geometric measurement between two explicitly supplied coordinate seeds.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GeoDistance {
    pub left: String,
    pub right: String,
    pub meters: f64,
    pub basis: &'static str,
}

/// Bound worst-case work and JSON output independently of pipeline target limits.
const MAX_GEO_POINTS: usize = 16;

fn geo_distances(seeds: &[NormalizedSeed]) -> (Vec<GeoDistance>, bool) {
    let coordinates: Vec<_> = seeds
        .iter()
        .filter(|seed| seed.kind == EntityKind::Coordinates)
        .filter_map(|seed| {
            crate::geohash::parse_coords(&seed.value)
                .map(|(lat, lon)| (seed.value.as_str(), lat, lon))
        })
        .collect();
    let truncated = coordinates.len() > MAX_GEO_POINTS;
    let coordinates = &coordinates[..coordinates.len().min(MAX_GEO_POINTS)];
    let pair_capacity = coordinates.len() * coordinates.len().saturating_sub(1) / 2;
    let mut distances = Vec::with_capacity(pair_capacity);
    for (index, &(left, lat_a, lon_a)) in coordinates.iter().enumerate() {
        for &(right, lat_b, lon_b) in &coordinates[index + 1..] {
            let meters = crate::geoint::haversine_m(lat_a, lon_a, lat_b, lon_b);
            if meters.is_finite() {
                distances.push(GeoDistance {
                    left: left.to_owned(),
                    right: right.to_owned(),
                    meters,
                    basis: "operator_supplied_coordinates",
                });
            }
        }
    }
    distances.sort_by(|a, b| {
        a.meters
            .total_cmp(&b.meters)
            .then_with(|| a.left.cmp(&b.left))
            .then_with(|| a.right.cmp(&b.right))
    });
    (distances, truncated)
}

/// The multi-hop result's bounded geographic distances are measurements,
/// not inferred identities, co-presence, or independent corroboration.
#[derive(Debug, Serialize)]
pub struct AnalysisView<'a> {
    pub accepted: &'a [NormalizedSeed],
    pub geo_distances: Vec<GeoDistance>,
    pub geo_truncated: bool,
    pub rejected: Vec<RejectedSeed<'a>>,
    pub entities: &'a [Entity],
    pub relations: &'a [EntityRelation],
    pub pivots: &'a [PivotScore],
    pub correlations: &'a [Correlation],
    /// Bridges to the saved scans of a history. `null` when no history was given.
    pub cross_scan: Option<&'a CrossScanCategory>,
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
        let (geo_distances, geo_truncated) = geo_distances(&self.normalization.accepted);
        AnalysisView {
            accepted: &self.normalization.accepted,
            geo_distances,
            geo_truncated,
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
            cross_scan: self.report.cross_scan.as_ref(),
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
    analyze_offline_with_history(seeds, None)
}

/// As [`analyze_offline`], and when `history` is given, bridges the seeds to the saved scans in it.
///
/// # Errors
/// Returns cross-scan storage failures, or the spine's own errors.
pub fn analyze_offline_with_history(
    seeds: &[String],
    history: Option<&ArtifactHistory>,
) -> Result<serde_json::Value, Error> {
    let input = InvestigationInput {
        scan_id: "analyze".to_owned(),
        seeds: seeds.to_vec(),
        mode: InvestigationMode::Offline,
    };
    let outcome = investigate_offline_with_history(
        &[],
        &input,
        &PipelineLimits::default(),
        &PlannerPolicy::default(),
        &[],
        history,
    )?;
    serde_json::to_value(outcome.analysis_view())
        .map_err(|error| Error::Invalid(format!("analysis view: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offline_geo_distances_cross_the_antimeridian_without_identity_inference() {
        let seeds = ["0.0,179.99", "0.0,-179.99", "0.0,0.0", "example.org"].map(str::to_owned);
        let view = analyze_offline(&seeds).expect("offline analysis");
        let distances = view["geo_distances"].as_array().expect("geo distances");
        assert_eq!(distances.len(), 3, "{view}");
        let nearest = &distances[0];
        assert_eq!(nearest["basis"], "operator_supplied_coordinates");
        assert!(
            nearest["meters"]
                .as_f64()
                .is_some_and(|m| m > 2000.0 && m < 3000.0),
            "{nearest}"
        );
        assert!(
            [nearest["left"].as_str(), nearest["right"].as_str()]
                .contains(&Some("0.000000,179.990000")),
            "{nearest}"
        );
        assert_eq!(view["geo_truncated"], false);
        assert!(
            view["relations"]
                .as_array()
                .unwrap()
                .iter()
                .all(|relation| {
                    relation["kind"] != "co_location" && relation["kind"] != "same_person"
                }),
            "{view}"
        );
        assert!(
            distances
                .iter()
                .all(|distance| { distance["meters"].as_f64().is_some_and(f64::is_finite) })
        );
    }

    #[test]
    fn geo_distances_cap_pairwise_work_at_sixteen_points() {
        let seeds: Vec<NormalizedSeed> = (0..40)
            .map(|index| NormalizedSeed {
                raw: format!("0,{index}"),
                kind: EntityKind::Coordinates,
                value: format!("0,{index}"),
            })
            .collect();
        let (distances, truncated) = geo_distances(&seeds);
        assert!(truncated);
        assert_eq!(distances.len(), 120);
        assert!(distances.iter().all(|pair| pair.meters.is_finite()));
    }

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
    fn admit_round_names_each_refusal() {
        let admissible = MetaPlan {
            seed: "example.com".into(),
            hypotheses: vec!["domain".into()],
            determination_method: "reversal-tested case construction".into(),
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
        assert!(admit_round(admissible.clone()).is_ok());
        type Refuse = fn(&mut MetaPlan);
        let cases: [(Refuse, &str); 5] = [
            (|plan| plan.seed = " ".into(), "empty seed"),
            (
                |plan| {
                    plan.stop_rule.clear();
                },
                "missing stop_rule",
            ),
            (
                |plan| {
                    plan.actions.clear();
                },
                "empty dispatch",
            ),
            (
                |plan| plan.determination_method = "fallback to static source table".into(),
                "inherited fallback",
            ),
            (
                |plan| plan.actions[0].why = "this source is verified".into(),
                "verification claim",
            ),
        ];
        for (refuse, reason) in cases {
            let mut plan = admissible.clone();
            refuse(&mut plan);
            assert_eq!(
                admit_round(plan).unwrap_err().to_string(),
                format!("invalid input: meta-plan refused: {reason}")
            );
        }
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
