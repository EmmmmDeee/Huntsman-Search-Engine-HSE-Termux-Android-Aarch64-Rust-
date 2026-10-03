//! Pure operational action-selection policy.
//!
//! This module consumes normalized facts resolved elsewhere. It performs no I/O and
//! does not own provider, dependency, credential, or evidence registries.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use crate::roi::{DispatchUtility, DispatchUtilityInputs, compute_dispatch_utility};
use crate::termination::{
    FrontierState, TerminationReason, TerminationSignals, decide_termination,
};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RequirementState {
    pub id: String,
    pub satisfied: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EligibilitySnapshot {
    pub hard_constraints: Vec<RequirementState>,
    pub dependencies: Vec<RequirementState>,
    pub permissions: Vec<RequirementState>,
    pub provider_executable: bool,
    pub preconditions: Vec<RequirementState>,
    pub blocked_reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ActionCandidate {
    pub id: String,
    pub capability: String,
    pub provider: Option<String>,
    pub target: String,
    pub eligibility: EligibilitySnapshot,
    pub satisfied_obligations: BTreeSet<String>,
    pub expected_decision_impact: f64,
    pub roi_inputs: DispatchUtilityInputs,
    pub resource_cost: f64,
    pub irreversible_risk: f64,
    pub blast_radius: f64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum IneligibilityReason {
    HardConstraintFailed(String),
    MissingDependency(String),
    MissingPermission(String),
    ProviderUnavailable,
    FailedPrecondition(String),
    ExplicitlyBlocked(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Eligibility {
    Eligible,
    Ineligible(Vec<IneligibilityReason>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct DecisionState {
    pub state_version: String,
    pub unresolved_proof_obligations: BTreeSet<String>,
    pub all_relevant_claims_defeated: bool,
    pub frontier: FrontierState,
    pub termination_signals: TerminationSignals,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyTerminationReason {
    ProofObligationsResolved,
    AllRelevantClaimsDefeated,
    NoEligibleEvidencePath,
    NonPositiveDecisionValue,
    Existing(TerminationReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Select(String),
    Terminate(PolicyTerminationReason),
}

#[derive(Debug, Clone, PartialEq)]
pub struct EdvComponents {
    pub expected_decision_impact: f64,
    pub dispatch_utility: DispatchUtility,
    pub resource_cost: f64,
    pub irreversible_risk: f64,
    pub blast_radius: f64,
    pub final_edv: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ActionEvaluation {
    pub action_id: String,
    pub components: EdvComponents,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectedAction {
    pub action_id: String,
    pub reasons: Vec<IneligibilityReason>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DominanceElimination {
    pub dominated_action: String,
    pub dominating_action: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RankedAction {
    pub action_id: String,
    pub edv: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DecisionRecord {
    pub state_version: String,
    pub decision: Decision,
    pub eligible_actions: Vec<String>,
    pub rejected_actions: Vec<RejectedAction>,
    pub dominance_eliminations: Vec<DominanceElimination>,
    pub evaluations: Vec<ActionEvaluation>,
    pub ranking: Vec<RankedAction>,
    pub dependencies: BTreeMap<String, Vec<RequirementState>>,
    pub evidence_lineage_inputs: BTreeMap<String, Option<u32>>,
    pub termination_signals: TerminationSignals,
    pub explanation: Vec<String>,
}

#[must_use]
pub fn evaluate_eligibility(candidate: &ActionCandidate) -> Eligibility {
    let mut reasons = Vec::new();

    reasons.extend(
        candidate
            .eligibility
            .hard_constraints
            .iter()
            .filter(|requirement| !requirement.satisfied)
            .map(|requirement| IneligibilityReason::HardConstraintFailed(requirement.id.clone())),
    );
    reasons.extend(
        candidate
            .eligibility
            .dependencies
            .iter()
            .filter(|requirement| !requirement.satisfied)
            .map(|requirement| IneligibilityReason::MissingDependency(requirement.id.clone())),
    );
    reasons.extend(
        candidate
            .eligibility
            .permissions
            .iter()
            .filter(|requirement| !requirement.satisfied)
            .map(|requirement| IneligibilityReason::MissingPermission(requirement.id.clone())),
    );
    if !candidate.eligibility.provider_executable {
        reasons.push(IneligibilityReason::ProviderUnavailable);
    }
    reasons.extend(
        candidate
            .eligibility
            .preconditions
            .iter()
            .filter(|requirement| !requirement.satisfied)
            .map(|requirement| IneligibilityReason::FailedPrecondition(requirement.id.clone())),
    );
    reasons.extend(
        candidate
            .eligibility
            .blocked_reasons
            .iter()
            .cloned()
            .map(IneligibilityReason::ExplicitlyBlocked),
    );

    reasons.sort();
    reasons.dedup();
    if reasons.is_empty() {
        Eligibility::Eligible
    } else {
        Eligibility::Ineligible(reasons)
    }
}

fn evaluate_edv(candidate: &ActionCandidate) -> EdvComponents {
    let expected_decision_impact = candidate.expected_decision_impact.clamp(0.0, 1.0);
    let dispatch_utility = compute_dispatch_utility(&candidate.roi_inputs);
    let resource_cost = candidate.resource_cost.max(0.0);
    let irreversible_risk = candidate.irreversible_risk.max(0.0);
    let blast_radius = candidate.blast_radius.max(0.0);
    let final_edv = expected_decision_impact * dispatch_utility.final_utility
        - resource_cost
        - irreversible_risk
        - blast_radius;

    EdvComponents {
        expected_decision_impact,
        dispatch_utility,
        resource_cost,
        irreversible_risk,
        blast_radius,
        final_edv,
    }
}

fn known_cost_leq(a: Option<f64>, b: Option<f64>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => a <= b,
        (None, None) => true,
        _ => false,
    }
}

fn known_cost_lt(a: Option<f64>, b: Option<f64>) -> bool {
    matches!((a, b), (Some(a), Some(b)) if a < b)
}

fn dominates(
    a: &ActionCandidate,
    a_eval: &EdvComponents,
    b: &ActionCandidate,
    b_eval: &EdvComponents,
) -> bool {
    let at_least_same_obligations = a
        .satisfied_obligations
        .is_superset(&b.satisfied_obligations);
    let at_least_as_beneficial = a_eval.expected_decision_impact >= b_eval.expected_decision_impact;
    let no_more_monetary_cost = known_cost_leq(
        a.roi_inputs.cost_per_request_usd,
        b.roi_inputs.cost_per_request_usd,
    );
    let no_more_resource_cost = a_eval.resource_cost <= b_eval.resource_cost;
    let no_more_irreversible_risk = a_eval.irreversible_risk <= b_eval.irreversible_risk;
    let no_more_blast_radius = a_eval.blast_radius <= b_eval.blast_radius;
    let no_more_latency = a.roi_inputs.configured_timeout_ms <= b.roi_inputs.configured_timeout_ms;

    let strictly_better = a_eval.expected_decision_impact > b_eval.expected_decision_impact
        || known_cost_lt(
            a.roi_inputs.cost_per_request_usd,
            b.roi_inputs.cost_per_request_usd,
        )
        || a_eval.resource_cost < b_eval.resource_cost
        || a_eval.irreversible_risk < b_eval.irreversible_risk
        || a_eval.blast_radius < b_eval.blast_radius
        || a.roi_inputs.configured_timeout_ms < b.roi_inputs.configured_timeout_ms
        || a.satisfied_obligations != b.satisfied_obligations;

    at_least_same_obligations
        && at_least_as_beneficial
        && no_more_monetary_cost
        && no_more_resource_cost
        && no_more_irreversible_risk
        && no_more_blast_radius
        && no_more_latency
        && strictly_better
}

fn optional_cost_cmp(a: Option<f64>, b: Option<f64>) -> Ordering {
    match (a, b) {
        (Some(a), Some(b)) => a.total_cmp(&b),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

fn rank_cmp(
    a: (&ActionCandidate, &EdvComponents),
    b: (&ActionCandidate, &EdvComponents),
) -> Ordering {
    b.1.final_edv
        .total_cmp(&a.1.final_edv)
        .then_with(|| a.1.irreversible_risk.total_cmp(&b.1.irreversible_risk))
        .then_with(|| {
            optional_cost_cmp(
                a.0.roi_inputs.cost_per_request_usd,
                b.0.roi_inputs.cost_per_request_usd,
            )
        })
        .then_with(|| {
            a.0.roi_inputs
                .configured_timeout_ms
                .cmp(&b.0.roi_inputs.configured_timeout_ms)
        })
        .then_with(|| a.0.id.cmp(&b.0.id))
}

fn base_record(state: &DecisionState, candidates: &[ActionCandidate]) -> DecisionRecord {
    let dependencies = candidates
        .iter()
        .map(|candidate| {
            (
                candidate.id.clone(),
                candidate.eligibility.dependencies.clone(),
            )
        })
        .collect();
    let evidence_lineage_inputs = candidates
        .iter()
        .map(|candidate| {
            (
                candidate.id.clone(),
                candidate.roi_inputs.independent_root_count,
            )
        })
        .collect();

    DecisionRecord {
        state_version: state.state_version.clone(),
        decision: Decision::Terminate(PolicyTerminationReason::NoEligibleEvidencePath),
        eligible_actions: Vec::new(),
        rejected_actions: Vec::new(),
        dominance_eliminations: Vec::new(),
        evaluations: Vec::new(),
        ranking: Vec::new(),
        dependencies,
        evidence_lineage_inputs,
        termination_signals: state.termination_signals,
        explanation: Vec::new(),
    }
}

fn finish_termination(
    record: &mut DecisionRecord,
    reason: PolicyTerminationReason,
    explanation: impl Into<String>,
) {
    record.decision = Decision::Terminate(reason);
    record.explanation.push(explanation.into());
}

fn precheck_termination(
    state: &DecisionState,
) -> Option<(PolicyTerminationReason, String)> {
    if state.unresolved_proof_obligations.is_empty() {
        return Some((
            PolicyTerminationReason::ProofObligationsResolved,
            "terminated: all consequential proof obligations resolved".to_owned(),
        ));
    }
    if state.all_relevant_claims_defeated {
        return Some((
            PolicyTerminationReason::AllRelevantClaimsDefeated,
            "terminated: all relevant claims defeated".to_owned(),
        ));
    }
    decide_termination(state.frontier, state.termination_signals).map(|reason| {
        (
            PolicyTerminationReason::Existing(reason),
            format!("terminated by existing termination signal: {reason:?}"),
        )
    })
}

fn collect_eligible<'a>(
    record: &mut DecisionRecord,
    candidates: &'a [ActionCandidate],
) -> Vec<&'a ActionCandidate> {
    let mut sorted_candidates: Vec<&ActionCandidate> = candidates.iter().collect();
    sorted_candidates.sort_by(|a, b| a.id.cmp(&b.id));

    let mut eligible = Vec::new();
    for candidate in sorted_candidates {
        match evaluate_eligibility(candidate) {
            Eligibility::Eligible => {
                record.eligible_actions.push(candidate.id.clone());
                eligible.push(candidate);
            }
            Eligibility::Ineligible(reasons) => {
                record
                    .explanation
                    .push(format!("rejected {}: {reasons:?}", candidate.id));
                record.rejected_actions.push(RejectedAction {
                    action_id: candidate.id.clone(),
                    reasons,
                });
            }
        }
    }
    eligible
}

fn evaluate_candidates(
    record: &mut DecisionRecord,
    eligible: &[&ActionCandidate],
) -> Vec<EdvComponents> {
    let evaluations: Vec<EdvComponents> = eligible
        .iter()
        .map(|candidate| evaluate_edv(candidate))
        .collect();
    record.evaluations = eligible
        .iter()
        .zip(&evaluations)
        .map(|(candidate, components)| ActionEvaluation {
            action_id: candidate.id.clone(),
            components: components.clone(),
        })
        .collect();
    evaluations
}

fn eliminate_dominated(
    record: &mut DecisionRecord,
    eligible: &[&ActionCandidate],
    evaluations: &[EdvComponents],
) -> BTreeSet<usize> {
    let mut dominated = BTreeSet::new();
    for (b_index, b) in eligible.iter().enumerate() {
        for (a_index, a) in eligible.iter().enumerate() {
            if a_index == b_index {
                continue;
            }
            if dominates(a, &evaluations[a_index], b, &evaluations[b_index]) {
                dominated.insert(b_index);
                record.dominance_eliminations.push(DominanceElimination {
                    dominated_action: b.id.clone(),
                    dominating_action: a.id.clone(),
                });
                record
                    .explanation
                    .push(format!("eliminated {}: dominated by {}", b.id, a.id));
                break;
            }
        }
    }
    dominated
}

fn rank_candidates(
    eligible: &[&ActionCandidate],
    evaluations: &[EdvComponents],
    dominated: &BTreeSet<usize>,
) -> Vec<usize> {
    let mut ranking: Vec<usize> = (0..eligible.len())
        .filter(|index| !dominated.contains(index))
        .collect();
    ranking.sort_by(|a, b| {
        rank_cmp(
            (eligible[*a], &evaluations[*a]),
            (eligible[*b], &evaluations[*b]),
        )
    });
    ranking
}

fn record_ranking(
    record: &mut DecisionRecord,
    eligible: &[&ActionCandidate],
    evaluations: &[EdvComponents],
    ranking: &[usize],
) {
    record.ranking = ranking
        .iter()
        .map(|index| RankedAction {
            action_id: eligible[*index].id.clone(),
            edv: evaluations[*index].final_edv,
        })
        .collect();

    for (position, index) in ranking.iter().enumerate() {
        let candidate = eligible[*index];
        let components = &evaluations[*index];
        record.explanation.push(format!(
            "rank {} {}: edv={:.6} = impact {:.3} * roi {:.6} - resource {:.3} - irreversible_risk {:.3} - blast_radius {:.3}",
            position + 1,
            candidate.id,
            components.final_edv,
            components.expected_decision_impact,
            components.dispatch_utility.final_utility,
            components.resource_cost,
            components.irreversible_risk,
            components.blast_radius
        ));
    }
}

fn finalize_decision(
    record: &mut DecisionRecord,
    eligible: &[&ActionCandidate],
    evaluations: &[EdvComponents],
    ranking: &[usize],
) {
    let Some(selected_index) = ranking.first().copied() else {
        finish_termination(
            record,
            PolicyTerminationReason::NoEligibleEvidencePath,
            "terminated: dominance elimination left no admissible action",
        );
        return;
    };

    let selected = eligible[selected_index];
    let selected_components = &evaluations[selected_index];
    if selected_components.final_edv <= 0.0 {
        finish_termination(
            record,
            PolicyTerminationReason::NonPositiveDecisionValue,
            format!(
                "terminated: best eligible edv {:.6} <= 0",
                selected_components.final_edv
            ),
        );
        return;
    }

    record.decision = Decision::Select(selected.id.clone());
    record.explanation.push(format!(
        "selected {} with edv {:.6}",
        selected.id, selected_components.final_edv
    ));
}

#[must_use]
pub fn select_action(state: &DecisionState, candidates: &[ActionCandidate]) -> DecisionRecord {
    let mut record = base_record(state, candidates);

    if let Some((reason, explanation)) = precheck_termination(state) {
        finish_termination(&mut record, reason, explanation);
        return record;
    }

    let eligible = collect_eligible(&mut record, candidates);
    if eligible.is_empty() {
        finish_termination(
            &mut record,
            PolicyTerminationReason::NoEligibleEvidencePath,
            "terminated: no eligible evidence path remains",
        );
        return record;
    }

    let evaluations = evaluate_candidates(&mut record, &eligible);
    let dominated = eliminate_dominated(&mut record, &eligible, &evaluations);
    let ranking = rank_candidates(&eligible, &evaluations, &dominated);
    record_ranking(&mut record, &eligible, &evaluations, &ranking);
    finalize_decision(&mut record, &eligible, &evaluations, &ranking);
    record
}
