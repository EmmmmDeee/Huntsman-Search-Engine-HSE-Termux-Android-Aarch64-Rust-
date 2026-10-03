//! Replaceable JSON boundary for the pure operational decision kernel.
//!
//! Wire-format concerns live here so the policy model can evolve independently from
//! today’s CLI/request representation. This module stores no state and performs no
//! filesystem, network, subprocess, provider, or credential I/O.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::decision_policy::{
    ActionCandidate, Decision, DecisionRecord, DecisionState, EligibilitySnapshot,
    IneligibilityReason, PolicyTerminationReason, RequirementState, select_action,
};
use crate::roi::{DispatchUtility, DispatchUtilityInputs};
use crate::termination::{FrontierState, TerminationReason, TerminationSignals};

#[derive(Debug, Deserialize)]
struct DecisionRequest {
    state: DecisionStateInput,
    candidates: Vec<ActionCandidateInput>,
}

impl DecisionRequest {
    fn into_policy(self) -> (DecisionState, Vec<ActionCandidate>) {
        (
            self.state.into(),
            self.candidates.into_iter().map(Into::into).collect(),
        )
    }
}

#[derive(Debug, Deserialize)]
struct DecisionStateInput {
    state_version: String,
    unresolved_proof_obligations: BTreeSet<String>,
    all_relevant_claims_defeated: bool,
    frontier: FrontierStateInput,
    termination_signals: TerminationSignalsInput,
}

impl From<DecisionStateInput> for DecisionState {
    fn from(value: DecisionStateInput) -> Self {
        Self {
            state_version: value.state_version,
            unresolved_proof_obligations: value.unresolved_proof_obligations,
            all_relevant_claims_defeated: value.all_relevant_claims_defeated,
            frontier: value.frontier.into(),
            termination_signals: value.termination_signals.into(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct FrontierStateInput {
    admissible_work: usize,
    delayed_retry_work: usize,
    in_flight_work: usize,
    derivable_novel_work: usize,
}

impl From<FrontierStateInput> for FrontierState {
    fn from(value: FrontierStateInput) -> Self {
        Self {
            admissible_work: value.admissible_work,
            delayed_retry_work: value.delayed_retry_work,
            in_flight_work: value.in_flight_work,
            derivable_novel_work: value.derivable_novel_work,
        }
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Deserialize)]
struct TerminationSignalsInput {
    cancelled: bool,
    fatal_error: bool,
    max_depth_reached: bool,
    time_limit_reached: bool,
    request_budget_exhausted: bool,
    provider_budget_exhausted: bool,
    resource_limit_reached: bool,
    marginal_gain_below_floor: bool,
}

impl From<TerminationSignalsInput> for TerminationSignals {
    fn from(value: TerminationSignalsInput) -> Self {
        Self {
            cancelled: value.cancelled,
            fatal_error: value.fatal_error,
            max_depth_reached: value.max_depth_reached,
            time_limit_reached: value.time_limit_reached,
            request_budget_exhausted: value.request_budget_exhausted,
            provider_budget_exhausted: value.provider_budget_exhausted,
            resource_limit_reached: value.resource_limit_reached,
            marginal_gain_below_floor: value.marginal_gain_below_floor,
        }
    }
}

#[derive(Debug, Deserialize)]
struct RequirementInput {
    id: String,
    satisfied: bool,
}

impl From<RequirementInput> for RequirementState {
    fn from(value: RequirementInput) -> Self {
        Self {
            id: value.id,
            satisfied: value.satisfied,
        }
    }
}

#[derive(Debug, Deserialize)]
struct EligibilityInput {
    hard_constraints: Vec<RequirementInput>,
    dependencies: Vec<RequirementInput>,
    permissions: Vec<RequirementInput>,
    provider_executable: bool,
    preconditions: Vec<RequirementInput>,
    blocked_reasons: Vec<String>,
}

impl From<EligibilityInput> for EligibilitySnapshot {
    fn from(value: EligibilityInput) -> Self {
        Self {
            hard_constraints: value.hard_constraints.into_iter().map(Into::into).collect(),
            dependencies: value.dependencies.into_iter().map(Into::into).collect(),
            permissions: value.permissions.into_iter().map(Into::into).collect(),
            provider_executable: value.provider_executable,
            preconditions: value.preconditions.into_iter().map(Into::into).collect(),
            blocked_reasons: value.blocked_reasons,
        }
    }
}

#[derive(Debug, Deserialize)]
struct DispatchUtilityInputsInput {
    source_count: u32,
    independent_root_count: Option<u32>,
    entity_confidence: Option<f64>,
    optionality_prior: f64,
    novelty_prior: f64,
    reliability_prior: f64,
    cost_per_request_usd: Option<f64>,
    quota_remaining: Option<bool>,
    configured_timeout_ms: u64,
    already_dispatched_this_module_target: bool,
    geoint_bearing: bool,
}

impl From<DispatchUtilityInputsInput> for DispatchUtilityInputs {
    fn from(value: DispatchUtilityInputsInput) -> Self {
        Self {
            source_count: value.source_count,
            independent_root_count: value.independent_root_count,
            entity_confidence: value.entity_confidence,
            optionality_prior: value.optionality_prior,
            novelty_prior: value.novelty_prior,
            reliability_prior: value.reliability_prior,
            cost_per_request_usd: value.cost_per_request_usd,
            quota_remaining: value.quota_remaining,
            configured_timeout_ms: value.configured_timeout_ms,
            already_dispatched_this_module_target: value.already_dispatched_this_module_target,
            geoint_bearing: value.geoint_bearing,
        }
    }
}

#[derive(Debug, Deserialize)]
struct ActionCandidateInput {
    id: String,
    capability: String,
    provider: Option<String>,
    target: String,
    eligibility: EligibilityInput,
    satisfied_obligations: BTreeSet<String>,
    expected_decision_impact: f64,
    roi_inputs: DispatchUtilityInputsInput,
    resource_cost: f64,
    irreversible_risk: f64,
    blast_radius: f64,
}

impl From<ActionCandidateInput> for ActionCandidate {
    fn from(value: ActionCandidateInput) -> Self {
        Self {
            id: value.id,
            capability: value.capability,
            provider: value.provider,
            target: value.target,
            eligibility: value.eligibility.into(),
            satisfied_obligations: value.satisfied_obligations,
            expected_decision_impact: value.expected_decision_impact,
            roi_inputs: value.roi_inputs.into(),
            resource_cost: value.resource_cost,
            irreversible_risk: value.irreversible_risk,
            blast_radius: value.blast_radius,
        }
    }
}

/// Decode a normalized request, execute the pure policy, and return its complete
/// reconstructable record as JSON. The caller owns any external I/O.
pub fn decide_json(input: &[u8]) -> Result<Value, serde_json::Error> {
    let request: DecisionRequest = serde_json::from_slice(input)?;
    let (state, candidates) = request.into_policy();
    Ok(record_to_value(&select_action(&state, &candidates)))
}

fn requirement_value(requirement: &RequirementState) -> Value {
    json!({
        "id": requirement.id,
        "satisfied": requirement.satisfied,
    })
}

fn ineligibility_value(reason: &IneligibilityReason) -> Value {
    match reason {
        IneligibilityReason::HardConstraintFailed(detail) => {
            json!({"kind": "hard_constraint_failed", "detail": detail})
        }
        IneligibilityReason::MissingDependency(detail) => {
            json!({"kind": "missing_dependency", "detail": detail})
        }
        IneligibilityReason::MissingPermission(detail) => {
            json!({"kind": "missing_permission", "detail": detail})
        }
        IneligibilityReason::ProviderUnavailable => json!({"kind": "provider_unavailable"}),
        IneligibilityReason::FailedPrecondition(detail) => {
            json!({"kind": "failed_precondition", "detail": detail})
        }
        IneligibilityReason::ExplicitlyBlocked(detail) => {
            json!({"kind": "explicitly_blocked", "detail": detail})
        }
    }
}

const fn termination_reason_name(reason: TerminationReason) -> &'static str {
    match reason {
        TerminationReason::FixedPoint => "fixed_point",
        TerminationReason::MaxDepth => "max_depth",
        TerminationReason::TimeLimit => "time_limit",
        TerminationReason::RequestBudget => "request_budget",
        TerminationReason::ProviderBudget => "provider_budget",
        TerminationReason::ResourceLimit => "resource_limit",
        TerminationReason::MarginalGainLimit => "marginal_gain_limit",
        TerminationReason::Cancelled => "cancelled",
        TerminationReason::FatalError => "fatal_error",
    }
}

fn policy_termination_value(reason: &PolicyTerminationReason) -> Value {
    match reason {
        PolicyTerminationReason::ProofObligationsResolved => {
            json!({"kind": "proof_obligations_resolved"})
        }
        PolicyTerminationReason::AllRelevantClaimsDefeated => {
            json!({"kind": "all_relevant_claims_defeated"})
        }
        PolicyTerminationReason::NoEligibleEvidencePath => {
            json!({"kind": "no_eligible_evidence_path"})
        }
        PolicyTerminationReason::NonPositiveDecisionValue => {
            json!({"kind": "non_positive_decision_value"})
        }
        PolicyTerminationReason::Existing(existing) => {
            json!({"kind": "existing", "detail": termination_reason_name(*existing)})
        }
    }
}

fn decision_value(decision: &Decision) -> Value {
    match decision {
        Decision::Select(action_id) => json!({"kind": "select", "detail": action_id}),
        Decision::Terminate(reason) => {
            json!({"kind": "terminate", "detail": policy_termination_value(reason)})
        }
    }
}

fn dispatch_utility_value(utility: &DispatchUtility) -> Value {
    json!({
        "expected_information_value": utility.expected_information_value,
        "expected_novelty": utility.expected_novelty,
        "expected_independence": utility.expected_independence,
        "expected_optionality": utility.expected_optionality,
        "reliability": utility.reliability,
        "estimated_cost": utility.estimated_cost,
        "quota_cost": utility.quota_cost,
        "latency_penalty": utility.latency_penalty,
        "failure_penalty": utility.failure_penalty,
        "duplicate_penalty": utility.duplicate_penalty,
        "final_utility": utility.final_utility,
        "explanation": utility.explanation,
    })
}

fn termination_signals_value(signals: TerminationSignals) -> Value {
    json!({
        "cancelled": signals.cancelled,
        "fatal_error": signals.fatal_error,
        "max_depth_reached": signals.max_depth_reached,
        "time_limit_reached": signals.time_limit_reached,
        "request_budget_exhausted": signals.request_budget_exhausted,
        "provider_budget_exhausted": signals.provider_budget_exhausted,
        "resource_limit_reached": signals.resource_limit_reached,
        "marginal_gain_below_floor": signals.marginal_gain_below_floor,
    })
}

fn dependencies_value(dependencies: &BTreeMap<String, Vec<RequirementState>>) -> Value {
    let object: Map<String, Value> = dependencies
        .iter()
        .map(|(action, requirements)| {
            (
                action.clone(),
                Value::Array(requirements.iter().map(requirement_value).collect()),
            )
        })
        .collect();
    Value::Object(object)
}

fn record_to_value(record: &DecisionRecord) -> Value {
    let rejected_actions: Vec<Value> = record
        .rejected_actions
        .iter()
        .map(|entry| {
            json!({
                "action_id": entry.action_id,
                "reasons": entry.reasons.iter().map(ineligibility_value).collect::<Vec<_>>(),
            })
        })
        .collect();
    let dominance_eliminations: Vec<Value> = record
        .dominance_eliminations
        .iter()
        .map(|entry| {
            json!({
                "dominated_action": entry.dominated_action,
                "dominating_action": entry.dominating_action,
            })
        })
        .collect();
    let evaluations: Vec<Value> = record
        .evaluations
        .iter()
        .map(|entry| {
            let components = &entry.components;
            json!({
                "action_id": entry.action_id,
                "components": {
                    "expected_decision_impact": components.expected_decision_impact,
                    "dispatch_utility": dispatch_utility_value(&components.dispatch_utility),
                    "resource_cost": components.resource_cost,
                    "irreversible_risk": components.irreversible_risk,
                    "blast_radius": components.blast_radius,
                    "final_edv": components.final_edv,
                }
            })
        })
        .collect();
    let ranking: Vec<Value> = record
        .ranking
        .iter()
        .map(|entry| json!({"action_id": entry.action_id, "edv": entry.edv}))
        .collect();

    json!({
        "state_version": record.state_version,
        "decision": decision_value(&record.decision),
        "eligible_actions": record.eligible_actions,
        "rejected_actions": rejected_actions,
        "dominance_eliminations": dominance_eliminations,
        "evaluations": evaluations,
        "ranking": ranking,
        "dependencies": dependencies_value(&record.dependencies),
        "evidence_lineage_inputs": record.evidence_lineage_inputs,
        "termination_signals": termination_signals_value(record.termination_signals),
        "explanation": record.explanation,
    })
}
