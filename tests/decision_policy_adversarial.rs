use std::collections::BTreeSet;

use huntsman_recon::decision_policy::{
    ActionCandidate, Decision, DecisionState, EligibilitySnapshot, IneligibilityReason,
    PolicyTerminationReason, RequirementState, select_action,
};
use huntsman_recon::roi::DispatchUtilityInputs;
use huntsman_recon::termination::{FrontierState, TerminationReason, TerminationSignals};

fn req(id: &str, satisfied: bool) -> RequirementState {
    RequirementState {
        id: id.to_owned(),
        satisfied,
    }
}

fn candidate(id: &str, impact: f64) -> ActionCandidate {
    ActionCandidate {
        id: id.to_owned(),
        capability: "lookup".to_owned(),
        provider: Some(format!("provider:{id}")),
        target: "subject@example.com".to_owned(),
        eligibility: EligibilitySnapshot {
            hard_constraints: vec![req("scope:public", true)],
            dependencies: vec![req("dependency:ready", true)],
            permissions: vec![req("permission:network", true)],
            provider_executable: true,
            preconditions: vec![req("target:valid", true)],
            blocked_reasons: Vec::new(),
        },
        satisfied_obligations: BTreeSet::from(["claim:identity".to_owned()]),
        expected_decision_impact: impact,
        roi_inputs: DispatchUtilityInputs {
            source_count: 1,
            independent_root_count: Some(1),
            entity_confidence: Some(0.4),
            optionality_prior: 0.6,
            novelty_prior: 0.8,
            reliability_prior: 0.9,
            cost_per_request_usd: Some(0.0),
            quota_remaining: Some(true),
            configured_timeout_ms: 1_000,
            already_dispatched_this_module_target: false,
            geoint_bearing: false,
        },
        resource_cost: 0.05,
        irreversible_risk: 0.0,
        blast_radius: 0.0,
    }
}

fn state() -> DecisionState {
    DecisionState {
        state_version: "adversarial-state".to_owned(),
        unresolved_proof_obligations: BTreeSet::from(["claim:identity".to_owned()]),
        all_relevant_claims_defeated: false,
        frontier: FrontierState {
            admissible_work: 4,
            ..FrontierState::default()
        },
        termination_signals: TerminationSignals::default(),
    }
}

#[test]
fn unavailable_high_value_provider_falls_back_to_viable_action() {
    let mut unavailable = candidate("unavailable", 1.0);
    unavailable.eligibility.provider_executable = false;
    let fallback = candidate("fallback", 0.5);

    let record = select_action(&state(), &[unavailable, fallback]);

    assert_eq!(record.decision, Decision::Select("fallback".to_owned()));
    assert_eq!(record.ranking[0].action_id, "fallback");
    assert_eq!(record.rejected_actions.len(), 1);
    assert_eq!(
        record.rejected_actions[0].reasons,
        vec![IneligibilityReason::ProviderUnavailable]
    );
}

#[test]
fn candidate_input_permutation_does_not_change_decision_record() {
    let mut high_value = candidate("high-value", 0.9);
    high_value.resource_cost = 0.2;
    let low_cost = candidate("low-cost", 0.4);
    let medium = candidate("medium", 0.6);

    let forward = select_action(
        &state(),
        &[high_value.clone(), low_cost.clone(), medium.clone()],
    );
    let reverse = select_action(&state(), &[medium, low_cost, high_value]);

    assert_eq!(forward, reverse);
}

#[test]
fn existing_request_budget_termination_is_preserved() {
    let mut budgeted = state();
    budgeted.termination_signals.request_budget_exhausted = true;

    let record = select_action(&budgeted, &[candidate("valuable", 1.0)]);

    assert_eq!(
        record.decision,
        Decision::Terminate(PolicyTerminationReason::Existing(
            TerminationReason::RequestBudget
        ))
    );
}

#[test]
fn unknown_monetary_cost_cannot_dominate_known_cost_alternative() {
    let mut unknown = candidate("unknown-cost", 0.9);
    unknown.roi_inputs.cost_per_request_usd = None;
    let mut known = candidate("known-cost", 0.8);
    known.resource_cost = 0.1;

    let record = select_action(&state(), &[unknown, known]);

    assert_eq!(record.ranking.len(), 2);
    assert!(!record.dominance_eliminations.iter().any(|entry| {
        entry.dominating_action == "unknown-cost" && entry.dominated_action == "known-cost"
    }));
}

#[test]
fn unknown_lineage_gets_no_independence_reward_in_policy_evaluation() {
    let mut unknown = candidate("unknown-lineage", 0.8);
    unknown.roi_inputs.independent_root_count = None;

    let record = select_action(&state(), &[unknown]);
    let evaluation = record
        .evaluations
        .iter()
        .find(|entry| entry.action_id == "unknown-lineage")
        .expect("candidate must be evaluated");

    assert_eq!(
        evaluation.components.dispatch_utility.expected_independence,
        0.0
    );
    assert_eq!(record.evidence_lineage_inputs["unknown-lineage"], None);
}

#[test]
fn raw_impact_cannot_dominate_higher_expected_value() {
    let mut raw_impact = candidate("raw-impact", 0.9);
    raw_impact.roi_inputs.reliability_prior = 0.1;

    let expected_value = candidate("expected-value", 0.8);

    let record = select_action(&state(), &[raw_impact, expected_value]);

    assert_eq!(
        record.decision,
        Decision::Select("expected-value".to_owned())
    );
    assert_eq!(record.ranking[0].action_id, "expected-value");
    assert!(!record.dominance_eliminations.iter().any(|entry| {
        entry.dominating_action == "raw-impact" && entry.dominated_action == "expected-value"
    }));
}
