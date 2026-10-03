use std::collections::BTreeSet;

use huntsman_recon::decision_policy::{
    ActionCandidate, Decision, DecisionState, EligibilitySnapshot, PolicyTerminationReason,
    RequirementState, select_action,
};
use huntsman_recon::roi::DispatchUtilityInputs;
use huntsman_recon::termination::{FrontierState, TerminationSignals};

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
        provider: Some("provider".to_owned()),
        target: "subject@example.com".to_owned(),
        eligibility: EligibilitySnapshot {
            hard_constraints: vec![req("scope:public", true)],
            dependencies: vec![req("credential:provider", true)],
            permissions: vec![req("permission:network", true)],
            provider_executable: true,
            preconditions: vec![req("target:email", true)],
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
        state_version: "state-7".to_owned(),
        unresolved_proof_obligations: BTreeSet::from(["claim:identity".to_owned()]),
        all_relevant_claims_defeated: false,
        frontier: FrontierState {
            admissible_work: 2,
            ..FrontierState::default()
        },
        termination_signals: TerminationSignals::default(),
    }
}

#[test]
fn higher_edv_candidate_is_selected() {
    let record = select_action(&state(), &[candidate("a", 0.4), candidate("b", 0.9)]);
    assert_eq!(record.decision, Decision::Select("b".to_owned()));
    assert_eq!(record.ranking[0].action_id, "b");
    assert!(record.ranking[0].edv > record.ranking[1].edv);
}

#[test]
fn dominated_action_is_removed_before_ranking() {
    let dominant = candidate("dominant", 0.9);
    let mut dominated = candidate("dominated", 0.5);
    dominated.resource_cost = 0.2;
    dominated.irreversible_risk = 0.1;
    dominated.roi_inputs.configured_timeout_ms = 4_000;

    let record = select_action(&state(), &[dominated, dominant]);

    assert_eq!(record.decision, Decision::Select("dominant".to_owned()));
    assert_eq!(record.ranking.len(), 1);
    assert!(record.dominance_eliminations.iter().any(|entry| {
        entry.dominated_action == "dominated" && entry.dominating_action == "dominant"
    }));
}

#[test]
fn equal_scores_use_stable_action_identifier_tie_break() {
    let record = select_action(&state(), &[candidate("zeta", 0.8), candidate("alpha", 0.8)]);
    assert_eq!(record.decision, Decision::Select("alpha".to_owned()));
    assert_eq!(record.ranking[0].action_id, "alpha");
}

#[test]
fn all_ineligible_actions_terminate_without_ranking() {
    let mut a = candidate("a", 1.0);
    a.eligibility.permissions[0].satisfied = false;
    let mut b = candidate("b", 1.0);
    b.eligibility.provider_executable = false;

    let record = select_action(&state(), &[a, b]);

    assert_eq!(
        record.decision,
        Decision::Terminate(PolicyTerminationReason::NoEligibleEvidencePath)
    );
    assert!(record.ranking.is_empty());
    assert_eq!(record.rejected_actions.len(), 2);
}

#[test]
fn non_positive_best_edv_terminates() {
    let mut no_value = candidate("no-value", 0.0);
    no_value.resource_cost = 0.2;

    let record = select_action(&state(), &[no_value]);

    assert_eq!(
        record.decision,
        Decision::Terminate(PolicyTerminationReason::NonPositiveDecisionValue)
    );
    assert!(record.ranking[0].edv < 0.0);
}

#[test]
fn resolved_obligations_terminate_before_dispatch() {
    let mut resolved = state();
    resolved.unresolved_proof_obligations.clear();

    let record = select_action(&resolved, &[candidate("a", 1.0)]);

    assert_eq!(
        record.decision,
        Decision::Terminate(PolicyTerminationReason::ProofObligationsResolved)
    );
}

#[test]
fn decision_record_uses_the_same_components_as_ranking() {
    let record = select_action(&state(), &[candidate("a", 0.7)]);
    let evaluation = record
        .evaluations
        .iter()
        .find(|entry| entry.action_id == "a")
        .unwrap();

    assert_eq!(record.state_version, "state-7");
    assert_eq!(record.ranking[0].edv, evaluation.components.final_edv);
    assert_eq!(record.evidence_lineage_inputs["a"], Some(1));
    assert_eq!(record.dependencies["a"][0].id, "credential:provider");
    assert!(
        record
            .explanation
            .iter()
            .any(|line| line.contains("selected a"))
    );
}
