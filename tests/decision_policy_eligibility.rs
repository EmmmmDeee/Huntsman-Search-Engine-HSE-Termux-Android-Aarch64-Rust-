use std::collections::BTreeSet;

use huntsman_recon::decision_policy::{
    ActionCandidate, Eligibility, EligibilitySnapshot, IneligibilityReason, RequirementState,
    evaluate_eligibility,
};
use huntsman_recon::roi::DispatchUtilityInputs;

fn req(id: &str, satisfied: bool) -> RequirementState {
    RequirementState {
        id: id.to_owned(),
        satisfied,
    }
}

fn candidate() -> ActionCandidate {
    ActionCandidate {
        id: "provider.email_lookup".to_owned(),
        capability: "email_lookup".to_owned(),
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
        satisfied_obligations: BTreeSet::from(["claim:email".to_owned()]),
        expected_decision_impact: 0.8,
        roi_inputs: DispatchUtilityInputs {
            source_count: 1,
            independent_root_count: Some(1),
            entity_confidence: Some(0.5),
            optionality_prior: 0.5,
            novelty_prior: 0.8,
            reliability_prior: 0.9,
            cost_per_request_usd: Some(0.0),
            quota_remaining: Some(true),
            configured_timeout_ms: 1_000,
            already_dispatched_this_module_target: false,
            geoint_bearing: false,
        },
        resource_cost: 0.1,
        irreversible_risk: 0.0,
        blast_radius: 0.0,
    }
}

#[test]
fn fully_satisfied_candidate_is_eligible() {
    assert_eq!(evaluate_eligibility(&candidate()), Eligibility::Eligible);
}

#[test]
fn missing_dependency_is_machine_readable() {
    let mut c = candidate();
    c.eligibility.dependencies[0].satisfied = false;
    assert_eq!(
        evaluate_eligibility(&c),
        Eligibility::Ineligible(vec![IneligibilityReason::MissingDependency(
            "credential:provider".to_owned()
        )])
    );
}

#[test]
fn missing_permission_is_machine_readable() {
    let mut c = candidate();
    c.eligibility.permissions[0].satisfied = false;
    assert_eq!(
        evaluate_eligibility(&c),
        Eligibility::Ineligible(vec![IneligibilityReason::MissingPermission(
            "permission:network".to_owned()
        )])
    );
}

#[test]
fn unavailable_provider_is_ineligible() {
    let mut c = candidate();
    c.eligibility.provider_executable = false;
    assert_eq!(
        evaluate_eligibility(&c),
        Eligibility::Ineligible(vec![IneligibilityReason::ProviderUnavailable])
    );
}

#[test]
fn failed_precondition_is_machine_readable() {
    let mut c = candidate();
    c.eligibility.preconditions[0].satisfied = false;
    assert_eq!(
        evaluate_eligibility(&c),
        Eligibility::Ineligible(vec![IneligibilityReason::FailedPrecondition(
            "target:email".to_owned()
        )])
    );
}

#[test]
fn hard_constraint_and_explicit_block_cannot_be_outscored() {
    let mut c = candidate();
    c.eligibility.hard_constraints[0].satisfied = false;
    c.eligibility.blocked_reasons.push("operator:block".to_owned());
    c.expected_decision_impact = 1.0;
    c.roi_inputs.novelty_prior = 1.0;
    c.roi_inputs.reliability_prior = 1.0;

    assert_eq!(
        evaluate_eligibility(&c),
        Eligibility::Ineligible(vec![
            IneligibilityReason::HardConstraintFailed("scope:public".to_owned()),
            IneligibilityReason::ExplicitlyBlocked("operator:block".to_owned()),
        ])
    );
}
