use huntsman_recon::roi::{DispatchUtilityInputs, compute_dispatch_utility};

fn inputs(source_count: u32) -> DispatchUtilityInputs {
    DispatchUtilityInputs {
        source_count,
        entity_confidence: Some(0.5),
        optionality_prior: 0.5,
        novelty_prior: 0.5,
        reliability_prior: 0.5,
        cost_per_request_usd: Some(0.0),
        quota_remaining: Some(true),
        configured_timeout_ms: 5_000,
        already_dispatched_this_module_target: false,
        geoint_bearing: false,
    }
}

#[test]
fn source_multiplicity_does_not_manufacture_independence() {
    let one = compute_dispatch_utility(&inputs(1));
    let many = compute_dispatch_utility(&inputs(100));

    assert_eq!(
        one.expected_independence, many.expected_independence,
        "source count is multiplicity, not demonstrated evidentiary independence"
    );
    assert_eq!(
        one.expected_independence, 0.0,
        "unknown independence must remain unknown/non-positive for action scoring"
    );
}
