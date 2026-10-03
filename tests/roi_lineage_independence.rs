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
fn raw_source_count_does_not_create_evidentiary_independence() {
    let one_source = compute_dispatch_utility(&inputs(1));
    let many_sources = compute_dispatch_utility(&inputs(20));

    assert_eq!(
        one_source.expected_independence, many_sources.expected_independence,
        "provider/source volume must not manufacture independent evidentiary roots"
    );
}
