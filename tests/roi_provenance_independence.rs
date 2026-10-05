use huntsman_recon::roi::{
    DispatchUtilityInputs, EvidentiaryIndependence, compute_dispatch_utility,
};

fn inputs(independence: EvidentiaryIndependence) -> DispatchUtilityInputs {
    DispatchUtilityInputs {
        source_count: 100,
        evidentiary_independence: independence,
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
fn unknown_and_shared_ancestry_never_earn_independence_utility() {
    let unknown = compute_dispatch_utility(&inputs(EvidentiaryIndependence::Unknown));
    let shared = compute_dispatch_utility(&inputs(EvidentiaryIndependence::SharedRoot));

    assert_eq!(unknown.expected_independence, 0.0);
    assert_eq!(shared.expected_independence, 0.0);
    assert_eq!(unknown.expected_independence, shared.expected_independence);
}

#[test]
fn only_demonstrated_distinct_roots_earn_independence_utility() {
    let unknown = compute_dispatch_utility(&inputs(EvidentiaryIndependence::Unknown));
    let demonstrated = compute_dispatch_utility(&inputs(
        EvidentiaryIndependence::DemonstratedIndependentRoots { distinct_roots: 2 },
    ));

    assert!(demonstrated.expected_independence > unknown.expected_independence);
    assert!(demonstrated.expected_independence > 0.0);
    assert!(demonstrated.expected_independence <= 1.0);
}

#[test]
fn demonstrated_independence_requires_at_least_two_distinct_roots() {
    let one_root = compute_dispatch_utility(&inputs(
        EvidentiaryIndependence::DemonstratedIndependentRoots { distinct_roots: 1 },
    ));

    assert_eq!(one_root.expected_independence, 0.0);
}
