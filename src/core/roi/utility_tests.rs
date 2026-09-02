use super::*;

fn baseline_inputs() -> DispatchUtilityInputs {
    DispatchUtilityInputs {
        source_count: 2,
        entity_confidence: Some(0.5),
        optionality_prior: 0.7,
        novelty_prior: 0.7,
        reliability_prior: 0.5,
        cost_per_request_usd: Some(0.0),
        quota_remaining: None,
        configured_timeout_ms: 5_000,
        already_dispatched_this_module_target: false,
    }
}

#[test]
fn missing_reliability_falls_back_to_neutral_prior_not_zero() {
    let inputs = DispatchUtilityInputs {
        reliability_prior: 0.5,
        ..baseline_inputs()
    };
    let out = compute_dispatch_utility(&inputs);
    assert_eq!(out.reliability, 0.5, "cold-start prior must surface, never a hard 0.0");
    assert_eq!(out.failure_penalty, 0.5, "failure_penalty is the deterministic complement");
}

#[test]
fn missing_cost_yields_fixed_penalty_not_infinite_or_zero() {
    let unknown = DispatchUtilityInputs {
        cost_per_request_usd: None,
        ..baseline_inputs()
    };
    let free = DispatchUtilityInputs {
        cost_per_request_usd: Some(0.0),
        ..baseline_inputs()
    };
    let expensive = DispatchUtilityInputs {
        cost_per_request_usd: Some(50.0),
        ..baseline_inputs()
    };

    let out_unknown = compute_dispatch_utility(&unknown);
    let out_free = compute_dispatch_utility(&free);
    let out_expensive = compute_dispatch_utility(&expensive);

    assert_eq!(out_unknown.estimated_cost, None);
    assert_eq!(out_free.estimated_cost, Some(0.0));
    assert_eq!(out_expensive.estimated_cost, Some(50.0));

    // Unknown cost's utility cost-penalty component equals exactly
    // W_COST * UNKNOWN_COST_PENALTY — distinguishing it from both a
    // confirmed-free (penalty 0.0) and a known-expensive case (penalty
    // approaching W_COST * 1.0).
    let unknown_cost_component = W_COST * UNKNOWN_COST_PENALTY;
    let free_utility_minus_cost = out_free.final_utility + 0.0; // free contributes 0 penalty
    let unknown_utility_plus_penalty = out_unknown.final_utility + unknown_cost_component;
    assert!(
        (free_utility_minus_cost - unknown_utility_plus_penalty).abs() < 1e-9,
        "unknown-cost utility must equal the free-cost utility minus exactly the fixed penalty \
         (free={free_utility_minus_cost}, unknown+penalty={unknown_utility_plus_penalty})"
    );
    assert!(
        out_expensive.final_utility < out_unknown.final_utility,
        "a known, expensive cost must penalize more than an unknown one"
    );
}

#[test]
fn missing_quota_yields_neutral_default_not_full_exhaustion() {
    let untracked = DispatchUtilityInputs {
        quota_remaining: None,
        ..baseline_inputs()
    };
    let has_budget = DispatchUtilityInputs {
        quota_remaining: Some(true),
        ..baseline_inputs()
    };
    let out_untracked = compute_dispatch_utility(&untracked);
    let out_has_budget = compute_dispatch_utility(&has_budget);

    assert_eq!(out_untracked.quota_cost, None);
    assert_eq!(out_has_budget.quota_cost, Some(0.0));

    // The untracked case's internal quota-penalty contribution is the small
    // neutral default, not zero and not the full penalty.
    let neutral_component = W_QUOTA * QUOTA_COST_NEUTRAL;
    assert!(
        (out_untracked.final_utility - (out_has_budget.final_utility - neutral_component)).abs()
            < 1e-9,
        "untracked quota must cost exactly W_QUOTA * QUOTA_COST_NEUTRAL relative to confirmed \
         full budget"
    );
}

#[test]
fn missing_factors_never_collapse_dominant_term() {
    // All uncertain/optional signals unknown.
    let all_unknown = DispatchUtilityInputs {
        entity_confidence: None, // -> max information value (1.0)
        reliability_prior: 0.5,
        cost_per_request_usd: None,
        quota_remaining: None,
        ..baseline_inputs()
    };
    // All uncertain signals at their worst KNOWN value.
    let all_worst_known = DispatchUtilityInputs {
        entity_confidence: Some(0.99), // almost nothing left to learn
        reliability_prior: 0.0,        // known-unreliable
        cost_per_request_usd: Some(1000.0), // known-expensive
        quota_remaining: Some(false),  // known-exhausted (would normally be gated pre-ranking;
        // scored here only to prove the formula itself never
        // collapses even in this adversarial case)
        ..baseline_inputs()
    };

    let out_unknown = compute_dispatch_utility(&all_unknown);
    let out_worst = compute_dispatch_utility(&all_worst_known);

    assert!(
        out_unknown.final_utility > out_worst.final_utility,
        "all-unknown must score strictly higher than all-known-worst"
    );
    assert!(
        out_unknown.final_utility > 0.0,
        "a candidate with strong expected information value must keep a positive score even \
         when every uncertain factor is unknown — no multiplicative collapse"
    );
    // A naive `weight *= reliability` formulation with reliability=0.0 would
    // zero the whole score; this additive formula must not.
    let reliability_zero = DispatchUtilityInputs {
        reliability_prior: 0.0,
        ..baseline_inputs()
    };
    let out_rel_zero = compute_dispatch_utility(&reliability_zero);
    assert!(
        out_rel_zero.final_utility > 0.0,
        "a zero-valued reliability factor must not zero out the other nine terms \
         (final_utility={})",
        out_rel_zero.final_utility
    );
}

#[test]
fn explanation_is_never_empty_and_always_restates_final_utility() {
    let out = compute_dispatch_utility(&baseline_inputs());
    assert!(
        out.explanation.len() >= 10,
        "expected one line per factor plus the final restatement, got {}",
        out.explanation.len()
    );
    let last = out.explanation.last().expect("non-empty explanation");
    assert!(last.starts_with("final_utility:"), "last line must restate final_utility, got: {last}");
    let parsed: f64 = last
        .trim_start_matches("final_utility:")
        .trim()
        .parse()
        .expect("final_utility line must parse as a float");
    assert!(
        (parsed - out.final_utility).abs() < 1e-2,
        "explanation's restated final_utility ({parsed}) must match the real value ({})",
        out.final_utility
    );
}

#[test]
fn duplicate_penalty_is_binary_and_dominant() {
    let fresh = DispatchUtilityInputs {
        already_dispatched_this_module_target: false,
        ..baseline_inputs()
    };
    let dup = DispatchUtilityInputs {
        already_dispatched_this_module_target: true,
        ..baseline_inputs()
    };
    let out_fresh = compute_dispatch_utility(&fresh);
    let out_dup = compute_dispatch_utility(&dup);

    assert_eq!(out_fresh.duplicate_penalty, 0.0);
    assert_eq!(out_dup.duplicate_penalty, 1.0);
    assert!(
        (out_fresh.final_utility - out_dup.final_utility - W_DUP).abs() < 1e-9,
        "duplicate dispatch must cost exactly W_DUP relative to an identical fresh candidate"
    );

    // A moderately-higher-information, already-dispatched candidate can
    // still rank below a lower-information, fresh one — duplication
    // genuinely suppresses ranking without needing a hard gate. `W_DUP`
    // (2.0) is a *near*-veto, not a full one: the info-value gap here
    // (W_INFO * (1.0 - 0.5) = 1.5) is smaller than W_DUP, so the fresh
    // candidate wins despite the dup's higher raw information value.
    let higher_info_dup = DispatchUtilityInputs {
        entity_confidence: None, // max information value (1.0)
        already_dispatched_this_module_target: true,
        ..baseline_inputs()
    };
    let lower_info_fresh = DispatchUtilityInputs {
        entity_confidence: Some(0.5), // moderate information value
        already_dispatched_this_module_target: false,
        ..baseline_inputs()
    };
    let out_higher_dup = compute_dispatch_utility(&higher_info_dup);
    let out_lower_fresh = compute_dispatch_utility(&lower_info_fresh);
    assert!(
        out_lower_fresh.final_utility > out_higher_dup.final_utility,
        "duplication must be able to suppress an otherwise-higher-information candidate below \
         a fresh, lower-information one when the info-value gap is smaller than W_DUP"
    );
}

#[test]
fn expected_independence_is_monotonic_and_bounded() {
    let zero = compute_dispatch_utility(&DispatchUtilityInputs {
        source_count: 0,
        ..baseline_inputs()
    })
    .expected_independence;
    let one = compute_dispatch_utility(&DispatchUtilityInputs {
        source_count: 1,
        ..baseline_inputs()
    })
    .expected_independence;
    let two = compute_dispatch_utility(&DispatchUtilityInputs {
        source_count: 2,
        ..baseline_inputs()
    })
    .expected_independence;
    let many = compute_dispatch_utility(&DispatchUtilityInputs {
        source_count: 1000,
        ..baseline_inputs()
    })
    .expected_independence;

    assert_eq!(zero, 0.0);
    assert!(zero < one && one < two && two < many);
    assert!(many < 1.0, "must approach but never reach 1.0");
}

#[test]
fn quota_exhausted_gate_only_blocks_quota_tracked_modules() {
    assert!(!quota_exhausted_blocked(None, Some(false)));
    assert!(!quota_exhausted_blocked(None, None));
    assert!(quota_exhausted_blocked(Some("query"), Some(false)));
    assert!(!quota_exhausted_blocked(Some("query"), Some(true)));
    assert!(
        !quota_exhausted_blocked(Some("query"), None),
        "an unknown remaining state must never be treated as exhausted"
    );
}
