use crate::dependency::ModuleCategory;
use crate::entity::EntityKind;

#[derive(Debug, Clone, PartialEq)]
pub struct DispatchUtility {
    pub expected_information_value: f64,
    pub expected_novelty: f64,
    pub expected_independence: f64,
    pub expected_optionality: f64,
    pub reliability: f64,
    pub estimated_cost: Option<f64>,
    pub quota_cost: Option<f64>,
    pub latency_penalty: f64,
    pub failure_penalty: f64,
    pub duplicate_penalty: f64,
    pub final_utility: f64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DispatchUtilityInputs {
    pub source_count: u32,
    pub entity_confidence: Option<f64>,
    pub optionality_prior: f64,
    pub novelty_prior: f64,
    pub reliability_prior: f64,
    pub cost_per_request_usd: Option<f64>,
    pub quota_remaining: Option<bool>,
    pub configured_timeout_ms: u64,
    pub already_dispatched_this_module_target: bool,
    pub geoint_bearing: bool,
}

pub const W_INFO: f64 = 3.0;
pub const W_NOV: f64 = 1.0;
pub const W_INDEP: f64 = 1.0;
pub const W_OPT: f64 = 1.0;
pub const W_REL: f64 = 1.0;
pub const W_COST: f64 = 1.0;
pub const W_QUOTA: f64 = 0.5;
pub const W_LAT: f64 = 0.5;
pub const W_GEO: f64 = 0.25;
pub const W_FAIL: f64 = 1.0;
pub const W_DUP: f64 = 2.0;
pub const UNKNOWN_COST_PENALTY: f64 = 0.3;
pub const QUOTA_COST_NEUTRAL: f64 = 0.2;
const COST_SOFTNESS: f64 = 5.0;
const MAX_REASONABLE_TIMEOUT_MS: f64 = 45_000.0;

/// Invalid provider metadata must not poison the entire dispatch ranking with NaN.
fn bounded_prior(value: f64, fallback: f64) -> f64 {
    if value.is_finite() {
        value.clamp(0.0, 1.0)
    } else {
        fallback
    }
}

fn normalised_cost_penalty(cost: Option<f64>) -> f64 {
    match cost {
        Some(cost) if cost.is_finite() && cost >= 0.0 => {
            (cost / (cost + COST_SOFTNESS)).clamp(0.0, 1.0)
        }
        // An unbounded stated price cannot become a free request.
        Some(cost) if cost.is_infinite() && cost.is_sign_positive() => 1.0,
        // Unknown or malformed prices are uncertain, not free.
        _ => UNKNOWN_COST_PENALTY,
    }
}

fn quota_penalty(remaining: Option<bool>) -> f64 {
    match remaining {
        Some(false) => 1.0,
        Some(true) => 0.0,
        None => QUOTA_COST_NEUTRAL,
    }
}

#[must_use]
#[allow(clippy::cast_precision_loss)]
pub fn compute_dispatch_utility(inputs: &DispatchUtilityInputs) -> DispatchUtility {
    let expected_information_value =
        1.0 - bounded_prior(inputs.entity_confidence.unwrap_or(0.0), 0.0);
    let expected_novelty = bounded_prior(inputs.novelty_prior, 0.5);
    let expected_independence = 1.0 - 1.0 / (1.0 + f64::from(inputs.source_count));
    let expected_optionality = bounded_prior(inputs.optionality_prior, 0.5);
    let reliability = bounded_prior(inputs.reliability_prior, 0.5);
    let failure_penalty = 1.0 - reliability;
    let cost_penalty = normalised_cost_penalty(inputs.cost_per_request_usd);
    let quota_penalty_value = quota_penalty(inputs.quota_remaining);
    let latency_penalty =
        ((inputs.configured_timeout_ms as f64) / MAX_REASONABLE_TIMEOUT_MS).clamp(0.0, 1.0);
    let duplicate_penalty = f64::from(u8::from(inputs.already_dispatched_this_module_target));
    let geoint_preference = f64::from(u8::from(inputs.geoint_bearing));

    let final_utility = W_INFO.mul_add(
        expected_information_value,
        W_NOV.mul_add(
            expected_novelty,
            W_INDEP.mul_add(
                expected_independence,
                W_OPT.mul_add(
                    expected_optionality,
                    W_GEO.mul_add(geoint_preference, W_REL * reliability),
                ),
            ),
        ),
    ) - W_COST.mul_add(
        cost_penalty,
        W_QUOTA.mul_add(
            quota_penalty_value,
            W_LAT.mul_add(
                latency_penalty,
                W_FAIL.mul_add(failure_penalty, W_DUP * duplicate_penalty),
            ),
        ),
    );

    DispatchUtility {
        expected_information_value,
        expected_novelty,
        expected_independence,
        expected_optionality,
        reliability,
        estimated_cost: inputs
            .cost_per_request_usd
            .filter(|cost| cost.is_finite() && *cost >= 0.0),
        quota_cost: inputs.quota_remaining.map(|_| quota_penalty_value),
        latency_penalty,
        failure_penalty,
        duplicate_penalty,
        final_utility,
    }
}

#[must_use]
pub fn is_geoint_bearing(produces: &[EntityKind], category: ModuleCategory) -> bool {
    matches!(category, ModuleCategory::Geo | ModuleCategory::Sensor)
        || produces
            .iter()
            .any(|kind| matches!(kind, EntityKind::Coordinates | EntityKind::Address))
}

const _: () = assert!(W_GEO * 4.0 < W_INFO, "W_GEO must stay well below W_INFO");

#[cfg(test)]
mod tests {
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
            geoint_bearing: false,
        }
    }

    #[test]
    fn utility_uses_neutral_defaults_for_unknowns() {
        let unknown_cost = compute_dispatch_utility(&DispatchUtilityInputs {
            cost_per_request_usd: None,
            ..baseline_inputs()
        });
        let free = compute_dispatch_utility(&baseline_inputs());
        assert_eq!(unknown_cost.estimated_cost, None);
        assert!(unknown_cost.final_utility < free.final_utility);

        let untracked_quota = compute_dispatch_utility(&DispatchUtilityInputs {
            quota_remaining: None,
            ..baseline_inputs()
        });
        let tracked_quota = compute_dispatch_utility(&DispatchUtilityInputs {
            quota_remaining: Some(true),
            ..baseline_inputs()
        });
        assert_eq!(untracked_quota.quota_cost, None);
        assert!(
            tracked_quota
                .quota_cost
                .is_some_and(|value| value.abs() < f64::EPSILON)
        );
    }

    #[test]
    fn duplicate_penalty_and_geoint_preference_are_visible() {
        let fresh = compute_dispatch_utility(&baseline_inputs());
        let duplicate = compute_dispatch_utility(&DispatchUtilityInputs {
            already_dispatched_this_module_target: true,
            ..baseline_inputs()
        });
        assert!((duplicate.duplicate_penalty - 1.0).abs() < f64::EPSILON);
        assert!((fresh.final_utility - duplicate.final_utility - W_DUP).abs() < 1e-9);

        let geo = compute_dispatch_utility(&DispatchUtilityInputs {
            geoint_bearing: true,
            ..baseline_inputs()
        });
        assert!((geo.final_utility - fresh.final_utility - W_GEO).abs() < 1e-9);
    }

    #[test]
    fn nonfinite_and_out_of_range_inputs_do_not_block_dispatch_sorting() {
        for invalid in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let score = compute_dispatch_utility(&DispatchUtilityInputs {
                entity_confidence: Some(invalid),
                optionality_prior: invalid,
                novelty_prior: invalid,
                reliability_prior: invalid,
                cost_per_request_usd: Some(invalid),
                ..baseline_inputs()
            });
            assert!(score.final_utility.is_finite(), "{invalid:?}: {score:?}");
            assert!(score.expected_information_value >= 0.0);
            assert!(score.expected_information_value <= 1.0);
            assert!(score.estimated_cost.is_none());
            assert!(score.expected_novelty >= 0.0 && score.expected_novelty <= 1.0);
            assert!(score.reliability >= 0.0 && score.reliability <= 1.0);
        }
        for confidence in [-8.0, 0.0, 0.8, 9.0] {
            let score = compute_dispatch_utility(&DispatchUtilityInputs {
                entity_confidence: Some(confidence),
                ..baseline_inputs()
            });
            assert!((0.0..=1.0).contains(&score.expected_information_value));
            assert!(score.final_utility.is_finite());
        }
    }

    #[test]
    fn invalid_cost_does_not_become_free_or_overflow_utility() {
        assert_eq!(
            normalised_cost_penalty(Some(f64::NAN)),
            UNKNOWN_COST_PENALTY
        );
        assert_eq!(normalised_cost_penalty(Some(-1.0)), UNKNOWN_COST_PENALTY);
        assert_eq!(normalised_cost_penalty(Some(f64::INFINITY)), 1.0);
        assert_eq!(normalised_cost_penalty(Some(0.0)), 0.0);
        assert!(normalised_cost_penalty(Some(f64::MAX)).is_finite());
        assert!(normalised_cost_penalty(Some(1.0)) > 0.0);
    }

    #[test]
    fn geoint_bearing_derives_from_category_or_outputs() {
        assert!(is_geoint_bearing(&[], ModuleCategory::Geo));
        assert!(is_geoint_bearing(
            &[EntityKind::Coordinates],
            ModuleCategory::Social
        ));
        assert!(!is_geoint_bearing(
            &[EntityKind::Email, EntityKind::Username],
            ModuleCategory::Social,
        ));
    }
}
