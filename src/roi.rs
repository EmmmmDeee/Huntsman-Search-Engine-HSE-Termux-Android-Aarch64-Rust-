use crate::dependency::ModuleCategory;
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance};

pub const SATURATION_CORROBORATION: u32 = 2;
pub const SATURATION_CONFIDENCE: f64 = 0.85;
pub const DEFAULT_MIN_MARGINAL_YIELD: f64 = 0.75;
pub const KNEE_FRACTION: f64 = 0.05;

#[must_use]
pub fn is_saturated(entity: &Entity) -> bool {
    entity.source_count() >= SATURATION_CORROBORATION
        && entity.c_effective() >= SATURATION_CONFIDENCE
}

#[must_use]
pub fn top_k_for_round(max_concurrent: usize) -> usize {
    2 * max_concurrent.max(1) + 8
}

#[must_use]
pub fn effective_cutoff(sorted_weights_desc: &[f64], max_concurrent: usize) -> usize {
    if sorted_weights_desc.is_empty() {
        return 0;
    }
    let cap = top_k_for_round(max_concurrent);
    let leader = sorted_weights_desc[0];
    let knee = if leader > 0.0 {
        let threshold = leader * KNEE_FRACTION;
        sorted_weights_desc
            .iter()
            .take_while(|&&weight| weight >= threshold)
            .count()
            .max(1)
    } else {
        sorted_weights_desc.len()
    };
    knee.min(cap).max(1)
}

#[must_use]
pub fn marginal_yield(new_entities: usize, dispatched_targets: usize) -> f64 {
    if dispatched_targets == 0 {
        f64::INFINITY
    } else {
        #[allow(clippy::cast_precision_loss)]
        {
            new_entities as f64 / dispatched_targets as f64
        }
    }
}

#[must_use]
pub fn should_terminate_adaptive(
    enabled: bool,
    new_entities: usize,
    dispatched_targets: usize,
    floor: f64,
) -> bool {
    enabled && dispatched_targets > 0 && marginal_yield(new_entities, dispatched_targets) < floor
}

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
    pub explanation: Vec<String>,
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

fn normalised_cost_penalty(cost: Option<f64>) -> (f64, String) {
    match cost {
        Some(cost) if cost <= 0.0 => (0.0, format!("CostModel confirmed free -> Some({cost:.4})")),
        Some(cost) => {
            let penalty = (cost / (cost + COST_SOFTNESS)).clamp(0.0, 1.0);
            (
                penalty,
                format!("cost_per_request=${cost:.4} -> normalised {penalty:.3}"),
            )
        }
        None => (
            UNKNOWN_COST_PENALTY,
            format!("cost unknown -> fixed penalty {UNKNOWN_COST_PENALTY:.3}"),
        ),
    }
}

fn quota_penalty(remaining: Option<bool>) -> (f64, String) {
    match remaining {
        Some(false) => (1.0, "quota reported exhausted".to_string()),
        Some(true) => (0.0, "quota has budget remaining -> 0.0".to_string()),
        None => (
            QUOTA_COST_NEUTRAL,
            format!("no local quota tracked -> neutral default {QUOTA_COST_NEUTRAL:.3}"),
        ),
    }
}

#[must_use]
#[allow(clippy::cast_precision_loss, clippy::too_many_lines)]
pub fn compute_dispatch_utility(inputs: &DispatchUtilityInputs) -> DispatchUtility {
    let expected_information_value = 1.0 - inputs.entity_confidence.unwrap_or(0.0);
    let expected_novelty = inputs.novelty_prior.clamp(0.0, 1.0);
    let expected_independence = 1.0 - 1.0 / (1.0 + f64::from(inputs.source_count));
    let expected_optionality = inputs.optionality_prior.clamp(0.0, 1.0);
    let reliability = inputs.reliability_prior.clamp(0.0, 1.0);
    let failure_penalty = 1.0 - reliability;
    let (cost_penalty, cost_note) = normalised_cost_penalty(inputs.cost_per_request_usd);
    let (quota_penalty_value, quota_note) = quota_penalty(inputs.quota_remaining);
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

    let explanation = vec![
        format!(
            "expected_information_value: +{:.3} (entity_confidence={:.3} -> {:.3}, x W_INFO={W_INFO})",
            W_INFO * expected_information_value,
            inputs.entity_confidence.unwrap_or(0.0),
            expected_information_value
        ),
        format!(
            "expected_novelty: +{:.3} (module_cascade -> {expected_novelty:.3}, x W_NOV={W_NOV})",
            W_NOV * expected_novelty
        ),
        format!(
            "expected_independence: +{:.3} (source_count={} -> {expected_independence:.3}, x W_INDEP={W_INDEP})",
            W_INDEP * expected_independence,
            inputs.source_count
        ),
        format!(
            "expected_optionality: +{:.3} (ProviderDescriptor.optionality_prior={:.3}, x W_OPT={W_OPT})",
            W_OPT * expected_optionality,
            inputs.optionality_prior
        ),
        format!(
            "reliability: +{:.3} (cold-start prior={reliability:.3} — circuit-open already gated upstream, x W_REL={W_REL})",
            W_REL * reliability
        ),
        format!(
            "geoint_preference: +{:.3} (geoint_bearing={}, x W_GEO={W_GEO})",
            W_GEO * geoint_preference,
            inputs.geoint_bearing
        ),
        format!(
            "estimated_cost: -{:.3} ({cost_note}, x W_COST={W_COST})",
            W_COST * cost_penalty
        ),
        format!(
            "quota_cost: -{:.3} ({quota_note}, x W_QUOTA={W_QUOTA})",
            W_QUOTA * quota_penalty_value
        ),
        format!(
            "latency_penalty: -{:.3} (configured_timeout_ms={} / {MAX_REASONABLE_TIMEOUT_MS}, x W_LAT={W_LAT})",
            W_LAT * latency_penalty,
            inputs.configured_timeout_ms
        ),
        format!(
            "failure_penalty: -{:.3} (1 - reliability={reliability:.3}, x W_FAIL={W_FAIL})",
            W_FAIL * failure_penalty
        ),
        format!(
            "duplicate_penalty: -{:.3} (already_dispatched={}, x W_DUP={W_DUP})",
            W_DUP * duplicate_penalty,
            inputs.already_dispatched_this_module_target
        ),
        format!("final_utility: {final_utility:.3}"),
    ];

    DispatchUtility {
        expected_information_value,
        expected_novelty,
        expected_independence,
        expected_optionality,
        reliability,
        estimated_cost: inputs.cost_per_request_usd,
        quota_cost: inputs.quota_remaining.map(|_| quota_penalty_value),
        latency_penalty,
        failure_penalty,
        duplicate_penalty,
        final_utility,
        explanation,
    }
}

#[must_use]
pub fn is_geoint_bearing(produces: &[EntityKind], category: ModuleCategory) -> bool {
    matches!(category, ModuleCategory::Geo | ModuleCategory::Sensor)
        || produces
            .iter()
            .any(|kind| matches!(kind, EntityKind::Coordinates | EntityKind::Address))
}

#[must_use]
pub fn quota_exhausted_blocked(quota_unit: Option<&'static str>, remaining: Option<bool>) -> bool {
    quota_unit.is_some() && remaining == Some(false)
}

const _: () = assert!(W_GEO * 4.0 < W_INFO, "W_GEO must stay well below W_INFO");

#[cfg(test)]
mod tests {
    use super::*;
    fn make(confidence: f64, corroboration: usize) -> Entity {
        let mut entity = Entity::new(EntityKind::Email, "x@y.com", confidence, "scan");
        for idx in 1..corroboration {
            entity.add_evidence(Evidence::new(
                EvidenceProvenance::new(format!("source-{idx}")),
                "seen",
            ));
        }
        entity
    }

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
    fn saturation_requires_sources_and_effective_confidence() {
        assert!(!is_saturated(&make(0.95, 1)));
        assert!(!is_saturated(&make(0.50, 2)));
        assert!(is_saturated(&make(0.90, 3)));
        assert!(is_saturated(&make(0.50, 5)));
    }

    #[test]
    fn cutoff_respects_knee_and_top_k() {
        let weights = [50.0, 40.0, 10.0, 5.0, 2.0, 2.0, 1.0, 0.5];
        assert_eq!(effective_cutoff(&weights, 4), 4);
        assert_eq!(effective_cutoff(&[], 4), 0);
        assert_eq!(effective_cutoff(&[42.0], 4), 1);
        let flat = vec![1.0; 20];
        assert_eq!(effective_cutoff(&flat, 4), 16);
    }

    #[test]
    fn adaptive_termination_needs_real_data() {
        assert!(marginal_yield(0, 0).is_infinite());
        assert!((marginal_yield(10, 5) - 2.0).abs() < f64::EPSILON);
        assert!(!should_terminate_adaptive(false, 0, 100, 1.0));
        assert!(!should_terminate_adaptive(true, 0, 0, 1.0));
        assert!(!should_terminate_adaptive(true, 10, 5, 1.0));
        assert!(should_terminate_adaptive(true, 1, 10, 1.0));
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
        assert!(
            geo.explanation
                .iter()
                .any(|line| line.contains("geoint_preference"))
        );
    }

    #[test]
    fn utility_explanation_restates_final_score() {
        let utility = compute_dispatch_utility(&baseline_inputs());
        let last = utility.explanation.last().unwrap();
        assert!(last.starts_with("final_utility:"));
    }

    #[test]
    fn quota_gate_only_blocks_tracked_exhaustion() {
        assert!(!quota_exhausted_blocked(None, Some(false)));
        assert!(quota_exhausted_blocked(Some("query"), Some(false)));
        assert!(!quota_exhausted_blocked(Some("query"), None));
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
