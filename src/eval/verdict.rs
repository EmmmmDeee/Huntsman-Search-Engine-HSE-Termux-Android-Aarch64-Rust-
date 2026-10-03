use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Promote,
    Repair,
    Replace,
    Rollback,
    Hold,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EvalPolicy {
    pub min_primary_gain: f64,
    pub min_ci_low: f64,
    pub max_false_merge_delta: isize,
    pub min_evidence_completeness_delta: f64,
    pub min_worst_decile_delta: f64,
    pub max_cost_ratio: f64,
}

impl Default for EvalPolicy {
    fn default() -> Self {
        Self {
            min_primary_gain: 0.02,
            min_ci_low: 0.0,
            max_false_merge_delta: 0,
            min_evidence_completeness_delta: 0.0,
            min_worst_decile_delta: -0.02,
            max_cost_ratio: 2.0,
        }
    }
}

#[allow(clippy::struct_excessive_bools)] // independent preconditions checked by decide()
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ComparisonEvidence {
    pub complete: bool,
    pub comparable: bool,
    pub primary_gain: f64,
    pub primary_ci_low: f64,
    pub false_merge_delta: isize,
    pub evidence_completeness_delta: f64,
    pub adversarial_pass: bool,
    pub holdout_pass: bool,
    pub critical_guardrails_pass: bool,
    pub worst_decile_delta: f64,
    pub cost_ratio: f64,
    pub dominated_by_alternative: bool,
    pub severe_regression: bool,
}

#[must_use]
pub fn decide(evidence: ComparisonEvidence, policy: EvalPolicy) -> Decision {
    let measured = [
        evidence.primary_gain,
        evidence.primary_ci_low,
        evidence.evidence_completeness_delta,
        evidence.worst_decile_delta,
        evidence.cost_ratio,
    ];
    if !evidence.complete
        || !evidence.comparable
        || !measured.iter().all(|m| m.is_finite())
        || evidence.cost_ratio < 0.0
    {
        return Decision::Hold;
    }
    if evidence.severe_regression {
        return Decision::Rollback;
    }
    if evidence.dominated_by_alternative {
        return Decision::Replace;
    }

    let upside = evidence.primary_gain >= policy.min_primary_gain;
    let gates_pass = evidence.primary_ci_low >= policy.min_ci_low
        && evidence.false_merge_delta <= policy.max_false_merge_delta
        && evidence.evidence_completeness_delta >= policy.min_evidence_completeness_delta
        && evidence.adversarial_pass
        && evidence.holdout_pass
        && evidence.critical_guardrails_pass
        && evidence.worst_decile_delta >= policy.min_worst_decile_delta
        && evidence.cost_ratio <= policy.max_cost_ratio;

    if upside && gates_pass {
        Decision::Promote
    } else if upside {
        Decision::Repair
    } else {
        Decision::Hold
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn robust_gain() -> ComparisonEvidence {
        ComparisonEvidence {
            complete: true,
            comparable: true,
            primary_gain: 0.10,
            primary_ci_low: 0.03,
            false_merge_delta: 0,
            evidence_completeness_delta: 0.02,
            adversarial_pass: true,
            holdout_pass: true,
            critical_guardrails_pass: true,
            worst_decile_delta: 0.0,
            cost_ratio: 1.2,
            dominated_by_alternative: false,
            severe_regression: false,
        }
    }

    #[test]
    fn false_merge_regression_blocks_promotion() {
        let mut evidence = robust_gain();
        evidence.false_merge_delta = 1;
        assert_eq!(decide(evidence, EvalPolicy::default()), Decision::Repair);
    }

    #[test]
    fn incomplete_comparison_holds() {
        let mut evidence = robust_gain();
        evidence.comparable = false;
        assert_eq!(decide(evidence, EvalPolicy::default()), Decision::Hold);
    }

    #[test]
    fn robust_gain_promotes() {
        assert_eq!(
            decide(robust_gain(), EvalPolicy::default()),
            Decision::Promote
        );
    }

    #[test]
    fn holdout_failure_blocks_promotion() {
        let mut evidence = robust_gain();
        evidence.holdout_pass = false;
        assert_eq!(decide(evidence, EvalPolicy::default()), Decision::Repair);
    }

    #[test]
    fn critical_guardrail_failure_blocks_promotion() {
        let mut evidence = robust_gain();
        evidence.critical_guardrails_pass = false;
        assert_eq!(decide(evidence, EvalPolicy::default()), Decision::Repair);
    }

    #[test]
    fn severe_regression_rolls_back() {
        let mut evidence = robust_gain();
        evidence.severe_regression = true;
        assert_eq!(decide(evidence, EvalPolicy::default()), Decision::Rollback);
    }

    #[test]
    fn falsify_non_finite_measurement_cannot_promote() {
        let mut evidence = robust_gain();
        evidence.primary_gain = f64::INFINITY;
        assert_eq!(decide(evidence, EvalPolicy::default()), Decision::Hold);
        let mut evidence = robust_gain();
        evidence.cost_ratio = f64::NEG_INFINITY;
        assert_eq!(decide(evidence, EvalPolicy::default()), Decision::Hold);
    }

    #[test]
    fn falsify_negative_cost_ratio_cannot_promote() {
        let mut evidence = robust_gain();
        evidence.cost_ratio = -5.0;
        assert_eq!(decide(evidence, EvalPolicy::default()), Decision::Hold);
        evidence.cost_ratio = 0.0;
        assert_eq!(decide(evidence, EvalPolicy::default()), Decision::Promote);
    }
}
