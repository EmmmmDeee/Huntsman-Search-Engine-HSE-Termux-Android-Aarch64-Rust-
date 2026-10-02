//! Explicit scan termination semantics.
//!
//! "Fixed point" means no admissible, delayed, in-flight, or newly derivable
//! work remains. A bounded stop is recorded under the bound that actually
//! stopped execution rather than being mislabeled convergence.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminationReason {
    FixedPoint,
    MaxDepth,
    TimeLimit,
    RequestBudget,
    ProviderBudget,
    ResourceLimit,
    MarginalGainLimit,
    Cancelled,
    FatalError,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FrontierState {
    pub admissible_work: usize,
    pub delayed_retry_work: usize,
    pub in_flight_work: usize,
    pub derivable_novel_work: usize,
}

impl FrontierState {
    #[must_use]
    pub const fn is_fixed_point(self) -> bool {
        self.admissible_work == 0
            && self.delayed_retry_work == 0
            && self.in_flight_work == 0
            && self.derivable_novel_work == 0
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct TerminationSignals {
    pub cancelled: bool,
    pub fatal_error: bool,
    pub max_depth_reached: bool,
    pub time_limit_reached: bool,
    pub request_budget_exhausted: bool,
    pub provider_budget_exhausted: bool,
    pub resource_limit_reached: bool,
    pub marginal_gain_below_floor: bool,
}

/// Resolve one explicit reason using a deterministic severity/causality order.
#[must_use]
pub const fn decide_termination(
    frontier: FrontierState,
    signals: TerminationSignals,
) -> Option<TerminationReason> {
    if signals.fatal_error {
        Some(TerminationReason::FatalError)
    } else if signals.cancelled {
        Some(TerminationReason::Cancelled)
    } else if signals.resource_limit_reached {
        Some(TerminationReason::ResourceLimit)
    } else if signals.time_limit_reached {
        Some(TerminationReason::TimeLimit)
    } else if signals.provider_budget_exhausted {
        Some(TerminationReason::ProviderBudget)
    } else if signals.request_budget_exhausted {
        Some(TerminationReason::RequestBudget)
    } else if signals.max_depth_reached {
        Some(TerminationReason::MaxDepth)
    } else if signals.marginal_gain_below_floor {
        Some(TerminationReason::MarginalGainLimit)
    } else if frontier.is_fixed_point() {
        Some(TerminationReason::FixedPoint)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delayed_retry_prevents_false_fixed_point() {
        let frontier = FrontierState {
            delayed_retry_work: 1,
            ..FrontierState::default()
        };
        assert_eq!(
            decide_termination(frontier, TerminationSignals::default()),
            None
        );
    }

    #[test]
    fn budget_stop_is_not_mislabeled_fixed_point() {
        assert_eq!(
            decide_termination(
                FrontierState::default(),
                TerminationSignals {
                    request_budget_exhausted: true,
                    ..TerminationSignals::default()
                }
            ),
            Some(TerminationReason::RequestBudget)
        );
    }
}
