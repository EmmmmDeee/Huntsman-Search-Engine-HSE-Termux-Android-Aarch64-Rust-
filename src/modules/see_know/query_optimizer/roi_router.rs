//! ROI-based query routing
//!
//! Routes queries based on ROI = ValueScore / EffectiveCost
//! Prioritizes execution to maximize discovery efficiency

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum RoutingDecision {
    /// Execute immediately (ROI >50)
    ExecuteFirst,
    /// Execute if budget permits (ROI 20-50)
    ExecuteIfBudget,
    /// Execute only if time permits (ROI 10-20)
    ExecuteIfTime,
    /// Skip this query (ROI <10)
    Skip,
}

pub struct RoiRouter;

impl RoiRouter {
    pub fn new() -> Self {
        Self
    }

    /// Calculate ROI for a query
    /// Phase 1.3+
    pub fn calculate_roi(&self, value_score: f32, effective_cost: f32) -> f32 {
        if effective_cost > 0.0 {
            value_score / effective_cost
        } else {
            0.0
        }
    }

    /// Decide whether to execute query
    /// Phase 1.3+
    pub fn route_query(&self, roi: f32) -> RoutingDecision {
        // TODO: Phase 1.3
        match roi {
            r if r > 50.0 => RoutingDecision::ExecuteFirst,
            r if r > 20.0 => RoutingDecision::ExecuteIfBudget,
            r if r > 10.0 => RoutingDecision::ExecuteIfTime,
            _ => RoutingDecision::Skip,
        }
    }

    /// Sort candidate queries by ROI
    /// Phase 1.3+
    pub fn prioritize_queries(
        &self,
        candidates: Vec<(String, f32, f32)>,
    ) -> Vec<(String, f32, f32, RoutingDecision)> {
        // TODO: Phase 1.3
        // Calculate ROI for each candidate
        // Sort by ROI descending
        // Assign routing decision
        candidates
            .into_iter()
            .map(|(endpoint, value, cost)| {
                let roi = self.calculate_roi(value, cost);
                let decision = self.route_query(roi);
                (endpoint, value, cost, decision)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roi_calculation() {
        // TODO: Phase 1.3
        let router = RoiRouter::new();
        assert_eq!(router.calculate_roi(85.0, 1.0), 85.0);
        assert_eq!(router.calculate_roi(50.0, 2.0), 25.0);
    }

    #[test]
    fn test_routing_decision() {
        // TODO: Phase 1.3
        let router = RoiRouter::new();
        assert_eq!(router.route_query(60.0), RoutingDecision::ExecuteFirst);
        assert_eq!(router.route_query(30.0), RoutingDecision::ExecuteIfBudget);
        assert_eq!(router.route_query(15.0), RoutingDecision::ExecuteIfTime);
        assert_eq!(router.route_query(5.0), RoutingDecision::Skip);
    }
}
