//! ROI-based query routing - COMPLETE IMPLEMENTATION
//!
//! Routes queries based on ROI = ValueScore / EffectiveCost
//! Prioritizes execution to maximize discovery efficiency

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum RoutingDecision {
    /// Execute immediately (ROI >50) - highest priority
    ExecuteFirst = 4,
    /// Execute if budget permits (ROI 20-50) - high priority
    ExecuteIfBudget = 3,
    /// Execute if time permits (ROI 10-20) - medium priority
    ExecuteIfTime = 2,
    /// Execute only if explicitly requested (ROI 5-10) - low priority
    ExecuteIfRequested = 1,
    /// Skip this query (ROI <5) - never execute
    Skip = 0,
}

impl RoutingDecision {
    pub fn as_str(&self) -> &'static str {
        match self {
            RoutingDecision::ExecuteFirst => "ExecuteFirst",
            RoutingDecision::ExecuteIfBudget => "ExecuteIfBudget",
            RoutingDecision::ExecuteIfTime => "ExecuteIfTime",
            RoutingDecision::ExecuteIfRequested => "ExecuteIfRequested",
            RoutingDecision::Skip => "Skip",
        }
    }

    pub fn should_execute(&self) -> bool {
        !matches!(self, RoutingDecision::Skip)
    }
}

pub struct RoiRouter;

impl RoiRouter {
    pub fn new() -> Self {
        Self
    }

    /// Calculate ROI for a query (COMPLETE IMPLEMENTATION)
    pub fn calculate_roi(&self, value_score: f32, effective_cost: f32) -> f32 {
        if effective_cost <= 0.0 {
            // Free queries (ROI is value only)
            value_score.min(1000.0)
        } else {
            value_score / effective_cost
        }
    }

    /// Decide whether to execute query based on ROI
    pub fn route_query(&self, roi: f32) -> RoutingDecision {
        match roi {
            r if r > 50.0 => RoutingDecision::ExecuteFirst,
            r if r > 20.0 => RoutingDecision::ExecuteIfBudget,
            r if r > 10.0 => RoutingDecision::ExecuteIfTime,
            r if r > 5.0 => RoutingDecision::ExecuteIfRequested,
            _ => RoutingDecision::Skip,
        }
    }

    /// Sort candidate queries by ROI (descending)
    pub fn prioritize_queries(
        &self,
        candidates: Vec<(String, f32, f32)>,
    ) -> Vec<(String, f32, f32, f32, RoutingDecision)> {
        let mut results: Vec<_> = candidates
            .into_iter()
            .map(|(endpoint, value, cost)| {
                let roi = self.calculate_roi(value, cost);
                let decision = self.route_query(roi);
                (endpoint, value, cost, roi, decision)
            })
            .collect();
        
        // Sort by ROI descending
        results.sort_by(|a, b| b.3.partial_cmp(&a.3).unwrap_or(std::cmp::Ordering::Equal));
        results
    }

    /// Get execution sequence based on priorities
    pub fn get_execution_sequence(
        &self,
        candidates: Vec<(String, f32, f32)>,
    ) -> (Vec<String>, Vec<String>, Vec<String>, Vec<String>) {
        let prioritized = self.prioritize_queries(candidates);
        
        let mut execute_first = Vec::new();
        let mut execute_if_budget = Vec::new();
        let mut execute_if_time = Vec::new();
        let mut execute_if_requested = Vec::new();
        
        for (endpoint, _, _, roi, decision) in prioritized {
            match decision {
                RoutingDecision::ExecuteFirst => execute_first.push(endpoint),
                RoutingDecision::ExecuteIfBudget => execute_if_budget.push(endpoint),
                RoutingDecision::ExecuteIfTime => execute_if_time.push(endpoint),
                RoutingDecision::ExecuteIfRequested => execute_if_requested.push(endpoint),
                RoutingDecision::Skip => {}, // Don't add to any list
            }
        }
        
        (execute_first, execute_if_budget, execute_if_time, execute_if_requested)
    }

    /// Estimate total cost of execution sequence
    pub fn estimate_sequence_cost(&self, sequence: &[(String, f32)]) -> f32 {
        sequence.iter().map(|(_, cost)| cost).sum()
    }
}

impl Default for RoiRouter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roi_calculation() {
        let router = RoiRouter::new();
        
        assert_eq!(router.calculate_roi(85.0, 1.0), 85.0);
        assert_eq!(router.calculate_roi(50.0, 2.0), 25.0);
        assert_eq!(router.calculate_roi(100.0, 0.0), 100.0); // Free query
    }

    #[test]
    fn test_routing_decision() {
        let router = RoiRouter::new();
        
        assert_eq!(router.route_query(60.0), RoutingDecision::ExecuteFirst);
        assert_eq!(router.route_query(30.0), RoutingDecision::ExecuteIfBudget);
        assert_eq!(router.route_query(15.0), RoutingDecision::ExecuteIfTime);
        assert_eq!(router.route_query(7.0), RoutingDecision::ExecuteIfRequested);
        assert_eq!(router.route_query(3.0), RoutingDecision::Skip);
    }

    #[test]
    fn test_routing_decision_as_str() {
        assert_eq!(RoutingDecision::ExecuteFirst.as_str(), "ExecuteFirst");
        assert_eq!(RoutingDecision::Skip.as_str(), "Skip");
    }

    #[test]
    fn test_routing_decision_should_execute() {
        assert!(RoutingDecision::ExecuteFirst.should_execute());
        assert!(RoutingDecision::ExecuteIfBudget.should_execute());
        assert!(!RoutingDecision::Skip.should_execute());
    }

    #[test]
    fn test_prioritize_queries() {
        let router = RoiRouter::new();
        
        let candidates = vec![
            ("/search".to_string(), 85.0, 1.0),              // ROI: 85
            ("/username/social".to_string(), 50.0, 2.0),    // ROI: 25
            ("/search/deep".to_string(), 95.0, 3.0),        // ROI: 31.67
        ];
        
        let results = router.prioritize_queries(candidates);
        
        // Should be sorted by ROI descending: /search (85) > /search/deep (31.67) > /username/social (25)
        assert_eq!(results[0].0, "/search");
        assert_eq!(results[1].0, "/search/deep");
        assert_eq!(results[2].0, "/username/social");
    }

    #[test]
    fn test_execution_sequence() {
        let router = RoiRouter::new();
        
        let candidates = vec![
            ("/search".to_string(), 85.0, 1.0),
            ("/username/social".to_string(), 50.0, 2.0),
            ("/search/deep".to_string(), 95.0, 3.0),
        ];
        
        let (first, budget, time, requested) = router.get_execution_sequence(candidates);
        
        // First should have the high-ROI queries
        assert!(!first.is_empty());
        
        // Search (ROI 85) should be in first
        assert!(first.contains(&"/search".to_string()));
    }

    #[test]
    fn test_sequence_cost_estimation() {
        let router = RoiRouter::new();
        
        let sequence = vec![
            ("/search".to_string(), 1.0),
            ("/username/social".to_string(), 2.0),
        ];
        
        let total = router.estimate_sequence_cost(&sequence);
        assert_eq!(total, 3.0);
    }

    #[test]
    fn test_routing_decision_ordering() {
        // Test that routing decisions have correct ordering
        assert!(RoutingDecision::ExecuteFirst > RoutingDecision::ExecuteIfBudget);
        assert!(RoutingDecision::ExecuteIfBudget > RoutingDecision::ExecuteIfTime);
        assert!(RoutingDecision::ExecuteIfTime > RoutingDecision::ExecuteIfRequested);
        assert!(RoutingDecision::ExecuteIfRequested > RoutingDecision::Skip);
    }
}
