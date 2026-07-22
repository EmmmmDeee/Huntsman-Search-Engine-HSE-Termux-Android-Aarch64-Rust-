//! High-Value Query Optimization System
//!
//! Automatically identifies, prioritizes, and routes queries to maximize
//! information discovery per credit spent.
//!
//! Core components:
//! - value_scorer: Score queries on entity diversity, hit rate, pivot potential
//! - cost_analyzer: Calculate effective cost including credit, latency, cache
//! - roi_router: Route queries based on ROI (value/cost)
//! - cascade_optimizer: Intelligent cascade routing and depth allocation
//!
//! Integrated across all 4 phases with progressive sophistication.

pub mod value_scorer;
pub mod cost_analyzer;
pub mod roi_router;
pub mod cascade_optimizer;
pub mod query_planner;

use anyhow::Result;
use serde::{Deserialize, Serialize};

pub use query_planner::{ExecutionPlan, QueryPhase, QueryCandidate, QueryPlanner};

/// Query optimization result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizedQuery {
    pub endpoint: String,
    pub value_score: f32,
    pub effective_cost: f32,
    pub roi: f32,
    pub priority: u8,
    pub reasoning: String,
}

/// Query plan for multi-step optimization
#[derive(Debug, Clone)]
pub struct QueryPlan {
    pub steps: Vec<OptimizedQuery>,
    pub total_value: f32,
    pub total_cost: f32,
    pub overall_roi: f32,
    pub cascade_budget: u32,
}

impl QueryPlan {
    pub fn new() -> Self {
        Self {
            steps: Vec::new(),
            total_value: 0.0,
            total_cost: 0.0,
            overall_roi: 0.0,
            cascade_budget: 0,
        }
    }
}

impl Default for QueryPlan {
    fn default() -> Self {
        Self::new()
    }
}

/// Main optimizer interface
pub struct QueryOptimizer {
    value_scorer: value_scorer::ValueScorer,
    cost_analyzer: cost_analyzer::CostAnalyzer,
    roi_router: roi_router::RoiRouter,
    cascade_optimizer: cascade_optimizer::CascadeOptimizer,
    query_planner: QueryPlanner,
}

impl QueryOptimizer {
    pub fn new() -> Self {
        Self {
            value_scorer: value_scorer::ValueScorer::new(),
            cost_analyzer: cost_analyzer::CostAnalyzer::new(),
            roi_router: roi_router::RoiRouter::new(),
            cascade_optimizer: cascade_optimizer::CascadeOptimizer::new(),
            query_planner: QueryPlanner::new(),
        }
    }

    /// Generate optimal query sequence for a target
    pub fn optimize_query_sequence(
        &self,
        target_entity: &str,
        target_type: &str,
        budget: f32,
        time_budget_secs: f32,
        cascade_enabled: bool,
        max_depth: usize,
    ) -> ExecutionPlan {
        self.query_planner.generate_execution_plan(
            target_entity,
            target_type,
            budget,
            time_budget_secs,
            cascade_enabled,
            max_depth,
        )
    }

    /// Serialize execution plan to JSON
    pub fn serialize_plan(&self, plan: &ExecutionPlan) -> Result<String> {
        self.query_planner
            .serialize_plan(plan)
            .map_err(|e| anyhow::anyhow!("Failed to serialize plan: {}", e))
    }

    /// Deserialize execution plan from JSON
    pub fn deserialize_plan(&self, json: &str) -> Result<ExecutionPlan> {
        QueryPlanner::deserialize_plan(json)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize plan: {}", e))
    }

    /// Estimate total execution time for plan
    pub fn estimate_execution_time(&self, plan: &ExecutionPlan) -> f32 {
        self.query_planner.estimate_execution_time(plan)
    }

    /// Decide whether to cascade and which pivots to follow
    pub async fn should_cascade(
        &self,
        pivot_type: &str,
        cascade_depth: u8,
        budget_remaining: u32,
    ) -> Result<bool> {
        let roi_threshold = self
            .cascade_optimizer
            .get_roi_threshold_for_depth(cascade_depth as usize);
        // Return true if cascade ROI positive and budget sufficient
        Ok(budget_remaining >= 50 && roi_threshold < 100.0)
    }
}

impl Default for QueryOptimizer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_optimizer_initialization() {
        let optimizer = QueryOptimizer::new();
        // TODO: Add initialization tests
    }

    #[test]
    fn test_query_plan_creation() {
        let plan = QueryPlan::new();
        assert_eq!(plan.steps.len(), 0);
        assert_eq!(plan.total_roi, 0.0);
    }
}
