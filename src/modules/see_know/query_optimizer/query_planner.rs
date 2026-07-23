//! Query execution plan generation for autonomous See-Know operation.
//!
//! Generates optimal, multi-phase query sequences by combining the value
//! scorer, cost analyzer, ROI router and cascade optimizer. Plans serialize to
//! JSON for local storage on Termux (autonomous, resumable operation).

use serde::{Deserialize, Serialize};

use super::cascade_optimizer::CascadeOptimizer;
use super::cost_analyzer::CostAnalyzer;
use super::roi_router::RoiRouter;
use super::value_scorer::ValueScorer;
use crate::util::see_know::config;

/// Default assumed latency (ms) when planning before any live timing exists.
const PLAN_LATENCY_MS: u32 = 15_000;
/// Default per-query specificity assumption during planning (0.0-1.0).
const PLAN_SPECIFICITY: f32 = 0.8;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryCandidate {
    pub endpoint: String,
    pub target_type: String,
    pub value_score: f32,
    pub effective_cost: f32,
    pub roi: f32,
    pub routing_decision: String,
    pub reasoning: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryPhase {
    pub phase_number: usize,
    pub candidates: Vec<QueryCandidate>,
    pub total_value: f32,
    pub total_cost: f32,
    pub phase_budget: f32,
    pub reasoning: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionPlan {
    pub target_entity: String,
    pub target_type: String,
    pub total_budget: f32,
    pub time_budget_seconds: f32,
    pub phases: Vec<QueryPhase>,
    pub total_planned_value: f32,
    pub total_planned_cost: f32,
    pub estimated_roi: f32,
    pub autonomous_mode: bool,
    pub cascading_enabled: bool,
    pub max_cascade_depth: usize,
    pub plan_reasoning: String,
}

pub struct QueryPlanner {
    value_scorer: ValueScorer,
    cost_analyzer: CostAnalyzer,
    roi_router: RoiRouter,
    cascade_optimizer: CascadeOptimizer,
}

impl QueryPlanner {
    pub fn new() -> Self {
        Self {
            value_scorer: ValueScorer::new(),
            cost_analyzer: CostAnalyzer::new(),
            roi_router: RoiRouter::new(),
            cascade_optimizer: CascadeOptimizer::new(),
        }
    }

    /// Generate all viable query candidates for a target entity type.
    pub fn generate_candidates(&self, target_type: &str) -> Vec<&'static str> {
        match target_type.to_lowercase().as_str() {
            "email" => vec!["/search", "/network/email-check", "/search/deep"],
            "username" => vec!["/search", "/username/social", "/username/history"],
            "discord_id" => vec!["/discord/user", "/search"],
            "phone" => vec!["/network/phone", "/search"],
            "domain" => vec!["/domain/intel", "/domain/whois", "/search"],
            "ip_address" | "ip" => vec!["/network/ip", "/search"],
            "organization" => vec!["/search", "/domain/intel"],
            _ => vec!["/search"],
        }
    }

    /// Build Phase 1 execution plan (direct queries only).
    pub fn plan_phase_1(&self, target_type: &str, budget: f32, time_budget: f32) -> QueryPhase {
        let mut phase_candidates = Vec::new();
        let mut budget_used = 0.0_f32;

        for endpoint in self.generate_candidates(target_type) {
            if budget_used >= budget {
                break;
            }

            let remaining_budget = (budget - budget_used).max(0.0) as u32;
            let value = self.value_scorer.calculate_composite_value(
                endpoint,
                target_type,
                None,
                PLAN_SPECIFICITY,
            );
            let cost = self.cost_analyzer.calculate_effective_cost(
                endpoint,
                1,
                None,
                PLAN_LATENCY_MS,
                time_budget as u32,
                remaining_budget,
            );
            let roi = self
                .roi_router
                .calculate_roi(value.composite, cost.effective_cost);
            let routing = self.roi_router.route_query(roi);

            if routing.should_execute() {
                phase_candidates.push(QueryCandidate {
                    endpoint: endpoint.to_string(),
                    target_type: target_type.to_string(),
                    value_score: value.composite,
                    effective_cost: cost.effective_cost,
                    roi,
                    routing_decision: routing.as_str().to_string(),
                    reasoning: format!(
                        "Value {:.1}, Cost {:.2}c, ROI {:.1} — {}",
                        value.composite, cost.effective_cost, roi, value.reasoning
                    ),
                });
                budget_used += cost.effective_cost;
            }
        }

        Self::finalize_phase(1, phase_candidates, budget)
    }

    /// Build a cascade phase from discovered pivots at a given depth.
    pub fn plan_cascade_phase(
        &self,
        discovered_pivots: &[(&str, &str)],
        remaining_budget: f32,
        time_budget: f32,
        cascade_depth: usize,
    ) -> QueryPhase {
        let mut phase_candidates = Vec::new();
        let mut budget_used = 0.0_f32;
        let depth_budget = remaining_budget * config::BUDGET_DEPTH_2_RATIO;
        let next_depth = (cascade_depth + 1) as u8;
        let roi_threshold = self
            .cascade_optimizer
            .get_roi_threshold_for_depth(next_depth);

        for (pivot_type, pivot_value) in discovered_pivots {
            if budget_used >= depth_budget {
                break;
            }
            let tier = self.cascade_optimizer.classify_pivot_tier(pivot_type);

            for endpoint in self.generate_candidates(pivot_type) {
                let remaining = (depth_budget - budget_used).max(0.0);
                let value = self.value_scorer.calculate_composite_value(
                    endpoint,
                    pivot_type,
                    None,
                    PLAN_SPECIFICITY,
                );
                let cost = self.cost_analyzer.calculate_effective_cost(
                    endpoint,
                    next_depth,
                    None,
                    PLAN_LATENCY_MS,
                    time_budget as u32,
                    remaining as u32,
                );
                let roi = self
                    .roi_router
                    .calculate_roi(value.composite, cost.effective_cost);

                if roi >= roi_threshold && budget_used + cost.effective_cost <= depth_budget {
                    let decision = self.cascade_optimizer.should_cascade(
                        tier,
                        roi,
                        next_depth,
                        remaining as u32,
                        time_budget as u32,
                    );
                    if decision.should_cascade {
                        phase_candidates.push(QueryCandidate {
                            endpoint: endpoint.to_string(),
                            target_type: pivot_type.to_string(),
                            value_score: value.composite,
                            effective_cost: cost.effective_cost,
                            roi,
                            routing_decision: format!("{tier:?} pivot"),
                            reasoning: format!(
                                "Cascade from {} ({:?}): Value {:.1}, ROI {:.1} — {}",
                                pivot_value, tier, value.composite, roi, decision.reasoning
                            ),
                        });
                        budget_used += cost.effective_cost;
                    }
                }
            }
        }

        Self::finalize_phase(cascade_depth + 1, phase_candidates, depth_budget)
    }

    fn finalize_phase(
        phase_number: usize,
        candidates: Vec<QueryCandidate>,
        phase_budget: f32,
    ) -> QueryPhase {
        let total_value: f32 = candidates.iter().map(|c| c.value_score).sum();
        let total_cost: f32 = candidates.iter().map(|c| c.effective_cost).sum();
        let roi = if total_cost > 0.0 {
            total_value / total_cost
        } else {
            0.0
        };
        QueryPhase {
            phase_number,
            reasoning: format!(
                "Phase {}: {} candidates, {:.1} value, {:.2}c cost, {:.1} ROI",
                phase_number,
                candidates.len(),
                total_value,
                total_cost,
                roi
            ),
            candidates,
            total_value,
            total_cost,
            phase_budget,
        }
    }

    /// Generate a complete multi-phase execution plan for autonomous operation.
    pub fn generate_execution_plan(
        &self,
        target_entity: &str,
        target_type: &str,
        budget: f32,
        time_budget: f32,
        cascading_enabled: bool,
        max_depth: usize,
    ) -> ExecutionPlan {
        let mut phases = Vec::new();
        let mut total_value = 0.0;
        let mut total_cost = 0.0;

        let phase_1 = self.plan_phase_1(target_type, budget, time_budget);
        total_value += phase_1.total_value;
        total_cost += phase_1.total_cost;
        phases.push(phase_1);

        if cascading_enabled && budget - total_cost > 50.0 && max_depth > 1 {
            let discovered_pivots = vec![
                ("discord_id", target_entity),
                ("email", target_entity),
                ("username", target_entity),
            ];

            for depth in 1..max_depth {
                if total_cost >= budget * 0.95 {
                    break;
                }
                let phase = self.plan_cascade_phase(
                    &discovered_pivots,
                    budget - total_cost,
                    time_budget,
                    depth,
                );
                if phase.candidates.is_empty() {
                    break;
                }
                total_value += phase.total_value;
                total_cost += phase.total_cost;
                phases.push(phase);
            }
        }

        let estimated_roi = if total_cost > 0.0 {
            total_value / total_cost
        } else {
            0.0
        };
        ExecutionPlan {
            target_entity: target_entity.to_string(),
            target_type: target_type.to_string(),
            total_budget: budget,
            time_budget_seconds: time_budget,
            plan_reasoning: format!(
                "Plan for {} ({}): {} phases, {:.1} value, {:.2}c cost, {:.1} ROI",
                target_entity,
                target_type,
                phases.len(),
                total_value,
                total_cost,
                estimated_roi
            ),
            phases,
            total_planned_value: total_value,
            total_planned_cost: total_cost,
            estimated_roi,
            autonomous_mode: true,
            cascading_enabled,
            max_cascade_depth: max_depth,
        }
    }

    /// Estimate total execution time (seconds) for a plan.
    pub fn estimate_execution_time(&self, plan: &ExecutionPlan) -> f32 {
        plan.phases
            .iter()
            .flat_map(|phase| phase.candidates.iter())
            .map(|c| {
                if c.endpoint.contains("deep") {
                    30.0
                } else {
                    10.0
                }
            })
            .sum()
    }

    /// Serialize a plan to pretty JSON for Termux storage.
    pub fn serialize_plan(&self, plan: &ExecutionPlan) -> serde_json::Result<String> {
        serde_json::to_string_pretty(plan)
    }

    /// Deserialize a plan from JSON.
    pub fn deserialize_plan(json: &str) -> serde_json::Result<ExecutionPlan> {
        serde_json::from_str(json)
    }
}

impl Default for QueryPlanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_candidates_email() {
        let planner = QueryPlanner::new();
        let candidates = planner.generate_candidates("email");
        assert!(candidates.iter().any(|ep| ep.contains("search")));
    }

    #[test]
    fn test_generate_candidates_username() {
        let planner = QueryPlanner::new();
        assert!(planner.generate_candidates("username").len() >= 2);
    }

    #[test]
    fn test_plan_phase_1() {
        let planner = QueryPlanner::new();
        let phase = planner.plan_phase_1("email", 500.0, 300.0);
        assert_eq!(phase.phase_number, 1);
        assert!(phase.total_cost <= 500.0);
    }

    #[test]
    fn test_execution_plan_generation() {
        let planner = QueryPlanner::new();
        let plan =
            planner.generate_execution_plan("test@example.com", "email", 1000.0, 600.0, true, 3);
        assert_eq!(plan.target_type, "email");
        assert!(plan.total_planned_cost <= plan.total_budget);
    }

    #[test]
    fn test_plan_serialization_roundtrip() {
        let planner = QueryPlanner::new();
        let plan =
            planner.generate_execution_plan("test@example.com", "email", 500.0, 300.0, false, 1);
        let json = planner.serialize_plan(&plan).unwrap();
        assert!(json.contains("test@example.com"));
        let back = QueryPlanner::deserialize_plan(&json).unwrap();
        assert_eq!(back.target_entity, plan.target_entity);
    }

    #[test]
    fn test_estimate_execution_time() {
        let planner = QueryPlanner::new();
        let plan = planner.generate_execution_plan("testuser", "username", 300.0, 200.0, false, 1);
        assert!(planner.estimate_execution_time(&plan) > 0.0);
    }

    #[test]
    fn test_cascade_phase_planning() {
        let planner = QueryPlanner::new();
        let phase = planner.plan_cascade_phase(
            &[("discord_id", "123456789"), ("email", "user@test.com")],
            300.0,
            200.0,
            1,
        );
        assert_eq!(phase.phase_number, 2);
    }

    #[test]
    fn test_plan_respects_budget() {
        let planner = QueryPlanner::new();
        let plan = planner.generate_execution_plan("target", "email", 100.0, 300.0, true, 3);
        assert!(plan.total_planned_cost <= plan.total_budget);
    }

    #[test]
    fn test_plan_roi_non_negative() {
        let planner = QueryPlanner::new();
        let plan =
            planner.generate_execution_plan("complex_target", "email", 2500.0, 600.0, true, 3);
        assert!(plan.estimated_roi >= 0.0);
    }
}
