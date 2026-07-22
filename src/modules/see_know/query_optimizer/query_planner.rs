// src/modules/see_know/query_optimizer/query_planner.rs
// Query execution plan generation for autonomous See-Know operation
// Generates optimal query sequences based on value/cost ROI and cascade strategy

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::cascade_optimizer::{CascadeOptimizer, PivotTier};
use super::cost_analyzer::CostAnalyzer;
use super::roi_router::{RoiRouter, RoutingDecision};
use super::value_scorer::ValueScorer;
use crate::util::see_know::config;

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
        QueryPlanner {
            value_scorer: ValueScorer::new(),
            cost_analyzer: CostAnalyzer::new(),
            roi_router: RoiRouter::new(),
            cascade_optimizer: CascadeOptimizer::new(),
        }
    }

    /// Generate all viable query candidates for a target entity type
    pub fn generate_candidates(&self, target_type: &str) -> Vec<(&'static str, f32)> {
        match target_type.to_lowercase().as_str() {
            "email" => vec![
                ("/search", 85.0),
                ("/network/email-check", 65.0),
                ("/search/deep", 95.0),
            ],
            "username" => vec![
                ("/search", 50.0),
                ("/username/social", 75.0),
                ("/username/history", 40.0),
            ],
            "discord_id" => vec![
                ("/discord/user", 80.0),
                ("/search", 45.0),
            ],
            "phone" => vec![
                ("/network/phone-check", 60.0),
                ("/search", 30.0),
            ],
            "domain" => vec![
                ("/domain/info", 70.0),
                ("/search", 50.0),
                ("/domain/email-finder", 75.0),
            ],
            "ip_address" => vec![
                ("/network/ip", 65.0),
                ("/search", 40.0),
            ],
            "organization" => vec![
                ("/search", 55.0),
                ("/domain/info", 50.0),
            ],
            _ => vec![("/search", 50.0)],
        }
    }

    /// Build Phase 1 execution plan (direct queries only)
    pub fn plan_phase_1(
        &self,
        target_entity: &str,
        target_type: &str,
        budget: f32,
        time_budget: f32,
    ) -> QueryPhase {
        let candidates = self.generate_candidates(target_type);
        let mut phase_candidates = Vec::new();
        let mut phase_budget_used = 0.0;

        for (endpoint, base_value) in candidates {
            if phase_budget_used >= budget {
                break;
            }

            let value_analysis = self.value_scorer.score_endpoint(
                endpoint,
                target_type,
                false,
                None,
            );

            let cost_analysis = self.cost_analyzer.analyze_query(
                endpoint,
                15.0,
                1,
                None,
                budget - phase_budget_used,
                time_budget,
            );

            let roi = self.roi_router.calculate_roi(
                value_analysis.composite,
                cost_analysis.effective_cost,
            );

            let routing = self.roi_router.route_query(roi, 1);

            if routing.should_execute() {
                phase_candidates.push(QueryCandidate {
                    endpoint: endpoint.to_string(),
                    target_type: target_type.to_string(),
                    value_score: value_analysis.composite,
                    effective_cost: cost_analysis.effective_cost,
                    roi,
                    routing_decision: routing.as_str().to_string(),
                    reasoning: format!(
                        "Value: {:.1}, Cost: {:.2}c, ROI: {:.1} - {}",
                        value_analysis.composite,
                        cost_analysis.effective_cost,
                        roi,
                        value_analysis.reasoning
                    ),
                });

                phase_budget_used += cost_analysis.effective_cost;
            }
        }

        let total_value: f32 = phase_candidates.iter().map(|c| c.value_score).sum();
        let total_cost: f32 = phase_candidates.iter().map(|c| c.effective_cost).sum();

        QueryPhase {
            phase_number: 1,
            candidates: phase_candidates,
            total_value,
            total_cost,
            phase_budget: budget,
            reasoning: format!(
                "Phase 1 direct queries: {} candidates, {:.1} value, {:.2}c cost, {:.1} ROI",
                phase_candidates.len(),
                total_value,
                total_cost,
                if total_cost > 0.0 { total_value / total_cost } else { 0.0 }
            ),
        }
    }

    /// Build Phase 2 cascade plan (if cascades enabled)
    pub fn plan_phase_2(
        &self,
        discovered_pivots: Vec<(&str, &str)>,
        remaining_budget: f32,
        time_budget: f32,
        cascade_depth: usize,
    ) -> QueryPhase {
        let mut phase_candidates = Vec::new();
        let mut phase_budget_used = 0.0;
        let depth_budget = remaining_budget * config::BUDGET_DEPTH_2_RATIO;

        for (pivot_type, pivot_value) in discovered_pivots {
            if phase_budget_used >= depth_budget {
                break;
            }

            let tier = self
                .cascade_optimizer
                .classify_pivot_tier(pivot_type);

            let roi_threshold = self
                .cascade_optimizer
                .get_roi_threshold_for_depth(cascade_depth + 1);

            let candidates = self.generate_candidates(pivot_type);

            for (endpoint, _) in candidates {
                let value_analysis = self.value_scorer.score_endpoint(
                    endpoint,
                    pivot_type,
                    false,
                    None,
                );

                let cost_analysis = self.cost_analyzer.analyze_query(
                    endpoint,
                    15.0,
                    cascade_depth + 1,
                    None,
                    depth_budget - phase_budget_used,
                    time_budget,
                );

                let roi = self.roi_router.calculate_roi(
                    value_analysis.composite,
                    cost_analysis.effective_cost,
                );

                if roi >= roi_threshold && phase_budget_used + cost_analysis.effective_cost <= depth_budget {
                    let cascade_decision = self.cascade_optimizer.should_cascade(
                        pivot_type,
                        roi,
                        (depth_budget - phase_budget_used) as i32,
                        time_budget as i32,
                        cascade_depth + 1,
                    );

                    if cascade_decision.should_cascade {
                        phase_candidates.push(QueryCandidate {
                            endpoint: endpoint.to_string(),
                            target_type: pivot_type.to_string(),
                            value_score: value_analysis.composite,
                            effective_cost: cost_analysis.effective_cost,
                            roi,
                            routing_decision: format!("{:?} pivot", tier),
                            reasoning: format!(
                                "Cascade from {}: Value {:.1}, ROI {:.1} - {}",
                                pivot_value, value_analysis.composite, roi, cascade_decision.reasoning
                            ),
                        });

                        phase_budget_used += cost_analysis.effective_cost;
                    }
                }
            }
        }

        let total_value: f32 = phase_candidates.iter().map(|c| c.value_score).sum();
        let total_cost: f32 = phase_candidates.iter().map(|c| c.effective_cost).sum();

        QueryPhase {
            phase_number: 2,
            candidates: phase_candidates,
            total_value,
            total_cost,
            phase_budget: depth_budget,
            reasoning: format!(
                "Phase 2 cascades (depth {}): {} candidates, {:.1} value, {:.2}c cost",
                cascade_depth + 1,
                phase_candidates.len(),
                total_cost
            ),
        }
    }

    /// Generate complete execution plan for autonomous operation
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

        let phase_1 = self.plan_phase_1(target_entity, target_type, budget, time_budget);
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

                let phase_n = self.plan_phase_2(
                    discovered_pivots.clone(),
                    budget - total_cost,
                    time_budget,
                    depth,
                );

                if phase_n.candidates.is_empty() {
                    break;
                }

                total_value += phase_n.total_value;
                total_cost += phase_n.total_cost;
                phases.push(phase_n);
            }
        }

        ExecutionPlan {
            target_entity: target_entity.to_string(),
            target_type: target_type.to_string(),
            total_budget: budget,
            time_budget_seconds: time_budget,
            phases,
            total_planned_value: total_value,
            total_planned_cost: total_cost,
            estimated_roi: if total_cost > 0.0 {
                total_value / total_cost
            } else {
                0.0
            },
            autonomous_mode: true,
            cascading_enabled,
            max_cascade_depth: max_depth,
            plan_reasoning: format!(
                "Complete plan for {} ({}): {} phases, {:.1} value, {:.2}c cost, {:.1} ROI",
                target_entity,
                target_type,
                phases.len(),
                total_value,
                total_cost,
                if total_cost > 0.0 { total_value / total_cost } else { 0.0 }
            ),
        }
    }

    /// Estimate total execution time for plan
    pub fn estimate_execution_time(&self, plan: &ExecutionPlan) -> f32 {
        plan.phases
            .iter()
            .map(|phase| {
                phase
                    .candidates
                    .iter()
                    .map(|c| {
                        if c.endpoint.contains("deep") {
                            30.0
                        } else {
                            10.0
                        }
                    })
                    .sum::<f32>()
            })
            .sum()
    }

    /// Serialize plan to JSON for Termux storage
    pub fn serialize_plan(&self, plan: &ExecutionPlan) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(plan)
    }

    /// Deserialize plan from JSON
    pub fn deserialize_plan(json: &str) -> Result<ExecutionPlan, serde_json::Error> {
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
        assert!(!candidates.is_empty());
        assert!(candidates.iter().any(|(ep, _)| ep.contains("search")));
    }

    #[test]
    fn test_generate_candidates_username() {
        let planner = QueryPlanner::new();
        let candidates = planner.generate_candidates("username");
        assert!(candidates.len() >= 2);
    }

    #[test]
    fn test_plan_phase_1() {
        let planner = QueryPlanner::new();
        let phase = planner.plan_phase_1("test@example.com", "email", 500.0, 300.0);
        assert!(!phase.candidates.is_empty());
        assert!(phase.total_cost <= 500.0);
    }

    #[test]
    fn test_execution_plan_generation() {
        let planner = QueryPlanner::new();
        let plan = planner.generate_execution_plan(
            "test@example.com",
            "email",
            1000.0,
            600.0,
            true,
            3,
        );
        assert_eq!(plan.target_type, "email");
        assert!(plan.total_planned_cost <= plan.total_budget);
    }

    #[test]
    fn test_plan_serialization() {
        let planner = QueryPlanner::new();
        let plan = planner.generate_execution_plan(
            "test@example.com",
            "email",
            500.0,
            300.0,
            false,
            1,
        );
        let json = planner.serialize_plan(&plan).unwrap();
        assert!(json.contains("test@example.com"));

        let deserialized = QueryPlanner::deserialize_plan(&json).unwrap();
        assert_eq!(deserialized.target_entity, plan.target_entity);
    }

    #[test]
    fn test_estimate_execution_time() {
        let planner = QueryPlanner::new();
        let plan = planner.generate_execution_plan(
            "testuser",
            "username",
            300.0,
            200.0,
            false,
            1,
        );
        let time = planner.estimate_execution_time(&plan);
        assert!(time > 0.0);
    }

    #[test]
    fn test_cascade_phase_planning() {
        let planner = QueryPlanner::new();
        let phase = planner.plan_phase_2(
            vec![("discord_id", "123456789"), ("email", "user@test.com")],
            300.0,
            200.0,
            1,
        );
        assert_eq!(phase.phase_number, 2);
    }

    #[test]
    fn test_plan_respects_budget() {
        let planner = QueryPlanner::new();
        let plan = planner.generate_execution_plan(
            "target",
            "email",
            100.0,
            300.0,
            true,
            3,
        );
        assert!(plan.total_planned_cost <= plan.total_budget);
    }

    #[test]
    fn test_plan_roi_calculation() {
        let planner = QueryPlanner::new();
        let plan = planner.generate_execution_plan(
            "complex_target",
            "email",
            2500.0,
            600.0,
            true,
            3,
        );
        if plan.total_planned_cost > 0.0 {
            assert!(plan.estimated_roi >= 0.0);
        }
    }
}
