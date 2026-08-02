//! Cost analysis for queries - COMPLETE IMPLEMENTATION
//!
//! Calculates effective cost including:
//! - Direct credit cost
//! - Latency cost (time-adjusted)
//! - Cascade cost (depth multiplier)
//! - Cache benefit (discount)

use crate::util::see_know::config;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CostAnalysis {
    pub direct_credit_cost: f32,
    pub latency_cost: f32,
    pub cascade_cost_multiplier: f32,
    pub cache_benefit_discount: f32,
    pub effective_cost: f32,
    pub reasoning: String,
}

pub struct CostAnalyzer;

impl CostAnalyzer {
    pub fn new() -> Self {
        Self
    }

    /// Get direct credit cost for endpoint
    pub fn get_credit_cost(&self, endpoint: &str) -> f32 {
        config::get_endpoint_cost(endpoint)
    }

    /// Calculate latency cost (time-adjusted, 0-5 points)
    pub fn calculate_latency_cost(
        &self,
        latency_ms: u32,
        remaining_time_secs: u32,
        _total_time_budget: u32,
    ) -> f32 {
        let latency_secs = latency_ms as f32 / 1000.0;

        // Latency score points
        let latency_points = match latency_secs {
            l if l < 5.0 => 1.0,  // Fast: <5s
            l if l < 15.0 => 3.0, // Standard: 5-15s
            l if l < 45.0 => 5.0, // Deep: 15-45s
            _ => 8.0,             // Very slow: >45s
        };

        // Adjust by remaining time budget (if tight, penalize slow queries)
        let time_stress = if remaining_time_secs < 60 {
            2.0 // Time-stressed: double penalty
        } else if remaining_time_secs < 300 {
            1.5 // Moderately time-stressed
        } else {
            1.0 // Plenty of time
        };

        latency_points * time_stress
    }

    /// Get cascade cost multiplier by depth
    pub fn get_cascade_multiplier(&self, cascade_depth: u8) -> f32 {
        match cascade_depth {
            1 => 1.0,  // No cascade overhead
            2 => 2.5,  // Secondary queries
            3 => 5.0,  // Tertiary queries
            4 => 10.0, // Quaternary queries
            _ => 20.0, // Beyond 4 hops
        }
    }

    /// Get cache benefit discount by age
    pub fn get_cache_discount(&self, cache_age_hours: Option<f32>) -> f32 {
        match cache_age_hours {
            None => 1.0,                    // Cache miss: full price
            Some(age) if age < 1.0 => 0.1,  // Fresh (<1h): 10% of cost
            Some(age) if age < 6.0 => 0.3,  // Recent (1-6h): 30% of cost
            Some(age) if age < 12.0 => 0.5, // Moderate (6-12h): 50% of cost
            Some(age) if age < 24.0 => 0.7, // Aging (12-24h): 70% of cost
            Some(_) => 0.9,                 // Stale (>24h): 90% of cost
        }
    }

    /// Calculate effective cost for query (COMPLETE IMPLEMENTATION)
    pub fn calculate_effective_cost(
        &self,
        endpoint: &str,
        cascade_depth: u8,
        cache_age: Option<f32>,
        latency_ms: u32,
        remaining_time: u32,
        remaining_budget: u32,
    ) -> CostAnalysis {
        let credit_cost = self.get_credit_cost(endpoint);
        let latency_cost = self.calculate_latency_cost(latency_ms, remaining_time, 3600);
        let cascade_mult = self.get_cascade_multiplier(cascade_depth);
        let cache_discount = self.get_cache_discount(cache_age);

        // Effective cost formula:
        // (CreditCost + LatencyCost*0.15 + CascadeMultiplier*0.8) * CacheDiscount
        let effective =
            (credit_cost + (latency_cost * 0.15) + (cascade_mult * 0.8)) * cache_discount;

        // Budget pressure adjustment (if running low, penalize expensive queries)
        let budget_pressure = if remaining_budget < 50 {
            1.5 // Desperate: 50% cost increase
        } else if remaining_budget < 200 {
            1.2 // Low budget: 20% cost increase
        } else {
            1.0 // Plenty of budget
        };

        let final_cost = effective * budget_pressure;

        let reasoning = format!(
            "Credit: {credit_cost:.1} + Latency: {latency_cost:.2}*0.15 + Cascade: {cascade_mult:.1}*0.8 = {effective:.2} × Cache: {cache_discount:.1} × Budget: {budget_pressure:.1} = {final_cost:.2} effective credits"
        );

        CostAnalysis {
            direct_credit_cost: credit_cost,
            latency_cost,
            cascade_cost_multiplier: cascade_mult,
            cache_benefit_discount: cache_discount,
            effective_cost: final_cost,
            reasoning,
        }
    }
}

impl Default for CostAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credit_costs() {
        let analyzer = CostAnalyzer::new();
        assert_eq!(analyzer.get_credit_cost("/search"), 1.0);
        assert_eq!(analyzer.get_credit_cost("/search/deep"), 3.0);
        assert_eq!(analyzer.get_credit_cost("/enterprise/discord/history"), 5.0);
        assert_eq!(analyzer.get_credit_cost("/credits"), 0.0);
    }

    #[test]
    fn test_latency_cost_calculation() {
        let analyzer = CostAnalyzer::new();

        // Fast query: <5s
        let fast = analyzer.calculate_latency_cost(3000, 3600, 3600);
        assert_eq!(fast, 1.0);

        // Standard query: 10s
        let standard = analyzer.calculate_latency_cost(10000, 3600, 3600);
        assert_eq!(standard, 3.0);

        // Deep query: 30s
        let deep = analyzer.calculate_latency_cost(30000, 3600, 3600);
        assert_eq!(deep, 5.0);
    }

    #[test]
    fn test_cascade_multipliers() {
        let analyzer = CostAnalyzer::new();
        assert_eq!(analyzer.get_cascade_multiplier(1), 1.0);
        assert_eq!(analyzer.get_cascade_multiplier(2), 2.5);
        assert_eq!(analyzer.get_cascade_multiplier(3), 5.0);
        assert_eq!(analyzer.get_cascade_multiplier(4), 10.0);
    }

    #[test]
    fn test_cache_discount() {
        let analyzer = CostAnalyzer::new();

        // Miss: full price
        assert_eq!(analyzer.get_cache_discount(None), 1.0);

        // Fresh: 10%
        assert_eq!(analyzer.get_cache_discount(Some(0.5)), 0.1);

        // Stale: 90%
        assert_eq!(analyzer.get_cache_discount(Some(25.0)), 0.9);
    }

    #[test]
    fn test_effective_cost_calculation() {
        let analyzer = CostAnalyzer::new();

        let cost = analyzer.calculate_effective_cost(
            "/search", // 1 credit
            1,         // Depth 1
            None,      // Cache miss
            5000,      // 5s latency
            3600,      // Plenty of time
            1000,      // Plenty of budget
        );

        // (1 + 3*0.15 + 1*0.8) * 1.0 = 1.65
        assert!(cost.effective_cost > 1.0);
        assert!(cost.effective_cost < 2.5);
    }

    #[test]
    fn test_cache_benefit_cheap() {
        let analyzer = CostAnalyzer::new();

        let cost = analyzer.calculate_effective_cost(
            "/search",
            1,
            Some(0.5), // Fresh cache
            5000,
            3600,
            1000,
        );

        // Should be much cheaper with fresh cache
        assert!(cost.effective_cost < 0.5);
    }

    #[test]
    fn test_budget_pressure() {
        let analyzer = CostAnalyzer::new();

        // Plenty of budget
        let plenty = analyzer.calculate_effective_cost("/search", 1, None, 5000, 3600, 1000);

        // Low budget (50 credits left)
        let low = analyzer.calculate_effective_cost("/search", 1, None, 5000, 3600, 50);

        // Low budget should be more expensive (1.5x multiplier)
        assert!(low.effective_cost > plenty.effective_cost);
    }
}
