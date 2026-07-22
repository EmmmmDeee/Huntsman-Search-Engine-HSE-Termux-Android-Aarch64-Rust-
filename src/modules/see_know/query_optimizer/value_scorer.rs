//! Value scoring for queries
//!
//! Assigns value to each query based on:
//! - Entity diversity (how many types discovered)
//! - Hit rate (likelihood of finding data)
//! - Pivot potential (enables cascades)
//! - Freshness (cache age)
//! - Coverage (vs. alternatives)

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValueScore {
    pub entity_diversity: f32,
    pub hit_rate: f32,
    pub pivot_potential: f32,
    pub freshness: f32,
    pub coverage: f32,
    pub composite: f32,
}

pub struct ValueScorer;

impl ValueScorer {
    pub fn new() -> Self {
        Self
    }

    /// Score query on entity diversity
    /// Phase 1.1+
    pub fn score_entity_diversity(&self, endpoint: &str) -> f32 {
        // TODO: Phase 1.1
        // Map endpoint to entity count
        // /search → 17 types → 100
        // /username/social → 3 types → 30
        // etc.
        0.0
    }

    /// Score query on historical hit rate
    /// Phase 1.1+
    pub fn score_hit_rate(&self, endpoint: &str, target_type: &str, target_specificity: f32) -> f32 {
        // TODO: Phase 1.1
        // Learn from historical queries
        // email with breach history: high hit rate
        // random email: low hit rate
        0.0
    }

    /// Score query on cascade potential
    /// Phase 2.1+
    pub fn score_pivot_potential(&self, endpoint: &str) -> f32 {
        // TODO: Phase 2.1
        // /discord/user → Can pivot to Roblox/Steam → 80
        // /network/email-check → Can pivot to services → 75
        // /username/history → Limited cascade → 20
        0.0
    }

    /// Score based on cache age
    /// Phase 1.2+
    pub fn score_freshness(&self, cache_age_hours: Option<f32>) -> f32 {
        // TODO: Phase 1.2
        // None (miss) → 100
        // <6h → 80
        // 6-12h → 60
        // 12-24h → 30
        0.0
    }

    /// Score query coverage vs. alternatives
    /// Phase 1.1+
    pub fn score_coverage(&self, endpoint: &str, target_type: &str) -> f32 {
        // TODO: Phase 1.1
        // Primary endpoint: 100
        // Secondary endpoint: 50
        // Fallback endpoint: 25
        0.0
    }

    /// Calculate composite value score
    /// Phase 1.1+
    pub fn calculate_composite_value(
        &self,
        endpoint: &str,
        target_type: &str,
        cache_age: Option<f32>,
    ) -> ValueScore {
        // TODO: Phase 1.1
        // Weighted average of all dimensions
        ValueScore {
            entity_diversity: self.score_entity_diversity(endpoint),
            hit_rate: self.score_hit_rate(endpoint, target_type, 0.7),
            pivot_potential: self.score_pivot_potential(endpoint),
            freshness: self.score_freshness(cache_age),
            coverage: self.score_coverage(endpoint, target_type),
            composite: 0.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entity_diversity_scoring() {
        // TODO: Phase 1.1
    }

    #[test]
    fn test_hit_rate_scoring() {
        // TODO: Phase 1.1
    }

    #[test]
    fn test_composite_value_calculation() {
        // TODO: Phase 1.1
        // Verify weighted average calculation
    }
}
