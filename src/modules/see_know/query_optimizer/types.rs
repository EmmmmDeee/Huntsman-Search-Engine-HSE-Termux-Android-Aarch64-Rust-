// src/modules/see_know/query_optimizer/types.rs
// Shared types and traits for the HVQS system - refactored for reusability

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Generic score trait for all scoring dimensions
pub trait Score: Serialize {
    fn value(&self) -> f32;
    fn is_valid(&self) -> bool {
        let v = self.value();
        v >= 0.0 && v <= 100.0
    }
}

/// Analysis result with reasoning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Analysis<T: Score> {
    pub result: T,
    pub reasoning: String,
}

impl<T: Score> Analysis<T> {
    pub fn new(result: T, reasoning: impl Into<String>) -> Self {
        Self {
            result,
            reasoning: reasoning.into(),
        }
    }
}

/// Composite scoring dimensions
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct DimensionalScore {
    pub dimension: f32, // 0-100
}

impl Score for DimensionalScore {
    fn value(&self) -> f32 {
        self.dimension
    }
}

/// Weighted composite score
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct CompositeScore {
    pub value: f32, // 0-100
    pub components: usize,
}

impl Score for CompositeScore {
    fn value(&self) -> f32 {
        self.value
    }
}

/// Query routing decision
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
pub enum RoutingPriority {
    Skip = 0,
    ExecuteIfRequested = 1,
    ExecuteIfTime = 2,
    ExecuteIfBudget = 3,
    ExecuteFirst = 4,
}

impl RoutingPriority {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Skip => "Skip",
            Self::ExecuteIfRequested => "ExecuteIfRequested",
            Self::ExecuteIfTime => "ExecuteIfTime",
            Self::ExecuteIfBudget => "ExecuteIfBudget",
            Self::ExecuteFirst => "ExecuteFirst",
        }
    }

    pub fn should_execute(&self) -> bool {
        *self as u8 > 0
    }
}

/// Cascade tier classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CascadeTier {
    Tier1,
    Tier2,
    Tier3,
    None,
}

impl CascadeTier {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Tier1 => "Tier1",
            Self::Tier2 => "Tier2",
            Self::Tier3 => "Tier3",
            Self::None => "None",
        }
    }
}

/// Endpoint metadata (pre-computed, centralized)
#[derive(Debug, Clone)]
pub struct EndpointMetadata {
    pub entity_type_count: usize,
    pub base_credit_cost: f32,
    pub typical_latency_seconds: f32,
    pub pivot_potential_score: f32,
    pub coverage_tier: CoverageTier,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverageTier {
    Primary,   // 100 points
    Secondary, // 50 points
    Tertiary,  // 25 points
}

impl CoverageTier {
    pub fn score(&self) -> f32 {
        match self {
            Self::Primary => 100.0,
            Self::Secondary => 50.0,
            Self::Tertiary => 25.0,
        }
    }
}

/// Endpoint registry - centralized metadata
pub struct EndpointRegistry {
    metadata: HashMap<String, EndpointMetadata>,
}

impl EndpointRegistry {
    pub fn new() -> Self {
        let mut metadata = HashMap::new();

        // Search endpoints
        metadata.insert(
            "/search".to_string(),
            EndpointMetadata {
                entity_type_count: 17,
                base_credit_cost: 1.0,
                typical_latency_seconds: 10.0,
                pivot_potential_score: 65.0,
                coverage_tier: CoverageTier::Primary,
            },
        );

        metadata.insert(
            "/search/deep".to_string(),
            EndpointMetadata {
                entity_type_count: 17,
                base_credit_cost: 3.0,
                typical_latency_seconds: 30.0,
                pivot_potential_score: 95.0,
                coverage_tier: CoverageTier::Tertiary,
            },
        );

        // Username endpoints
        metadata.insert(
            "/username/social".to_string(),
            EndpointMetadata {
                entity_type_count: 3,
                base_credit_cost: 2.0,
                typical_latency_seconds: 12.0,
                pivot_potential_score: 80.0,
                coverage_tier: CoverageTier::Primary,
            },
        );

        metadata.insert(
            "/username/history".to_string(),
            EndpointMetadata {
                entity_type_count: 3,
                base_credit_cost: 2.0,
                typical_latency_seconds: 15.0,
                pivot_potential_score: 40.0,
                coverage_tier: CoverageTier::Secondary,
            },
        );

        // Discord endpoints
        metadata.insert(
            "/discord/user".to_string(),
            EndpointMetadata {
                entity_type_count: 2,
                base_credit_cost: 1.0,
                typical_latency_seconds: 8.0,
                pivot_potential_score: 80.0,
                coverage_tier: CoverageTier::Primary,
            },
        );

        // Network endpoints
        metadata.insert(
            "/network/email-check".to_string(),
            EndpointMetadata {
                entity_type_count: 3,
                base_credit_cost: 1.0,
                typical_latency_seconds: 10.0,
                pivot_potential_score: 75.0,
                coverage_tier: CoverageTier::Primary,
            },
        );

        metadata.insert(
            "/network/ip".to_string(),
            EndpointMetadata {
                entity_type_count: 5,
                base_credit_cost: 1.0,
                typical_latency_seconds: 12.0,
                pivot_potential_score: 65.0,
                coverage_tier: CoverageTier::Primary,
            },
        );

        // Domain endpoints
        metadata.insert(
            "/domain/info".to_string(),
            EndpointMetadata {
                entity_type_count: 4,
                base_credit_cost: 1.0,
                typical_latency_seconds: 11.0,
                pivot_potential_score: 70.0,
                coverage_tier: CoverageTier::Primary,
            },
        );

        metadata.insert(
            "/domain/email-finder".to_string(),
            EndpointMetadata {
                entity_type_count: 2,
                base_credit_cost: 2.0,
                typical_latency_seconds: 18.0,
                pivot_potential_score: 75.0,
                coverage_tier: CoverageTier::Secondary,
            },
        );

        // Gaming endpoints
        metadata.insert(
            "/gaming/roblox".to_string(),
            EndpointMetadata {
                entity_type_count: 2,
                base_credit_cost: 1.0,
                typical_latency_seconds: 9.0,
                pivot_potential_score: 60.0,
                coverage_tier: CoverageTier::Secondary,
            },
        );

        metadata.insert(
            "/gaming/steam".to_string(),
            EndpointMetadata {
                entity_type_count: 2,
                base_credit_cost: 1.0,
                typical_latency_seconds: 9.0,
                pivot_potential_score: 60.0,
                coverage_tier: CoverageTier::Secondary,
            },
        );

        Self { metadata }
    }

    pub fn get(&self, endpoint: &str) -> Option<&EndpointMetadata> {
        self.metadata.get(endpoint)
    }

    pub fn entity_type_count(&self, endpoint: &str) -> usize {
        self.get(endpoint)
            .map(|m| m.entity_type_count)
            .unwrap_or(1)
    }

    pub fn credit_cost(&self, endpoint: &str) -> f32 {
        self.get(endpoint)
            .map(|m| m.base_credit_cost)
            .unwrap_or(1.0)
    }

    pub fn pivot_potential(&self, endpoint: &str) -> f32 {
        self.get(endpoint)
            .map(|m| m.pivot_potential_score)
            .unwrap_or(50.0)
    }

    pub fn coverage_score(&self, endpoint: &str) -> f32 {
        self.get(endpoint)
            .map(|m| m.coverage_tier.score())
            .unwrap_or(50.0)
    }

    pub fn all_endpoints(&self) -> Vec<&str> {
        self.metadata.keys().map(|s| s.as_str()).collect()
    }
}

impl Default for EndpointRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_routing_priority_ordering() {
        assert!(RoutingPriority::ExecuteFirst > RoutingPriority::ExecuteIfBudget);
        assert!(RoutingPriority::ExecuteIfBudget > RoutingPriority::Skip);
    }

    #[test]
    fn test_endpoint_registry() {
        let registry = EndpointRegistry::new();
        assert_eq!(registry.entity_type_count("/search"), 17);
        assert_eq!(registry.credit_cost("/search"), 1.0);
        assert!(registry.all_endpoints().len() > 10);
    }

    #[test]
    fn test_coverage_tier_scoring() {
        assert_eq!(CoverageTier::Primary.score(), 100.0);
        assert_eq!(CoverageTier::Secondary.score(), 50.0);
        assert_eq!(CoverageTier::Tertiary.score(), 25.0);
    }
}
