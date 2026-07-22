//! Intelligent cascade routing and optimization
//!
//! Decides which pivots to cascade based on:
//! - Pivot ROI (value/cost)
//! - Cascade depth ROI threshold
//! - Budget allocation per depth
//! - Query type classification (Tier-1, Tier-2, Tier-3)

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PivotTier {
    /// Always cascade if budget allows (Discord ID, Email, Username)
    Tier1,
    /// Cascade only if ROI positive (ASN, Domain, Phone)
    Tier2,
    /// Skip unless explicitly requested (Coordinates, Organization)
    Tier3,
}

pub struct CascadeOptimizer;

impl CascadeOptimizer {
    pub fn new() -> Self {
        Self
    }

    /// Classify pivot by tier
    /// Phase 2.1+
    pub fn classify_pivot_tier(&self, pivot_type: &str) -> PivotTier {
        // TODO: Phase 2.1
        match pivot_type {
            "discord_id" | "email" | "username" => PivotTier::Tier1,
            "asn" | "domain" | "phone" => PivotTier::Tier2,
            "coordinates" | "organization" => PivotTier::Tier3,
            _ => PivotTier::Tier2,
        }
    }

    /// Get ROI threshold for cascade depth
    /// Phase 2.1+
    pub fn get_roi_threshold_for_depth(&self, depth: u8) -> f32 {
        // TODO: Phase 2.1
        match depth {
            1 => 10.0,
            2 => 25.0,
            3 => 50.0,
            _ => 100.0,
        }
    }

    /// Decide whether to cascade based on ROI and tier
    /// Phase 2.1+
    pub fn should_cascade(
        &self,
        pivot_tier: PivotTier,
        pivot_roi: f32,
        cascade_depth: u8,
        budget_remaining: u32,
    ) -> bool {
        // TODO: Phase 2.1
        let threshold = self.get_roi_threshold_for_depth(cascade_depth);

        match pivot_tier {
            PivotTier::Tier1 => pivot_roi > 5.0 && budget_remaining > 50,
            PivotTier::Tier2 => pivot_roi > threshold && budget_remaining > (threshold as u32),
            PivotTier::Tier3 => false,
        }
    }

    /// Calculate budget allocation per cascade depth
    /// Phase 2.1+
    pub fn allocate_cascade_budget(&self, total_budget: u32) -> (u32, u32, u32) {
        // TODO: Phase 2.1
        // Depth 1: 60%
        // Depth 2: 30%
        // Depth 3: 10%
        let depth1 = (total_budget as f32 * 0.60) as u32;
        let depth2 = (total_budget as f32 * 0.30) as u32;
        let depth3 = (total_budget as f32 * 0.10) as u32;
        (depth1, depth2, depth3)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pivot_tier_classification() {
        // TODO: Phase 2.1
        let optimizer = CascadeOptimizer::new();
        assert_eq!(
            optimizer.classify_pivot_tier("discord_id"),
            PivotTier::Tier1
        );
        assert_eq!(optimizer.classify_pivot_tier("asn"), PivotTier::Tier2);
    }

    #[test]
    fn test_roi_threshold_by_depth() {
        // TODO: Phase 2.1
        let optimizer = CascadeOptimizer::new();
        assert_eq!(optimizer.get_roi_threshold_for_depth(1), 10.0);
        assert_eq!(optimizer.get_roi_threshold_for_depth(2), 25.0);
        assert_eq!(optimizer.get_roi_threshold_for_depth(3), 50.0);
    }

    #[test]
    fn test_budget_allocation() {
        // TODO: Phase 2.1
        let optimizer = CascadeOptimizer::new();
        let (d1, d2, d3) = optimizer.allocate_cascade_budget(1000);
        assert_eq!(d1, 600);
        assert_eq!(d2, 300);
        assert_eq!(d3, 100);
    }
}
