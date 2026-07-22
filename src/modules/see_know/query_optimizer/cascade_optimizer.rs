//! Intelligent cascade routing - COMPLETE IMPLEMENTATION
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CascadeDecision {
    pub pivot_type: String,
    pub tier: PivotTier,
    pub roi: f32,
    pub should_cascade: bool,
    pub reasoning: String,
}

pub struct CascadeOptimizer;

impl CascadeOptimizer {
    pub fn new() -> Self {
        Self
    }

    /// Classify pivot by tier (COMPLETE)
    pub fn classify_pivot_tier(&self, pivot_type: &str) -> PivotTier {
        match pivot_type.to_lowercase().as_str() {
            // Tier-1: High-value pivots, always cascade
            "discord_id" | "discord" => PivotTier::Tier1,
            "email" => PivotTier::Tier1,
            "username" => PivotTier::Tier1,
            "platform_account" => PivotTier::Tier1,
            
            // Tier-2: Medium-value pivots, cascade if ROI positive
            "asn" => PivotTier::Tier2,
            "domain" => PivotTier::Tier2,
            "phone" => PivotTier::Tier2,
            "registrant_email" => PivotTier::Tier2,
            
            // Tier-3: Low-value pivots, skip by default
            "coordinates" => PivotTier::Tier3,
            "organization" => PivotTier::Tier3,
            "geolocation" => PivotTier::Tier3,
            
            _ => PivotTier::Tier2, // Conservative default
        }
    }

    /// Get ROI threshold for cascade depth
    pub fn get_roi_threshold_for_depth(&self, depth: u8) -> f32 {
        match depth {
            1 => 10.0,   // First cascade: low threshold
            2 => 25.0,   // Second cascade: medium threshold
            3 => 50.0,   // Third cascade: high threshold
            4 => 100.0,  // Fourth+ cascade: very high threshold
            _ => 200.0,
        }
    }

    /// Decide whether to cascade (COMPLETE IMPLEMENTATION)
    pub fn should_cascade(
        &self,
        pivot_tier: PivotTier,
        pivot_roi: f32,
        cascade_depth: u8,
        budget_remaining: u32,
        time_remaining_secs: u32,
    ) -> CascadeDecision {
        let threshold = self.get_roi_threshold_for_depth(cascade_depth);
        
        let (should_cascade, reasoning) = match pivot_tier {
            PivotTier::Tier1 => {
                // Always cascade if budget and time permit
                if budget_remaining >= 50 && time_remaining_secs >= 30 {
                    (true, format!("Tier-1 pivot: cascade (budget: {}, time: {}s)", budget_remaining, time_remaining_secs))
                } else {
                    (false, "Tier-1 pivot: insufficient budget or time".to_string())
                }
            }
            PivotTier::Tier2 => {
                // Cascade only if ROI positive and threshold met
                if pivot_roi > threshold && budget_remaining > (threshold as u32) && time_remaining_secs >= 30 {
                    (true, format!("Tier-2 pivot: ROI {:.1} > threshold {:.1}, cascade", pivot_roi, threshold))
                } else {
                    (false, format!("Tier-2 pivot: ROI {:.1} <= threshold {:.1}, skip", pivot_roi, threshold))
                }
            }
            PivotTier::Tier3 => {
                // Never cascade automatically
                (false, "Tier-3 pivot: low value, skip by default".to_string())
            }
        };
        
        CascadeDecision {
            pivot_type: "unknown".to_string(),
            tier: pivot_tier,
            roi: pivot_roi,
            should_cascade,
            reasoning,
        }
    }

    /// Calculate budget allocation per cascade depth (COMPLETE)
    pub fn allocate_cascade_budget(&self, total_budget: u32) -> (u32, u32, u32) {
        // Depth 1: 60% of total
        // Depth 2: 30% of total
        // Depth 3: 10% of total
        let depth1 = (total_budget as f32 * 0.60) as u32;
        let depth2 = (total_budget as f32 * 0.30) as u32;
        let depth3 = (total_budget as f32 * 0.10) as u32;
        (depth1, depth2, depth3)
    }

    /// Get remaining budget for current depth
    pub fn get_remaining_budget_for_depth(
        &self,
        total_budget: u32,
        current_depth: u8,
        spent_at_depth: u32,
    ) -> u32 {
        let (d1, d2, d3) = self.allocate_cascade_budget(total_budget);
        let allocated = match current_depth {
            1 => d1,
            2 => d2,
            3 => d3,
            _ => total_budget / 10,
        };
        
        allocated.saturating_sub(spent_at_depth)
    }
}

impl Default for CascadeOptimizer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pivot_tier_classification() {
        let optimizer = CascadeOptimizer::new();
        
        assert_eq!(optimizer.classify_pivot_tier("discord_id"), PivotTier::Tier1);
        assert_eq!(optimizer.classify_pivot_tier("email"), PivotTier::Tier1);
        assert_eq!(optimizer.classify_pivot_tier("asn"), PivotTier::Tier2);
        assert_eq!(optimizer.classify_pivot_tier("coordinates"), PivotTier::Tier3);
    }

    #[test]
    fn test_roi_threshold_by_depth() {
        let optimizer = CascadeOptimizer::new();
        
        assert_eq!(optimizer.get_roi_threshold_for_depth(1), 10.0);
        assert_eq!(optimizer.get_roi_threshold_for_depth(2), 25.0);
        assert_eq!(optimizer.get_roi_threshold_for_depth(3), 50.0);
        assert_eq!(optimizer.get_roi_threshold_for_depth(4), 100.0);
    }

    #[test]
    fn test_cascade_decision_tier1() {
        let optimizer = CascadeOptimizer::new();
        
        let decision = optimizer.should_cascade(
            PivotTier::Tier1,
            80.0,   // High ROI
            1,      // Depth 1
            500,    // Budget
            3600,   // Time
        );
        
        assert!(decision.should_cascade);
    }

    #[test]
    fn test_cascade_decision_tier2_low_roi() {
        let optimizer = CascadeOptimizer::new();
        
        let decision = optimizer.should_cascade(
            PivotTier::Tier2,
            15.0,   // Below threshold (25.0)
            2,      // Depth 2
            500,
            3600,
        );
        
        assert!(!decision.should_cascade);
    }

    #[test]
    fn test_cascade_decision_tier3() {
        let optimizer = CascadeOptimizer::new();
        
        let decision = optimizer.should_cascade(
            PivotTier::Tier3,
            100.0,  // Even high ROI
            1,
            500,
            3600,
        );
        
        assert!(!decision.should_cascade);
    }

    #[test]
    fn test_budget_allocation() {
        let optimizer = CascadeOptimizer::new();
        
        let (d1, d2, d3) = optimizer.allocate_cascade_budget(1000);
        
        assert_eq!(d1, 600);
        assert_eq!(d2, 300);
        assert_eq!(d3, 100);
    }

    #[test]
    fn test_remaining_budget_calculation() {
        let optimizer = CascadeOptimizer::new();
        
        let remaining = optimizer.get_remaining_budget_for_depth(1000, 1, 100);
        
        // Depth 1 allocated 600, spent 100, remaining 500
        assert_eq!(remaining, 500);
    }
}
