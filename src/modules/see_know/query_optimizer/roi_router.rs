//! ROI-based query routing.
//!
//! Routes queries based on ROI = ValueScore / EffectiveCost.

pub struct RoiRouter;

impl RoiRouter {
    pub fn new() -> Self {
        Self
    }

    /// Calculate ROI for a query.
    pub fn calculate_roi(&self, value_score: f32, effective_cost: f32) -> f32 {
        if effective_cost <= 0.0 {
            // Free queries (ROI is value only)
            value_score.min(1000.0)
        } else {
            value_score / effective_cost
        }
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
}
