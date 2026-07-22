//! Plan tier detection and management
//!
//! Auto-detect API plan tier (Free, Pro, Enterprise) from responses
//! and cache for session lifetime. Enables conditional endpoint dispatch.
//!
//! Phase 1.3 Implementation

use std::sync::{Arc, Mutex};
use anyhow::Result;

/// API plan tier
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanTier {
    /// Free tier (limited endpoints, low credits)
    Free,
    /// Pro tier (most endpoints, medium credits)
    Pro,
    /// Enterprise tier (all endpoints including Discord export, high credits)
    Enterprise,
}

impl PlanTier {
    /// Get endpoint availability for this tier
    pub fn has_endpoint(&self, endpoint: &str) -> bool {
        match self {
            PlanTier::Free => {
                matches!(endpoint, "/search" | "/username/social" | "/credits")
            }
            PlanTier::Pro => {
                !endpoint.starts_with("/enterprise")
            }
            PlanTier::Enterprise => true,
        }
    }

    /// Get daily credit limit for this tier
    pub fn daily_credit_limit(&self) -> u32 {
        match self {
            PlanTier::Free => 300,
            PlanTier::Pro => 1000,
            PlanTier::Enterprise => 5000,
        }
    }
}

/// Plan tier cache for session
pub struct TierCache {
    tier: Arc<Mutex<Option<PlanTier>>>,
}

impl TierCache {
    pub fn new() -> Self {
        Self {
            tier: Arc::new(Mutex::new(None)),
        }
    }

    /// Get cached tier or None if not detected yet
    pub fn get(&self) -> Option<PlanTier> {
        self.tier.lock().ok().and_then(|t| *t)
    }

    /// Cache the detected tier
    pub fn set(&self, tier: PlanTier) -> Result<()> {
        *self.tier.lock()? = Some(tier);
        Ok(())
    }
}

/// Detect plan tier from API response headers
///
/// Phase 1.3: Implement tier detection from:
/// - X-Plan-Tier header
/// - X-Remaining-Credits header (infer tier from credit limits)
/// - Endpoint availability (infer from 403 responses)
pub fn detect_tier_from_headers(headers: &std::collections::HashMap<String, String>) -> Option<PlanTier> {
    // TODO: Phase 1.3
    // 1. Check X-Plan-Tier header
    // 2. Check X-Daily-Credits header (infer tier from limit)
    // 3. Return detected tier or None
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tier_endpoint_availability() {
        // TODO: Phase 1.3
        // Test Free tier endpoint restrictions
        assert!(!PlanTier::Free.has_endpoint("/enterprise/discord/history"));
        
        // Test Enterprise tier has all endpoints
        assert!(PlanTier::Enterprise.has_endpoint("/enterprise/discord/history"));
    }

    #[test]
    fn test_tier_credit_limits() {
        // TODO: Phase 1.3
        assert_eq!(PlanTier::Free.daily_credit_limit(), 300);
        assert_eq!(PlanTier::Enterprise.daily_credit_limit(), 5000);
    }

    #[test]
    fn test_tier_cache() {
        // TODO: Phase 1.3
        let cache = TierCache::new();
        assert_eq!(cache.get(), None);
        cache.set(PlanTier::Enterprise).unwrap();
        assert_eq!(cache.get(), Some(PlanTier::Enterprise));
    }
}
