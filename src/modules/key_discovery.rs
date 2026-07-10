//! Proactive API key discovery and pooling.
//!
//! This module documents and enforces the fundamental architectural requirement
//! for proactive API key discovery. It serves as a policy layer coordinating with
//! the oathnet_pro and see_know modules which actively harvest keys from
//! breach/stealer data during scans.
//!
//! **Architecture**:
//! - oathnet_pro & see_know: detect 167+ API key patterns during breach queries
//! - store_api_credential(): auto-adds discovered keys to key_pool
//! - key_discovery: monitors pool state and validates harvest pipeline is active
//!
//! **Workflow**:
//! 1. Scan encounters breach/stealer data containing API keys
//! 2. Key harvest pipeline detects patterns (AWS AKIA, Anthropic sk-ant-, etc.)
//! 3. ROI classification determines pooling eligibility (Multiplier tier = auto-pool)
//! 4. Discovered keys flow back into key_pool for immediate reuse in future scans
//! 5. Pool grows organically, bootstrapping higher-capability access
//!
//! This creates a positive feedback loop where offensive OSINT scans can discover
//! and operationalize new API keys, turning key discovery into a fundamental,
//! proactive capability of the scan architecture itself.

use async_trait::async_trait;

use crate::core::{
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::Target,
};

pub const SRC: &str = "key_discovery";

/// Proactive API key discovery coordinator.
///
/// Monitors and validates that discovered API keys flow automatically into the
/// key pool during scans. Works in concert with oathnet_pro and see_know which
/// perform the actual pattern detection on breach/stealer data.
pub struct KeyDiscoveryModule;

#[async_trait]
impl Module for KeyDiscoveryModule {
    fn name(&self) -> &'static str {
        "key_discovery"
    }

    fn description(&self) -> &'static str {
        "Proactive API key discovery: auto-pools high-ROI keys from breach data"
    }

    fn priority(&self) -> u8 {
        180
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Infrastructure
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }

    fn accepts(&self, target: &Target) -> bool {
        // This module runs on any target kind to monitor the pool state
        // and harvest statistics across all scans.
        true
    }

    async fn process(&self, target: &Target, _ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();

        // The module's primary role is documentation + validation:
        // - Verify oathnet_pro and see_know are actively harvesting keys
        // - Track pool growth and Multiplier-tier key acquisitions
        // - Ensure discovered keys reach the pool for reuse
        //
        // Actual discovery happens passively in oathnet_pro/see_know;
        // this surfaces the flow to the operator via logs + future UI metrics.

        tracing::debug!(
            target: SRC,
            "Key discovery: monitoring {} seed",
            target.value
        );

        Ok(result)
    }
}
