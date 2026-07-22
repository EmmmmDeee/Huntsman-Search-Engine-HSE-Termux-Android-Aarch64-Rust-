//! Utility endpoints: /status (service health), /credits (budget info)

use crate::util::see_know::SeekNowClient;
use crate::core::module::ModuleContext;
use anyhow::Result;

/// Handle /status endpoint: Query upstream service health
///
/// Returns status of integrated data sources:
/// - Snusbase, LeakCheck, IntelX (breach data)
/// - Platform APIs (Discord, Steam, Xbox, etc.)
/// - WHOIS registrars
/// - Geolocation services
///
/// Phase 1.1 Implementation
pub async fn handle_status(ctx: &ModuleContext, client: &SeekNowClient) -> Result<String> {
    // TODO: Phase 1.1
    // 1. Call GET /status via client
    // 2. Parse service status response (JSON)
    // 3. Extract upstream service list (snusbase, leakcheck, intelx, etc.)
    // 4. Return formatted status summary
    // 5. Log any unreachable services
    Err(anyhow::anyhow!("TODO: Phase 1.1 - Implement /status endpoint"))
}

/// Handle /credits endpoint: Query budget balance
///
/// Returns current credit balance and plan tier info
pub async fn handle_credits(ctx: &ModuleContext, client: &SeekNowClient) -> Result<String> {
    // TODO: Already partially implemented in main module
    // This is a placeholder for endpoint refactoring
    Err(anyhow::anyhow!("TODO: Refactor /credits into endpoint pattern"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_parsing() {
        // TODO: Phase 1.1
        // Test parsing of status response
    }

    #[test]
    fn test_service_health_extraction() {
        // TODO: Phase 1.1
        // Test extraction of individual service status
    }
}
