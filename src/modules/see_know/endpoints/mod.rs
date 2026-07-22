//! See-Know endpoint routing and dispatch.
//!
//! Organizes endpoint implementations by category:
//! - Search: /search, /search/deep
//! - Username: /username/*, /username/history
//! - Discord: /discord/*, /enterprise/discord/*
//! - Network: /network/ip, /network/email-check, /network/phone
//! - Domain: /domain/intel, /domain/whois
//! - Gaming: /gaming/xbox, /gaming/roblox, /gaming/minecraft, /gaming/steam
//! - Utility: /status, /credits

pub mod utility;

// Future modules (Phase 1-2)
// pub mod search;
// pub mod username;
// pub mod discord;
// pub mod network;
// pub mod domain;
// pub mod gaming;

use crate::util::see_know::{EndpointCall, SeekNowClient};
use crate::core::module::ModuleContext;
use anyhow::Result;

/// Dispatch an endpoint call to its handler.
pub async fn dispatch(
    ctx: &ModuleContext,
    client: &SeekNowClient,
    endpoint: EndpointCall,
) -> Result<String> {
    match endpoint {
        EndpointCall::Status => utility::handle_status(ctx, client).await,
        EndpointCall::Credits => utility::handle_credits(ctx, client).await,
        _ => {
            Err(anyhow::anyhow!("Endpoint not yet implemented in refactored structure"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dispatch_router() {
        // TODO: Add dispatch router tests
    }
}
