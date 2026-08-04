//! The `util`-backed implementation of [`crate::core::engine_host::EngineHost`].
//!
//! This is the composition seam that lets `core/engine` drive the egress proxy
//! pool and the module-health quarantine without naming `util` — the direction
//! of the dependency is `util → core`, matching how `storage::Store` implements
//! `core::port::StoragePort`.
//!
//! Every method here is a thin delegation on purpose. The policy stays where it
//! already lives (`util::egress`, `util::scraper_health`); this type only makes
//! it reachable through a contract `core` owns.

use std::collections::HashSet;

use async_trait::async_trait;

use crate::core::engine_host::EngineHost;
use crate::core::event::Event;

/// The real host: the egress pool and health policy the shipped binary uses.
///
/// Constructed by the application composition root (`app::runtime`), never by
/// `core` — which is the whole point of the indirection.
#[derive(Debug, Default, Clone, Copy)]
pub struct UtilEngineHost;

#[async_trait]
impl EngineHost for UtilEngineHost {
    fn egress_is_configured(&self) -> bool {
        // Both halves of the original engine-side condition. The env-var name
        // moves in here with the rest of the policy: `core` should no more know
        // `HUNTSMAN_PROXY_FEEDS` than it should know the pool's representation.
        crate::util::egress::pool_is_configured()
            || std::env::var(crate::util::egress::PROXY_FEEDS_ENV).is_ok()
    }

    async fn refresh_egress_pool(&self) -> (usize, usize) {
        crate::util::egress::refresh_pool().await
    }

    fn health_events_limit(&self) -> usize {
        crate::util::scraper_health::RECENT_EVENTS_WINDOW
    }

    fn quarantined_modules(&self, events_newest_first: &[Event]) -> HashSet<String> {
        crate::util::scraper_health::quarantined_modules(
            &crate::util::scraper_health::aggregate_source_health(events_newest_first),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::UtilEngineHost;
    use crate::core::engine_host::EngineHost;

    /// The delegation must stay a delegation: if these drift from the `util`
    /// values, the engine silently reads a different window or applies a
    /// different quarantine than the rest of the system believes it does.
    #[test]
    fn host_delegates_to_the_util_policy_rather_than_restating_it() {
        let host = UtilEngineHost;
        assert_eq!(
            host.health_events_limit(),
            crate::util::scraper_health::RECENT_EVENTS_WINDOW,
            "the engine's health window must be the one `scraper_health` defines"
        );
        // No events means nothing to quarantine, which is also the shape the
        // engine falls back to when the store read fails.
        assert!(host.quarantined_modules(&[]).is_empty());
    }
}
