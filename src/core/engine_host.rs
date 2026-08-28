//! Host-layer effects consumed by the scan engine.
//!
//! The sibling of [`crate::core::module_runtime::ModuleRuntime`]. That contract
//! covers *module-layer* effects and is implemented in `modules`; this one
//! covers effects that live in `util` — the outbound-egress proxy pool and the
//! module-health quarantine policy.
//!
//! `core` names the contract, `util` implements it, `app` injects it, which
//! keeps the dependency edge `util → core` and never `core → util`
//! (enforced by `tests/architecture.rs::core_does_not_import_util_directly`).
//!
//! # Why this exists
//!
//! `core/engine/mod.rs` previously reached straight into
//! `crate::util::egress` and `crate::util::scraper_health`. The layering
//! invariant had never reported it because the scanner backing that test
//! truncated each file at its first `#[cfg(test)]`, and this file declares one
//! at line 63 of 2724 — so 2661 lines, including every one of those calls, went
//! unscanned. Fixing the scanner surfaced them; this is the fix for what it
//! surfaced.
//!
//! The exceptions carved into that invariant are scoped to *pure, leaf* helpers
//! (`util::geometry`, `util::union_find`, `util::oathnet_batch` — no state, no
//! I/O, no deps). Neither of these qualifies: `util::egress` owns a mutable
//! proxy pool, reads the environment, probes the network and spawns a task.
//! Widening the allow-list would have silenced the assertion rather than
//! answered it.

use std::collections::HashSet;

use async_trait::async_trait;

use crate::core::event::Event;

/// Host effects the engine drives but must not name directly.
///
/// Every method has a no-op default, so an isolated engine (tests, or any
/// deliberately host-free instance) opts out simply by taking
/// [`NoopEngineHost`] — the same pattern `ModuleRuntime`/`NoopModuleRuntime`
/// already uses.
#[async_trait]
pub trait EngineHost: Send + Sync {
    /// Whether outbound egress has a proxy pool or a published feed configured.
    ///
    /// The engine skips the refresh entirely when this is `false`. That is
    /// load-bearing, not an optimisation: the original code was explicit that a
    /// proxy-less deployment "pays nothing", and an implementation that always
    /// returns `true` would make every scan spawn a pointless task.
    fn egress_is_configured(&self) -> bool {
        false
    }

    /// Refresh the proxy pool from published feeds and re-probe due proxies,
    /// returning `(fed, validated_ok)`.
    ///
    /// Called from a detached task, so this must never be relied on to
    /// complete before the scan proceeds.
    async fn refresh_egress_pool(&self) -> (usize, usize) {
        (0, 0)
    }

    /// How many recent module-outcome events the health policy wants to read.
    ///
    /// The engine owns the store, so it performs the read; this only supplies
    /// the policy's window. Zero means "read nothing", which is why the no-op
    /// default quarantines nothing without needing a store round-trip.
    fn health_events_limit(&self) -> usize {
        0
    }

    /// Modules to skip this scan, given recent outcome events newest-first.
    ///
    /// An empty set means quarantine nothing, which is also the correct
    /// degraded answer when the health read fails — a health-read error must
    /// never fail a scan.
    fn quarantined_modules(&self, _events_newest_first: &[Event]) -> HashSet<String> {
        HashSet::new()
    }
}

/// Host used by tests and deliberately isolated engine instances: no egress
/// refresh, no quarantine, no process-wide state touched.
#[derive(Debug, Default)]
pub struct NoopEngineHost;

impl EngineHost for NoopEngineHost {}

#[cfg(test)]
mod tests {
    use super::{EngineHost, NoopEngineHost};

    #[test]
    fn noop_host_is_object_safe_and_side_effect_free() {
        let host: &dyn EngineHost = &NoopEngineHost;
        assert!(
            !host.egress_is_configured(),
            "the no-op host must not claim egress is configured, or every \
             isolated engine spawns a refresh task"
        );
        assert_eq!(
            host.health_events_limit(),
            0,
            "a zero window is what lets the engine skip the store read entirely"
        );
        assert!(
            host.quarantined_modules(&[]).is_empty(),
            "the no-op host must quarantine nothing"
        );
    }

    #[tokio::test]
    async fn noop_refresh_reports_no_work() {
        let host: &dyn EngineHost = &NoopEngineHost;
        assert_eq!(host.refresh_egress_pool().await, (0, 0));
    }
}
