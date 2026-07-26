//! Module-layer runtime effects consumed by the scan engine.
//!
//! `core` is module-agnostic: the engine drives a handful of cross-cutting,
//! per-scan module effects — rate-budget resets, the foreign-API-key sink, and
//! the vendor-key pattern matcher — through this injected contract. The
//! application composition root supplies the `modules` implementation when it
//! constructs the engine. This keeps the dependency edge `modules → core`,
//! never `core → modules`
//! (enforced by `tests/architecture.rs::core_does_not_import_modules`).
//!
//! The regional-search flag is a **different** case: it is a pure, no-I/O
//! per-scan ambient (like the found-key scan-scope), so the engine sets it
//! directly via the allow-listed [`crate::util::regional::with_regional`] leaf
//! rather than through a hook — a `fn(bool)`-shaped hook cannot wrap a future,
//! which per-scan task-local scoping needs (PROBLEM_TREE T2.11).
//!
//! Isolated engines use [`NoopModuleRuntime`], making their behaviour explicit
//! and preventing one engine's setup from mutating process-wide state.

use crate::core::entity::Entity;

/// Cross-cutting module effects required by the engine.
///
/// The contract belongs to `core`; concrete module state remains in the
/// `modules` layer and is supplied through dependency injection.
pub trait ModuleRuntime: Send + Sync {
    /// Reset per-scan module state and the scan's found-key bucket.
    fn reset_per_scan(&self, _scan_id: &str) {}

    /// Refresh module budgets that renew between expansion rounds.
    fn refresh_round_budget(&self) {}

    /// Identify a vendor API key embedded in `value`.
    fn identify_api_key<'a>(&self, _value: &'a str) -> Option<(&'static str, &'a str)> {
        None
    }

    /// Drain keys found by modules into first-class entities for `scan_id`.
    fn drain_found_keys(&self, _scan_id: &str) -> Vec<Entity> {
        Vec::new()
    }
}

/// Runtime used by tests and deliberately module-free engine instances.
#[derive(Debug, Default)]
pub struct NoopModuleRuntime;

impl ModuleRuntime for NoopModuleRuntime {}

#[cfg(test)]
mod tests {
    use super::{ModuleRuntime, NoopModuleRuntime};

    #[test]
    fn noop_runtime_is_object_safe_and_side_effect_free() {
        let runtime: &dyn ModuleRuntime = &NoopModuleRuntime;
        runtime.reset_per_scan("scan");
        runtime.refresh_round_budget();
        assert_eq!(runtime.identify_api_key("candidate"), None);
        assert!(runtime.drain_found_keys("scan").is_empty());
    }
}
