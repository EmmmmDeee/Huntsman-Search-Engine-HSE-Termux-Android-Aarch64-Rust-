//! Module-layer hooks installed into `core` at startup.
//!
//! `core` is module-agnostic: the engine drives a handful of cross-cutting,
//! per-scan module effects — rate-budget resets, the regional-search flag, the
//! foreign-API-key sink, and the vendor-key pattern matcher — through these
//! function-pointer hooks, which the `modules` layer installs from
//! [`crate::modules::registry`]. This keeps the dependency edge
//! `modules → core`, never `core → modules` (enforced by
//! `tests/architecture.rs::core_does_not_import_modules`).
//!
//! When the hooks are not installed (e.g. a unit test that constructs an engine
//! without going through the module registry) every wrapper degrades to a
//! no-op / empty result, so no caller has to special-case the uninstalled state.

use std::sync::OnceLock;

use crate::core::entity::Entity;

/// The cross-cutting per-scan effects the engine drives, implemented by the
/// `modules` layer and installed via [`install`].
pub struct ModuleHooks {
    /// Reset every module's per-scan state — rate budgets + the found-key sink.
    pub reset_per_scan: fn(),
    /// Apply the regional-search augmentation flag for the current scan.
    pub set_regional: fn(bool),
    /// Refresh the per-round SeekNow budget between expansion rounds.
    pub refresh_round_budget: fn(),
    /// Identify a vendor API key embedded in a string → `(service, key)`.
    pub identify_api_key: fn(&str) -> Option<(&'static str, &str)>,
    /// Drain the foreign-API-key sink into first-class `ApiKey` / wallet
    /// entities for `scan_id`.
    pub drain_found_keys: fn(&str) -> Vec<Entity>,
}

static HOOKS: OnceLock<ModuleHooks> = OnceLock::new();

/// Install the module hooks. Idempotent — the first call wins. Called from
/// [`crate::modules::registry`], so the hooks are set before any engine (which
/// is constructed from `registry()`) runs.
pub fn install(hooks: ModuleHooks) {
    let _ = HOOKS.set(hooks);
}

pub(crate) fn reset_per_scan() {
    if let Some(h) = HOOKS.get() {
        (h.reset_per_scan)();
    }
}

pub(crate) fn set_regional(on: bool) {
    if let Some(h) = HOOKS.get() {
        (h.set_regional)(on);
    }
}

pub(crate) fn refresh_round_budget() {
    if let Some(h) = HOOKS.get() {
        (h.refresh_round_budget)();
    }
}

pub(crate) fn identify_api_key(value: &str) -> Option<(&'static str, &str)> {
    HOOKS.get().and_then(|h| (h.identify_api_key)(value))
}

pub(crate) fn drain_found_keys(scan_id: &str) -> Vec<Entity> {
    HOOKS
        .get()
        .map(|h| (h.drain_found_keys)(scan_id))
        .unwrap_or_default()
}
