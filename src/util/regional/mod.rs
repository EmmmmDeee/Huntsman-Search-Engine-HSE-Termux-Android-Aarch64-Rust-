//! Per-scan regional-search-augmentation ambient.
//!
//! `search_engines` decides whether to widen its dork set with geolocation-
//! biased terms based on a single scan-level toggle
//! (`ScanOptions::regional_search`, OR'd with the persistent
//! `feature.regional` default). Before this module the toggle lived in a
//! single process-global `AtomicBool` (`search_engines::REGIONAL_SEARCH`),
//! shared — unkeyed — across every scan `hse serve` runs concurrently
//! (`MAX_CONCURRENT_SCANS = 8`): if scan B started while scan A's
//! `search_engines` module was still mid-flight, B's `set_regional` call
//! silently flipped A's in-progress query building to B's setting too (last
//! writer wins for the overlap window) — the same unisolated-static shape
//! PROBLEM_TREE T2.11 already fixed for [`crate::util::found_keys`].
//!
//! [`with_regional`] scopes the setting to the current async task via a
//! [`tokio::task_local`], mirroring [`crate::util::found_keys::with_scan`]
//! exactly: the engine wraps each scan's `run_with_ledger` **and** each
//! spawned dispatch task in it (task-locals don't cross `spawn`), so
//! [`regional_enabled`] always reads back the setting of the scan actually
//! executing on the calling task, never a concurrently-running sibling's.

tokio::task_local! {
    /// The regional-search setting of the scan whose modules are executing on
    /// this task. Unset outside a scan (e.g. a unit test) ⇒ [`regional_enabled`]
    /// degrades to `false` (geolocation-neutral queries), the same default
    /// `ScanOptions::regional_search` itself defaults to.
    static REGIONAL: bool;
}

/// Run `f` with the current-task regional-search ambient set to `on`. The
/// engine wraps `run_with_ledger`'s future **and** re-wraps each spawned
/// dispatch task's future in this (task-locals don't cross `spawn`), so
/// [`regional_enabled`] is always correct for whichever scan's module is
/// actually executing on the calling task under `hse serve`'s concurrency.
pub async fn with_regional<F: std::future::Future>(on: bool, f: F) -> F::Output {
    REGIONAL.scope(on, f).await
}

/// Whether regional-search augmentation is enabled for the scan currently
/// executing on this task. `false` when unscoped (unit tests, or a call
/// outside any scan), matching `ScanOptions::regional_search`'s own default.
#[must_use]
pub fn regional_enabled() -> bool {
    REGIONAL.try_with(|&b| b).unwrap_or(false)
}

/// Test-only synchronous scope: run `f` with the regional ambient set
/// (mirrors [`with_regional`] for sync test bodies). The production path
/// uses the async [`with_regional`].
#[cfg(test)]
fn with_regional_sync<R>(on: bool, f: impl FnOnce() -> R) -> R {
    REGIONAL.sync_scope(on, f)
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
