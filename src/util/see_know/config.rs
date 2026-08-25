//! See-Know module configuration and constants
//! Termux-compatible paths and settings

use std::path::PathBuf;

/// Get Termux storage directory (works without root)
pub fn get_termux_storage_dir() -> PathBuf {
    // Termux home: /data/data/com.termux/files/home
    // Termux storage: ~/storage (symlink to /storage/emulated/0)
    if let Ok(home) = std::env::var("HOME") {
        let storage = PathBuf::from(&home).join("storage").join("downloads");
        if storage.exists() {
            return storage;
        }
    }

    // Fallback to home directory
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home);
    }

    // Last resort: current directory
    PathBuf::from(".")
}

/// Legacy See-Know results directory — the **pure path only**, never created.
///
/// No production code writes here any more. `data_log` used to, which put raw
/// provider records (plaintext credentials, for a breach/stealer source) and
/// the queried values under `~/storage/downloads` whenever Termux storage was
/// set up — shared external storage, readable by any app holding
/// `READ_EXTERNAL_STORAGE`. It is now rooted at the app-private
/// `$HOME/.huntsman` tree via [`crate::util::paths::subdir`].
///
/// This survives solely so `data_log` can *detect* a tree an older build left
/// behind and tell the operator about it. There is deliberately no
/// directory-creating counterpart: the creating variant was removed with the
/// migration, because a helper that materialises a directory on shared storage
/// is an invitation to reintroduce the same leak.
#[must_use]
pub fn get_results_dir_path() -> PathBuf {
    get_termux_storage_dir()
        .join(".hse")
        .join("see_know_results")
}

/// True when [`get_termux_storage_dir`] resolves to Termux's shared-storage
/// symlink (`~/storage/downloads`) rather than one of the private fallbacks.
///
/// `~/storage` points at `/storage/emulated/0`, so anything beneath it is
/// readable by any app holding `READ_EXTERNAL_STORAGE`. Credential- or
/// PII-bearing data must never be written there — see `data_log`, which is
/// rooted at the app-private `$HOME/.huntsman` tree for exactly this reason.
#[must_use]
pub fn results_dir_is_shared_storage() -> bool {
    std::env::var("HOME").is_ok_and(|home| {
        get_termux_storage_dir() == PathBuf::from(home).join("storage").join("downloads")
    })
}

/// SeekNow authentication credentials (web login fallback).
/// Priority order: tries each password until one succeeds.
pub const SEEKNOW_EMAIL: &str = "matthewdiegmann@gmail.com";
pub const SEEKNOW_PASSWORDS: &[&str] = &[
    "thelord123",       // Primary password
    "moose1991",        // Fallback 1
    "fuckthefrench123", // Fallback 2
];

/// Value scoring weights — the single source of truth consumed by
/// [`crate::modules::see_know::query_optimizer`]'s `ValueScorer`.
/// Editing a weight here changes the composite scoring; they are expected to
/// sum to 1.0 (asserted by the scorer's tests).
pub const VALUE_ENTITY_DIVERSITY_WEIGHT: f32 = 0.25;
pub const VALUE_HIT_RATE_WEIGHT: f32 = 0.30;
pub const VALUE_PIVOT_POTENTIAL_WEIGHT: f32 = 0.25;
pub const VALUE_FRESHNESS_WEIGHT: f32 = 0.10;
pub const VALUE_COVERAGE_WEIGHT: f32 = 0.10;

/// Endpoint credit costs
pub const ENDPOINT_COSTS: &[(&str, f32)] = &[
    ("/search", 1.0),
    ("/search/deep", 1.0),
    ("/username/social", 1.0),
    ("/username/github", 1.0),
    ("/username/twitter", 1.0),
    ("/username/tiktok", 1.0),
    ("/username/reddit", 1.0),
    ("/username/history", 1.0),
    ("/discord/user", 1.0),
    ("/discord/to-roblox", 1.0),
    ("/enterprise/discord/history", 5.0),
    ("/enterprise/discord/messages", 5.0),
    ("/enterprise/discord/export", 5.0),
    ("/network/ip", 1.0),
    ("/network/email-check", 1.0),
    ("/network/phone", 1.0),
    ("/domain/intel", 1.0),
    ("/domain/whois", 1.0),
    ("/gaming/xbox", 1.0),
    ("/gaming/roblox", 1.0),
    ("/gaming/minecraft", 1.0),
    ("/gaming/steam", 1.0),
    ("/credits", 0.0),
    ("/status", 0.0),
];

pub fn get_endpoint_cost(endpoint: &str) -> f32 {
    ENDPOINT_COSTS
        .iter()
        .find(|(name, _)| *name == endpoint)
        .map_or(1.0, |(_, cost)| *cost)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The legacy accessor must stay a pure path: it names a location that can
    /// be shared external storage, and merely asking for it must never bring
    /// that directory into existence. Replaces an older test that asserted the
    /// opposite (that calling it created the directory) — the creating variant
    /// was removed when `data_log` moved to the app-private root.
    #[test]
    fn legacy_results_dir_path_is_pure_and_creates_nothing() {
        let dir = get_results_dir_path();
        let existed = dir.exists();
        let _ = get_results_dir_path();
        assert_eq!(
            dir.exists(),
            existed,
            "get_results_dir_path must not create {}",
            dir.display()
        );
    }

    #[test]
    fn test_endpoint_costs() {
        // Pinned to the SeekNow contract's documented credit charges. `search`,
        // `search/deep`, `username/social` and `username/history` are all
        // 1-credit endpoints — `search/deep`'s own doc in `endpoints.rs` calls
        // it "the same 1-credit cost" as `search` — but the table previously
        // billed them 3/2/2, over-stating cost to the ROI router and
        // de-prioritising them. Enterprise stays 5, and `credits`/`status` 0.
        assert_eq!(get_endpoint_cost("/search"), 1.0);
        assert_eq!(get_endpoint_cost("/search/deep"), 1.0);
        assert_eq!(get_endpoint_cost("/username/social"), 1.0);
        assert_eq!(get_endpoint_cost("/username/history"), 1.0);
        assert_eq!(get_endpoint_cost("/enterprise/discord/history"), 5.0);
        assert_eq!(get_endpoint_cost("/credits"), 0.0);
        assert_eq!(get_endpoint_cost("/status"), 0.0);
    }
}
