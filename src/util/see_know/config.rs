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

/// Get HSE results directory (creates if needed)
pub fn get_results_dir() -> PathBuf {
    let results = get_termux_storage_dir().join(".hse").join("see_know_results");
    let _ = std::fs::create_dir_all(&results);
    results
}

/// Get cache directory
pub fn get_cache_dir() -> PathBuf {
    let cache = get_termux_storage_dir().join(".hse").join("cache");
    let _ = std::fs::create_dir_all(&cache);
    cache
}

/// Value scoring weights (configurable)
pub const VALUE_ENTITY_DIVERSITY_WEIGHT: f32 = 0.25;
pub const VALUE_HIT_RATE_WEIGHT: f32 = 0.30;
pub const VALUE_PIVOT_POTENTIAL_WEIGHT: f32 = 0.25;
pub const VALUE_FRESHNESS_WEIGHT: f32 = 0.10;
pub const VALUE_COVERAGE_WEIGHT: f32 = 0.10;

/// ROI thresholds per cascade depth
pub const ROI_DEPTH_1_THRESHOLD: f32 = 10.0;
pub const ROI_DEPTH_2_THRESHOLD: f32 = 25.0;
pub const ROI_DEPTH_3_THRESHOLD: f32 = 50.0;
pub const ROI_DEPTH_4_PLUS_THRESHOLD: f32 = 100.0;

/// Budget allocation per cascade depth
pub const BUDGET_DEPTH_1_RATIO: f32 = 0.60;
pub const BUDGET_DEPTH_2_RATIO: f32 = 0.30;
pub const BUDGET_DEPTH_3_RATIO: f32 = 0.10;

/// Cache TTL in seconds (24 hours)
pub const CACHE_TTL_SECS: u64 = 86400;

/// Query timeout in seconds
pub const QUERY_TIMEOUT_SECS: u64 = 78;

/// Maximum concurrent queries
pub const MAX_CONCURRENT_QUERIES: usize = 10;

/// Endpoint credit costs
pub const ENDPOINT_COSTS: &[(&str, f32)] = &[
    ("/search", 1.0),
    ("/search/deep", 3.0),
    ("/username/social", 2.0),
    ("/username/github", 1.0),
    ("/username/twitter", 1.0),
    ("/username/tiktok", 1.0),
    ("/username/reddit", 1.0),
    ("/username/history", 2.0),
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
        .map(|(_, cost)| *cost)
        .unwrap_or(1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_results_directory_creation() {
        let dir = get_results_dir();
        assert!(dir.exists());
    }

    #[test]
    fn test_endpoint_costs() {
        assert_eq!(get_endpoint_cost("/search"), 1.0);
        assert_eq!(get_endpoint_cost("/search/deep"), 3.0);
        assert_eq!(get_endpoint_cost("/enterprise/discord/history"), 5.0);
    }
}
