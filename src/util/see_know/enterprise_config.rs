//! Enterprise-hardcoded configuration for SeekNow integration — the SeekNow
//! plan parameters (15,000 daily credits) the `budget` module reads via
//! [`ENTERPRISE`]. The speculative workflow/monitoring/SLA/key-pattern tables
//! that once lived here were unwired scaffolding and were removed (see the
//! dead-code sweep, `PROBLEM_TREE` T2.58/T2.62); only the live plan config
//! remains.

/// Enterprise plan parameters (hardcoded).
pub struct EnterprisePlan {
    pub daily_limit: u32,
    pub per_scan_cap: u32,
    pub scan_budget_floor: u32,
    pub scan_budget_ceil: u32,
    pub session_cap: u32,
    pub cache_size: usize,
    pub max_retries: u32,
    pub curl_timeout_secs: u64,
    pub tokio_timeout_millis: u64,
}

/// Production enterprise configuration (15,000 credits/day).
/// These are the operator's actual plan parameters.
pub const ENTERPRISE: EnterprisePlan = EnterprisePlan {
    daily_limit: 15_000,
    per_scan_cap: 750, // daily_limit / 20 = 15,000 / 20 = 750 (clamped 300-2500)
    scan_budget_floor: 300, // minimum per-scan budget
    scan_budget_ceil: 2_500, // maximum per-scan budget
    session_cap: 100_000, // local session ceiling (server quota is backstop)
    cache_size: 1_024, // in-process response cache entries
    max_retries: 3,    // transient error retry count
    curl_timeout_secs: 75, // curl timeout (above /search max ~55s)
    tokio_timeout_millis: 78_000, // outer tokio timeout (curl < outer)
};
