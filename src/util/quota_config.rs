//! Unified API quota configuration system.
//!
//! Pre-configures quota limits for API modules via environment variables,
//! enabling repeatable testing of rate-limit behavior across concurrent scans.
//!
//! Environment variables — only `HSE_OATHNET_PER_SCAN_LIMIT` is currently
//! consumed by a live code path (`oathnet::BUDGET`, `src/util/oathnet/mod.rs`);
//! the other three are parsed here but nothing outside this file reads them
//! (`see_know_quota()`/`wigle_quota()` have no external callers, and
//! `OathnetQuotaConfig::daily_limit` is read once into a local `config` binding
//! at `oathnet/mod.rs:51` and never used again — a *different*, same-named
//! field on `RealQuota`, populated from the live API's own response, is what
//! actually tracks the daily limit). See REQ-ENV-003 in
//! `docs/REQUIREMENTS_LEDGER.md` for the full finding.
//! - `HSE_OATHNET_PER_SCAN_LIMIT`: oathnet queries per scan (default 4) — **live**
//! - `HSE_OATHNET_DAILY_LIMIT`: oathnet daily limit (default 10000) — parsed, not consumed
//! - `HSE_SEE_KNOW_PER_SCAN_LIMIT`: see_know queries per scan (default 8) — parsed, not consumed
//! - `HSE_WIGLE_PER_SCAN_LIMIT`: wigle queries per scan (default 50) — parsed, not consumed

use std::env;
use std::sync::OnceLock;

/// Pre-configured quota limits for oathnet module.
#[derive(Debug, Clone, Copy)]
pub struct OathnetQuotaConfig {
    pub per_scan_limit: u32,
    pub daily_limit: u32,
}

impl Default for OathnetQuotaConfig {
    fn default() -> Self {
        Self {
            per_scan_limit: 4,
            daily_limit: 10000,
        }
    }
}

impl OathnetQuotaConfig {
    pub fn from_env() -> Self {
        Self {
            per_scan_limit: env::var("HSE_OATHNET_PER_SCAN_LIMIT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(Self::default().per_scan_limit),
            daily_limit: env::var("HSE_OATHNET_DAILY_LIMIT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(Self::default().daily_limit),
        }
    }
}

static OATHNET_QUOTA: OnceLock<OathnetQuotaConfig> = OnceLock::new();

pub fn oathnet_quota() -> OathnetQuotaConfig {
    *OATHNET_QUOTA.get_or_init(OathnetQuotaConfig::from_env)
}

/// Pre-configured quota limits for see_know module.
#[derive(Debug, Clone, Copy)]
pub struct SeeKnowQuotaConfig {
    pub per_scan_limit: u32,
}

impl Default for SeeKnowQuotaConfig {
    fn default() -> Self {
        Self { per_scan_limit: 8 }
    }
}

impl SeeKnowQuotaConfig {
    pub fn from_env() -> Self {
        Self {
            per_scan_limit: env::var("HSE_SEE_KNOW_PER_SCAN_LIMIT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(Self::default().per_scan_limit),
        }
    }
}

static SEE_KNOW_QUOTA: OnceLock<SeeKnowQuotaConfig> = OnceLock::new();

pub fn see_know_quota() -> SeeKnowQuotaConfig {
    *SEE_KNOW_QUOTA.get_or_init(SeeKnowQuotaConfig::from_env)
}

/// Pre-configured quota limits for wigle module.
#[derive(Debug, Clone, Copy)]
pub struct WigleQuotaConfig {
    pub per_scan_limit: u32,
}

impl Default for WigleQuotaConfig {
    fn default() -> Self {
        Self { per_scan_limit: 50 }
    }
}

impl WigleQuotaConfig {
    pub fn from_env() -> Self {
        Self {
            per_scan_limit: env::var("HSE_WIGLE_PER_SCAN_LIMIT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(Self::default().per_scan_limit),
        }
    }
}

static WIGLE_QUOTA: OnceLock<WigleQuotaConfig> = OnceLock::new();

pub fn wigle_quota() -> WigleQuotaConfig {
    *WIGLE_QUOTA.get_or_init(WigleQuotaConfig::from_env)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oathnet_quota_uses_defaults() {
        let quota = OathnetQuotaConfig::from_env();
        assert_eq!(quota.per_scan_limit, 4);
        assert_eq!(quota.daily_limit, 10000);
    }

    #[test]
    fn see_know_quota_uses_defaults() {
        let quota = SeeKnowQuotaConfig::from_env();
        assert_eq!(quota.per_scan_limit, 8);
    }

    #[test]
    fn wigle_quota_uses_defaults() {
        let quota = WigleQuotaConfig::from_env();
        assert_eq!(quota.per_scan_limit, 50);
    }
}
