//! Core key types: `KeyStatus`, `KeyTier`, and `KeyEntry`.

use serde::{Deserialize, Serialize};

/// Non-secret short identifier for a key value — the first 12 hex chars of its
/// SHA-256. Lets the web UI / API reference a specific pooled key (to revoke it)
/// without the plaintext secret ever crossing the wire. Stable for a given value
/// and collision-safe within a service's handful of keys.
#[must_use]
pub fn key_id(value: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(value.as_bytes());
    hex::encode(&digest[..6])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyStatus {
    Untested,
    Active,
    Exhausted,
    Invalid,
    RateLimited,
    /// Operator-revoked (compromised, retired, or rotated away). Retained in the
    /// pool for audit/history but never selected for use — a one-way terminal
    /// state distinct from `Invalid` (which the validator can set automatically).
    Revoked,
}

impl KeyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Untested => "untested",
            Self::Active => "active",
            Self::Exhausted => "exhausted",
            Self::Invalid => "invalid",
            Self::RateLimited => "rate_limited",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyTier {
    Trial = 0,
    #[default]
    Basic = 1,
    Standard = 2,
    Premium = 3,
}

impl KeyTier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Premium => "premium",
            Self::Standard => "standard",
            Self::Basic => "basic",
            Self::Trial => "trial",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyEntry {
    pub value: String,
    pub status: KeyStatus,
    #[serde(default)]
    pub tier: KeyTier,
    #[serde(default)]
    pub use_count: u64,
    #[serde(default)]
    pub error_count: u64,
    #[serde(default)]
    pub last_used: Option<u64>,
    #[serde(default)]
    pub last_validated: Option<u64>,
    #[serde(default)]
    pub rate_limit_reset: Option<u64>,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub discovered_at: Option<u64>,
    #[serde(default)]
    pub discovered_by: Option<String>,
    #[serde(default)]
    pub discovered_in_scan: Option<String>,
    #[serde(default)]
    pub source_entity: Option<String>,
    /// Deployment environment this key belongs to (e.g. "prod", "dev",
    /// "personal"). `None` ⇒ the implicit `default` environment. Lets one pool
    /// hold keys for several contexts and lets export/list filter by context.
    #[serde(default)]
    pub environment: Option<String>,
    /// Unix seconds when this key was created by a `rotate` (replacing a prior,
    /// now-revoked key). `None` for a key added directly.
    #[serde(default)]
    pub rotated_at: Option<u64>,
}

impl KeyEntry {
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            status: KeyStatus::Untested,
            tier: KeyTier::Basic,
            use_count: 0,
            error_count: 0,
            last_used: None,
            last_validated: None,
            rate_limit_reset: None,
            notes: None,
            discovered_at: None,
            discovered_by: None,
            discovered_in_scan: None,
            source_entity: None,
            environment: None,
            rotated_at: None,
        }
    }

    /// This key's environment label, defaulting to `"default"` when unset.
    #[must_use]
    pub fn environment(&self) -> &str {
        self.environment.as_deref().unwrap_or("default")
    }

    pub fn is_usable(&self) -> bool {
        match self.status {
            KeyStatus::Untested | KeyStatus::Active => true,
            KeyStatus::RateLimited => {
                if let Some(reset) = self.rate_limit_reset {
                    crate::core::entity::unix_now() >= reset
                } else {
                    true
                }
            }
            KeyStatus::Exhausted | KeyStatus::Invalid | KeyStatus::Revoked => false,
        }
    }

    pub fn success_rate(&self) -> f64 {
        if self.use_count == 0 {
            return 1.0;
        }
        let successes = self.use_count.saturating_sub(self.error_count) as f64;
        successes / self.use_count as f64
    }

    /// Real-time, load-balancing selection rank for [`super::KeyPool::next_key`] —
    /// the pool serves the USABLE key with the GREATEST rank. Compared in order
    /// (each derived from live telemetry, so selection adapts as the scan runs):
    ///
    /// 1. **tier** — a premium key carries more capacity, so it leads;
    /// 2. **health band** — a key that just recovered from a rate-limit, or has
    ///    accumulated repeated errors, drops a band so the pool leans on healthier
    ///    keys until it settles — staying inside each key's operational boundary;
    /// 3. **idleness** — the LEAST-recently-used key wins, so requests fan out
    ///    evenly and no single key is driven to its rate limit (sustained
    ///    throughput rather than hammering the one nominally-best key).
    ///
    /// Deterministic: equal ranks fall through to the caller's round-robin index.
    #[must_use]
    pub(crate) fn selection_rank(&self, now: u64) -> (KeyTier, u8, u64) {
        (self.tier, self.health_band(now), self.idleness(now))
    }

    /// `1` = healthy, `0` = degraded. Coarse on purpose: a degraded key is
    /// de-prioritised behind healthy peers of the same tier, NOT starved — it is
    /// still served when every healthier key of that tier is cooling down, so the
    /// pool never goes idle while a usable credential remains.
    fn health_band(&self, now: u64) -> u8 {
        // Just came back from a rate-limit (cooldown elapsed but within the grace
        // window): it was sitting at its boundary, so ease it back in rather than
        // immediately re-hammering it.
        if let Some(reset) = self.rate_limit_reset
            && now >= reset
            && now.saturating_sub(reset) < THROTTLE_GRACE_SECS
        {
            return 0;
        }
        // Repeated 429/401/403s mean it's failing or near a limit → back off.
        if self.error_count >= ERROR_BACKOFF_COUNT {
            return 0;
        }
        1
    }

    /// Seconds since this key was last used — higher = idler = more preferred, so
    /// the rotation spreads load LRU-first. A never-used key is maximally idle.
    fn idleness(&self, now: u64) -> u64 {
        self.last_used.map_or(u64::MAX, |t| now.saturating_sub(t))
    }
}

/// After a key's rate-limit cooldown ends it stays one health band lower for this
/// long, so the rotation eases it back in instead of re-hammering a credential
/// that was just sitting at its boundary.
const THROTTLE_GRACE_SECS: u64 = 30;

/// Cumulative error count past which a key is treated as degraded (one health band
/// lower) — repeated failures mean it's near a limit or unhealthy, so the rotation
/// leans on healthier keys until it is the last one usable.
const ERROR_BACKOFF_COUNT: u64 = 3;
