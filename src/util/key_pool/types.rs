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

/// Provenance class of a pooled key — the axis that decides whether HSE may
/// authenticate with it, kept strictly separate from [`KeyStatus`] (which only
/// tracks a key's live health). This is the type-level enforcement of the
/// discovered-vs-operator credential separation:
///
/// * [`KeyOrigin::Operator`] — a credential the operator deliberately supplied
///   (`hse keys add`, `set-key`, `import-json`, a `rotate`) or explicitly
///   promoted. Only these enter a provider authentication cascade.
/// * [`KeyOrigin::Discovered`] — a third party's credential HSE observed inside
///   scan data (harvested from a page/breach/stealer record, or bulk-imported
///   from a dump). It is retained as **evidence** and remains fully catalogued,
///   but is quarantined from authentication until an operator promotes it: HSE
///   must never authenticate against a real third-party service with someone
///   else's captured secret on its own initiative.
///
/// The field is `Option<KeyOrigin>` on [`KeyEntry`] with a `None` default so a
/// pool written before this type existed still loads; [`KeyEntry::origin`]
/// resolves that absence conservatively (see there), which is what quarantines
/// credentials a prior build had already auto-pooled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyOrigin {
    /// Operator-supplied or operator-promoted — eligible to authenticate.
    Operator,
    /// Observed in scan data — evidence only, never authenticates until promoted.
    Discovered,
}

impl KeyOrigin {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Operator => "operator",
            Self::Discovered => "discovered",
        }
    }
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
    /// Provenance class deciding authentication eligibility. `None` in a pool
    /// written before this field existed; [`Self::origin`] resolves the absence
    /// (a legacy entry carrying discovery provenance is treated as
    /// [`KeyOrigin::Discovered`] and thereby quarantined, everything else as
    /// [`KeyOrigin::Operator`]). Never read directly for an auth decision — go
    /// through [`Self::origin`] / [`Self::is_auth_eligible`] so the migration
    /// rule is applied in exactly one place.
    #[serde(default)]
    pub origin: Option<KeyOrigin>,
    /// Unix seconds when an operator promoted this key from `Discovered` to
    /// `Operator`, making it auth-eligible. `None` unless it was promoted — the
    /// provenance record item 02 requires for a deliberate promotion.
    #[serde(default)]
    pub promoted_at: Option<u64>,
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
            origin: None,
            promoted_at: None,
        }
    }

    /// Construct a **discovered** credential (evidence only, not auth-eligible)
    /// with its acquisition provenance stamped. Used by the harvest path so a
    /// key HSE merely observed can never slip into an authentication cascade
    /// without an explicit [`super::KeyPool::promote_by_id`]. `source` is the
    /// discovering subsystem (e.g. `"key_harvest"`), `scan_id` the scan it was
    /// seen in, `entity` the evidentiary entity it came from.
    #[must_use]
    pub fn discovered(
        value: impl Into<String>,
        source: impl Into<String>,
        scan_id: impl Into<String>,
        entity: Option<String>,
    ) -> Self {
        let mut e = Self::new(value);
        e.origin = Some(KeyOrigin::Discovered);
        e.discovered_at = Some(crate::core::entity::unix_now());
        e.discovered_by = Some(source.into());
        e.discovered_in_scan = Some(scan_id.into());
        e.source_entity = entity;
        e
    }

    /// This key's environment label, defaulting to `"default"` when unset.
    #[must_use]
    pub fn environment(&self) -> &str {
        self.environment.as_deref().unwrap_or("default")
    }

    /// Resolved provenance class — the **single** place the `Option<KeyOrigin>`
    /// field is interpreted, so the migration rule for a pool written before the
    /// field existed lives in exactly one spot:
    ///
    /// 1. An explicit [`KeyOrigin`] always wins.
    /// 2. Otherwise a key carrying discovery provenance (`discovered_by` set) is
    ///    [`KeyOrigin::Discovered`] — this is what **quarantines** credentials a
    ///    prior build auto-pooled from scan data (harvest and TSV-dump imports
    ///    both stamp `discovered_by`), so upgrading cannot leave a captured
    ///    third-party secret silently auth-eligible.
    /// 3. Otherwise (`hse keys add`/`set-key`/`rotate`/`import-json`, none of
    ///    which set discovery provenance) it is an operator credential.
    #[must_use]
    pub fn origin(&self) -> KeyOrigin {
        match self.origin {
            Some(o) => o,
            None if self.discovered_by.is_some() => KeyOrigin::Discovered,
            None => KeyOrigin::Operator,
        }
    }

    /// Whether HSE may authenticate with this key. Only operator-supplied or
    /// operator-promoted credentials qualify; a discovered credential is evidence
    /// until explicitly promoted. This is ANDed with [`Self::is_usable`] at the
    /// pool's selection chokepoint, so no auth path can serve a discovered key.
    #[must_use]
    pub fn is_auth_eligible(&self) -> bool {
        matches!(self.origin(), KeyOrigin::Operator)
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

    /// A single quantified "operational health" number in `0.0..=1.0`, derived
    /// purely from this key's live telemetry — the operator-facing companion to
    /// the internal [`Self::selection_rank`] (which only needs a relative order
    /// for rotation, not an absolute score). Deterministic and pure: the same
    /// entry + the same `now` always yield the same value, so it is safe to
    /// render in an API/UI and to assert on in tests.
    ///
    /// Construction — a reliability base plus a mild capacity bonus, scaled by
    /// live availability, with terminal states overriding everything:
    ///
    /// 1. **Terminal states win outright.** `Invalid` / `Revoked` / `Exhausted`
    ///    are dead credentials — there is no "health" left to grade, so they
    ///    short-circuit to `0.0` regardless of any past success. Checked first so
    ///    a key with a flawless history that was just revoked still reads as dead.
    /// 2. **Reliability is the dominant base (weight [`RELIABILITY_W`]).**
    ///    [`Self::success_rate`] is the primary signal; a never-used key inherits
    ///    that method's optimistic `1.0` prior, so a fresh `Active`/`Untested` key
    ///    starts at the top of its band.
    /// 3. **Tier adds a mild capacity bonus (weight [`TIER_W`]).** A `Premium`
    ///    key carries more headroom than a `Trial` one, so at equal reliability
    ///    the higher tier reads as slightly healthier. The reliability and tier
    ///    weights sum to `1.0`, so the bonus is deliberately small — it can nudge
    ///    ordering but never lift a failing key above a reliable lower-tier peer.
    /// 4. **Availability scales the result (multiplier in `0.0..=1.0`).** A key
    ///    whose rate-limit cooldown has NOT elapsed is healthy in the long run but
    ///    useless right now, so the score is scaled down hard ([`COOLDOWN_AVAIL`]).
    ///    A key inside the post-recovery grace window is scaled less
    ///    ([`GRACE_AVAIL`]) — usable again, but it was just at its boundary. A
    ///    fully available key keeps its score (factor `1.0`).
    ///
    /// Consequently a fully-reliable, top-tier, fully-available key scores exactly
    /// `1.0`; a poor success rate, a non-top tier, or an active cooldown are what
    /// pull it down toward (but never below) `0.0`.
    #[must_use]
    pub fn health_score(&self, now: u64) -> f64 {
        // (1) Dead credentials have no health to grade — short-circuit to zero so
        //     a once-great key reads as dead the instant it is revoked/invalidated.
        match self.status {
            KeyStatus::Invalid | KeyStatus::Revoked | KeyStatus::Exhausted => return 0.0,
            KeyStatus::Untested | KeyStatus::Active | KeyStatus::RateLimited => {}
        }

        // (2) Reliability base + (3) tier bonus. The weights sum to 1.0, so the
        //     maximum pre-availability score is exactly 1.0 (fully reliable, top
        //     tier) and the tier bonus can never dominate reliability.
        let reliability = RELIABILITY_W * self.success_rate();
        let tier_bonus = TIER_W * tier_fraction(self.tier);
        let base = reliability + tier_bonus;

        // (4) Scale by how usable the key is *right now*.
        base * self.availability_factor(now)
    }

    /// How available this key is *at `now`*, as a `0.0..=1.0` multiplier for
    /// [`Self::health_score`]. Mirrors the rate-limit reasoning in
    /// [`Self::is_usable`] / [`Self::health_band`] but yields a graded factor
    /// rather than a boolean / coarse band:
    ///
    /// * **In cooldown** (rate-limited, `rate_limit_reset` not yet reached):
    ///   scaled to [`COOLDOWN_AVAIL`] — long-run healthy but unusable this instant.
    /// * **In the post-recovery grace window** (cooldown elapsed less than
    ///   [`THROTTLE_GRACE_SECS`] ago): scaled to [`GRACE_AVAIL`] — usable again
    ///   but eased back in, since it was just sitting at its boundary.
    /// * **Otherwise** (no pending reset, or grace long past): fully available
    ///   (factor `1.0`).
    fn availability_factor(&self, now: u64) -> f64 {
        if let Some(reset) = self.rate_limit_reset {
            if now < reset {
                // Cooldown still running: cannot be served right now.
                return COOLDOWN_AVAIL;
            }
            if now.saturating_sub(reset) < THROTTLE_GRACE_SECS {
                // Just recovered: usable, but eased back in during the grace window.
                return GRACE_AVAIL;
            }
        }
        1.0
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

// ── `health_score` weighting ──────────────────────────────────────────────────
//
// The two additive weights sum to exactly 1.0, so a fully-reliable, top-tier,
// fully-available key scores 1.0 and nothing can exceed that ceiling. Reliability
// dominates so heavily that the tier term spans only `TIER_W` of the range: a
// fresh key of ANY tier still scores "high" (>= 1 - TIER_W ≈ 0.95), with tier just
// a mild nudge among otherwise-equal keys — deliberately small so it can never
// outweigh a real reliability gap. The availability multipliers are applied
// *after* this sum (see `KeyEntry::availability_factor`).

/// Weight of the success-rate term in [`KeyEntry::health_score`] — the dominant
/// reliability signal. With `TIER_W` it sums to `1.0`.
const RELIABILITY_W: f64 = 0.95;

/// Weight of the tier capacity bonus in [`KeyEntry::health_score`] — a mild nudge
/// so a higher-tier key edges out an equally-reliable lower-tier one. Kept small
/// (only 5% of the range) so even a `Trial` key, when fully reliable, still scores
/// high and the bonus can never outweigh a real reliability gap. With
/// `RELIABILITY_W` it sums to `1.0`.
const TIER_W: f64 = 0.05;

/// Availability multiplier for a key whose rate-limit cooldown has NOT yet elapsed
/// — long-run healthy but unusable right now, so its `health_score` is scaled down
/// hard (it should read as nearly, but not entirely, dead so an operator can still
/// tell it apart from a truly terminal key).
const COOLDOWN_AVAIL: f64 = 0.10;

/// Availability multiplier for a key inside the post-recovery grace window — usable
/// again, but eased back in (it was just at its boundary), so it reads as a touch
/// below a fully-available peer.
const GRACE_AVAIL: f64 = 0.80;

/// Map a [`KeyTier`] to a `0.0..=1.0` capacity fraction for the tier bonus in
/// [`KeyEntry::health_score`]: `Trial` is the floor (`0.0`, no bonus) and `Premium`
/// the ceiling (`1.0`, full bonus), with `Basic`/`Standard` evenly spaced between.
/// Pure and total over the four-variant enum.
fn tier_fraction(tier: KeyTier) -> f64 {
    match tier {
        KeyTier::Trial => 0.0,
        KeyTier::Basic => 1.0 / 3.0,
        KeyTier::Standard => 2.0 / 3.0,
        KeyTier::Premium => 1.0,
    }
}
