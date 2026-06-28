//! `PoolData` and `KeyPool` — the in-memory pool structure and all mutation methods.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use super::types::{KeyEntry, KeyStatus, KeyTier};

/// Per-service rate-limit reset window. Imported from service_defs via the parent module.
pub(super) use crate::util::service_defs::rate_limit_reset;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PoolData {
    pub services: HashMap<String, Vec<KeyEntry>>,

    /// Per-service round-robin start index for [`KeyPool::next_key`] tie-breaking.
    /// Ephemeral session state, NOT durable intelligence: `#[serde(skip)]` keeps it
    /// out of the on-disk JSON (so the export/import format is unchanged) and it
    /// resets to empty on load. Folded in here — rather than a parallel
    /// `Mutex<HashMap>` on [`KeyPool`] — so `next_key` takes a single lock,
    /// removing both the second per-selection lock acquisition and the latent
    /// data-then-indices lock-ordering hazard. Keyed by the lowercased service.
    #[serde(skip)]
    pub(super) rr_index: HashMap<String, usize>,
}

/// Keep a service's round-robin start (`rr_index`) consistent with its live key
/// vector after a shrink. Drops the entry entirely once the service has no keys
/// (so removed services don't accumulate stale starts), otherwise clamps the
/// stored start below the new length. Called from the pruning/removal paths so
/// the index tracks the live vec rather than relying solely on the read-time
/// `% len` normalisation in [`KeyPool::next_key`].
fn clamp_rr_index(rr_index: &mut HashMap<String, usize>, service: &str, new_len: usize) {
    if new_len == 0 {
        rr_index.remove(service);
    } else if let Some(idx) = rr_index.get_mut(service)
        && *idx >= new_len
    {
        *idx %= new_len;
    }
}

/// The most recent activity timestamp (unix seconds) recorded against a key,
/// used by [`KeyPool::prune_terminal`] to age out dead credentials. Takes the
/// maximum across every timestamp the entry carries — last use, last validation,
/// rotation, and discovery — so a key only ages once ALL of its recorded
/// activity is older than the retention window. A key with no timestamp at all
/// (e.g. a freshly-imported, never-used Revoked entry) returns `0`, so it is
/// treated as maximally old and becomes eligible the moment the operator runs a
/// compaction — there is no telemetry to preserve for it.
fn last_activity(entry: &KeyEntry) -> u64 {
    [
        entry.last_used,
        entry.last_validated,
        entry.rotated_at,
        entry.discovered_at,
    ]
    .into_iter()
    .flatten()
    .max()
    .unwrap_or(0)
}

/// Per-status key counts for one service — the breakdown surfaced inside a
/// [`ServiceHealth`]. Each field counts keys in that [`KeyStatus`]; the fields
/// sum to [`ServiceHealth::total`]. Value-free (no key plaintext) and
/// `serde::Serialize` so it can feed an API/UI directly.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusBreakdown {
    pub untested: usize,
    pub active: usize,
    pub exhausted: usize,
    pub invalid: usize,
    pub rate_limited: usize,
    pub revoked: usize,
}

impl StatusBreakdown {
    /// Tally one key's status into the matching bucket. Exhaustive over
    /// [`KeyStatus`] so a new variant forces an update here at compile time.
    fn record(&mut self, status: KeyStatus) {
        match status {
            KeyStatus::Untested => self.untested += 1,
            KeyStatus::Active => self.active += 1,
            KeyStatus::Exhausted => self.exhausted += 1,
            KeyStatus::Invalid => self.invalid += 1,
            KeyStatus::RateLimited => self.rate_limited += 1,
            KeyStatus::Revoked => self.revoked += 1,
        }
    }
}

/// Operator-facing health roll-up for ONE service's slice of the pool, produced
/// by [`KeyPool::health_report`]. Quantifies the service's key-pool health from
/// the live per-key [`KeyEntry::health_score`]:
///
/// * `total` / `usable` — capacity headlines (how many keys, how many servable
///   right now per [`KeyEntry::is_usable`]);
/// * `breakdown` — the per-status census (so a UI can show *why* keys are or
///   aren't usable);
/// * `avg_health` / `min_health` — the quantified health: the mean health across
///   ALL keys (the at-a-glance number) and the worst single key (the floor that
///   flags a lurking dead/throttled credential the average would mask). Both are
///   `0.0` for a service with no keys.
///
/// Value-free by construction (no key plaintext) and `serde::Serialize`, so it is
/// safe to hand straight to the localhost dashboard / API.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ServiceHealth {
    pub service: String,
    pub total: usize,
    pub usable: usize,
    pub breakdown: StatusBreakdown,
    pub avg_health: f64,
    pub min_health: f64,
}

pub struct KeyPool {
    pub(super) data: Mutex<PoolData>,
    /// Monotonic counter bumped every time [`KeyPool::add`] admits a NEW key
    /// (and once at construction for any keys loaded from disk). It is the cheap
    /// dirty-flag that lets the engine's per-module `hot_inject_keys` cascade
    /// skip the full `service_defs()` sweep + per-service pool probe when no new
    /// key has appeared since the last inject: a single relaxed atomic load
    /// replaces ~80 lock acquisitions per sequential round on the common
    /// no-new-key path. Bumped only on a genuine *new key available* event (not
    /// on `next_key` telemetry writes, revoke, or rotate's revoke half), so a
    /// changed generation always means there is potentially a key to inject.
    generation: AtomicU64,
}

impl Default for KeyPool {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyPool {
    pub fn new() -> Self {
        Self {
            data: Mutex::new(PoolData::default()),
            generation: AtomicU64::new(0),
        }
    }

    pub fn from_data(data: PoolData) -> Self {
        // Seed the generation at 1 when the pool loads with any keys, so the
        // engine's first `hot_inject_keys` (which starts from generation 0) sees
        // a changed counter and performs the initial full sweep that injects the
        // operator's persisted keys. A pool that loads empty stays at 0 and the
        // first inject correctly short-circuits.
        let seed = u64::from(!data.services.is_empty());
        Self {
            data: Mutex::new(data),
            generation: AtomicU64::new(seed),
        }
    }

    /// Current generation of the key pool — bumped each time a NEW key is
    /// admitted via [`Self::add`]. Cheap (a single relaxed atomic load) so the
    /// engine can gate its full `hot_inject_keys` sweep on `generation()` having
    /// changed since the previous inject, avoiding the per-service pool probe on
    /// the common no-new-key path.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Relaxed)
    }

    pub fn add(&self, service: &str, key: KeyEntry) -> bool {
        // The rotation pool only holds keys the cascade can REUSE — recognised
        // keyed providers (see `service_defs::is_poolable_service`). Reject
        // everything else (the `generic_hex` catch-all, `crypto_*` wallet tags,
        // `jwt_token`, `<svc>_login` pseudo-services, foreign consumer keys) at
        // this single chokepoint, so NO ingest path — harvest in search_engines/
        // web_crawler/key_harvest, import, or validate — can bloat it. A live
        // name-scan otherwise pooled 12 499 `generic_hex` blobs (6 MB) because
        // only one of the harvest paths was gated.
        if !crate::util::service_defs::is_poolable_service(service) {
            return false;
        }
        let mut data = self.data.lock();
        let entries = data.services.entry(service.to_lowercase()).or_default();
        if entries.iter().any(|e| e.value == key.value) {
            return false;
        }
        entries.push(key);
        // A genuinely-new key is now poolable: bump the dirty-flag so the engine's
        // next `hot_inject_keys` performs its full sweep instead of short-circuiting.
        // Relaxed is sufficient — the engine only needs to observe *that* the value
        // changed, and the subsequent pool probe takes the data lock (which provides
        // the ordering for the keys it reads). Done while holding the lock so the
        // counter and the new entry become visible together.
        self.generation.fetch_add(1, Ordering::Relaxed);
        true
    }

    /// Serialize the whole pool to pretty JSON — the same shape `save_pool`
    /// persists, so an export round-trips through `import_json`. The output
    /// contains **plaintext key values**; callers must treat it as a secret
    /// (write `0600`, never log it). Optionally restrict to one `environment`.
    pub fn export_json(&self, environment: Option<&str>) -> serde_json::Result<String> {
        let mut data = self.snapshot();
        if let Some(env) = environment {
            for entries in data.services.values_mut() {
                entries.retain(|e| e.environment() == env);
            }
            data.services.retain(|_, entries| !entries.is_empty());
        }
        serde_json::to_string_pretty(&data)
    }

    /// Merge keys from an exported pool JSON into this pool. Dedup is by value
    /// within a service (identical to `add`), so re-importing an export is
    /// idempotent. An `environment` override stamps every imported key with that
    /// label (useful for slotting a teammate's export into your "shared" env).
    /// Returns the number of keys newly added.
    pub fn import_json(&self, json: &str, environment: Option<&str>) -> serde_json::Result<usize> {
        let incoming: PoolData = serde_json::from_str(json)?;
        let mut added = 0usize;
        for (service, entries) in incoming.services {
            for mut entry in entries {
                if let Some(env) = environment {
                    entry.environment = Some(env.to_string());
                }
                if self.add(&service, entry) {
                    added += 1;
                }
            }
        }
        Ok(added)
    }

    /// Revoke a key: a one-way move to `Revoked` so it's retained for audit but
    /// never selected again (compromised / retired). Returns true if found.
    pub fn revoke(&self, service: &str, value: &str) -> bool {
        let mut data = self.data.lock();
        if let Some(entries) = data.services.get_mut(&service.to_lowercase()) {
            for e in entries.iter_mut() {
                if e.value == value {
                    e.status = KeyStatus::Revoked;
                    return true;
                }
            }
        }
        false
    }

    /// Revoke the key in `service` whose [`super::key_id`] matches `id`. Lets the web UI
    /// revoke a key by its non-secret short id without ever transmitting the
    /// plaintext value. Returns true if found.
    pub fn revoke_by_id(&self, service: &str, id: &str) -> bool {
        let mut data = self.data.lock();
        if let Some(entries) = data.services.get_mut(&service.to_lowercase()) {
            for e in entries.iter_mut() {
                if super::key_id(&e.value) == id {
                    e.status = KeyStatus::Revoked;
                    return true;
                }
            }
        }
        false
    }

    /// Rotate the key in `service` whose [`super::key_id`] matches `id` to `new` — the
    /// web/API counterpart to [`Self::rotate`], identifying the old key by its
    /// non-secret id so its plaintext never has to be sent back to rotate it.
    /// Returns true if a key with that id was found.
    pub fn rotate_by_id(&self, service: &str, id: &str, new: &str) -> bool {
        let old = {
            let data = self.data.lock();
            data.services
                .get(&service.to_lowercase())
                .and_then(|es| es.iter().find(|e| super::key_id(&e.value) == id))
                .map(|e| e.value.clone())
        };
        match old {
            Some(old) => self.rotate(service, &old, new),
            None => false,
        }
    }

    /// Rotate a key: revoke `old` and add `new` in one step, carrying the old
    /// key's environment and notes so provenance survives the swap and the new
    /// key lands in the same context. Returns true if `old` was found.
    pub fn rotate(&self, service: &str, old: &str, new: &str) -> bool {
        let lower = service.to_lowercase();
        let carried = {
            let data = self.data.lock();
            data.services
                .get(&lower)
                .and_then(|es| es.iter().find(|e| e.value == old))
                .map(|e| (e.environment.clone(), e.notes.clone()))
        };
        let Some((env, notes)) = carried else {
            return false;
        };
        self.revoke(service, old);
        let mut entry = KeyEntry::new(new);
        entry.environment = env;
        entry.notes = notes;
        entry.rotated_at = Some(crate::core::entity::unix_now());
        self.add(service, entry);
        true
    }

    /// Assign a key to an `environment` (e.g. "prod"/"dev"). Returns true if
    /// found.
    pub fn set_environment(&self, service: &str, value: &str, env: &str) -> bool {
        let mut data = self.data.lock();
        if let Some(entries) = data.services.get_mut(&service.to_lowercase()) {
            for e in entries.iter_mut() {
                if e.value == value {
                    e.environment = Some(env.to_string());
                    return true;
                }
            }
        }
        false
    }

    /// Select a key for a service with telemetry-driven, load-spreading rotation.
    ///
    /// Among the USABLE keys (cooled-down / invalid / revoked already filtered by
    /// [`KeyEntry::is_usable`]) it serves the one with the greatest live
    /// [`KeyEntry::selection_rank`] — highest tier, healthiest, then
    /// least-recently-used — so requests fan out across the pool and no single key
    /// is driven to its rate limit. The round-robin start makes equal-rank ties
    /// deterministic and adds extra spread. The selection mutates telemetry
    /// (`use_count`/`last_used`), so the *next* call sees the load it just placed
    /// and naturally moves on to the next-idlest key.
    pub fn next_key(&self, service: &str) -> Option<String> {
        let lower = service.to_lowercase();
        let now = crate::core::entity::unix_now();
        // Single lock: the round-robin start index now lives in `PoolData`
        // (`rr_index`) alongside `services`, so there is no second mutex to take
        // and no data-then-indices lock-ordering hazard.
        let mut data = self.data.lock();

        // Read the round-robin start (copied out) BEFORE the mutable `entries`
        // borrow, so the two disjoint fields of `data` are never borrowed at once.
        // `% len` keeps a start carried over from a now-shorter vec in range.
        let start = data.rr_index.get(&lower).copied().unwrap_or(0);

        let entries = data.services.get_mut(&lower)?;
        let len = entries.len();
        if len == 0 {
            return None;
        }
        let start = start % len;

        let mut best: Option<usize> = None;
        let mut best_rank: Option<(KeyTier, u8, u64)> = None;
        for offset in 0..len {
            let i = (start + offset) % len;
            let entry = &entries[i];
            if !entry.is_usable() {
                continue;
            }
            let rank = entry.selection_rank(now);
            // Strict `>`: the FIRST key at the best rank (in rotated scan order)
            // wins, so equal-rank keys round-robin via the start index.
            if best_rank.is_none_or(|b| rank > b) {
                best = Some(i);
                best_rank = Some(rank);
            }
        }

        let i = best?;
        let entry = &mut entries[i];
        // A key whose rate-limit cooldown has elapsed is healthy again: flip the
        // status so it surfaces accurately and the post-throttle grace can lift.
        if entry.status == KeyStatus::RateLimited
            && entry.rate_limit_reset.is_some_and(|r| now >= r)
        {
            entry.status = KeyStatus::Active;
        }
        entry.use_count += 1;
        entry.last_used = Some(now);
        let value = entry.value.clone();
        // Advance the start past the served key for the next call. Re-borrow
        // `rr_index` only now that the `entries` borrow has ended.
        data.rr_index.insert(lower, i.wrapping_add(1));
        Some(value)
    }

    pub fn mark_status(&self, service: &str, value: &str, status: KeyStatus) {
        let lower = service.to_lowercase();
        let mut data = self.data.lock();
        if let Some(entries) = data.services.get_mut(&lower)
            && let Some(entry) = entries.iter_mut().find(|e| e.value == value)
        {
            entry.status = status;
            if status == KeyStatus::RateLimited {
                let reset = rate_limit_reset(service);
                entry.rate_limit_reset = Some(crate::core::entity::unix_now() + reset);
            }
        }
    }

    pub fn mark_validated(&self, service: &str, value: &str, valid: bool) {
        let lower = service.to_lowercase();
        let mut data = self.data.lock();
        if let Some(entries) = data.services.get_mut(&lower)
            && let Some(entry) = entries.iter_mut().find(|e| e.value == value)
        {
            entry.status = if valid {
                KeyStatus::Active
            } else {
                KeyStatus::Invalid
            };
            entry.last_validated = Some(crate::core::entity::unix_now());
        }
    }

    pub fn record_error(&self, service: &str, value: &str) {
        let lower = service.to_lowercase();
        let mut data = self.data.lock();
        if let Some(entries) = data.services.get_mut(&lower)
            && let Some(entry) = entries.iter_mut().find(|e| e.value == value)
        {
            entry.error_count = entry.error_count.saturating_add(1);
        }
    }

    /// Status of an existing key (by service + value), if the pool holds it.
    /// Enables the "validate once" policy: a caller can skip a live re-probe of
    /// a key whose verdict the pool has already settled.
    #[must_use]
    pub fn entry_status(&self, service: &str, value: &str) -> Option<KeyStatus> {
        let data = self.data.lock();
        data.services
            .get(&service.to_lowercase())?
            .iter()
            .find(|e| e.value == value)
            .map(|e| e.status)
    }

    /// Remove low-value keys whose [`KeyEntry::success_rate`] has fallen below
    /// `min_success_rate` (i.e. their error rate is too high), once they have at
    /// least `min_uses` recorded uses to judge by. Returns the number pruned.
    ///
    /// High-value keys (Standard/Premium tier) are **always retained**: a scarce,
    /// expensive credential isn't discarded over a transient error streak — the
    /// operator revokes those deliberately. Trial/Basic keys prune normally.
    pub fn prune_degraded(&self, min_success_rate: f64, min_uses: u64) -> usize {
        let mut data = self.data.lock();
        let mut pruned = 0;
        // Services whose vec shrank: their round-robin start may now point past
        // the live end, so clamp each afterwards to keep the index tracking the
        // vec. Collected first because `services.iter_mut()` borrows `data`.
        let mut shrunk: Vec<(String, usize)> = Vec::new();
        for (service, entries) in &mut data.services {
            let before = entries.len();
            entries.retain(|e| {
                e.tier >= KeyTier::Standard
                    || e.use_count < min_uses
                    || e.success_rate() >= min_success_rate
            });
            let after = entries.len();
            if after < before {
                pruned += before - after;
                shrunk.push((service.clone(), after));
            }
        }
        for (service, len) in shrunk {
            clamp_rr_index(&mut data.rr_index, &service, len);
        }
        pruned
    }

    /// Drop terminal-state keys (`Revoked` / `Invalid`) whose most recent activity
    /// is older than `retain_secs` seconds, returning the number compacted. The
    /// audit-preserving counterpart to [`Self::prune_degraded`]: `Revoked` is a
    /// one-way flip and `Invalid` is set by the validator, so without compaction a
    /// long-lived install accumulates dead entries forever — every one is re-scanned
    /// on each [`Self::next_key`] selection and re-serialised to disk on every
    /// `save`, so the on-device JSON and the per-selection scan grow without bound
    /// across the install lifetime (cf. the historic 6 MB `generic_hex` bloat).
    ///
    /// This is **explicitly operator-invoked** and **retention-windowed** so audit
    /// intent is preserved: a key revoked or invalidated within `retain_secs` is
    /// kept so a recently-compromised credential stays visible in the pool's
    /// history; only entries dead *and* untouched for the whole window are dropped.
    /// "Activity" is the newest of the entry's use / validation / rotation /
    /// discovery timestamps (see `last_activity`); a terminal key with no timestamp
    /// at all carries no telemetry to preserve and is eligible immediately. Live
    /// statuses (`Untested`/`Active`/`Exhausted`/`RateLimited`) are never touched —
    /// `Exhausted` and `RateLimited` recover, so they are not terminal here.
    ///
    /// `now` is passed in (rather than sampled internally) so the caller can use the
    /// single `crate::core::entity::unix_now()` it already sampled and so the cutoff
    /// is testable. As with the other shrink paths, each affected service's
    /// round-robin start is clamped afterwards to keep `rr_index` tracking the live
    /// vec. The generation counter is deliberately NOT bumped: removing dead keys
    /// makes no NEW key available to inject, so the engine's `hot_inject_keys`
    /// dirty-flag must stay put.
    pub fn prune_terminal(&self, retain_secs: u64, now: u64) -> usize {
        let cutoff = now.saturating_sub(retain_secs);
        let mut data = self.data.lock();
        let mut pruned = 0;
        // Services whose vec shrank, clamped after the borrow ends (see
        // `prune_degraded` for the same two-phase pattern).
        let mut shrunk: Vec<(String, usize)> = Vec::new();
        for (service, entries) in &mut data.services {
            let before = entries.len();
            entries.retain(|e| {
                let terminal = matches!(e.status, KeyStatus::Revoked | KeyStatus::Invalid);
                // Keep non-terminal keys, and terminal keys still inside the
                // retention window (last activity at/after the cutoff).
                !terminal || last_activity(e) >= cutoff
            });
            let after = entries.len();
            if after < before {
                pruned += before - after;
                shrunk.push((service.clone(), after));
            }
        }
        for (service, len) in shrunk {
            clamp_rr_index(&mut data.rr_index, &service, len);
        }
        pruned
    }

    pub fn remove(&self, service: &str, value: &str) -> bool {
        let lower = service.to_lowercase();
        let mut data = self.data.lock();
        let new_len = if let Some(entries) = data.services.get_mut(&lower) {
            let before = entries.len();
            entries.retain(|e| e.value != value);
            let after = entries.len();
            if after == before {
                return false;
            }
            after
        } else {
            return false;
        };
        // The vec shrank: keep the round-robin start in range (and drop it once
        // the service has no keys left).
        clamp_rr_index(&mut data.rr_index, &lower, new_len);
        true
    }

    pub fn snapshot(&self) -> PoolData {
        self.data.lock().clone()
    }

    pub fn service_count(&self, service: &str) -> usize {
        let data = self.data.lock();
        data.services
            .get(&service.to_lowercase())
            .map_or(0, std::vec::Vec::len)
    }

    pub fn total_keys(&self) -> usize {
        let data = self.data.lock();
        data.services.values().map(std::vec::Vec::len).sum()
    }

    pub fn total_active(&self) -> usize {
        let data = self.data.lock();
        data.services
            .values()
            .flat_map(|v| v.iter())
            .filter(|e| e.is_usable())
            .count()
    }

    /// Per-service operational health roll-up for the operator dashboard / API —
    /// the pool-level companion to the per-key [`KeyEntry::health_score`]. For
    /// each service it reports total keys, how many are usable right now, the
    /// per-status [`StatusBreakdown`], and the aggregate health: the AVERAGE
    /// `health_score` (the at-a-glance number) plus the MINIMUM (the floor that
    /// exposes a single dead/throttled credential the average would otherwise
    /// mask). See [`ServiceHealth`] for field semantics.
    ///
    /// All keys share one `now` (`crate::core::entity::unix_now()` sampled once)
    /// so every score in the report is consistent. The result is sorted by
    /// service name for a deterministic, stable ordering (the underlying
    /// `HashMap` iteration order is not). Value-free: no key plaintext is copied,
    /// so the output is safe to serialise to the dashboard.
    #[must_use]
    pub fn health_report(&self) -> Vec<ServiceHealth> {
        let now = crate::core::entity::unix_now();
        let data = self.data.lock();
        let mut out: Vec<ServiceHealth> = data
            .services
            .iter()
            .map(|(service, entries)| {
                let total = entries.len();
                let mut usable = 0usize;
                let mut breakdown = StatusBreakdown::default();
                let mut sum = 0.0f64;
                // Track the worst score; left at 0.0 when the service has no keys.
                let mut min = if total == 0 { 0.0 } else { f64::INFINITY };
                for e in entries {
                    if e.is_usable() {
                        usable += 1;
                    }
                    breakdown.record(e.status);
                    let score = e.health_score(now);
                    sum += score;
                    if score < min {
                        min = score;
                    }
                }
                // Mean over all keys; 0.0 for an empty service (avoids 0/0).
                let avg_health = if total == 0 { 0.0 } else { sum / total as f64 };
                ServiceHealth {
                    service: service.clone(),
                    total,
                    usable,
                    breakdown,
                    avg_health,
                    min_health: min,
                }
            })
            .collect();
        out.sort_by(|a, b| a.service.cmp(&b.service));
        out
    }
}
