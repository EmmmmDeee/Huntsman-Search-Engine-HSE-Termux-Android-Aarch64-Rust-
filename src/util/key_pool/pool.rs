//! `PoolData` and `KeyPool` — the in-memory pool structure and all mutation methods.

use std::collections::HashMap;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use super::types::{KeyEntry, KeyStatus, KeyTier};

/// Per-service rate-limit reset window. Imported from service_defs via the parent module.
pub(super) use crate::util::service_defs::rate_limit_reset;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PoolData {
    pub services: HashMap<String, Vec<KeyEntry>>,
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
    pub(super) indices: Mutex<HashMap<String, usize>>,
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
            indices: Mutex::new(HashMap::new()),
        }
    }

    pub fn from_data(data: PoolData) -> Self {
        Self {
            data: Mutex::new(data),
            indices: Mutex::new(HashMap::new()),
        }
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
        if let Some(existing) = entries.iter_mut().find(|e| e.value == key.value) {
            // Duplicate value: not a NEW key, but an independent re-observation of
            // one we already hold. Fold it in as corroboration (the pool-layer
            // verified-duplicate signal that lifts the key's health_score and
            // shields it from pruning) instead of discarding it silently. Still
            // returns `false` — no new entry was added, so callers counting
            // additions and the idempotent-import contract are unchanged.
            existing.record_corroboration();
            return false;
        }
        entries.push(key);
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
    /// within a service, so re-importing an export is idempotent. An `environment`
    /// override stamps every imported key with that label (useful for slotting a
    /// teammate's export into your "shared" env). Returns the number of keys newly
    /// added.
    ///
    /// A duplicate value is GREATEST-merged ([`KeyEntry::greatest_merge`]) rather
    /// than discarded, so restoring a backup never REDUCES the accumulated
    /// self-funding value (corroboration, usage, validation) already held — it only
    /// ever keeps the greater. This is what makes the pool a perpetual,
    /// loss-resistant store of harvested value across re-imports and merges.
    pub fn import_json(&self, json: &str, environment: Option<&str>) -> serde_json::Result<usize> {
        let incoming: PoolData = serde_json::from_str(json)?;
        let mut added = 0usize;
        for (service, entries) in incoming.services {
            for mut entry in entries {
                if let Some(env) = environment {
                    entry.environment = Some(env.to_string());
                }
                if self.merge_or_add(&service, entry) {
                    added += 1;
                }
            }
        }
        Ok(added)
    }

    /// Import one entry, GREATEST-merging it when the value is already pooled.
    ///
    /// Unlike [`Self::add`] (whose duplicate path folds a single *re-observation*
    /// into `+1` corroboration), this preserves the FULL accumulated telemetry of
    /// the incoming record by merging it field-by-field with
    /// [`KeyEntry::greatest_merge`] — so importing a backup that holds more value
    /// than the live pool retains that value rather than throwing it away. Returns
    /// `true` only when a genuinely new key was added.
    fn merge_or_add(&self, service: &str, entry: KeyEntry) -> bool {
        // Same poolability gate as `add`: only reusable keyed-provider keys are
        // retained, so an import cannot bloat the pool with non-poolable values.
        if !crate::util::service_defs::is_poolable_service(service) {
            return false;
        }
        let mut data = self.data.lock();
        let entries = data.services.entry(service.to_lowercase()).or_default();
        if let Some(existing) = entries.iter_mut().find(|e| e.value == entry.value) {
            existing.greatest_merge(&entry);
            return false;
        }
        entries.push(entry);
        true
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
    /// Every USABLE key is eligible regardless of provenance — a key HSE
    /// discovered while scanning is reusable by the cascade, by design. The
    /// `discovered_by` field records origin for `keys list` reporting only; it
    /// does not gate selection.
    ///
    /// Among the USABLE keys (cooled-down / invalid / revoked already filtered by
    /// [`KeyEntry::is_usable`]) it serves the one with the greatest live
    /// [`KeyEntry::selection_rank`] — highest tier, healthiest, then
    /// least-recently-used — so requests fan out across the pool and no single key
    /// is driven to its rate limit. A key's [`KeyEntry::corroboration`] count is a
    /// final tiebreak *after* idleness, so among otherwise-identical keys a proven,
    /// independently re-confirmed credential is preferred without disturbing the
    /// load-spreading. The round-robin start makes any remaining ties deterministic
    /// and adds extra spread. The selection mutates telemetry
    /// (`use_count`/`last_used`), so the *next* call sees the load it just placed
    /// and naturally moves on to the next-idlest key.
    pub fn next_key(&self, service: &str) -> Option<String> {
        let lower = service.to_lowercase();
        let now = crate::core::entity::unix_now();
        let mut data = self.data.lock();
        let entries = data.services.get_mut(&lower)?;
        if entries.is_empty() {
            return None;
        }

        let mut indices = self.indices.lock();
        let idx = indices.entry(lower.clone()).or_insert(0);
        let len = entries.len();

        let mut best: Option<usize> = None;
        let mut best_key: Option<((KeyTier, u8, u64), u32)> = None;
        for offset in 0..len {
            let i = (*idx + offset) % len;
            let entry = &entries[i];
            if !entry.is_usable() {
                continue;
            }
            // Compare on (selection_rank, corroboration): the rank decides exactly
            // as before, and corroboration is a FINAL tiebreak so that among
            // otherwise-equal keys (same tier / health band / idleness) a proven,
            // independently re-confirmed credential is preferred — without
            // disturbing the load-spreading that idleness drives. Uncorroborated
            // keys all carry 0, so this is identical to the prior behaviour whenever
            // no key in the service is corroborated.
            let key = (entry.selection_rank(now), entry.corroboration);
            // Strict `>`: the FIRST key at the best (rank, corroboration) in rotated
            // scan order wins, so equal keys round-robin via the start index.
            if best_key.is_none_or(|b| key > b) {
                best = Some(i);
                best_key = Some(key);
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
        *idx = i.wrapping_add(1);
        Some(entry.value.clone())
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
    /// High-value keys (Standard/Premium tier) and independently corroborated
    /// keys are **always retained**: a scarce, expensive credential — or one
    /// re-confirmed across multiple independent sightings — is not discarded over a
    /// transient error streak; the operator revokes those deliberately. Trial/Basic,
    /// uncorroborated keys prune normally.
    pub fn prune_degraded(&self, min_success_rate: f64, min_uses: u64) -> usize {
        let mut data = self.data.lock();
        let mut pruned = 0;
        for entries in data.services.values_mut() {
            let before = entries.len();
            entries.retain(|e| {
                e.tier >= KeyTier::Standard
                    || e.is_corroborated()
                    || e.use_count < min_uses
                    || e.success_rate() >= min_success_rate
            });
            pruned += before - entries.len();
        }
        pruned
    }

    pub fn remove(&self, service: &str, value: &str) -> bool {
        let lower = service.to_lowercase();
        let mut data = self.data.lock();
        if let Some(entries) = data.services.get_mut(&lower) {
            let before = entries.len();
            entries.retain(|e| e.value != value);
            return entries.len() < before;
        }
        false
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
