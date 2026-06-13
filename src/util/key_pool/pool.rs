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
        if entries.iter().any(|e| e.value == key.value) {
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

    /// Select the optimal key for a service. Prefers higher-tier keys with
    /// better success rates. Falls back to round-robin among equally-ranked
    /// candidates so no single key is over-used.
    pub fn next_key(&self, service: &str) -> Option<String> {
        let lower = service.to_lowercase();
        let mut data = self.data.lock();
        let entries = data.services.get_mut(&lower)?;
        if entries.is_empty() {
            return None;
        }

        let mut indices = self.indices.lock();
        let idx = indices.entry(lower.clone()).or_insert(0);
        let len = entries.len();

        let mut best: Option<usize> = None;
        let mut best_score: (KeyTier, u64) = (KeyTier::Trial, u64::MAX);

        for offset in 0..len {
            let i = (*idx + offset) % len;
            let entry = &entries[i];
            if !entry.is_usable() {
                continue;
            }
            let score = (entry.tier, u64::MAX - entry.error_count);
            if best.is_none() || score > best_score {
                best = Some(i);
                best_score = score;
            }
        }

        if let Some(i) = best {
            let entry = &mut entries[i];
            entry.use_count += 1;
            entry.last_used = Some(crate::core::entity::unix_now());
            *idx = i.wrapping_add(1);
            Some(entry.value.clone())
        } else {
            None
        }
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

    /// Remove keys with error rates above the threshold. Returns the number
    /// of keys pruned.
    pub fn prune_degraded(&self, max_error_rate: f64, min_uses: u64) -> usize {
        let mut data = self.data.lock();
        let mut pruned = 0;
        for entries in data.services.values_mut() {
            let before = entries.len();
            entries.retain(|e| e.use_count < min_uses || e.success_rate() >= max_error_rate);
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
}
