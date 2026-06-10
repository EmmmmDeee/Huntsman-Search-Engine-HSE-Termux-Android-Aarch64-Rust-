//! Multi-key pool manager with per-service cycling, validation, and
//! rate-limit awareness. Complements `util/keys.rs` (single env-var
//! keys) by supporting multiple keys per service with intelligent
//! rotation.
//!
//! Storage: `$HOME/.huntsman/key_pool.json` (mode 0600).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
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

// ── Key entry ────────────────────────────────────────────────────────────────

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
}

// ── Service definitions ──────────────────────────────────────────────────────

// Service definitions extracted to service_defs.rs
pub use super::service_defs::*;

// ── Pool ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PoolData {
    pub services: HashMap<String, Vec<KeyEntry>>,
}

pub struct KeyPool {
    data: Mutex<PoolData>,
    indices: Mutex<HashMap<String, usize>>,
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

    /// Revoke the key in `service` whose [`key_id`] matches `id`. Lets the web UI
    /// revoke a key by its non-secret short id without ever transmitting the
    /// plaintext value. Returns true if found.
    pub fn revoke_by_id(&self, service: &str, id: &str) -> bool {
        let mut data = self.data.lock();
        if let Some(entries) = data.services.get_mut(&service.to_lowercase()) {
            for e in entries.iter_mut() {
                if key_id(&e.value) == id {
                    e.status = KeyStatus::Revoked;
                    return true;
                }
            }
        }
        false
    }

    /// Rotate the key in `service` whose [`key_id`] matches `id` to `new` — the
    /// web/API counterpart to [`Self::rotate`], identifying the old key by its
    /// non-secret id so its plaintext never has to be sent back to rotate it.
    /// Returns true if a key with that id was found.
    pub fn rotate_by_id(&self, service: &str, id: &str, new: &str) -> bool {
        let old = {
            let data = self.data.lock();
            data.services
                .get(&service.to_lowercase())
                .and_then(|es| es.iter().find(|e| key_id(&e.value) == id))
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

// ── Persistence ──────────────────────────────────────────────────────────────

pub fn pool_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    let dir = PathBuf::from(home).join(".huntsman");
    let _ = std::fs::create_dir_all(&dir);
    dir.join("key_pool.json")
}

pub fn load_pool() -> KeyPool {
    let path = pool_path();
    match std::fs::read_to_string(&path) {
        Ok(content) => match serde_json::from_str::<PoolData>(&content) {
            Ok(data) => KeyPool::from_data(data),
            Err(e) => {
                tracing::warn!(
                    "key pool at {} is corrupted ({e}); backing up and starting fresh",
                    path.display()
                );
                let backup = path.with_extension("json.bak");
                let _ = std::fs::rename(&path, &backup);
                KeyPool::new()
            }
        },
        Err(_) => KeyPool::new(),
    }
}

pub fn save_pool(pool: &KeyPool) -> std::io::Result<()> {
    let path = pool_path();
    let data = pool.snapshot();
    let json = serde_json::to_string_pretty(&data).map_err(std::io::Error::other)?;
    // Atomic write via the shared helper: a UNIQUE temp + fsync + rename. A plain
    // truncate-then-write leaves corrupt/truncated JSON if the process is killed
    // mid-write (the OOM-killer is realistic on a 4 GB device), and `load_pool`
    // then discards EVERY harvested key. The unique temp also makes concurrent
    // saves safe: modules harvest keys during overlapping scans in `hse serve`,
    // and a shared fixed temp could be interleaved by two writers into a corrupt
    // file. The rename is atomic on the same filesystem, so a crash leaves the
    // previous valid pool intact.
    crate::util::atomic_file::write(&path, json.as_bytes())
}

/// Write secret text (an exported key pool) to an arbitrary path with `0600`
/// permissions, atomically. Shared by `hse keys export --out` so an exported
/// secret is never left world-readable.
pub fn write_secret_file(path: &str, contents: &str) -> std::io::Result<()> {
    crate::util::atomic_file::write(std::path::Path::new(path), contents.as_bytes())
}

/// Persist the pool, logging (not propagating) any failure.
///
/// Use this at the fire-and-forget sites that harvest keys during a scan: a
/// persistence failure there must not abort the scan, but it must not be silent
/// either. `save_pool` takes pains to write atomically so harvested keys survive
/// a crash; dropping its error with `let _ =` would mean a disk-full / read-only
/// `$HOME` (both realistic on a Termux device) silently discards every key
/// harvested this run with no trace to debug from. Callers that genuinely need
/// to surface the failure to a user (e.g. CLI key-management commands) should
/// call [`save_pool`] directly and handle the `Result`.
pub fn save_pool_best_effort(pool: &KeyPool) {
    if let Err(e) = save_pool(pool) {
        tracing::warn!(
            error = %e,
            path = %pool_path().display(),
            "failed to persist harvested API keys — they will be lost when the process exits"
        );
    }
}

// ── Validation ───────────────────────────────────────────────────────────────

/// Add a key and validate it immediately against the service endpoint.
/// If valid, marks it Active and stores it. If invalid, marks it Invalid
/// but still stores it (won't be used by next_key).
/// Returns true if the key is valid and was stored.
pub async fn add_and_validate(service: &str, key_value: &str, notes: Option<String>) -> bool {
    let pool = global_pool();
    let mut entry = KeyEntry::new(key_value);
    entry.notes = notes;

    if let Some(valid) = validate_key(service, key_value).await {
        if valid {
            entry.status = KeyStatus::Active;
            entry.last_validated = Some(crate::core::entity::unix_now());
            let added = pool.add(service, entry);
            if added {
                save_pool_best_effort(&pool);
                tracing::info!(service, "validated and stored API key");
            }
            true
        } else {
            entry.status = KeyStatus::Invalid;
            entry.last_validated = Some(crate::core::entity::unix_now());
            pool.add(service, entry);
            save_pool_best_effort(&pool);
            tracing::warn!(service, "API key failed validation — stored as invalid");
            false
        }
    } else {
        pool.add(service, entry);
        save_pool_best_effort(&pool);
        false
    }
}

pub async fn validate_key(service: &str, key: &str) -> Option<bool> {
    let sdef = find_service(service)?;
    let result = validate_against_endpoint(sdef, key).await;
    Some(result)
}

async fn validate_against_endpoint(sdef: &ServiceDef, key: &str) -> bool {
    let timeout_ms = 10_000u64;
    let secs = (timeout_ms / 1000).to_string();

    let mut cmd = tokio::process::Command::new("curl");
    cmd.args([
        "-s",
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}",
        "--max-time",
        &secs,
    ]);

    match sdef.key_header {
        KeyPlacement::QueryParam(param) => {
            let url = if sdef.test_url.contains('?') {
                if sdef.test_url.ends_with('=') {
                    format!("{}{}", sdef.test_url, key)
                } else {
                    format!("{}&{}={}", sdef.test_url, param, key)
                }
            } else {
                format!("{}?{}={}", sdef.test_url, param, key)
            };
            cmd.args(["--", &url]);
        }
        KeyPlacement::Header(header) => {
            let h = format!("{header}: {key}");
            cmd.args(["-H", &h, "--", sdef.test_url]);
        }
        KeyPlacement::BasicAuth => {
            cmd.args(["-u", key, "--", sdef.test_url]);
        }
        KeyPlacement::BearerAuth => {
            let h = format!("Authorization: bearer {key}");
            cmd.args(["-H", &h, "--", sdef.test_url]);
        }
    }

    cmd.kill_on_drop(true);

    let output = tokio::time::timeout(Duration::from_millis(timeout_ms + 2000), cmd.output())
        .await
        .ok()
        .and_then(std::result::Result::ok);

    let Some(output) = output else { return false };
    let code = String::from_utf8_lossy(&output.stdout);
    let code = code.trim();
    matches!(code, "200" | "201" | "204" | "301" | "302")
}

// ── Integration with ModuleContext keys ──────────────────────────────────────

pub fn merge_pool_into_env(pool: &KeyPool, keys: &mut HashMap<String, String>) {
    let defs = service_defs();
    for sdef in defs {
        if keys.contains_key(sdef.env_var) {
            continue;
        }
        if let Some(val) = pool.next_key(sdef.name) {
            keys.insert(sdef.env_var.to_string(), val);
        }
    }
}

// ── Shared pool singleton ────────────────────────────────────────────────────

static GLOBAL_POOL: std::sync::OnceLock<Arc<KeyPool>> = std::sync::OnceLock::new();

pub fn global_pool() -> Arc<KeyPool> {
    Arc::clone(GLOBAL_POOL.get_or_init(|| Arc::new(load_pool())))
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_import_roundtrips_and_is_idempotent() {
        let src = KeyPool::new();
        let mut a = KeyEntry::new("key-a");
        a.environment = Some("prod".into());
        src.add("shodan", a);
        src.add("intelx", KeyEntry::new("key-b")); // default env

        let json = src.export_json(None).unwrap();
        let dst = KeyPool::new();
        assert_eq!(
            dst.import_json(&json, None).unwrap(),
            2,
            "both keys imported"
        );
        // Re-import is idempotent (dedup by value).
        assert_eq!(dst.import_json(&json, None).unwrap(), 0, "no duplicates");
        // Environment survives the round-trip.
        let snap = dst.snapshot();
        assert_eq!(snap.services["shodan"][0].environment(), "prod");
        assert_eq!(snap.services["intelx"][0].environment(), "default");
    }

    #[test]
    fn export_filters_by_environment() {
        let pool = KeyPool::new();
        let mut p = KeyEntry::new("prod-key");
        p.environment = Some("prod".into());
        pool.add("shodan", p);
        pool.add("shodan", KeyEntry::new("default-key")); // default env

        let only_prod = pool.export_json(Some("prod")).unwrap();
        assert!(only_prod.contains("prod-key"));
        assert!(
            !only_prod.contains("default-key"),
            "env filter must exclude other environments"
        );
    }

    #[test]
    fn revoke_and_rotate_by_id_reference_keys_without_plaintext() {
        let pool = KeyPool::new();
        let mut p = KeyEntry::new("old-secret");
        p.environment = Some("prod".into());
        pool.add("shodan", p);
        let id = key_id("old-secret");
        assert_ne!(id, "old-secret", "id is a hash, not the value");

        // Rotate by id: old revoked (retained), new added in the same env, served.
        assert!(pool.rotate_by_id("shodan", &id, "new-secret"));
        let snap = pool.snapshot();
        let entries = &snap.services["shodan"];
        let old = entries.iter().find(|e| e.value == "old-secret").unwrap();
        let new = entries.iter().find(|e| e.value == "new-secret").unwrap();
        assert_eq!(old.status, KeyStatus::Revoked);
        assert_eq!(new.environment(), "prod");
        assert_eq!(pool.next_key("shodan").as_deref(), Some("new-secret"));

        // Revoke the new key by its id.
        assert!(pool.revoke_by_id("shodan", &key_id("new-secret")));
        assert_eq!(pool.next_key("shodan"), None);
        // Unknown id is a no-op.
        assert!(!pool.revoke_by_id("shodan", "00ff00ff00ff"));
        assert!(!pool.rotate_by_id("shodan", "00ff00ff00ff", "x"));
    }

    #[test]
    fn revoke_makes_a_key_unusable_but_retained() {
        let pool = KeyPool::new();
        pool.add("shodan", KeyEntry::new("compromised"));
        assert_eq!(pool.next_key("shodan").as_deref(), Some("compromised"));
        assert!(pool.revoke("shodan", "compromised"));
        // Retained for audit…
        assert_eq!(pool.snapshot().services["shodan"].len(), 1);
        assert_eq!(
            pool.snapshot().services["shodan"][0].status,
            KeyStatus::Revoked
        );
        // …but never selected again.
        assert_eq!(
            pool.next_key("shodan"),
            None,
            "revoked key must not be used"
        );
        assert!(!pool.revoke("shodan", "nonexistent"));
    }

    #[test]
    fn rotate_revokes_old_adds_new_carrying_environment() {
        let pool = KeyPool::new();
        let mut old = KeyEntry::new("old-key");
        old.environment = Some("prod".into());
        old.notes = Some("primary".into());
        pool.add("shodan", old);

        assert!(pool.rotate("shodan", "old-key", "new-key"));
        let snap = pool.snapshot();
        let entries = &snap.services["shodan"];
        let old_e = entries.iter().find(|e| e.value == "old-key").unwrap();
        let new_e = entries.iter().find(|e| e.value == "new-key").unwrap();
        assert_eq!(old_e.status, KeyStatus::Revoked, "old key revoked");
        assert_eq!(new_e.environment(), "prod", "new key inherits environment");
        assert_eq!(
            new_e.notes.as_deref(),
            Some("primary"),
            "provenance carried"
        );
        assert!(new_e.rotated_at.is_some(), "rotation timestamp stamped");
        // The pool now serves the new key, not the revoked old one.
        assert_eq!(pool.next_key("shodan").as_deref(), Some("new-key"));
        // Rotating a missing key is a no-op.
        assert!(!pool.rotate("shodan", "ghost", "x"));
    }

    #[test]
    fn add_and_cycle() {
        let pool = KeyPool::new();
        assert!(pool.add("shodan", KeyEntry::new("key-a")));
        assert!(pool.add("shodan", KeyEntry::new("key-b")));
        assert!(!pool.add("shodan", KeyEntry::new("key-a")));

        assert_eq!(pool.service_count("shodan"), 2);

        let k1 = pool.next_key("shodan").unwrap();
        let k2 = pool.next_key("shodan").unwrap();
        let k3 = pool.next_key("shodan").unwrap();
        assert_eq!(k1, "key-a");
        assert_eq!(k2, "key-b");
        assert_eq!(k3, "key-a");
    }

    #[test]
    fn skips_invalid_keys() {
        let pool = KeyPool::new();
        pool.add("intelx", KeyEntry::new("good"));
        pool.add("intelx", KeyEntry::new("bad"));
        pool.mark_status("intelx", "bad", KeyStatus::Invalid);

        let k1 = pool.next_key("intelx").unwrap();
        let k2 = pool.next_key("intelx").unwrap();
        assert_eq!(k1, "good");
        assert_eq!(k2, "good");
    }

    #[test]
    fn mark_validated() {
        let pool = KeyPool::new();
        pool.add("shodan", KeyEntry::new("test-key"));
        pool.mark_validated("shodan", "test-key", true);

        let snap = pool.snapshot();
        let entry = &snap.services["shodan"][0];
        assert_eq!(entry.status, KeyStatus::Active);
        assert!(entry.last_validated.is_some());
    }

    #[test]
    fn remove_key() {
        let pool = KeyPool::new();
        pool.add("shodan", KeyEntry::new("k1"));
        pool.add("shodan", KeyEntry::new("k2"));
        assert!(pool.remove("shodan", "k1"));
        assert_eq!(pool.service_count("shodan"), 1);
        assert!(!pool.remove("shodan", "k1"));
    }

    #[test]
    fn empty_service_returns_none() {
        let pool = KeyPool::new();
        assert!(pool.next_key("nonexistent").is_none());
    }

    #[test]
    fn case_insensitive_service() {
        let pool = KeyPool::new();
        pool.add("Shodan", KeyEntry::new("k1"));
        assert!(pool.next_key("shodan").is_some());
        assert!(pool.next_key("SHODAN").is_some());
    }

    #[test]
    fn merge_fills_gaps() {
        let pool = KeyPool::new();
        pool.add("shodan", KeyEntry::new("pool-key"));

        let mut keys = HashMap::new();
        merge_pool_into_env(&pool, &mut keys);
        assert_eq!(keys.get("HUNTSMAN_SHODAN_KEY").unwrap(), "pool-key");
    }

    #[test]
    fn merge_does_not_override_existing() {
        let pool = KeyPool::new();
        pool.add("shodan", KeyEntry::new("pool-key"));

        let mut keys = HashMap::new();
        keys.insert("HUNTSMAN_SHODAN_KEY".to_string(), "env-key".to_string());
        merge_pool_into_env(&pool, &mut keys);
        assert_eq!(keys.get("HUNTSMAN_SHODAN_KEY").unwrap(), "env-key");
    }

    #[test]
    fn all_services_defined() {
        let defs = service_defs();
        assert!(defs.len() >= 24);
        for d in defs {
            assert!(d.env_var.starts_with("HUNTSMAN_"));
            assert!(!d.test_url.is_empty());
        }
    }

    #[test]
    fn find_service_works() {
        assert!(find_service("shodan").is_some());
        assert!(find_service("intelx").is_some());
        assert!(find_service("nonexistent").is_none());
    }

    #[test]
    fn tier_ordering() {
        assert!(KeyTier::Premium > KeyTier::Standard);
        assert!(KeyTier::Standard > KeyTier::Basic);
        assert!(KeyTier::Basic > KeyTier::Trial);
    }

    #[test]
    fn next_key_prefers_higher_tier() {
        let pool = KeyPool::new();
        let mut basic = KeyEntry::new("basic-key");
        basic.tier = KeyTier::Basic;
        basic.status = KeyStatus::Active;
        let mut premium = KeyEntry::new("premium-key");
        premium.tier = KeyTier::Premium;
        premium.status = KeyStatus::Active;
        pool.add("shodan", basic);
        pool.add("shodan", premium);

        let k = pool.next_key("shodan").unwrap();
        assert_eq!(k, "premium-key", "should prefer higher-tier key");
    }

    #[test]
    fn next_key_avoids_error_prone_key() {
        let pool = KeyPool::new();
        let mut good = KeyEntry::new("good-key");
        good.status = KeyStatus::Active;
        good.error_count = 0;
        let mut bad = KeyEntry::new("bad-key");
        bad.status = KeyStatus::Active;
        bad.error_count = 50;
        pool.add("shodan", good);
        pool.add("shodan", bad);

        let k = pool.next_key("shodan").unwrap();
        assert_eq!(k, "good-key", "should prefer key with fewer errors");
    }

    #[test]
    fn add_rejects_non_poolable_services() {
        // The pool only holds reusable provider keys; the harvest catch-alls
        // (generic_hex, crypto_*, jwt_token, <svc>_login) must never enter it,
        // regardless of which ingest path calls add() — this is the chokepoint
        // that stopped a 6 MB generic_hex pool.
        let pool = KeyPool::new();
        assert!(
            pool.add("shodan", KeyEntry::new("real")),
            "provider key pools"
        );
        assert!(!pool.add("generic_hex", KeyEntry::new("deadbeefdeadbeef")));
        assert!(!pool.add("crypto_sol", KeyEntry::new("So11111111111111")));
        assert!(!pool.add("shodan_login", KeyEntry::new("user:pass")));
        assert_eq!(pool.service_count("generic_hex"), 0);
        assert_eq!(pool.service_count("shodan"), 1);
    }

    #[test]
    fn record_error_increments() {
        let pool = KeyPool::new();
        pool.add("shodan", KeyEntry::new("k1"));
        pool.record_error("shodan", "k1");
        pool.record_error("shodan", "k1");
        let snap = pool.snapshot();
        assert_eq!(snap.services["shodan"][0].error_count, 2);
    }

    #[test]
    fn success_rate_calculation() {
        let mut e = KeyEntry::new("k");
        assert!((e.success_rate() - 1.0).abs() < 1e-9, "unused key = 100%");
        e.use_count = 10;
        e.error_count = 3;
        assert!((e.success_rate() - 0.7).abs() < 1e-9);
    }

    #[test]
    fn prune_degraded_removes_bad_keys() {
        let pool = KeyPool::new();
        let mut good = KeyEntry::new("good");
        good.use_count = 100;
        good.error_count = 5;
        let mut bad = KeyEntry::new("bad");
        bad.use_count = 100;
        bad.error_count = 90;
        pool.add("shodan", good);
        pool.add("shodan", bad);

        let pruned = pool.prune_degraded(0.50, 10);
        assert_eq!(pruned, 1);
        assert_eq!(pool.service_count("shodan"), 1);
        assert!(pool.next_key("shodan").unwrap() == "good");
    }

    #[test]
    fn prune_degraded_spares_low_use_keys() {
        let pool = KeyPool::new();
        let mut new_key = KeyEntry::new("new");
        new_key.use_count = 2;
        new_key.error_count = 2;
        pool.add("shodan", new_key);

        let pruned = pool.prune_degraded(0.50, 10);
        assert_eq!(pruned, 0, "keys below min_uses should be spared");
    }
}
