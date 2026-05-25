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

// ── Key entry ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyStatus {
    Untested,
    Active,
    Exhausted,
    Invalid,
    RateLimited,
}

impl KeyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Untested => "untested",
            Self::Active => "active",
            Self::Exhausted => "exhausted",
            Self::Invalid => "invalid",
            Self::RateLimited => "rate_limited",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyEntry {
    pub value: String,
    pub status: KeyStatus,
    #[serde(default)]
    pub use_count: u64,
    #[serde(default)]
    pub last_used: Option<u64>,
    #[serde(default)]
    pub last_validated: Option<u64>,
    #[serde(default)]
    pub rate_limit_reset: Option<u64>,
    #[serde(default)]
    pub notes: Option<String>,
}

impl KeyEntry {
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            status: KeyStatus::Untested,
            use_count: 0,
            last_used: None,
            last_validated: None,
            rate_limit_reset: None,
            notes: None,
        }
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
            KeyStatus::Exhausted | KeyStatus::Invalid => false,
        }
    }
}

// ── Service definitions ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceDef {
    pub name: &'static str,
    pub env_var: &'static str,
    pub category: &'static str,
    pub test_url: &'static str,
    pub key_header: KeyPlacement,
    pub rate_limit_reset_secs: u64,
}

pub fn rate_limit_reset(service: &str) -> u64 {
    find_service(service)
        .map(|d| d.rate_limit_reset_secs)
        .unwrap_or(3600)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyPlacement {
    QueryParam(&'static str),
    Header(&'static str),
    BasicAuth,
    BearerAuth,
}

pub fn service_defs() -> Vec<ServiceDef> {
    vec![
        ServiceDef {
            name: "shodan",
            env_var: "HUNTSMAN_SHODAN_KEY",
            category: "infrastructure",
            test_url: "https://api.shodan.io/api-info?key=",
            key_header: KeyPlacement::QueryParam("key"),
            rate_limit_reset_secs: 300,
        },
        ServiceDef {
            name: "intelx",
            env_var: "HUNTSMAN_INTELX_KEY",
            category: "breach",
            test_url: "https://2.intelx.io/authenticate/info",
            key_header: KeyPlacement::Header("x-key"),
            rate_limit_reset_secs: 60,
        },
        ServiceDef {
            name: "securitytrails",
            env_var: "HUNTSMAN_SECTRAILS_KEY",
            category: "infrastructure",
            test_url: "https://api.securitytrails.com/v1/account/usage",
            key_header: KeyPlacement::Header("APIKEY"),
            rate_limit_reset_secs: 60,
        },
        ServiceDef {
            name: "leakix",
            env_var: "HUNTSMAN_LEAKIX_KEY",
            category: "breach",
            test_url: "https://leakix.net/api/subdomains/example.com",
            key_header: KeyPlacement::Header("api-key"),
            rate_limit_reset_secs: 60,
        },
        ServiceDef {
            name: "ipqs",
            env_var: "HUNTSMAN_IPQS_KEY",
            category: "threat_intel",
            test_url: "https://ipqualityscore.com/api/json/account/",
            key_header: KeyPlacement::QueryParam("key"),
            rate_limit_reset_secs: 60,
        },
        ServiceDef {
            name: "numverify",
            env_var: "HUNTSMAN_NUMVERIFY_KEY",
            category: "identity",
            test_url: "https://apilayer.net/api/validate?number=14158586273&access_key=",
            key_header: KeyPlacement::QueryParam("access_key"),
            rate_limit_reset_secs: 60,
        },
        ServiceDef {
            name: "criminal_ip",
            env_var: "HUNTSMAN_CRIMINALIP_KEY",
            category: "threat_intel",
            test_url: "https://api.criminalip.io/v1/user/me",
            key_header: KeyPlacement::Header("x-api-key"),
            rate_limit_reset_secs: 60,
        },
        ServiceDef {
            name: "virustotal",
            env_var: "HUNTSMAN_VIRUSTOTAL_KEY",
            category: "threat_intel",
            test_url: "https://www.virustotal.com/api/v3/urls",
            key_header: KeyPlacement::Header("x-apikey"),
            rate_limit_reset_secs: 15,
        },
        ServiceDef {
            name: "wigle",
            env_var: "HUNTSMAN_WIGLE_TOKEN",
            category: "geoint",
            test_url: "https://api.wigle.net/api/v2/profile/user",
            key_header: KeyPlacement::Header("Authorization"),
            rate_limit_reset_secs: 60,
        },
        ServiceDef {
            name: "hunter",
            env_var: "HUNTSMAN_HUNTER_KEY",
            category: "identity",
            test_url: "https://api.hunter.io/v2/account?api_key=",
            key_header: KeyPlacement::QueryParam("api_key"),
            rate_limit_reset_secs: 4,
        },
        ServiceDef {
            name: "hibp",
            env_var: "HUNTSMAN_HIBP_KEY",
            category: "breach",
            test_url: "https://haveibeenpwned.com/api/v3/breaches",
            key_header: KeyPlacement::Header("hibp-api-key"),
            rate_limit_reset_secs: 6,
        },
        ServiceDef {
            name: "dehashed",
            env_var: "HUNTSMAN_DEHASHED_KEY",
            category: "breach",
            test_url: "https://api.dehashed.com/search?query=email:test@example.com&size=1",
            key_header: KeyPlacement::BasicAuth,
            rate_limit_reset_secs: 60,
        },
        ServiceDef {
            name: "threatfox",
            env_var: "HUNTSMAN_THREATFOX_KEY",
            category: "threat_intel",
            test_url: "https://threatfox-api.abuse.ch/api/v1/",
            key_header: KeyPlacement::Header("API-KEY"),
            rate_limit_reset_secs: 60,
        },
        ServiceDef {
            name: "passivetotal",
            env_var: "HUNTSMAN_PASSIVETOTAL_KEY",
            category: "infrastructure",
            test_url: "https://api.passivetotal.org/v2/account/quota",
            key_header: KeyPlacement::BasicAuth,
            rate_limit_reset_secs: 60,
        },
        ServiceDef {
            name: "onyphe",
            env_var: "HUNTSMAN_ONYPHE_KEY",
            category: "infrastructure",
            test_url: "https://www.onyphe.io/api/v2/simple/whois/best/8.8.8.8",
            key_header: KeyPlacement::BearerAuth,
            rate_limit_reset_secs: 60,
        },
        ServiceDef {
            name: "zoomeye",
            env_var: "HUNTSMAN_ZOOMEYE_KEY",
            category: "infrastructure",
            test_url: "https://api.zoomeye.org/resources-info",
            key_header: KeyPlacement::Header("API-KEY"),
            rate_limit_reset_secs: 60,
        },
        ServiceDef {
            name: "fofa",
            env_var: "HUNTSMAN_FOFA_KEY",
            category: "infrastructure",
            test_url: "https://fofa.info/api/v1/info/my",
            key_header: KeyPlacement::QueryParam("key"),
            rate_limit_reset_secs: 60,
        },
        ServiceDef {
            name: "netlas",
            env_var: "HUNTSMAN_NETLAS_KEY",
            category: "infrastructure",
            test_url: "https://app.netlas.io/api/users/current/",
            key_header: KeyPlacement::Header("X-API-Key"),
            rate_limit_reset_secs: 60,
        },
        ServiceDef {
            name: "pulsedive",
            env_var: "HUNTSMAN_PULSEDIVE_KEY",
            category: "threat_intel",
            test_url: "https://pulsedive.com/api/info.php?indicator=pulsedive.com&key=",
            key_header: KeyPlacement::QueryParam("key"),
            rate_limit_reset_secs: 30,
        },
        ServiceDef {
            name: "builtwith",
            env_var: "HUNTSMAN_BUILTWITH_KEY",
            category: "infrastructure",
            test_url: "https://api.builtwith.com/usagev2/api.json?KEY=",
            key_header: KeyPlacement::QueryParam("KEY"),
            rate_limit_reset_secs: 60,
        },
        ServiceDef {
            name: "emailrep",
            env_var: "HUNTSMAN_EMAILREP_KEY",
            category: "identity",
            test_url: "https://emailrep.io/test@example.com",
            key_header: KeyPlacement::Header("Key"),
            rate_limit_reset_secs: 60,
        },
        ServiceDef {
            name: "whoisxml",
            env_var: "HUNTSMAN_WHOISXML_KEY",
            category: "infrastructure",
            test_url: "https://www.whoisxmlapi.com/whoisserver/WhoisService?domainName=example.com&outputFormat=JSON&apiKey=",
            key_header: KeyPlacement::QueryParam("apiKey"),
            rate_limit_reset_secs: 60,
        },
        ServiceDef {
            name: "breachdirectory",
            env_var: "HUNTSMAN_BREACHDIR_KEY",
            category: "breach",
            test_url: "https://breachdirectory.p.rapidapi.com/?func=auto&term=test@example.com",
            key_header: KeyPlacement::Header("X-RapidAPI-Key"),
            rate_limit_reset_secs: 60,
        },
        ServiceDef {
            name: "c99",
            env_var: "HUNTSMAN_C99_KEY",
            category: "infrastructure",
            test_url: "https://api.c99.nl/",
            key_header: KeyPlacement::QueryParam("key"),
            rate_limit_reset_secs: 60,
        },
    ]
}

pub fn find_service(name: &str) -> Option<ServiceDef> {
    let lower = name.to_lowercase();
    service_defs().into_iter().find(|s| s.name == lower)
}

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
        let mut data = self.data.lock();
        let entries = data.services.entry(service.to_lowercase()).or_default();
        if entries.iter().any(|e| e.value == key.value) {
            return false;
        }
        entries.push(key);
        true
    }

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

        for _ in 0..len {
            let entry = &mut entries[*idx % len];
            *idx = idx.wrapping_add(1);
            if entry.is_usable() {
                entry.use_count += 1;
                entry.last_used = Some(crate::core::entity::unix_now());
                return Some(entry.value.clone());
            }
        }
        None
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
            .map_or(0, |e| e.len())
    }

    pub fn active_count(&self, service: &str) -> usize {
        let data = self.data.lock();
        data.services
            .get(&service.to_lowercase())
            .map_or(0, |entries| {
                entries.iter().filter(|e| e.is_usable()).count()
            })
    }

    pub fn total_keys(&self) -> usize {
        let data = self.data.lock();
        data.services.values().map(|v| v.len()).sum()
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
            Err(_) => KeyPool::new(),
        },
        Err(_) => KeyPool::new(),
    }
}

pub fn save_pool(pool: &KeyPool) -> std::io::Result<()> {
    let path = pool_path();
    let data = pool.snapshot();
    let json = serde_json::to_string_pretty(&data).map_err(std::io::Error::other)?;
    std::fs::write(&path, json)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

// ── Validation ───────────────────────────────────────────────────────────────

pub async fn validate_key(service: &str, key: &str) -> Option<bool> {
    let sdef = find_service(service)?;
    let result = validate_against_endpoint(sdef, key).await;
    Some(result)
}

async fn validate_against_endpoint(sdef: ServiceDef, key: &str) -> bool {
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
        .and_then(|r| r.ok());

    let Some(output) = output else { return false };
    let code = String::from_utf8_lossy(&output.stdout);
    let code = code.trim();
    matches!(code, "200" | "201" | "204" | "301" | "302")
}

// ── Integration with ModuleContext keys ──────────────────────────────────────

pub fn merge_pool_into_env(pool: &KeyPool, keys: &mut HashMap<String, String>) {
    let defs = service_defs();
    for sdef in &defs {
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
        for d in &defs {
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
}
