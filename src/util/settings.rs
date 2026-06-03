//! Persisted feature/capability toggles — the foundation of HSE's universal
//! toggleability (SpiderFoot-style on/off switches).
//!
//! Boolean switches keyed by a stable string (e.g. `engine.google`) so any
//! capability can be turned on or off without a rebuild. Only *overrides* are
//! stored; an absent key resolves to the caller's `default`, so the registry of
//! defaults lives in code and the file stays minimal (and forward-compatible —
//! new toggles default sanely on an old settings file). Persisted to
//! `~/.huntsman/settings.json` (atomic temp + fsync + rename, mode 0600) and
//! cached in-process for fast reads on hot paths (the search dispatch loop
//! checks a toggle per engine). Mutated via `hse config` (and, later, the web
//! Settings panel / a `/api/v1/settings/toggles` endpoint).

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, RwLock};

/// In-process cache of the override map, loaded once from disk. Reads on hot
/// paths hit this, never the filesystem.
static CACHE: LazyLock<RwLock<BTreeMap<String, bool>>> =
    LazyLock::new(|| RwLock::new(read_map(&settings_path())));

/// `~/.huntsman/settings.json` (same dir as the key pool / DB).
pub fn settings_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    let dir = PathBuf::from(home).join(".huntsman");
    let _ = std::fs::create_dir_all(&dir);
    dir.join("settings.json")
}

/// Read the override map from `path`. Empty on missing/corrupt — toggles are a
/// cache of defaults, never load-bearing state, so a parse error is non-fatal.
fn read_map(path: &Path) -> BTreeMap<String, bool> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// Atomically write the override map to `path`: temp file + fsync + rename, mode
/// 0600. Mirrors `key_pool::save_pool` / `keys::write_keys_at`.
fn write_map_at(path: &Path, map: &BTreeMap<String, bool>) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(map).map_err(std::io::Error::other)?;
    let tmp = path.with_extension("json.tmp");
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(json.as_bytes())?;
        f.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&tmp, json.as_bytes())?;
    }
    std::fs::rename(&tmp, path)
}

/// Pure resolution: stored override else `default`. Split out for testing.
fn resolve(map: &BTreeMap<String, bool>, key: &str, default: bool) -> bool {
    map.get(key).copied().unwrap_or(default)
}

/// Resolve a boolean toggle: the stored override, else `default`.
#[must_use]
pub fn get_bool(key: &str, default: bool) -> bool {
    let guard = CACHE
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    resolve(&guard, key, default)
}

/// Set and persist a toggle. Updates the in-process cache immediately so the
/// change is visible without a restart, then writes the file atomically.
pub fn set_bool(key: &str, value: bool) -> std::io::Result<()> {
    let snapshot = {
        let mut m = CACHE
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        m.insert(key.to_string(), value);
        m.clone()
    };
    write_map_at(&settings_path(), &snapshot)
}

/// All stored overrides (for `hse config` listing / the settings API).
#[must_use]
pub fn overrides() -> BTreeMap<String, bool> {
    CACHE
        .read()
        .map(|m| m.clone())
        .unwrap_or_else(|e| e.into_inner().clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn resolve_uses_override_then_default() {
        let mut m = BTreeMap::new();
        m.insert("engine.google".to_string(), false);
        // Stored override wins.
        assert!(!resolve(&m, "engine.google", true));
        // Absent key → caller default (so new toggles default sanely).
        assert!(resolve(&m, "engine.bing", true));
        assert!(!resolve(&m, "engine.bing", false));
    }

    #[test]
    fn write_then_read_round_trips() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("settings.json");
        let mut m = BTreeMap::new();
        m.insert("engine.google".to_string(), false);
        m.insert("feature.regional".to_string(), true);
        write_map_at(&path, &m).unwrap();
        let back = read_map(&path);
        assert_eq!(back, m);
        // Missing file → empty (non-fatal).
        assert!(read_map(&dir.path().join("nope.json")).is_empty());
    }

    #[test]
    fn corrupt_file_reads_as_empty() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(&path, "{ not valid json ").unwrap();
        assert!(read_map(&path).is_empty());
    }
}
