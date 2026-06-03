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
/// 0600. Mirrors `key_pool::save_pool` / `keys::write_keys_at`, but uses a
/// **unique** temp name per write (pid + a process-local counter) instead of a
/// fixed `settings.json.tmp`: this surface is web-writable (`PUT
/// /settings/toggles`), so two concurrent writers could otherwise truncate and
/// interleave into the same temp and rename a corrupt file into place. A unique
/// temp makes each write self-contained (the final rename is last-writer-wins
/// over a complete, internally-consistent snapshot — never a torn one), and the
/// temp is removed on any error so a failed write leaves no straggler.
fn write_map_at(path: &Path, map: &BTreeMap<String, bool>) -> std::io::Result<()> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let json = serde_json::to_string_pretty(map).map_err(std::io::Error::other)?;
    let tmp = path.with_extension(format!(
        "json.tmp.{}.{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let result = write_tmp_then_rename(&tmp, path, json.as_bytes());
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Write `bytes` to `tmp` (mode 0600 + fsync on unix) then atomically rename it
/// onto `path`. Split out so [`write_map_at`] can clean up `tmp` on any failure.
fn write_tmp_then_rename(tmp: &Path, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(tmp, bytes)?;
    }
    std::fs::rename(tmp, path)
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

/// Built-in *feature* toggles — capability switches that aren't a single search
/// engine or module: `(key, default)`. Kept here as the one registry of known
/// features so the `hse config` listing, the web toggle catalogue, and the
/// `PUT /settings/toggles` validator all agree on what `feature.*` keys exist.
pub const FEATURE_TOGGLES: &[(&str, bool)] = &[
    // Autonomous region-scoped search augmentation. Default OFF (queries stay
    // geolocation-neutral). Turning it on makes regional the baseline for every
    // scan; the per-scan `--regional` flag still forces it on for one scan.
    ("feature.regional", false),
];

/// The feature toggles with their current effective state (override else
/// default) — for the `hse config` listing and the settings UI.
#[must_use]
pub fn feature_toggles() -> Vec<(String, bool)> {
    FEATURE_TOGGLES
        .iter()
        .map(|(k, d)| ((*k).to_string(), get_bool(k, *d)))
        .collect()
}

/// True if `key` names a known built-in feature toggle — bounds web/API writes
/// (and the `hse config` listing) to real `feature.*` switches.
#[must_use]
pub fn is_feature_key(key: &str) -> bool {
    FEATURE_TOGGLES.iter().any(|(k, _)| *k == key)
}

/// The in-code default for a toggle key: a `feature.*` key uses its registered
/// default (which may be off, e.g. `feature.regional`); every other key
/// (engines, modules) defaults on. Used by `hse config <key>` so a never-set
/// toggle is shown with the same default the runtime would actually apply.
#[must_use]
pub fn default_for(key: &str) -> bool {
    // None (not a feature key) ⇒ default on, as engines/modules do; otherwise
    // the feature's registered default.
    FEATURE_TOGGLES
        .iter()
        .find(|(k, _)| *k == key)
        .is_none_or(|(_, d)| *d)
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

    #[test]
    fn concurrent_writes_never_corrupt_the_file() {
        // The web `PUT /settings/toggles` makes concurrent writers realistic. A
        // shared fixed temp could be truncated + interleaved by two writers and
        // a torn file renamed into place; the unique-temp scheme must keep every
        // persisted state a complete, valid snapshot and leave no straggler.
        let dir = tempdir().unwrap();
        let path = dir.path().join("settings.json");
        let handles: Vec<_> = (0..8)
            .map(|i| {
                let path = path.clone();
                std::thread::spawn(move || {
                    for j in 0..25u32 {
                        let mut m = BTreeMap::new();
                        m.insert(format!("engine.e{i}"), j % 2 == 0);
                        let _ = write_map_at(&path, &m);
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        // Always valid JSON of some complete state — never a torn temp.
        let s = std::fs::read_to_string(&path).unwrap();
        serde_json::from_str::<BTreeMap<String, bool>>(&s)
            .expect("persisted settings must stay valid JSON under concurrent writes");
        // No temp files left behind.
        let strays: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp"))
            .map(|e| e.file_name())
            .collect();
        assert!(strays.is_empty(), "temp stragglers left behind: {strays:?}");
    }

    #[test]
    fn feature_registry_is_well_formed() {
        // Every built-in feature key uses the `feature.` namespace and is
        // recognised by the membership check that bounds web/API writes.
        for (key, _default) in FEATURE_TOGGLES {
            assert!(
                key.starts_with("feature."),
                "feature toggle key must be namespaced: {key}"
            );
            assert!(is_feature_key(key), "{key} must be a known feature key");
        }
        // Regional search is the charter feature toggle, and defaults OFF so
        // queries stay geolocation-neutral until an operator opts in.
        assert!(is_feature_key("feature.regional"));
        assert_eq!(
            FEATURE_TOGGLES
                .iter()
                .find(|(k, _)| *k == "feature.regional")
                .map(|(_, d)| *d),
            Some(false),
            "feature.regional must default off (geo-neutral)"
        );
        // An unknown key is not a feature.
        assert!(!is_feature_key("feature.bogus"));
        assert!(!is_feature_key("engine.google"));
        // The listing resolves a (key, current-state) pair for every feature.
        assert_eq!(feature_toggles().len(), FEATURE_TOGGLES.len());
    }
}
