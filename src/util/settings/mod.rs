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

/// Atomically write the override map to `path` via [`crate::util::atomic_file`]
/// (unique temp + fsync + rename, mode 0600). The unique temp is what makes this
/// safe under the web-writable `PUT /settings/toggles`: a shared fixed temp could
/// be truncated + interleaved by two concurrent writers and a corrupt file
/// renamed into place, which then reads back empty (dropping every override).
fn write_map_at(path: &Path, map: &BTreeMap<String, bool>) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(map).map_err(std::io::Error::other)?;
    crate::util::atomic_file::write(path, json.as_bytes())
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
        .map_or_else(|e| e.into_inner().clone(), |m| m.clone())
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
    // Recall prior-scan findings from the local database at scan start, so the
    // store acts as a SOURCE for every scan and expansion round (not just a
    // sink). Default ON — total retention + reuse of collected intel. Turn off
    // (`hse config feature.recall off`) for a leave-no-memory session that must
    // ignore everything previously gathered.
    ("feature.recall", true),
    // Autonomous self-update: background task checks for upstream commits every
    // 6 h and applies them automatically when ON. The binary restarts in-place
    // via exec(2). Turn off to manage updates manually (`hse update`).
    ("feature.auto_update", true),
    // Update-available notification: when ON the web UI shows a badge and
    // notification when commits are available (even if auto_update is OFF).
    ("feature.update_notify", true),
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
    include!("tests.rs");
}
