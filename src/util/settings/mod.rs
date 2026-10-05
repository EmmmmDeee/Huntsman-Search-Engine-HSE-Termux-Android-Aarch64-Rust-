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
//!
//! The file holds the operator's own switches, kill-switches among them
//! (`feature.auto_update`, `feature.map_tiles`, `feature.live_radar`), so a
//! file that exists and does not parse is an error, never "no overrides": read
//! as empty, it silently turned every switch the operator had turned off back
//! on, and the next write replaced it (REQ-SETTINGS-001). Every command but
//! two that read no switch (`hse build-sha` and `hse provision --env-only`,
//! both run by install.sh) loads the file at startup ([`load`]) and stops if
//! it cannot; a write reads the file again and refuses to replace one it
//! cannot read; and an update loads it again before it replaces anything.
//!
//! What stays true without a lock across processes: two processes writing at
//! the same instant (`hse config` and a console toggle) can still lose one
//! change, and a running server sees a switch set by `hse config` only at its
//! next toggle write or update check.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock, PoisonError, RwLock};

/// The override map: switch key to on/off.
type Map = BTreeMap<String, bool>;

/// In-process cache of the override map. Reads on hot paths hit this, never
/// the filesystem. [`load`], which every command runs before anything reads a
/// toggle, fills it with the file as it is, and [`set_bool`] replaces it with
/// what it wrote. It is filled on first read only for a caller that did not
/// run [`load`] (a test, or the library used on its own); a file that cannot
/// be used is then logged and read as no overrides.
static CACHE: OnceLock<RwLock<Map>> = OnceLock::new();

/// Held from the file read to the cache swap by [`load`] and [`set_bool`], so
/// a load never puts back a map a write has just replaced, and two writes in
/// this process never lose each other's change. Toggle reads take only the
/// cache's read lock, so they never wait on the file.
static WRITER: Mutex<()> = Mutex::new(());

/// [`CACHE`], filled from the file on first use.
fn cache() -> &'static RwLock<Map> {
    CACHE.get_or_init(|| {
        RwLock::new(load_map(&settings_path()).unwrap_or_else(|e| {
            tracing::error!("{e}");
            Map::new()
        }))
    })
}

/// Make `map` what `cache` holds, filling it if nothing has yet.
fn replace(cache: &OnceLock<RwLock<Map>>, map: Map) {
    if let Err(fresh) = cache.set(RwLock::new(map)) {
        let map = fresh.into_inner().unwrap_or_else(PoisonError::into_inner);
        if let Some(held) = cache.get() {
            *held.write().unwrap_or_else(PoisonError::into_inner) = map;
        }
    }
}

/// `~/.huntsman/settings.json` (same dir as the key pool / DB).
pub fn settings_path() -> PathBuf {
    crate::util::paths::data_file("settings.json")
}

/// Why the settings file could not be used, or written.
#[derive(Debug)]
pub enum SettingsError {
    /// The file exists and could not be read.
    Read {
        /// The settings file.
        path: PathBuf,
        /// Why it could not be read.
        source: std::io::Error,
    },
    /// The file was read and is not a JSON object of on/off switches.
    Parse {
        /// The settings file.
        path: PathBuf,
        /// Where, and why, it does not parse.
        source: serde_json::Error,
    },
    /// The file could be used, and writing the change to it failed.
    Write {
        /// The settings file.
        path: PathBuf,
        /// Why the write failed.
        source: std::io::Error,
    },
}

impl std::fmt::Display for SettingsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read { path, source } => unusable(f, path, source),
            Self::Parse { path, source } => unusable(f, path, source),
            Self::Write { path, source } => write!(
                f,
                "the settings file {} could not be written ({source})",
                path.display()
            ),
        }
    }
}

/// The one message for a settings file that cannot be used, read or parse
/// failure alike.
fn unusable(
    f: &mut std::fmt::Formatter<'_>,
    path: &Path,
    cause: &dyn std::fmt::Display,
) -> std::fmt::Result {
    write!(
        f,
        "the settings file {} cannot be used ({cause}). It holds your on/off switches, so \
         they are not reset to their defaults: fix the file, or move it aside to start from \
         the defaults",
        path.display()
    )
}

impl std::error::Error for SettingsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Read { source, .. } | Self::Write { source, .. } => Some(source),
            Self::Parse { source, .. } => Some(source),
        }
    }
}

/// Read the override map from `path`: empty when there is no file, an error
/// when there is one that cannot be read or parsed. An empty file, and a
/// byte-order mark an editor put first, hold no switch and cost none, so they
/// are no reason to stop every command.
fn load_map(path: &Path) -> Result<Map, SettingsError> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Map::new()),
        Err(source) => {
            return Err(SettingsError::Read {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
    if text.trim().is_empty() {
        return Ok(Map::new());
    }
    serde_json::from_str(text).map_err(|source| SettingsError::Parse {
        path: path.to_path_buf(),
        source,
    })
}

/// Load the settings file into the in-process cache, so every toggle read
/// after this reads the file as it is now. Every command runs this before it
/// reads a toggle (`cli::run`), so a file that does not parse stops `hse` with
/// the reason instead of resetting the operator's switches, and `hse serve`
/// runs it again before an automatic update restarts it.
///
/// # Errors
///
/// [`SettingsError`] when the file exists and cannot be read or parsed. The
/// cache is then left as it was, and still empty if nothing filled it yet.
pub fn load() -> Result<(), SettingsError> {
    load_into(&CACHE, &settings_path())
}

/// [`load`] against an explicit cache and file.
fn load_into(cache: &OnceLock<RwLock<Map>>, path: &Path) -> Result<(), SettingsError> {
    let _writer = WRITER.lock().unwrap_or_else(PoisonError::into_inner);
    let map = load_map(path)?;
    replace(cache, map);
    Ok(())
}

/// Atomically write the override map to `path` via [`crate::util::atomic_file`]
/// (unique temp + fsync + rename, mode 0600). The unique temp is what makes this
/// safe under the web-writable `PUT /settings/toggles`: a shared fixed temp could
/// be truncated + interleaved by two concurrent writers and a corrupt file
/// renamed into place, which every command would then refuse until repaired.
fn write_map_at(path: &Path, map: &Map) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(map).map_err(std::io::Error::other)?;
    crate::util::atomic_file::write(path, json.as_bytes())
}

/// Pure resolution: stored override else `default`. Split out for testing.
fn resolve(map: &Map, key: &str, default: bool) -> bool {
    map.get(key).copied().unwrap_or(default)
}

/// Resolve a boolean toggle: the stored override, else `default`.
#[must_use]
pub fn get_bool(key: &str, default: bool) -> bool {
    let guard = cache().read().unwrap_or_else(PoisonError::into_inner);
    resolve(&guard, key, default)
}

/// Set and persist a toggle, visible in this process at once.
///
/// # Errors
///
/// [`SettingsError`] when the settings file cannot be read or parsed (it is
/// then left as it is), or the write fails. Either way nothing changes, on
/// disk or in this process.
pub fn set_bool(key: &str, value: bool) -> Result<(), SettingsError> {
    set_bool_in(&CACHE, &settings_path(), key, value)
}

/// [`set_bool`] against an explicit cache and file. The file is read again
/// rather than the cache written out, so a switch set in the file since this
/// process loaded it (`hse config` while `hse serve` runs) is kept, not
/// replaced by this process's older copy; and the cache changes only after
/// the file has (REQ-SETTINGS-001).
fn set_bool_in(
    cache: &OnceLock<RwLock<Map>>,
    path: &Path,
    key: &str,
    value: bool,
) -> Result<(), SettingsError> {
    let _writer = WRITER.lock().unwrap_or_else(PoisonError::into_inner);
    let mut map = load_map(path)?;
    map.insert(key.to_string(), value);
    write_map_at(path, &map).map_err(|source| SettingsError::Write {
        path: path.to_path_buf(),
        source,
    })?;
    replace(cache, map);
    Ok(())
}

/// All stored overrides (for `hse config` listing / the settings API).
#[must_use]
pub fn overrides() -> BTreeMap<String, bool> {
    cache()
        .read()
        .map_or_else(|e| e.into_inner().clone(), |m| m.clone())
}

/// Built-in *feature* toggles — capability switches that aren't a single search
/// engine or module: `(key, default)`. Kept here as the one registry of known
/// features so the `hse config` listing, the web toggle catalogue, and the
/// `PUT /settings/toggles` validator all agree on what `feature.*` keys exist.
pub const FEATURE_TOGGLES: &[(&str, bool)] = &[
    // Live-sensor radar (the device's own WiFi/Bluetooth/cell/GPS/LAN sweep, via
    // `hse radar`, `POST /api/v1/radar` and `POST /api/v1/radar/live`). Default ON
    // and armed: the radar is the operator's own deliberate action (the button /
    // the command IS the activation), so it requires no prior opt-in — a single
    // press runs it. This toggle is now a **kill-switch**: set it OFF
    // (`hse config feature.live_radar off`) to refuse the radar entirely. The real
    // safety invariant is independent of this toggle: seed scans NEVER enable live
    // sensors (`cli::scan` hard-sets `allow_live_sensors:false`, and the engine
    // dispatch gates the sensor modules on that per-scan flag, which only the radar
    // spec sets), so an ordinary scan can never attribute the operator's own
    // location/RF to a remote subject regardless of this default.
    ("feature.live_radar", true),
    // Map tiles for the Radar view: `hse serve` fetches map tiles for the
    // operator's browser through its own loopback proxy (`/api/v1/tiles/…`)
    // and keeps them on disk, so the browser never talks to a tile server and
    // a map seen once is there offline. Default ON — a tile is fetched only
    // when the operator opens the map. This toggle is a **kill-switch** for
    // the outbound fetch (`hse config feature.map_tiles off`): switched off,
    // tiles already cached still serve and an uncached one is refused, so a
    // device that must not reach out — or must not disclose where it is
    // looking — still shows every map it has seen.
    ("feature.map_tiles", true),
    // Autonomous region-scoped search augmentation. Default OFF (queries stay
    // geolocation-neutral). Turning it on makes regional the baseline for every
    // scan; the per-scan `--regional` flag still forces it on for one scan.
    ("feature.regional", false),
    // Recall prior-scan findings from the local database at scan start, so the
    // store can act as a SOURCE for a scan (not just a sink). Default **OFF** —
    // every scan is a FRESH START: it shows only what THIS run discovered, with
    // no archaic prior-scan entities injected into the working set (which also
    // kept the per-round correlation pass small and fast). The data is still
    // fully RETAINED in the store and reused by cross-scan corroboration at
    // finalise; recall only controls whether prior entities are *pre-loaded* into
    // a new scan. Turn it on (`hse config feature.recall on`) for a session that
    // should build on everything previously gathered.
    ("feature.recall", false),
    // Autonomous self-update: background task checks for upstream commits every
    // 6 h and applies them automatically when ON. The binary restarts in-place
    // via exec(2). Turn off to manage updates manually (`hse update`).
    ("feature.auto_update", true),
    // Update-available notification: when ON the web UI shows a badge and
    // notification when commits are available (even if auto_update is OFF).
    ("feature.update_notify", true),
    // Active gap-fill: after expansion, when a single-route (fragile) identity
    // link is found, run the missing orthogonal source family's modules on the
    // gap endpoints to actively seek the corroborating pathway AU-063 only names.
    // Default ON — it is part of the recursive search and is bounded (a small
    // probe cap, restricted to the missing-family modules, budget-gated, and
    // respects passive/free/exclude). Turn off (`hse config feature.gap_fill off`)
    // to skip the extra corroboration-seeking dispatch.
    ("feature.gap_fill", true),
    // Expansion depth-decay: discount an entity's effective confidence FOR
    // EXPANSION PURPOSES by its generation (distance in pivots from the seed),
    // so the recursion favours seed-adjacent leads and a deep chain must be more
    // strongly corroborated to keep expanding — a depth horizon on the working
    // graph. Default **OFF** (byte-identical expansion to today); the raw
    // c_effective every correlation/display/gate reads is never changed. Turn on
    // (`hse config feature.depth_decay on`) for a tighter, seed-focused sweep
    // that spends its budget nearer the subject.
    ("feature.depth_decay", false),
    // Final breach sweep: after expansion AND gap-fill have finished, compile
    // the scan's confident identity entities into one bulk breach-corpus probe
    // plan and dispatch it through the breach modules, then grade the result
    // with the autonomous consensus audit. Default ON — it is the last leg of
    // the recursive search, is bounded (anchor + probe caps, budget-gated,
    // cancel-aware, restricted to breach-family modules, and respects
    // passive/free/exclude), and never probes a quarantined value. Turn off
    // (`hse config feature.breach_sweep off`) to end the scan at gap-fill.
    ("feature.breach_sweep", true),
];

/// The `feature.*` key gating active gap-fill — one source of the key string so
/// the engine gate and the toggle registry can't drift.
pub const GAP_FILL_FEATURE: &str = "feature.gap_fill";

/// The `feature.*` key gating expansion depth-decay — one source of the key
/// string so the engine gate and the toggle registry can't drift.
pub const DEPTH_DECAY_FEATURE: &str = "feature.depth_decay";

/// The `feature.*` key gating the final breach sweep — one source of the key
/// string so the engine gate and the toggle registry can't drift.
pub const BREACH_SWEEP_FEATURE: &str = "feature.breach_sweep";

/// The `feature.*` key gating the live-sensor radar — the single source of the
/// key string so the CLI gate, the API gate, and the toggle registry can't drift.
pub const LIVE_RADAR_FEATURE: &str = "feature.live_radar";

/// Whether the live-sensor radar is armed. **On by default** — the radar is the
/// operator's own deliberate action (the button / `hse radar` command IS the
/// activation), so it needs no prior opt-in; this is a kill-switch that an
/// operator can set OFF to refuse the radar entirely. Independent of the real
/// safety invariant (seed scans never set `allow_live_sensors`, so they can never
/// run the sensors regardless of this default). All radar entry points consult it.
#[must_use]
pub fn live_radar_enabled() -> bool {
    get_bool(LIVE_RADAR_FEATURE, true)
}

/// The `feature.*` key gating the map-tile fetch — the single source of the
/// key string so the proxy's gate and the toggle registry can't drift.
pub const MAP_TILES_FEATURE: &str = "feature.map_tiles";

/// Whether the tile proxy may fetch from its upstream. **On by default**; a
/// kill-switch for the outbound fetch only — cached tiles serve regardless.
#[must_use]
pub fn map_tiles_enabled() -> bool {
    get_bool(MAP_TILES_FEATURE, true)
}

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
