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
use std::sync::{LazyLock, Mutex, RwLock};

/// In-process cache of the override map, loaded once from disk. Reads on hot
/// paths hit this, never the filesystem.
///
/// The cache is **authoritative**: every reader ([`get_bool`], [`overrides`], …)
/// sees the merged result of all completed writes the instant their `RwLock`
/// write guard is released, with no filesystem round-trip. Disk is a persistence
/// shadow that may momentarily lag the cache by at most one in-flight write —
/// but see [`WRITE_LOCK`] for why the *settled* on-disk view always matches the
/// cache state that produced the winning write.
static CACHE: LazyLock<RwLock<BTreeMap<String, bool>>> =
    LazyLock::new(|| RwLock::new(read_map(&settings_path())));

/// Serializes the whole *write* path of [`set_bool`] — the cache mutation, the
/// snapshot, and the atomic file write are one critical section per writer.
///
/// Without it two concurrent writers (e.g. `PUT /api/v1/settings/toggles` and a
/// `hse config` invocation in the same process) could each take a snapshot of a
/// different cache state under the `RwLock` and then race on the file write: the
/// `RwLock` merges both mutations into the cache, but the last writer to *rename*
/// wins on disk, and that winner's snapshot need not be the most recent cache
/// state — a lost update of the on-disk view versus the cache. [`crate::util::atomic_file`]'s
/// unique temp prevents a *torn* file, not this logical divergence.
///
/// Holding this mutex across snapshot-and-write makes the two strictly ordered:
/// each writer's on-disk snapshot is exactly the cache state *it* produced, and
/// the last writer to enter the critical section is both the last to mutate the
/// cache and the last to rename — so the settled disk view always equals the
/// authoritative cache. Readers are unaffected: this mutex is never taken on a
/// read path, and the `RwLock` write guard is released before the (slow) file
/// I/O so concurrent reads never block on disk.
static WRITE_LOCK: Mutex<()> = Mutex::new(());

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
///
/// The whole cache-mutate → snapshot → file-write sequence runs under
/// [`WRITE_LOCK`], so the on-disk snapshot always reflects the cache state that
/// produced it: two concurrent `set_bool` calls (e.g. the web `PUT` endpoint and
/// `hse config`) are strictly ordered, the second sees the first's mutation, and
/// the last writer's disk snapshot matches the authoritative cache. The cheap
/// `m.clone()` of the tiny toggle map is taken under the `RwLock` write guard,
/// which is then released *before* the file I/O so concurrent reads never block
/// on disk while still preserving the write ordering via [`WRITE_LOCK`].
pub fn set_bool(key: &str, value: bool) -> std::io::Result<()> {
    // Serialize the entire write path. A poisoned mutex still yields the guard —
    // the data is `()`, so there is no corrupt state to recover, and dropping the
    // write would be a worse failure mode than proceeding.
    let _write = WRITE_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
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
];

/// The `feature.*` key gating active gap-fill — one source of the key string so
/// the engine gate and the toggle registry can't drift.
pub const GAP_FILL_FEATURE: &str = "feature.gap_fill";

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
