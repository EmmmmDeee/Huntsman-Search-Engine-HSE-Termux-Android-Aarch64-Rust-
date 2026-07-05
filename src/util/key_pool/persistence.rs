//! Pool persistence: load from / save to `~/.huntsman/key_pool.json`.

use std::path::PathBuf;

use super::pool::{KeyPool, PoolData};

pub fn pool_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    let dir = PathBuf::from(home).join(".huntsman");
    // 0700 (owner-only): `~/.huntsman` holds the key pool and intelligence DB, so
    // a world-readable default-umask (0755) dir would let another local user
    // enumerate its contents. The `key_pool.json` file itself is already 0600.
    let _ = crate::util::atomic_file::create_dir_private(&dir);
    dir.join("key_pool.json")
}

pub fn load_pool() -> KeyPool {
    load_pool_from(&pool_path())
}

/// Env-free core of [`load_pool`] — load the pool from an explicit `path` so the
/// read/parse error handling is unit-testable against a temp file.
pub(super) fn load_pool_from(path: &std::path::Path) -> KeyPool {
    match std::fs::read_to_string(path) {
        Ok(content) => match serde_json::from_str::<PoolData>(&content) {
            Ok(data) => KeyPool::from_data(data),
            Err(e) => {
                tracing::warn!(
                    "key pool at {} is corrupted ({e}); backing up and starting fresh",
                    path.display()
                );
                backup_and_fresh(path)
            }
        },
        // A missing file is the legitimate first-run fresh start — quiet.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => KeyPool::new(),
        // The file EXISTS but could not be read: non-UTF-8 InvalidData corruption,
        // PermissionDenied, or a transient IO error. Mirror the JSON-corruption
        // branch — warn and preserve the file as `.json.bak` before starting fresh
        // — so a real read failure is observable and the still-present on-disk keys
        // are not silently dropped and then clobbered by the next atomic save.
        Err(e) => {
            tracing::warn!(
                "key pool at {} could not be read ({e}); backing up and starting fresh",
                path.display()
            );
            backup_and_fresh(path)
        }
    }
}

/// Rename a present-but-unusable pool file aside to `.json.bak` and return a fresh
/// empty pool. Best-effort: a failed rename still yields a working (empty) pool.
fn backup_and_fresh(path: &std::path::Path) -> KeyPool {
    let backup = path.with_extension("json.bak");
    let _ = std::fs::rename(path, &backup);
    KeyPool::new()
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
