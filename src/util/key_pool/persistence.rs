//! Pool persistence: load from / save to `~/.huntsman/key_pool.json`.

use std::path::PathBuf;

use super::pool::{KeyPool, PoolData};

pub fn pool_path() -> PathBuf {
    // `~/.huntsman` is created 0700 (owner-only) by `paths::data_file` so another
    // local user can't enumerate it; the `key_pool.json` file itself is 0600.
    crate::util::paths::data_file("key_pool.json")
}

pub fn load_pool() -> KeyPool {
    load_pool_from(&pool_path())
}

/// Env-free core of [`load_pool`] — load the pool from an explicit `path` so the
/// read/parse error handling is unit-testable against a temp file.
pub(super) fn load_pool_from(path: &std::path::Path) -> KeyPool {
    match std::fs::read_to_string(path) {
        Ok(content) => match serde_json::from_str::<PoolData>(&content) {
            Ok(data) => {
                let before: usize = data.services.values().map(Vec::len).sum();
                let pool = KeyPool::from_data(data);
                // `from_data` drops legacy non-poolable bloat (generic_hex &c.) that
                // predates the pool's insert gate. Rewrite the file NOW when that
                // happened, so the purge is permanent: without this, a device whose
                // persisted pool holds the measured 527 303 generic_hex entries
                // re-reads and re-parses that multi-MB JSON on EVERY load — every
                // read-only `hse keys` call and every localhost UI poll — because a
                // read path never triggers `save_pool`. The clean write makes the
                // one-time load cost one-time. Best-effort: a read-only `$HOME`
                // (realistic on Termux) must not fail the load, so a write failure
                // is warned, not propagated — the in-memory pool is already correct.
                if pool.total_keys() < before {
                    match serde_json::to_string_pretty(&pool.snapshot()) {
                        Ok(json) => {
                            if let Err(e) = crate::util::atomic_file::write(path, json.as_bytes()) {
                                tracing::warn!(
                                    error = %e, path = %path.display(),
                                    "key pool purged in memory but the cleaned file could not be \
                                     rewritten; the bloat will be re-parsed until the next save"
                                );
                            }
                        }
                        Err(e) => tracing::warn!(error = %e, "could not re-serialise purged pool"),
                    }
                }
                pool
            }
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

/// Persist the pool off the async runtime — the single canonical entry point
/// every opportunistic (fire-and-forget) persist site should call instead of
/// [`save_pool_best_effort`] directly.
///
/// `save_pool` does a blocking JSON serialize + `fsync` + rename (tens of ms on
/// Android flash storage under load); every realistic caller of the best-effort
/// save — a keyed-error handler reacting to a 401/403/429, or key-harvest
/// emitting a newly-discovered credential mid-scan — runs inside `async fn
/// process()` on a small, shared tokio worker pool. Calling `save_pool` inline
/// there stalls that worker thread, delaying every OTHER module concurrently
/// scheduled on it — exactly the class of hazard the codebase's other blocking
/// I/O (`src/api/handlers`, `scan_export`) already guards against with
/// `spawn_blocking`, but this path lacked it in three call sites (two in
/// `key_harvest::emit`, one in `key_pool::validation::add_and_validate`) that
/// called [`save_pool_best_effort`] directly instead of through this helper —
/// only the original keyed-error-handling call site in `core::module` had it,
/// hand-rolled and undiscoverable as the pattern every other persist site
/// should share. Consolidated here as the one canonical implementation.
///
/// Inside an active tokio runtime: `spawn_blocking`, fire-and-forget (the
/// in-memory pool state the caller already mutated is authoritative regardless
/// of whether the write has landed yet, and persistence is best-effort by
/// design — a failure is logged, never propagated). Outside one (a plain
/// `#[test]`, or a sync CLI path): saves inline, exactly as
/// [`save_pool_best_effort`] always did — so every existing caller keeps
/// working with zero required changes and no new failure mode.
pub fn persist_off_thread(pool: std::sync::Arc<KeyPool>) {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => {
            handle.spawn_blocking(move || {
                save_pool_best_effort(&pool);
            });
        }
        Err(_) => {
            save_pool_best_effort(&pool);
        }
    }
}
