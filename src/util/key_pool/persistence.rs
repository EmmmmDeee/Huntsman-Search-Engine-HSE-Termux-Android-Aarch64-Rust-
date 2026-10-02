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
            Ok(data) => KeyPool::from_data(data),
            Err(e) => {
                tracing::warn!(
                    "key pool at {} is corrupted ({e}); moving it aside",
                    path.display()
                );
                backup_and_fresh(path, &e.to_string())
            }
        },
        // A missing file is the legitimate first-run fresh start — quiet.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => KeyPool::new(),
        // The file EXISTS but could not be read: non-UTF-8 InvalidData corruption,
        // PermissionDenied, or a transient IO error. Mirror the JSON-corruption
        // branch — warn and move the file aside before starting fresh — so a
        // real read failure is observable and the still-present on-disk keys
        // are not silently dropped and then clobbered by the next atomic save.
        Err(e) => {
            tracing::warn!(
                "key pool at {} could not be read ({e}); moving it aside",
                path.display()
            );
            backup_and_fresh(path, &e.to_string())
        }
    }
}

/// Move a present-but-unusable pool file aside, to a backup name that holds
/// nothing yet, and return an empty pool (REQ-KEYPOOL-003). `load_error` says
/// why the file could not be used.
///
/// The file is kept either way, because it may still hold keys. The backup
/// went to `.json.bak` every time, so a second unusable file replaced the
/// first backup, and a failed rename was ignored, so the next save replaced
/// the file itself. Now a backup never replaces anything, and when the file
/// cannot be moved aside it stays where it is, and the returned pool refuses
/// every save, saying why.
fn backup_and_fresh(path: &std::path::Path, load_error: &str) -> KeyPool {
    backup_and_fresh_with(path, load_error, |from, to| std::fs::rename(from, to))
}

/// [`backup_and_fresh`] with the rename injected, so the branch where it
/// fails can be tested.
pub(super) fn backup_and_fresh_with(
    path: &std::path::Path,
    load_error: &str,
    rename: impl Fn(&std::path::Path, &std::path::Path) -> std::io::Result<()>,
) -> KeyPool {
    let moved = claim_backup_name(path).and_then(|backup| match rename(path, &backup) {
        Ok(()) => Ok(backup),
        Err(e) => {
            // The claimed name is this process's own empty placeholder.
            if let Err(cleanup) = std::fs::remove_file(&backup) {
                tracing::warn!(
                    "could not remove the unused backup name {}: {cleanup}",
                    backup.display()
                );
            }
            Err(e)
        }
    });
    match moved {
        Ok(backup) => {
            tracing::warn!(
                "the unusable key pool was moved to {}; starting with an empty pool",
                backup.display()
            );
            KeyPool::new()
        }
        // Gone already (another hse process moved it first): nothing is left
        // to protect, so the empty pool may save.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && is_absent(path) => {
            tracing::warn!(
                "the unusable key pool at {} was moved away by another process; starting \
                 with an empty pool",
                path.display()
            );
            KeyPool::new()
        }
        Err(e) => {
            let reason = format!(
                "the key pool at {} could not be loaded ({load_error}) or moved aside ({e}). \
                 It is left in place, and nothing is saved over it: repair or move it, then \
                 restart hse",
                path.display()
            );
            tracing::error!("{reason}");
            KeyPool::never_saved(reason)
        }
    }
}

/// Whether nothing is at `path`. A path that cannot be checked is not absent,
/// the same rule [`claim_backup_name`] applies to a name it cannot create.
fn is_absent(path: &std::path::Path) -> bool {
    std::fs::symlink_metadata(path).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
}

/// How many numbered backups ([`claim_backup_name`]) are tried before giving up.
const MAX_BACKUPS: u32 = 999;

/// Claim the first free backup name of `key_pool.json.bak`,
/// `key_pool.json.bak.1` … `.bak.999`, by creating it empty with `create_new`,
/// which fails if anything at all is there. Two processes can never claim the
/// same name, and the rename that follows replaces only the claimant's own
/// placeholder, so a backup never replaces anything. A name that cannot be
/// created counts as taken.
fn claim_backup_name(path: &std::path::Path) -> std::io::Result<PathBuf> {
    let first = path.with_extension("json.bak");
    let numbered = (1..=MAX_BACKUPS).map(|n| {
        let mut name = first.clone().into_os_string();
        name.push(format!(".{n}"));
        PathBuf::from(name)
    });
    std::iter::once(first.clone())
        .chain(numbered)
        .find(|candidate| {
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(candidate)
                .is_ok()
        })
        .ok_or_else(|| {
            std::io::Error::other(format!(
                "no usable backup name from {} to .bak.{MAX_BACKUPS}",
                first.display()
            ))
        })
}

pub fn save_pool(pool: &KeyPool) -> std::io::Result<()> {
    save_pool_to(pool, &pool_path())
}

/// The path-taking core of [`save_pool`], the counterpart of
/// [`load_pool_from`]. A pool that must not be saved over its file
/// (`KeyPool::never_saved`) is refused with the reason, and the file is not
/// touched.
pub(super) fn save_pool_to(pool: &KeyPool, path: &std::path::Path) -> std::io::Result<()> {
    if let Some(reason) = &pool.not_saved_over {
        return Err(std::io::Error::other(reason.clone()));
    }
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
    crate::util::atomic_file::write(path, json.as_bytes())
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
        // A pool kept off its unreadable file refuses every save on purpose,
        // and said so, once, as an error when the refusal was decided. One
        // warning per harvested key or status change would bury that line.
        if pool.save_refusal().is_some() {
            tracing::debug!(error = %e, "key pool not saved: its file is kept");
            return;
        }
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
