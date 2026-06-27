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
    let path = pool_path();
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return KeyPool::new(),
    };

    // Strict parse first — the overwhelmingly common clean case.
    if let Ok(data) = serde_json::from_str::<PoolData>(&content) {
        return KeyPool::from_data(data);
    }

    // Lenient salvage: a SINGLE unreadable entry (e.g. an unknown `status` enum
    // written by a newer build and then read by a downgrade, or a partially-
    // written record) must NOT discard EVERY harvested key. Re-parse the services
    // map with each entry as raw JSON, deserialize the entries independently, and
    // keep the good ones.
    if let Ok(raw) =
        serde_json::from_str::<std::collections::HashMap<String, Vec<serde_json::Value>>>(&content)
    {
        let mut services: std::collections::HashMap<String, Vec<super::KeyEntry>> =
            std::collections::HashMap::new();
        let mut dropped = 0usize;
        for (svc, entries) in raw {
            let good: Vec<super::KeyEntry> = entries
                .into_iter()
                .filter_map(|v| match serde_json::from_value::<super::KeyEntry>(v) {
                    Ok(entry) => Some(entry),
                    Err(_) => {
                        dropped += 1;
                        None
                    }
                })
                .collect();
            if !good.is_empty() {
                services.insert(svc, good);
            }
        }
        if dropped > 0 {
            tracing::warn!(
                "key pool at {}: dropped {dropped} unreadable entr(ies), kept the rest",
                path.display()
            );
        }
        return KeyPool::from_data(PoolData { services });
    }

    // Not even valid JSON → back up under a UNIQUE (timestamped) name so a second
    // failed load can't clobber the only prior backup, then start fresh.
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let backup = path.with_extension(format!("json.bak.{stamp}"));
    tracing::warn!(
        "key pool at {} is not valid JSON; backing up to {} and starting fresh",
        path.display(),
        backup.display()
    );
    let _ = std::fs::rename(&path, &backup);
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
