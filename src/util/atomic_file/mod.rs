//! Atomic file write: a **unique** temp file + fsync + rename, so neither a
//! concurrent writer nor a crashed/killed one can leave a torn or partial file
//! at the destination.
//!
//! Used by HSE's persisted JSON stores (`settings`, `key_pool`). The temp name
//! is unique per write (pid + a process-local counter), which is the load-bearing
//! detail: these stores are written from *concurrent* contexts — the toggle store
//! from `PUT /api/v1/settings/toggles`, the key pool from modules harvesting keys
//! during overlapping scans in `hse serve` — and a shared fixed temp would let two
//! writers truncate and interleave into it, then rename a corrupt file into place
//! (which the loaders treat as empty/corrupt, silently dropping all state). With a
//! unique temp each write is self-contained: the atomic rename is always over a
//! complete, internally-consistent snapshot (last writer wins), never a torn one.
//! The temp is removed on any error so a failed write leaves no straggler.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

/// Process-local monotonic counter; combined with the pid it makes every temp
/// filename unique across threads (and processes sharing the directory).
static SEQ: AtomicU64 = AtomicU64::new(0);

/// Atomically write `bytes` to `path` (created mode 0600 on unix) via a unique
/// temp + fsync + rename. On any failure the temp is removed before returning.
pub fn write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    // Build a sibling temp that preserves the full destination filename, so it is
    // unambiguous on disk (`settings.json` → `settings.json.tmp.<pid>.<seq>`).
    let mut name = path
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("atomic"))
        .to_os_string();
    name.push(format!(
        ".tmp.{}.{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let tmp = path.with_file_name(name);

    let result = write_inner(&tmp, path, bytes);
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

fn write_inner(tmp: &Path, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
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

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
