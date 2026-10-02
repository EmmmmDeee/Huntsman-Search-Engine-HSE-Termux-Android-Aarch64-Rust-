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
        return result;
    }
    // Best-effort fsync of the PARENT DIRECTORY so the rename itself is durable,
    // not just the file's data. `write_inner` fsyncs the temp file's bytes, but
    // the rename only updates the directory entry that points `path` at the new
    // inode; on ext4/f2fs (the Termux/Android targets) a power-cut or OOM-kill
    // immediately after `rename` returns can lose that entry and leave the OLD
    // file — or nothing — despite the durable data. fsyncing the directory
    // commits the rename. Swallowed: a directory that cannot be fsynced must
    // never fail an otherwise-successful write — this is a durability upgrade,
    // not a correctness gate. Unix-only (directory fsync is a POSIX concept).
    #[cfg(unix)]
    {
        let dir = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all();
        }
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

/// True when `mode`'s group and other bits are all clear — i.e. the directory is
/// owner-only, whatever the owner bits happen to be.
///
/// Tests the property that matters (nobody else can read, write or list) rather
/// than equality with `0o700`, so a `0o500` or `0o600` directory is correctly
/// treated as private instead of being reported as an exposure. Pure, so the
/// classification is driven by values in tests rather than by contriving a
/// filesystem this process cannot chmod.
#[cfg(unix)]
#[must_use]
pub(crate) fn is_private_mode(mode: u32) -> bool {
    mode & 0o077 == 0
}

/// Create `path` (and any missing parents) as a **private** directory — mode
/// `0700` on unix, so the sensitive trees under `~/.huntsman` (dossiers, key
/// pool, DB) aren't world-listable. Idempotent.
///
/// `DirBuilder::mode()` only applies to components this call CREATES, so a
/// pre-existing directory — an older install's `~/.huntsman` left world-listable
/// at `0755` by a plain `create_dir_all` — is repaired by the
/// `set_permissions` below rather than by the builder.
///
/// ## What the return value does and does not mean
///
/// `Ok(())` means the directory EXISTS, not that it is private. That distinction
/// used to be invisible and is the reason this function grew a verification
/// step: `recursive(true)` returns `Ok` for a directory that already exists, and
/// the repairing `set_permissions` was discarded, so a pre-existing `0755`
/// directory this process cannot chmod (not the owner, a read-only mount, a
/// filesystem with no POSIX modes) produced a clean `Ok` while `key_vault.db`
/// and `key_pool.json` sat readable by every other local UID. The doc comment
/// claimed a `0700` guarantee the code did not deliver.
///
/// The `Ok` contract is kept deliberately — every caller
/// ([`crate::util::paths::huntsman_dir`] and [`crate::util::paths::subdir`] are
/// infallible accessors returning `PathBuf`) wants a usable path even when the
/// mode could not be tightened, and failing the call would break a read path
/// that still works. So the mode is now VERIFIED after the repair attempt and a
/// failure is disclosed at `warn!` with the mode actually observed. The result
/// is the same directory, the same return value, and an operator who can find
/// out — instead of a silent exposure in the one primitive whose entire job is
/// preventing it.
pub fn create_dir_private(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        let created = std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path);
        // Re-tighten a PRE-EXISTING dir to owner-only. Best-effort so a dir owned
        // by another user can't turn a create success into an error; the create
        // result is what callers observe.
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));

        // Verify rather than assume. Only meaningful once the directory exists,
        // so a genuine create failure (which the caller already sees) is not
        // also reported as a permissions problem.
        if created.is_ok()
            && let Ok(meta) = std::fs::metadata(path)
        {
            let mode = meta.permissions().mode();
            if !is_private_mode(mode) {
                tracing::warn!(
                    path = %path.display(),
                    mode = format!("{:o}", mode & 0o777),
                    "directory is not owner-only and could not be tightened to 0700 — \
                     secrets stored beneath it are readable by other local users"
                );
            }
        }
        created
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(path)
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
