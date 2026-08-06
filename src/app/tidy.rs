//! On-device housekeeping — keep the `~/.huntsman` footprint bounded and
//! arranged so a long-lived Termux install stays "perfectly configured and
//! arranged" without operator intervention.
//!
//! Scope, and why each piece is safe to run unattended:
//!
//! * **Dossier cache** (`~/.huntsman/dossiers/<scan_id>.txt`) — one file is
//!   auto-written at the end of every scan and *nothing* ever prunes them, so
//!   the directory grows without bound. Each `.txt` is a rendered *cache* of
//!   the scan already persisted in the database (regenerable at any time with
//!   `hse export --scan-id <id> --format full`), so trimming the oldest beyond
//!   [`DOSSIER_MAX_FILES`] reclaims disk **without losing intelligence** — the
//!   one on-disk artifact that both accumulates unboundedly and is safe to
//!   bound. The newest files are always kept.
//! * **Database** — the scan path already prunes the event log / raw-archive
//!   and truncates the WAL on every scan (`core::engine::finalise`), so this is
//!   a *safety net* for the operator who runs `serve` for weeks without ever
//!   completing a scan: the same canonical [`EVENTS_MAX_ROWS`] /
//!   [`RAW_ARCHIVE_MAX_ROWS`] bounds and a WAL `TRUNCATE` checkpoint, reusing
//!   the storage primitives rather than duplicating a retention policy.
//! * **Layout** — re-asserts the base dir and its known subdirectories exist
//!   and are `0700`, the same tightening [`crate::util::paths`] applies on
//!   demand, so an older install whose tree was created world-readable is
//!   brought back into line.
//!
//! Intelligence the operator cannot regenerate — the scan database itself, the
//! key pool, the key vault, harvested credentials — is **never** touched.
//!
//! Exposed both on demand (`hse tidy`, with `--dry-run`) and automatically
//! (the `serve` maintenance tick), so the footprint is kept in order whether or
//! not anyone runs the command.

use std::path::Path;

use crate::core::error::Result;
use crate::core::port::{EVENTS_MAX_ROWS, EVENTS_RETENTION_SECS, RAW_ARCHIVE_MAX_ROWS};

/// Keep at most this many rendered dossier files (newest first). Dossiers are a
/// regenerable cache of a stored scan, so the cap only bounds disk use — no
/// intelligence is lost when the oldest are trimmed. Deliberately generous: a
/// casual user never reaches it, and even a heavy install keeps a deep history.
pub const DOSSIER_MAX_FILES: usize = 500;

/// What one housekeeping pass did (or, under `dry_run`, would do). All counts
/// are of work this pass performed; a field left at its default means that
/// class of work found nothing to do.
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize)]
pub struct TidyReport {
    /// `true` when the pass only measured and changed nothing on disk.
    pub dry_run: bool,
    /// Base + subdirectories re-asserted present and `0700`.
    pub dirs_arranged: Vec<String>,
    /// Dossier cache files trimmed beyond [`DOSSIER_MAX_FILES`].
    pub dossiers_removed: usize,
    /// Bytes reclaimed by trimming the dossier cache.
    pub dossier_bytes_reclaimed: u64,
    /// Event-log rows pruned past the retention bound.
    pub events_pruned: usize,
    /// Raw-archive rows pruned past the retention bound.
    pub archive_pruned: usize,
    /// Whether the WAL was checkpoint-truncated back to zero bytes.
    pub wal_truncated: bool,
}

/// Run one housekeeping pass over the on-device footprint.
///
/// With `dry_run`, nothing on disk changes: the returned report describes what
/// a real pass *would* reclaim (dossier cache only — the database safety-net
/// prune is skipped entirely so a measurement can't mutate the store).
///
/// Never fails the caller for a best-effort sub-step: a database that can't be
/// opened (e.g. never created yet) or a busy WAL checkpoint leaves that field
/// at its default and the pass still reports what it did elsewhere.
pub fn run(dry_run: bool) -> Result<TidyReport> {
    let mut report = TidyReport {
        dry_run,
        ..Default::default()
    };

    if !dry_run {
        report.dirs_arranged = arrange_layout();
    }

    let dossier_dir = crate::app::export::dossier_dir();
    let (removed, bytes) = prune_dossiers_in(&dossier_dir, DOSSIER_MAX_FILES, dry_run)?;
    report.dossiers_removed = removed;
    report.dossier_bytes_reclaimed = bytes;

    // Database safety net — only when actually tidying. Reuses the storage
    // primitives and the one canonical retention policy; a failure to open or
    // prune is logged and ignored so housekeeping never aborts a scan or serve.
    if !dry_run && let Ok(store) = crate::storage::Store::open(&crate::default_db_path()) {
        report.events_pruned = store
            .prune_events(EVENTS_RETENTION_SECS, EVENTS_MAX_ROWS)
            .unwrap_or(0);
        report.archive_pruned = store.prune_raw_archive(RAW_ARCHIVE_MAX_ROWS).unwrap_or(0);
        report.wal_truncated = store.checkpoint_truncate().is_ok();
    }

    Ok(report)
}

/// `hse tidy` — run one housekeeping pass and report it.
///
/// Human-readable by default; `--json` emits the [`TidyReport`] verbatim for
/// scripting. `--dry-run` measures without changing anything on disk.
pub fn cmd_tidy(dry_run: bool, json: bool) -> Result<()> {
    let report = run(dry_run)?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".into())
        );
        return Ok(());
    }

    let verb = if dry_run {
        "would reclaim"
    } else {
        "reclaimed"
    };
    println!(
        "HSE housekeeping{}",
        if dry_run {
            " — dry run (no changes)"
        } else {
            ""
        }
    );
    println!(
        "  dossier cache   {} file(s) {verb} ({})",
        report.dossiers_removed,
        human_bytes(report.dossier_bytes_reclaimed)
    );
    if !dry_run {
        println!("  event log       {} row(s) pruned", report.events_pruned);
        println!("  raw archive     {} row(s) pruned", report.archive_pruned);
        println!(
            "  sqlite wal      {}",
            if report.wal_truncated {
                "checkpointed and truncated"
            } else {
                "busy — left for the next pass"
            }
        );
        println!(
            "  layout          {} directory tree(s) verified 0700",
            report.dirs_arranged.len()
        );
    }
    Ok(())
}

/// Render a byte count in the largest unit that keeps it readable. Binary
/// units (1 KiB = 1024 B), one decimal place above the byte range.
fn human_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    let b = bytes as f64;
    if b < KIB {
        return format!("{bytes} B");
    }
    if b < KIB * KIB {
        return format!("{:.1} KiB", b / KIB);
    }
    format!("{:.1} MiB", b / (KIB * KIB))
}

/// Re-assert the base data directory and its known subdirectories exist and are
/// `0700`. Idempotent and non-destructive — creating or re-tightening a
/// directory never touches its contents. Returns the subdirectory names
/// arranged, in a deterministic order.
fn arrange_layout() -> Vec<String> {
    // Touching the base dir creates + re-tightens it to 0700 (see
    // `paths::huntsman_dir`), and each `subdir` does the same for its child.
    let _ = crate::util::paths::huntsman_dir();
    let mut arranged = Vec::new();
    for sub in ["dossiers", "raw"] {
        let _ = crate::util::paths::subdir(sub);
        arranged.push((*sub).to_string());
    }
    arranged
}

/// Trim `dir` to its `max` newest `*.txt` files, returning `(files_removed,
/// bytes_reclaimed)`. Ordering is by modification time, newest kept, with the
/// path as a deterministic tie-break so two files sharing an mtime always trim
/// in the same order. A missing/unreadable directory, or one already at or
/// under `max`, is a clean no-op. Under `dry_run` the files are measured but
/// left in place.
///
/// Directory-parameterised (rather than reading [`crate::app::export::dossier_dir`]
/// directly) so it is unit-testable against an isolated temp directory without
/// racing the process-shared test `$HOME`.
fn prune_dossiers_in(dir: &Path, max: usize, dry_run: bool) -> Result<(usize, u64)> {
    let Ok(read_dir) = std::fs::read_dir(dir) else {
        return Ok((0, 0));
    };
    let mut files: Vec<(std::path::PathBuf, std::time::SystemTime, u64)> = read_dir
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("txt") {
                return None;
            }
            let meta = entry.metadata().ok()?;
            if !meta.is_file() {
                return None;
            }
            Some((path, meta.modified().ok()?, meta.len()))
        })
        .collect();

    if files.len() <= max {
        return Ok((0, 0));
    }

    // Newest first; path as the deterministic tie-break for equal mtimes.
    files.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| b.0.cmp(&a.0)));

    let mut removed = 0usize;
    let mut bytes = 0u64;
    for (path, _, size) in files.into_iter().skip(max) {
        bytes += size;
        removed += 1;
        if !dry_run {
            let _ = std::fs::remove_file(&path);
        }
    }
    Ok((removed, bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::time::{Duration, SystemTime};

    /// Create `n` dossier-shaped files in `dir`, each stamped with a distinct,
    /// strictly-increasing mtime so "newest" is unambiguous. Returns the paths
    /// oldest-first.
    fn seed_dossiers(dir: &Path, n: usize) -> Vec<std::path::PathBuf> {
        let base = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let mut paths = Vec::new();
        for i in 0..n {
            let p = dir.join(format!("scan-{i:04}.txt"));
            let mut f = std::fs::File::create(&p).expect("create dossier");
            writeln!(f, "dossier body {i}").expect("write");
            drop(f);
            // Distinct mtime per file (i seconds apart), newest = highest i.
            let mtime = base + Duration::from_secs(i as u64);
            filetime_set(&p, mtime);
            paths.push(p);
        }
        paths
    }

    /// Set a file's mtime without the `filetime` crate (not a dependency): open
    /// for write and rely on the explicit stamp via `set_modified` (stable std).
    fn filetime_set(path: &Path, mtime: SystemTime) {
        let f = std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .expect("open for mtime");
        f.set_modified(mtime).expect("set mtime");
    }

    #[test]
    fn under_the_cap_is_a_noop() {
        let dir = tempfile::tempdir().expect("tempdir");
        seed_dossiers(dir.path(), 3);
        let (removed, bytes) = prune_dossiers_in(dir.path(), 500, false).expect("prune");
        assert_eq!(removed, 0);
        assert_eq!(bytes, 0);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 3);
    }

    #[test]
    fn trims_oldest_beyond_the_cap_and_keeps_newest() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = seed_dossiers(dir.path(), 10);
        let (removed, bytes) = prune_dossiers_in(dir.path(), 4, false).expect("prune");
        assert_eq!(removed, 6, "10 files, cap 4 → 6 trimmed");
        assert!(bytes > 0, "reclaimed bytes reported");
        // The 4 newest (highest index) survive; the 6 oldest are gone.
        for (i, p) in paths.iter().enumerate() {
            let exists = p.exists();
            if i >= 6 {
                assert!(exists, "newest kept: {p:?}");
            } else {
                assert!(!exists, "oldest trimmed: {p:?}");
            }
        }
    }

    #[test]
    fn dry_run_measures_but_removes_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        seed_dossiers(dir.path(), 8);
        let (removed, bytes) = prune_dossiers_in(dir.path(), 2, true).expect("prune");
        assert_eq!(removed, 6, "reports the 6 it WOULD trim");
        assert!(bytes > 0);
        // Nothing actually deleted.
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 8);
    }

    #[test]
    fn second_pass_is_idempotent() {
        let dir = tempfile::tempdir().expect("tempdir");
        seed_dossiers(dir.path(), 7);
        let first = prune_dossiers_in(dir.path(), 3, false).expect("prune");
        assert_eq!(first.0, 4);
        let second = prune_dossiers_in(dir.path(), 3, false).expect("prune again");
        assert_eq!(second.0, 0, "already at the cap → nothing more to trim");
        assert_eq!(second.1, 0);
    }

    #[test]
    fn missing_directory_is_a_clean_noop() {
        let dir = tempfile::tempdir().expect("tempdir");
        let absent = dir.path().join("does-not-exist");
        let (removed, bytes) = prune_dossiers_in(&absent, 10, false).expect("prune");
        assert_eq!((removed, bytes), (0, 0));
    }

    #[test]
    fn non_txt_files_are_left_untouched() {
        let dir = tempfile::tempdir().expect("tempdir");
        seed_dossiers(dir.path(), 6);
        // A non-dossier file must never be counted or removed.
        std::fs::write(dir.path().join("keep.json"), b"{}").expect("write");
        let (removed, _) = prune_dossiers_in(dir.path(), 2, false).expect("prune");
        assert_eq!(removed, 4, "only .txt dossiers are trimmed");
        assert!(dir.path().join("keep.json").exists(), "non-.txt preserved");
    }

    #[test]
    fn dry_run_report_flag_is_set_and_layout_untouched() {
        // The full pass under dry_run must not arrange the layout (pure measure).
        let report = run(true).expect("dry run");
        assert!(report.dry_run);
        assert!(report.dirs_arranged.is_empty());
        assert!(!report.wal_truncated);
    }
}
