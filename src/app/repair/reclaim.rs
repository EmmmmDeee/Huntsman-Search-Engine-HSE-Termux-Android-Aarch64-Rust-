//! The reclaim allowlist: which on-disk artefacts `hse repair` may delete.
//!
//! Deliberately an explicit list of *named* paths derived from a root, not a
//! glob or a walk. A repair command that deletes by pattern is one bad pattern
//! away from destroying the operator's intelligence data, so the set of
//! deletable things is enumerated in one place, each entry carrying the reason
//! it is safe — and every entry is reproducible from the network or a rebuild.
//!
//! Everything under `$HOME/.huntsman` is absent from this file by construction:
//! the scan database, key pool, key vault and dossiers are the operator's data,
//! not cache. The store is compacted in place by the repair's store stage; it is
//! never listed here.
//!
//! Pure over an arbitrary `home` so the whole policy is unit-testable against a
//! temporary directory rather than the developer's real `$HOME` — the tests
//! below build a fake Termux layout and assert both what is reclaimed and, more
//! importantly, what is refused.

use std::path::{Path, PathBuf};

use crate::core::error::{Error, Result};

/// What happened to one target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reclaimed {
    /// Deleted.
    Removed,
    /// Deliberately kept, with the reason (e.g. a live server owns it).
    Retained(&'static str),
}

/// One reclaimable artefact.
#[derive(Debug, Clone)]
pub struct ReclaimTarget {
    pub path: PathBuf,
    /// Why deleting this is safe — shown to the operator verbatim.
    pub why: &'static str,
    /// True when the entry is a directory tree rather than a single file.
    pub is_tree: bool,
    /// When set, the target is kept if this PID file names a live process.
    /// Guards the background server's own runtime state.
    pub guard_pid_file: Option<PathBuf>,
}

impl ReclaimTarget {
    fn file(path: PathBuf, why: &'static str) -> Self {
        Self {
            path,
            why,
            is_tree: false,
            guard_pid_file: None,
        }
    }

    fn tree(path: PathBuf, why: &'static str) -> Self {
        Self {
            path,
            why,
            is_tree: true,
            guard_pid_file: None,
        }
    }

    #[must_use]
    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    /// Total bytes this target occupies. Directory trees are summed
    /// recursively; an unreadable entry contributes 0 rather than aborting the
    /// walk, because a size estimate must never be the reason a repair fails.
    #[must_use]
    pub fn size_bytes(&self) -> u64 {
        dir_size(&self.path)
    }

    /// Delete the target, honouring its liveness guard.
    ///
    /// # Errors
    /// Returns the underlying I/O error when the path exists but cannot be
    /// removed (permissions, a busy mount).
    pub fn remove(&self) -> Result<Reclaimed> {
        if let Some(pid_file) = &self.guard_pid_file
            && pid_is_live(pid_file)
        {
            return Ok(Reclaimed::Retained(
                "the background server is running — stop it with `hse-bg stop` first",
            ));
        }
        if !self.path.exists() {
            return Ok(Reclaimed::Removed);
        }
        let res = if self.is_tree {
            std::fs::remove_dir_all(&self.path)
        } else {
            std::fs::remove_file(&self.path)
        };
        res.map(|()| Reclaimed::Removed)
            .map_err(|e| Error::Other(format!("{}: {e}", self.path.display())))
    }
}

/// Every artefact `hse repair` may reclaim, for this `home` and optional source
/// checkout.
///
/// `deep` adds the expensive-to-regenerate entries: the Cargo target directory
/// (a full aarch64 rebuild is ~15–20 minutes) and the logs, which are the
/// post-mortem record of the last install and server run and so are kept by
/// default. Everything in the shallow set is either re-downloadable in seconds
/// or pure scratch.
///
/// Each path mirrors one that `install.sh` itself creates; the comments name the
/// producer so the two cannot drift silently.
#[must_use]
pub fn reclaimable_targets(
    home: &Path,
    install_dir: Option<PathBuf>,
    deep: bool,
) -> Vec<ReclaimTarget> {
    let cache = home.join(".cache");
    let mut out = vec![
        // install.sh: `tmp="$HOME/.cache/hse-dl"` — release assets, re-fetched
        // on demand.
        ReclaimTarget::tree(
            cache.join("hse-dl"),
            "downloaded release assets — re-fetched on demand",
        ),
        // install.sh: `staged="$HOME/.cache/hse-prebuilt"` — a copy of the
        // binary already installed to $PREFIX/bin.
        ReclaimTarget::file(
            cache.join("hse-prebuilt"),
            "staged prebuilt copy — the installed binary is the live one",
        ),
        // install.sh seeds this to throttle the auto-update check; losing it
        // only causes one extra check.
        ReclaimTarget::file(
            cache.join("hse-autoupdate"),
            "auto-update throttle stamp — regenerated on the next check",
        ),
    ];

    if deep {
        // install.sh: `export CARGO_TARGET_DIR="$HOME/.cache/hse-build"`.
        // Routinely the largest thing on the device — a release target tree with
        // its .fingerprint/, deps/ and build/ subtrees runs to gigabytes.
        out.push(ReclaimTarget::tree(
            cache.join("hse-build"),
            "Cargo build cache — rebuilt on the next source build (~15-20 min)",
        ));
        // An in-tree `target/` from a build that ran without CARGO_TARGET_DIR
        // set. Same rationale, different location.
        if let Some(dir) = install_dir {
            out.push(ReclaimTarget::tree(
                dir.join("target"),
                "in-tree Cargo build cache — rebuilt on the next source build",
            ));
        }
        out.push(ReclaimTarget::file(
            cache.join("hse-install.log"),
            "installer log — post-mortem record of the last install",
        ));
        // The server log is guarded: truncating it out from under a running
        // server loses the live record.
        let mut bg_log = ReclaimTarget::file(
            cache.join("hse-bg.log"),
            "background server log — post-mortem record of the last run",
        );
        bg_log.guard_pid_file = Some(cache.join("hse-bg.pid"));
        out.push(bg_log);
    }

    // Never hand back anything containing the RUNNING binary. A dry run on a
    // development checkout proposed freeing 21.9 GiB from `<checkout>/target`,
    // which is where the executing `hse` had been built: reclaiming it would
    // have deleted the binary mid-run. On a normal Termux install the live
    // binary is at `$PREFIX/bin/hse`, outside every path above, so this is inert
    // there and decisive in the one place it matters.
    //
    // Applied to the WHOLE set as the last step rather than beside the entry
    // that prompted it, so a future addition inherits the guard instead of
    // needing to remember it. Filtered out rather than reported-and-refused: the
    // operator is never shown reclaimable space they cannot actually have.
    out.retain(|t| !contains_running_exe(&t.path));
    out
}

/// True when `dir` contains the currently-running executable.
///
/// Both sides are canonicalised so a symlinked `$PREFIX/bin/hse`, a relative
/// invocation, or a `..` in either path cannot defeat the comparison. When the
/// executable path cannot be resolved at all the answer is conservatively
/// `true` — refusing to reclaim costs the operator disk, deleting the running
/// binary costs them the install.
fn contains_running_exe(dir: &Path) -> bool {
    let Ok(exe) = std::env::current_exe() else {
        return true;
    };
    let exe = exe.canonicalize().unwrap_or(exe);
    // A non-existent candidate cannot contain anything; canonicalise falls back
    // to the literal path so the prefix test still runs on a fresh layout.
    let dir = dir.canonicalize().unwrap_or_else(|_| dir.to_path_buf());
    exe.starts_with(&dir)
}

/// Recursive size of a file or directory tree, in bytes.
///
/// Unreadable entries contribute 0 instead of propagating: this feeds a
/// human-facing estimate and a progress line, and a permission error deep in a
/// build tree must not abort the reclaim that would have fixed it. Symlinks are
/// measured by the link itself (`symlink_metadata`), never followed, so a link
/// pointing outside the tree can neither inflate the estimate nor be traversed.
fn dir_size(path: &Path) -> u64 {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return 0;
    };
    if meta.file_type().is_symlink() {
        return meta.len();
    }
    if meta.is_file() {
        return meta.len();
    }
    let Ok(entries) = std::fs::read_dir(path) else {
        return 0;
    };
    entries
        .flatten()
        .map(|e| dir_size(&e.path()))
        .sum::<u64>()
        .saturating_add(meta.len())
}

/// True when `pid_file` holds the PID of a process that is currently alive.
///
/// Absent, unreadable, or unparseable file → not live, so a stale PID file never
/// blocks a reclaim forever. Liveness is the presence of `/proc/<pid>`, which
/// Termux can read for its own UID's processes without root. Where that check is
/// unavailable the answer is conservatively "live", so nothing is deleted on a
/// platform this cannot verify.
///
/// The cfg must name **android** explicitly. HSE's deployment target is
/// `aarch64-linux-android`, whose `target_os` is `"android"` — NOT `"linux"`,
/// despite the triple containing the word. A bare `target_os = "linux"` gate
/// compiles this check out on the one platform the whole command exists for,
/// leaving `pid_is_live` permanently `true` there and making the background
/// server's log unreclaimable on every real device while the tests pass on the
/// x86_64 developer host. That is exactly the shape of bug that only shows up in
/// the operator's hands.
fn pid_is_live(pid_file: &Path) -> bool {
    let Ok(raw) = std::fs::read_to_string(pid_file) else {
        return false;
    };
    let Ok(pid) = raw.trim().parse::<i32>() else {
        return false;
    };
    if pid <= 0 {
        return false;
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        // No root, no libc signal call: /proc is readable for our own UID's
        // processes on Termux, and its presence is the liveness answer.
        Path::new(&format!("/proc/{pid}")).exists()
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        true
    }
}
