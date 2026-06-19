//! `hse update` — in-place self-upgrade.
//!
//! Finds the source install directory (via `HUNTSMAN_INSTALL_DIR` stored by
//! `install.sh`, then common locations, then binary path traversal), and runs
//! `install.sh` from there. The script is idempotent: it `git pull`s, rebuilds
//! with the same profile, and atomically swaps the binary — the running process
//! is unaffected (Unix keeps the old inode in memory).
//!
//! `--check` performs a read-only `git fetch` and reports how many commits are
//! available without installing anything.

use std::path::{Path, PathBuf};
use std::process::Stdio;

use crate::core::error::{Error, Result};

const INSTALL_CMD: &str = concat!(
    "curl -fsSL https://raw.githubusercontent.com/",
    "EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/",
    "main/install.sh | bash"
);

pub async fn cmd_update(check: bool, ref_: Option<String>) -> Result<()> {
    println!("hse {} — update", crate::VERSION);

    let install_dir = find_install_dir();

    if check {
        match &install_dir {
            Some(dir) => {
                print!("Source: {}  ", dir.display());
                match commits_behind(dir) {
                    Some(0) => println!("Already up to date."),
                    Some(n) => println!("{n} commit(s) available — run `hse update` to install."),
                    None => println!("(could not reach remote — offline?)"),
                }
            }
            None => {
                println!("Source directory not found.");
                println!("Re-run the installer to get updates:");
                println!("  {INSTALL_CMD}");
            }
        }
        return Ok(());
    }

    apply_update(ref_).await
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Search for the Huntsman source directory in order of priority:
///
/// 1. `HUNTSMAN_INSTALL_DIR` env var — written by `install.sh` on every run.
/// 2. Common install paths under `$HOME` (`.local/share/hse`, `hse`, `.hse`).
/// 3. Upward traversal from the running binary (dev / in-place builds).
pub(crate) fn find_install_dir() -> Option<PathBuf> {
    // 1. Env var written by install.sh
    if let Ok(d) = std::env::var("HUNTSMAN_INSTALL_DIR") {
        let p = PathBuf::from(d);
        if is_hse_source(&p) {
            return Some(p);
        }
    }

    // 2. Common install paths under $HOME
    if let Ok(home) = std::env::var("HOME") {
        let home = PathBuf::from(home);
        for rel in &[".local/share/hse", "hse", ".hse"] {
            let p = home.join(rel);
            if is_hse_source(&p) {
                return Some(p);
            }
        }
    }

    // 3. Walk up from the running binary (in-place dev builds)
    if let Ok(exe) = std::env::current_exe() {
        let mut p = exe.parent()?.to_path_buf();
        for _ in 0..5 {
            if is_hse_source(&p) {
                return Some(p);
            }
            match p.parent() {
                Some(parent) => p = parent.to_path_buf(),
                None => break,
            }
        }
    }

    None
}

fn is_hse_source(p: &Path) -> bool {
    p.join("Cargo.toml").exists() && p.join("install.sh").exists()
}

/// `git fetch` then count commits on `@{u}` not in `HEAD`.
/// Returns `None` when git is absent or the remote is unreachable.
pub(crate) fn commits_behind(dir: &Path) -> Option<u64> {
    let _ = std::process::Command::new("git")
        .args(["fetch", "--quiet"])
        .current_dir(dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    std::process::Command::new("git")
        .args(["rev-list", "--count", "HEAD..@{u}"])
        .current_dir(dir)
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse().ok())
}

/// Convenience wrapper: find the install dir and return how many commits behind
/// the tracking branch HEAD is. Returns `None` when offline or no install dir.
pub(crate) fn check_updates() -> Option<u64> {
    find_install_dir().and_then(|d| commits_behind(&d))
}

/// Apply an update by running `install.sh` from the located source directory.
/// Returns `Ok(())` on success, `Err` if the script is not found or exits
/// non-zero. Does not print banners (designed for headless background use).
pub(crate) async fn apply_update(ref_: Option<String>) -> Result<()> {
    // ── Locate install.sh ────────────────────────────────────────────────────
    let script = find_install_dir()
        .map(|d| d.join("install.sh"))
        .filter(|s| s.exists());

    let Some(script_path) = script else {
        return Err(Error::Other(format!(
            "No local source found. Re-run the installer: {INSTALL_CMD}"
        )));
    };

    // ── Invoke install.sh (inherits stdio for real-time progress) ────────────
    let mut cmd = std::process::Command::new("bash");
    cmd.arg(&script_path)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    if let Some(r) = ref_ {
        cmd.env("HSE_REF", r);
    }

    let status = tokio::task::spawn_blocking(move || cmd.status())
        .await
        .map_err(|e| Error::Other(e.to_string()))?
        .map_err(|e| Error::Other(format!("could not launch installer: {e}")))?;

    if !status.success() {
        return Err(Error::Other(format!(
            "installer exited {}",
            status.code().map_or("(signal)".into(), |c| c.to_string())
        )));
    }

    Ok(())
}

/// Re-exec the current binary with the same arguments via `exec(2)` on Unix.
///
/// This replaces the running process image in-place, preserving the bind
/// address and all argv flags. On success this function never returns (`!`).
/// On failure it prints a diagnostic and exits with code 1.
///
/// `CommandExt::exec` is a safe function — it is not declared `unsafe`.
#[cfg(unix)]
pub(crate) fn self_restart() -> ! {
    use std::os::unix::process::CommandExt;
    let exe = std::env::current_exe().expect("cannot determine current exe");
    let args: Vec<String> = std::env::args().skip(1).collect();
    let err = std::process::Command::new(&exe).args(&args).exec();
    // exec() only returns on failure
    eprintln!("hse: self-restart failed: {err}");
    std::process::exit(1);
}

/// Fallback for non-Unix platforms: print a notice and exit cleanly so the
/// process supervisor (if any) can restart us.
#[cfg(not(unix))]
pub(crate) fn self_restart() -> ! {
    eprintln!("hse: self-restart not supported on this platform; please restart manually");
    std::process::exit(0);
}
