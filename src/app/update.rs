//! Application update lifecycle.
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

pub const INSTALL_CMD: &str = concat!(
    "curl -fsSL https://raw.githubusercontent.com/",
    "EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/",
    "main/install.sh | bash"
);

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Search for the Huntsman source directory in order of priority:
///
/// 1. `HUNTSMAN_INSTALL_DIR` env var — written by `install.sh` on every run.
/// 2. Common install paths under `$HOME` (`.local/share/hse`, `hse`, `.hse`).
/// 3. Upward traversal from the running binary (dev / in-place builds).
pub fn find_install_dir() -> Option<PathBuf> {
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
pub fn commits_behind(dir: &Path) -> Option<u64> {
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

/// One-line subjects for commits on `@{u}` not in `HEAD`.
/// Returns an empty `Vec` when git is absent, the remote is unreachable, or
/// there are no new commits.
pub fn changelog_lines(dir: &Path) -> Vec<String> {
    std::process::Command::new("git")
        .args(["log", "--oneline", "HEAD..@{u}"])
        .current_dir(dir)
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.lines().map(str::to_owned).collect())
        .unwrap_or_default()
}

/// Convenience wrapper: find the install dir and return how many commits behind
/// the tracking branch HEAD is. Returns `None` when offline or no install dir.
pub fn check_updates() -> Option<u64> {
    find_install_dir().and_then(|d| commits_behind(&d))
}

// ── Opportunistic CLI self-update ────────────────────────────────────────────
//
// `hse serve` already self-updates on a timer, but a CLI-only operator (running
// `hse scan …`, `hse import …`, etc. and never the server) would drift behind
// `main`. This gate runs once near the start of every CLI command and keeps the
// binary current — without ever delaying or interfering with the command:
//   * skipped for the commands that own updates (`serve` loop, explicit
//     `update`) and a no-op unless `feature.auto_update`/`update_notify` is on;
//   * throttled by a stamp file so at most one upstream check happens per
//     window — every other invocation returns at zero git/network cost;
//   * the check is time-boxed (a dead network can't stall the command) and, when
//     an update is found, it is applied by a DETACHED background `install.sh`:
//     the current command finishes on the current binary (Unix keeps the old
//     inode mapped) and the NEXT invocation runs the rebuilt one.

/// HSE's runtime cache directory (`~/.cache`, the same place `install.sh` logs
/// to); falls back to the system temp dir when `$HOME` is unset.
fn cache_dir() -> PathBuf {
    std::env::var_os("HOME").map_or_else(std::env::temp_dir, |h| PathBuf::from(h).join(".cache"))
}

/// Stamp file holding the unix-seconds time of the last auto-update check, so the
/// throttle window survives across CLI invocations (each is a fresh process).
fn autoupdate_stamp_path() -> PathBuf {
    cache_dir().join("hse-autoupdate.stamp")
}

/// Where a detached background `install.sh` writes its output, so an auto-update
/// that happened between commands is auditable (`~/.cache/hse-autoupdate.log`).
fn autoupdate_log_path() -> PathBuf {
    cache_dir().join("hse-autoupdate.log")
}

/// Parse the throttle window (seconds) from the raw env value, applying a 30-min
/// floor and the 6-hour default. Pure, so the policy is unit-testable. Shares the
/// serve loop's `HUNTSMAN_AUTO_UPDATE_INTERVAL_SECS` knob for one consistent
/// cadence control across both update paths.
fn parse_throttle_secs(raw: Option<&str>) -> u64 {
    raw.and_then(|v| v.parse::<u64>().ok())
        .filter(|&n| n >= 1800)
        .unwrap_or(21_600)
}

fn autoupdate_throttle_secs() -> u64 {
    parse_throttle_secs(
        std::env::var("HUNTSMAN_AUTO_UPDATE_INTERVAL_SECS")
            .ok()
            .as_deref(),
    )
}

/// Pure throttle decision: run a check now given the last-check time? `None`
/// (never checked) ⇒ yes; otherwise only once `throttle` seconds have elapsed.
/// Saturating, so a stamp written in the future (clock skew) can't wedge the gate
/// shut — it simply yields `0` elapsed and waits out the window.
fn should_check_now(last_checked: Option<u64>, now: u64, throttle: u64) -> bool {
    match last_checked {
        None => true,
        Some(t) => now.saturating_sub(t) >= throttle,
    }
}

fn read_stamp() -> Option<u64> {
    std::fs::read_to_string(autoupdate_stamp_path())
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

/// Record that an update check happened at `now` (unix seconds). Shared by the
/// CLI gate and the serve loop so a recent server-side check throttles the CLI
/// path too (and vice-versa) — one device, one cadence. Best-effort.
pub fn record_check_stamp(now: u64) {
    let path = autoupdate_stamp_path();
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(path, now.to_string());
}

/// Lock-guarded, fully-detached `install.sh` so the rebuild outlives this
/// short-lived CLI process. Paths are passed via the environment (no shell
/// quoting); `mkdir` is the atomic lock (a stale lock >2 h is reclaimed) so two
/// concurrent CLI processes can't launch overlapping updaters; `nohup` keeps the
/// build alive after we exit (reparented to init). `forbid(unsafe)` rules out
/// `pre_exec`, so the shell does the detaching. Best-effort — any failure to
/// even spawn is swallowed (the command must never suffer for an update attempt).
fn spawn_detached_update() {
    let Some(dir) = find_install_dir() else {
        return;
    };
    let script = dir.join("install.sh");
    if !script.exists() {
        return;
    }
    const DETACHED_UPDATE_SH: &str = "\
        L=\"$HSE_AU_LOCK\"; \
        [ -d \"$L\" ] && find \"$L\" -maxdepth 0 -mmin +120 -exec rmdir {} \\; 2>/dev/null; \
        mkdir \"$L\" 2>/dev/null || exit 0; \
        trap 'rmdir \"$L\" 2>/dev/null' EXIT; \
        nohup bash \"$HSE_AU_SCRIPT\" >> \"$HSE_AU_LOG\" 2>&1";
    let _ = std::process::Command::new("bash")
        .arg("-c")
        .arg(DETACHED_UPDATE_SH)
        .env("HSE_AU_SCRIPT", script)
        .env("HSE_AU_LOG", autoupdate_log_path())
        .env("HSE_AU_LOCK", cache_dir().join("hse-autoupdate.lock"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
}

/// Result of an opportunistic update check. Presentation adapters decide how to
/// report the outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AutoUpdateOutcome {
    /// No notification is needed.
    None,
    /// An update was launched in the background.
    Applying { commits: u64, log: PathBuf },
    /// An update exists, but automatic installation is disabled.
    Available { commits: u64 },
}

/// Opportunistic, throttled update gate. Best-effort: every failure path is
/// silent so callers' primary work is never the casualty.
pub async fn maybe_auto_update() -> AutoUpdateOutcome {
    let auto = crate::util::settings::get_bool("feature.auto_update", true);
    let notify = crate::util::settings::get_bool("feature.update_notify", true);
    if !auto && !notify {
        return AutoUpdateOutcome::None;
    }
    let now = crate::core::entity::unix_now();
    if !should_check_now(read_stamp(), now, autoupdate_throttle_secs()) {
        return AutoUpdateOutcome::None;
    }
    // Record the attempt up front so a slow/failed check still resets the window
    // and a second concurrent CLI process won't also fire.
    record_check_stamp(now);

    // Time-box the git fetch so an unreachable remote never delays the command.
    let behind = match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::task::spawn_blocking(check_updates),
    )
    .await
    {
        Ok(Ok(b)) => b,
        _ => return AutoUpdateOutcome::None,
    };
    let Some(n) = behind.filter(|&n| n > 0) else {
        return AutoUpdateOutcome::None;
    };

    if auto {
        spawn_detached_update();
        AutoUpdateOutcome::Applying {
            commits: n,
            log: autoupdate_log_path(),
        }
    } else {
        AutoUpdateOutcome::Available { commits: n }
    }
}

/// Apply an update by running `install.sh` from the located source directory.
/// Returns `Ok(())` on success, `Err` if the script is not found or exits
/// non-zero. Does not print banners (designed for headless background use).
pub async fn apply_update(ref_: Option<String>) -> Result<()> {
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
///
/// Both failure modes take the documented path. `current_exe()` is a real
/// syscall (`/proc/self/exe` on Linux/Android), not an infallible lookup, and
/// this is the one call site where it is *most* likely to fail: a self-restart
/// follows an update that has just rewritten or unlinked the running binary.
/// Panicking there would contradict the contract above and dump a backtrace on
/// an operator instead of the one-line diagnostic the rest of this path emits.
#[cfg(unix)]
pub fn self_restart() -> ! {
    use std::os::unix::process::CommandExt;
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(err) => {
            eprintln!("hse: self-restart failed: cannot determine current executable: {err}");
            std::process::exit(1);
        }
    };
    let args: Vec<String> = std::env::args().skip(1).collect();
    let err = std::process::Command::new(&exe).args(&args).exec();
    // exec() only returns on failure
    eprintln!("hse: self-restart failed: {err}");
    std::process::exit(1);
}

/// Fallback for non-Unix platforms: print a notice and exit cleanly so the
/// process supervisor (if any) can restart us.
#[cfg(not(unix))]
pub fn self_restart() -> ! {
    eprintln!("hse: self-restart not supported on this platform; please restart manually");
    std::process::exit(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_check_now_respects_the_throttle_window() {
        let throttle = 21_600; // 6 h
        // Never checked → always check.
        assert!(should_check_now(None, 1_000_000, throttle));
        // Exactly the window elapsed → check (>=).
        assert!(should_check_now(
            Some(1_000_000 - throttle),
            1_000_000,
            throttle
        ));
        // One second short of the window → skip.
        assert!(!should_check_now(
            Some(1_000_000 - throttle + 1),
            1_000_000,
            throttle
        ));
        // Just checked → skip.
        assert!(!should_check_now(Some(1_000_000), 1_000_000, throttle));
        // Stamp in the FUTURE (clock skew) → saturating ⇒ 0 elapsed ⇒ skip, never
        // wedged (a later `now` past the window re-opens it).
        assert!(!should_check_now(Some(2_000_000), 1_000_000, throttle));
    }

    #[test]
    fn parse_throttle_secs_applies_floor_and_default() {
        assert_eq!(parse_throttle_secs(None), 21_600, "unset → 6 h default");
        assert_eq!(
            parse_throttle_secs(Some("garbage")),
            21_600,
            "invalid → default"
        );
        assert_eq!(
            parse_throttle_secs(Some("0")),
            21_600,
            "below floor → default"
        );
        assert_eq!(
            parse_throttle_secs(Some("60")),
            21_600,
            "below 30-min floor → default"
        );
        assert_eq!(
            parse_throttle_secs(Some("1800")),
            1_800,
            "exactly the floor is honoured"
        );
        assert_eq!(
            parse_throttle_secs(Some("43200")),
            43_200,
            "explicit 12 h honoured"
        );
    }

    // ── Real-git fixtures for `commits_behind` / `changelog_lines` ──────────
    //
    // Neither function had ever been exercised against an actual `git`
    // subprocess — every existing test above targets pure logic. A local
    // origin + clone pair (both plain directories, no network) reproduces the
    // exact "behind the tracking branch" state these functions parse.

    fn run_git(dir: &Path, args: &[&str]) {
        let status = std::process::Command::new("git")
            .args(args)
            .current_dir(dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("git must be installed to run this test");
        assert!(status.success(), "git {args:?} failed in {}", dir.display());
    }

    fn init_git_repo(dir: &Path) {
        run_git(dir, &["init", "--quiet", "-b", "main"]);
        run_git(dir, &["config", "user.email", "test@example.com"]);
        run_git(dir, &["config", "user.name", "Test"]);
    }

    fn commit_file(dir: &Path, name: &str, contents: &str, message: &str) {
        std::fs::write(dir.join(name), contents).expect("should succeed");
        run_git(dir, &["add", name]);
        run_git(dir, &["commit", "--quiet", "-m", message]);
    }

    #[test]
    fn commits_behind_returns_none_without_a_configured_upstream() {
        // A real git repo with no remote/tracking branch — `@{u}` cannot resolve,
        // mirroring the "git absent or remote unreachable" contract in the doc
        // comment without needing an actually-unreachable network remote.
        let dir = tempfile::tempdir().expect("should succeed");
        init_git_repo(dir.path());
        commit_file(dir.path(), "a.txt", "1", "solo commit");
        assert_eq!(
            commits_behind(dir.path()),
            None,
            "no upstream configured must yield None, not a bogus count"
        );
        assert!(
            changelog_lines(dir.path()).is_empty(),
            "no upstream configured must yield no changelog lines"
        );
    }

    #[test]
    fn autoupdate_paths_live_under_the_cache_dir() {
        // Stamp, log, and lock are siblings in the cache dir, so install.sh (which
        // seeds the stamp) and the CLI gate agree on the location.
        let stamp = autoupdate_stamp_path();
        let log = autoupdate_log_path();
        assert_eq!(
            stamp.parent(),
            log.parent(),
            "stamp + log share a directory"
        );
        assert_eq!(
            stamp.file_name().and_then(|s| s.to_str()),
            Some("hse-autoupdate.stamp")
        );
        assert!(
            stamp.parent().is_some_and(|p| p.ends_with(".cache"))
                || std::env::var_os("HOME").is_none(),
            "cache files live under ~/.cache when HOME is set"
        );
    }

    /// True when a `git` binary is reachable on `PATH` — checked once so
    /// [`commits_behind_and_changelog_lines_reflect_real_git_state`] can skip
    /// cleanly on a machine without git installed instead of panicking the
    /// whole test binary. `commits_behind`/`changelog_lines` themselves treat
    /// "git absent" as a documented, supported runtime fallback (`None`/
    /// empty), not an error — the test suite should be no less portable than
    /// the production code it exercises.
    fn git_available() -> bool {
        std::process::Command::new("git")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }

    /// Run `git` with a fixed, isolated author/committer identity and gpg
    /// signing off, so the fixture is deterministic regardless of the host's
    /// ambient git config (this sandbox, for one, has `commit.gpgsign=true`
    /// and a signing key set globally — a real config a CI runner won't
    /// share, so relying on it either way would be non-portable).
    fn git_fixture(dir: &Path, args: &[&str]) {
        let status = std::process::Command::new("git")
            .args(["-c", "commit.gpgsign=false"])
            .args(args)
            .current_dir(dir)
            .env("GIT_AUTHOR_NAME", "Test User")
            .env("GIT_AUTHOR_EMAIL", "test@example.com")
            .env("GIT_COMMITTER_NAME", "Test User")
            .env("GIT_COMMITTER_EMAIL", "test@example.com")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("git must be installed to run this test");
        assert!(status.success(), "git {args:?} failed in {dir:?}");
    }

    /// `commits_behind`/`changelog_lines` shell out to real `git` — this
    /// exercises them against a genuine local git-repo pair (a "remote" plus
    /// a clone with upstream tracking) rather than trusting the subprocess
    /// wiring untested. No network: the "remote" is a local filesystem path,
    /// so `git fetch`/`git clone` never leave the temp directory.
    #[test]
    fn commits_behind_and_changelog_lines_reflect_real_git_state() {
        if !git_available() {
            eprintln!(
                "skipping commits_behind_and_changelog_lines_reflect_real_git_state: git not installed"
            );
            return;
        }
        let tmp = tempfile::tempdir().expect("should succeed");
        let remote = tmp.path().join("remote");
        let local = tmp.path().join("local");
        std::fs::create_dir(&remote).expect("should succeed");

        git_fixture(&remote, &["init", "-q", "--initial-branch=main"]);
        git_fixture(&remote, &["commit", "-q", "-m", "init", "--allow-empty"]);
        git_fixture(
            tmp.path(),
            &[
                "clone",
                "-q",
                remote.to_str().expect("should succeed"),
                local.to_str().expect("should succeed"),
            ],
        );

        // Freshly cloned: local is fully up to date with no new upstream commits.
        assert_eq!(commits_behind(&local), Some(0));
        assert!(changelog_lines(&local).is_empty());

        // Advance the "remote" by two commits without touching the clone.
        std::fs::write(remote.join("a.txt"), "a").expect("should succeed");
        git_fixture(&remote, &["add", "a.txt"]);
        git_fixture(&remote, &["commit", "-q", "-m", "add a"]);
        std::fs::write(remote.join("b.txt"), "b").expect("should succeed");
        git_fixture(&remote, &["add", "b.txt"]);
        git_fixture(&remote, &["commit", "-q", "-m", "add b"]);

        assert_eq!(commits_behind(&local), Some(2));
        let lines = changelog_lines(&local);
        assert_eq!(lines.len(), 2, "got: {lines:?}");
        // `git log --oneline` is newest-first; hashes are non-deterministic,
        // so assert on the subject text only.
        assert!(lines[0].ends_with("add b"), "got: {lines:?}");
        assert!(lines[1].ends_with("add a"), "got: {lines:?}");

        // `commits_behind` only ever fetches — it never advances local `HEAD` —
        // so a repeated check with no local pull still reports the same 2
        // behind, not a spuriously-reset 0.
        assert_eq!(
            commits_behind(&local),
            Some(2),
            "fetching again with no local pull must not change the behind-count"
        );

        // Once local's HEAD actually advances to match the tracking branch
        // (what `hse update` does via `install.sh`'s `git pull`), both
        // functions report the caught-up state.
        git_fixture(&local, &["merge", "-q", "--ff-only", "@{u}"]);
        assert_eq!(commits_behind(&local), Some(0));
        assert!(changelog_lines(&local).is_empty());

        // No git repo at all → the documented "git absent/unreachable" fallback.
        let not_git = tmp.path().join("not_a_repo");
        std::fs::create_dir(&not_git).expect("should succeed");
        assert_eq!(commits_behind(&not_git), None);
        assert!(changelog_lines(&not_git).is_empty());
    }
}
