//! The verification gate, ported from `scripts/repair-gate.sh`.
//!
//! Each mode runs a fixed sequence of commands in the repository root, each under a time
//! limit. Before and after the sequence the repository is captured: the commit HEAD names, the
//! tracked diff against HEAD, and the bytes of every untracked file. A verification step that
//! writes into the tree, or a commit made during the run, fails the gate, instead of passing
//! with content it did not report.

use std::fs;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::Duration;

use crate::changelog;
use crate::error::{self, Error, Result};
use crate::proc::{GateLock, RunRecord, git_stdout, repository_root, run_step};

const USAGE: &str = "usage: cargo run --locked -p xtask -- gate [fast|msrv|full]

Use after any error, bug, broken file, malfunctioning code path, failed refactor,
or suspicious repository change.

fast  - syntax/format + no-unwrap lint of production code + focused repository self-check
msrv  - full Rust test suite + repository self-check (for Rust 1.87)
full  - host acceptance: format + no-unwrap lint + strict clippy + full tests + self-check

A full host pass is necessary but not sufficient for platform-specific changes.
Container and Android/Termux changes require their platform gates too.";

const DEFAULT_TIMEOUT_SECONDS: u64 = 3600;
/// Maximum memory used to capture the source baseline on a constrained Android device.
/// An oversized checkout is refused, never silently truncated or incorrectly marked clean.
const MAX_SNAPSHOT_BYTES: usize = 16 * 1024 * 1024;
const SNAPSHOT_TOO_LARGE: &str = "verification snapshot exceeds the 16 MiB memory budget";

/// The refusal for repository content that verification changed. `tests/repair_contract.rs`
/// pins this wording.
const MUTATED: &str = "verification mutated tracked or untracked repository content";

/// The gate's mode. `Full` is the default, as it was for the shell script.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Fast,
    Msrv,
    Full,
}

impl Mode {
    fn name(self) -> &'static str {
        match self {
            Self::Fast => "fast",
            Self::Msrv => "msrv",
            Self::Full => "full",
        }
    }
}

/// Runs the gate for the arguments after `gate`, and returns the process exit status.
pub fn run(args: &[String]) -> ExitCode {
    let mode = match args.first().map_or("full", String::as_str) {
        "fast" => Mode::Fast,
        "msrv" => Mode::Msrv,
        "full" => Mode::Full,
        "-h" | "--help" if args.len() == 1 => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        _ => return error::usage(USAGE),
    };
    if args.len() > 1 {
        return error::usage(USAGE);
    }
    let limit = match timeout_from_env() {
        Ok(limit) => limit,
        Err(problem) => return error::report("repair-gate", &problem),
    };
    let root = repository_root();
    match execute(mode, &root, limit) {
        Ok(logs) => {
            println!(
                "repair-gate: PASS mode={} timeout={}s logs={}",
                mode.name(),
                limit.as_secs(),
                logs.display()
            );
            ExitCode::SUCCESS
        }
        Err(problem) => error::report("repair-gate: FAIL", &problem),
    }
}

/// `REPAIR_GATE_TIMEOUT_SECONDS`, read as the shell did: unset or empty means the default, and
/// anything but whole seconds of at least one is a usage error.
fn timeout_from_env() -> Result<Duration> {
    let raw = match std::env::var("REPAIR_GATE_TIMEOUT_SECONDS") {
        Ok(value) if !value.is_empty() => value,
        _ => return Ok(Duration::from_secs(DEFAULT_TIMEOUT_SECONDS)),
    };
    let invalid = || Error::Invalid(format!("invalid REPAIR_GATE_TIMEOUT_SECONDS={raw}"));
    if !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid());
    }
    let seconds: u64 = raw.parse().map_err(|_| invalid())?;
    if seconds < 1 {
        return Err(Error::Invalid(
            "REPAIR_GATE_TIMEOUT_SECONDS must be >= 1".to_owned(),
        ));
    }
    Ok(Duration::from_secs(seconds))
}

/// Runs the steps of MODE. Returns the directory that holds their logs.
fn execute(mode: Mode, root: &Path, limit: Duration) -> Result<PathBuf> {
    if mode == Mode::Msrv {
        check_msrv_toolchain(root)?;
    }
    // One run per checkout: a second run would share the build directory and the tree.
    let _lock = GateLock::acquire(root)?;
    let mut record = RunRecord::create(root, mode.name())?;
    let before = baseline(root)?;

    // A malformed changelog fragment is refused before any build, in every mode.
    let fragments = changelog::check(root)?;
    println!("xtask: changelog fragments: {fragments} valid");

    for script in tracked_shell_scripts(root)? {
        if script == "scripts/container-entrypoint.sh" {
            run_step(root, limit, &mut record, "sh", &["-n", &script])?;
        } else {
            run_step(root, limit, &mut record, "bash", &["-n", &script])?;
        }
    }
    if matches!(mode, Mode::Fast | Mode::Full) {
        run_step(root, limit, &mut record, "cargo", &["fmt", "--check"])?;
        // Production code has no `unwrap()`: the library and both binaries compile without
        // `cfg(test)` here, so inline tests are not linted. A manifest-level deny would reach
        // the test binaries too, which is why the lint is a gate step instead.
        for package in [
            &["-p", "huntsman-recon", "--lib", "--bins"][..],
            &["-p", "xtask", "--bins"][..],
        ] {
            let mut args = vec!["clippy"];
            args.extend_from_slice(package);
            args.extend_from_slice(&["--locked", "--", "-D", "clippy::unwrap_used"]);
            run_step(root, limit, &mut record, "cargo", &args)?;
        }
    }
    if mode == Mode::Full {
        run_step(
            root,
            limit,
            &mut record,
            "cargo",
            &[
                "clippy",
                "--workspace",
                "--all-targets",
                "--locked",
                "--",
                "-D",
                "warnings",
            ],
        )?;
    }
    if matches!(mode, Mode::Msrv | Mode::Full) {
        run_step(
            root,
            limit,
            &mut record,
            "cargo",
            &["test", "--locked", "--workspace"],
        )?;
    } else {
        for test in [
            "functional_code_contract",
            "directive_lock",
            "deployment_targets",
            "repair_contract",
        ] {
            run_step(
                root,
                limit,
                &mut record,
                "cargo",
                &["test", "--locked", "--test", test],
            )?;
        }
        run_step(
            root,
            limit,
            &mut record,
            "cargo",
            &["test", "--locked", "-p", "xtask"],
        )?;
    }
    run_step(
        root,
        limit,
        &mut record,
        "cargo",
        &["run", "--locked", "--", "check"],
    )?;

    let after = baseline(root)?;
    if let Some(problem) = drift(&before, &after) {
        let _ = std::process::Command::new("git")
            .args(["status", "--short", "--untracked-files=all"])
            .current_dir(root)
            .status();
        return Err(Error::Refused(problem));
    }
    Ok(record.dir().to_path_buf())
}

/// `msrv` checks the crate on the toolchain it declares. A newer rustc would accept code that
/// the declared floor rejects, so the mode refuses to run on any other compiler.
fn check_msrv_toolchain(root: &Path) -> Result<()> {
    let path = root.join("Cargo.toml");
    let manifest = fs::read_to_string(&path).map_err(|source| Error::Io {
        path: path.clone(),
        source,
    })?;
    let declared = manifest
        .lines()
        .find_map(|line| {
            line.strip_prefix("rust-version = \"")
                .and_then(|rest| rest.strip_suffix('"'))
        })
        .ok_or_else(|| Error::Invalid("Cargo.toml declares no rust-version".to_owned()))?;
    let output = std::process::Command::new("rustc")
        .arg("--version")
        .output()
        .map_err(|source| Error::Command {
            shown: "rustc --version".to_owned(),
            reason: format!("could not start: {source}"),
        })?;
    let version = String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_owned();
    let major_minor = version
        .rsplit_once('.')
        .map_or(version.as_str(), |(head, _)| head);
    if major_minor != declared {
        return Err(Error::Refused(format!(
            "msrv needs the declared rust-version {declared}, but rustc is {version}. Run: rustup run {declared} cargo run --locked -p xtask -- gate msrv"
        )));
    }
    Ok(())
}

/// The shell scripts git tracks, so every one of them must still parse.
fn tracked_shell_scripts(root: &Path) -> Result<Vec<String>> {
    let listing = git_stdout(root, &["ls-files", "-z", "--", "*.sh"])?;
    let mut scripts: Vec<String> = listing
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
        .map(|path| String::from_utf8_lossy(path).into_owned())
        .collect();
    scripts.sort();
    Ok(scripts)
}

/// Collect a tracked diff with a hard byte limit. `Command::output` would buffer the
/// entire diff before checking its size, defeating the mobile memory budget.
fn tracked_diff(root: &Path) -> Result<Vec<u8>> {
    let mut child = Command::new("git")
        .args(["diff", "--binary", "--no-ext-diff", "HEAD", "--"])
        .current_dir(root)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|source| Error::Command {
            shown: "git diff --binary --no-ext-diff HEAD --".to_owned(),
            reason: format!("could not start: {source}"),
        })?;
    let mut out = Vec::new();
    let read = child
        .stdout
        .take()
        .ok_or_else(|| Error::Refused("git diff stdout is not available".to_owned()))?
        .take(MAX_SNAPSHOT_BYTES as u64 + 1)
        .read_to_end(&mut out);
    if read.is_err() || out.len() > MAX_SNAPSHOT_BYTES {
        let _ = child.kill();
        let _ = child.wait();
        if out.len() > MAX_SNAPSHOT_BYTES {
            return Err(Error::Refused(SNAPSHOT_TOO_LARGE.to_owned()));
        }
        return Err(Error::Command {
            shown: "git diff".to_owned(),
            reason: format!("could not read output: {}", read.expect_err("checked above")),
        });
    }
    let status = child.wait().map_err(|source| Error::Command {
        shown: "git diff".to_owned(),
        reason: format!("could not wait for git: {source}"),
    })?;
    if !status.success() {
        return Err(Error::Command {
            shown: "git diff".to_owned(),
            reason: format!("exited with {status}"),
        });
    }
    Ok(out)
}

/// Add a single baseline component without ever exceeding the memory budget.
fn append_snapshot(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    if bytes.len() > MAX_SNAPSHOT_BYTES.saturating_sub(out.len()) {
        return Err(Error::Refused(SNAPSHOT_TOO_LARGE.to_owned()));
    }
    out.extend_from_slice(bytes);
    Ok(())
}

/// The repository content verification must leave unchanged: the tracked diff against HEAD,
/// then every untracked file (by path, in byte order) with its bytes, or its link target.
/// Reject oversized baselines and non-regular files rather than hanging or exhausting RAM.
fn snapshot(root: &Path) -> Result<Vec<u8>> {
    let mut out = tracked_diff(root)?;
    let listing = git_stdout(root, &["ls-files", "--others", "--exclude-standard", "-z"])?;
    let mut paths: Vec<&[u8]> = listing
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
        .collect();
    paths.sort_unstable();
    for path in paths {
        append_snapshot(&mut out, b"\0untracked\0")?;
        append_snapshot(&mut out, path)?;
        append_snapshot(&mut out, &[0])?;
        let full = root.join(std::ffi::OsStr::from_bytes(path));
        let metadata = fs::symlink_metadata(&full).map_err(|source| Error::Io {
            path: full.clone(),
            source,
        })?;
        if metadata.file_type().is_symlink() {
            let target = fs::read_link(&full).map_err(|source| Error::Io {
                path: full.clone(),
                source,
            })?;
            append_snapshot(&mut out, target.as_os_str().as_bytes())?;
        } else if metadata.file_type().is_file() {
            let available = MAX_SNAPSHOT_BYTES.saturating_sub(out.len());
            if metadata.len() > available as u64 {
                return Err(Error::Refused(SNAPSHOT_TOO_LARGE.to_owned()));
            }
            let file = fs::File::open(&full).map_err(|source| Error::Io {
                path: full.clone(),
                source,
            })?;
            // Recheck the opened handle in case the path was replaced since lstat.
            let opened = file.metadata().map_err(|source| Error::Io {
                path: full.clone(),
                source,
            })?;
            if !opened.is_file() {
                return Err(Error::Refused(format!(
                    "verification cannot snapshot non-regular file: {}",
                    full.display()
                )));
            }
            file.take(available as u64 + 1)
                .read_to_end(&mut out)
                .map_err(|source| Error::Io {
                    path: full.clone(),
                    source,
                })?;
            if out.len() > MAX_SNAPSHOT_BYTES {
                return Err(Error::Refused(SNAPSHOT_TOO_LARGE.to_owned()));
            }
        } else {
            return Err(Error::Refused(format!(
                "verification cannot snapshot non-regular file: {}",
                full.display()
            )));
        }
    }
    Ok(out)
}

/// The state verification must leave unchanged: the commit HEAD names, then the content that
/// `snapshot` captures. A commit made during the run moves HEAD and so also changes the content,
/// so HEAD is compared on its own, which names the cause.
struct Baseline {
    head: Vec<u8>,
    content: Vec<u8>,
}

fn baseline(root: &Path) -> Result<Baseline> {
    Ok(Baseline {
        head: git_stdout(root, &["rev-parse", "HEAD"])?,
        content: snapshot(root)?,
    })
}

/// The refusal for a repository that verification changed, or `None` when it did not.
fn drift(before: &Baseline, after: &Baseline) -> Option<String> {
    if before.head != after.head {
        let from = short_id(&before.head);
        let to = short_id(&after.head);
        return Some(format!(
            "HEAD moved from {from} to {to} during verification; commit only after the gate passes"
        ));
    }
    if before.content != after.content {
        return Some(MUTATED.to_owned());
    }
    None
}

/// The first twelve characters of a commit id, as `git rev-parse` prints it.
fn short_id(head: &[u8]) -> String {
    String::from_utf8_lossy(head)
        .trim()
        .chars()
        .take(12)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::process::Command;

    /// A fresh repository with one commit, under the system temporary directory.
    fn fixture_repo(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("xtask-gate-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("fixture directory");
        let git = |args: &[&str]| {
            let status = Command::new("git")
                .args(args)
                .current_dir(&dir)
                .status()
                .expect("git must run");
            assert!(status.success(), "git {args:?} failed");
        };
        git(&["init", "-q"]);
        fs::write(dir.join("tracked.txt"), "one\n").expect("tracked file");
        git(&["add", "tracked.txt"]);
        git(&[
            "-c",
            "user.name=fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "-m",
            "base",
        ]);
        dir
    }

    /// Records an empty commit in DIR, as a verification step that commits would.
    fn commit_in(dir: &Path, message: &str) {
        let status = Command::new("git")
            .args([
                "-c",
                "user.name=fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-q",
                "--allow-empty",
                "-m",
                message,
            ])
            .current_dir(dir)
            .status()
            .expect("git must run");
        assert!(status.success(), "git commit failed");
    }

    #[test]
    fn an_oversized_untracked_file_is_refused_before_allocating_its_contents() {
        let dir = fixture_repo("oversized-untracked");
        let file = fs::File::create(dir.join("oversized.bin")).expect("create sparse file");
        file.set_len(MAX_SNAPSHOT_BYTES as u64 + 1)
            .expect("set logical size without allocating");
        let problem = snapshot(&dir).expect_err("large evidence must not exhaust device RAM");
        assert!(
            problem.to_string().contains(SNAPSHOT_TOO_LARGE),
            "{problem}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_untracked_fifo_is_refused_without_waiting_for_a_writer() {
        let dir = fixture_repo("fifo-untracked");
        let result = Command::new("mkfifo")
            .arg("pipe")
            .current_dir(&dir)
            .status()
            .expect("mkfifo is available on Unix");
        assert!(result.success(), "mkfifo failed");
        let problem = snapshot(&dir).expect_err("a named pipe must not block verification");
        assert!(
            problem.to_string().contains("non-regular file"),
            "{problem}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_file_written_during_verification_changes_the_snapshot() {
        let dir = fixture_repo("untracked");
        let before = snapshot(&dir).expect("snapshot before");
        assert_eq!(
            before,
            snapshot(&dir).expect("snapshot again"),
            "an unchanged tree is stable"
        );
        fs::write(dir.join("written-by-a-check.txt"), "output\n").expect("write");
        assert_ne!(
            before,
            snapshot(&dir).expect("snapshot after"),
            "a new untracked file must show"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_edit_to_a_tracked_file_changes_the_snapshot() {
        let dir = fixture_repo("tracked");
        let before = snapshot(&dir).expect("snapshot before");
        fs::write(dir.join("tracked.txt"), "two\n").expect("write");
        assert_ne!(
            before,
            snapshot(&dir).expect("snapshot after"),
            "an edit to a tracked file must show"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_commit_made_during_verification_is_named_as_a_moved_head() {
        let dir = fixture_repo("head");
        let before = baseline(&dir).expect("baseline before");
        commit_in(&dir, "made during verification");
        let after = baseline(&dir).expect("baseline after");
        let problem = drift(&before, &after).expect("a commit moves HEAD");
        assert!(problem.starts_with("HEAD moved from "), "{problem}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_written_file_is_reported_as_mutated_content() {
        let dir = fixture_repo("written");
        let before = baseline(&dir).expect("baseline before");
        fs::write(dir.join("written-by-a-check.txt"), "output\n").expect("write");
        let after = baseline(&dir).expect("baseline after");
        assert_eq!(drift(&before, &after).as_deref(), Some(MUTATED));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unchanged_repository_has_no_drift() {
        let dir = fixture_repo("stable");
        let before = baseline(&dir).expect("baseline before");
        let after = baseline(&dir).expect("baseline after");
        assert_eq!(drift(&before, &after), None);
        let _ = fs::remove_dir_all(&dir);
    }
}
