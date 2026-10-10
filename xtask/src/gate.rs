//! The verification gate, ported from `scripts/repair-gate.sh`.
//!
//! Each mode runs a fixed sequence of commands in the repository root, each under a time
//! limit. Before and after the sequence the repository content is captured: the tracked diff
//! against HEAD and the bytes of every untracked file. A verification step that writes into the
//! tree fails the gate, instead of passing with content it did not report.

use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::{Duration, Instant};

const USAGE: &str = "usage: cargo run --locked -p xtask -- gate [fast|msrv|full]

Use after any error, bug, broken file, malfunctioning code path, failed refactor,
or suspicious repository change.

fast  - syntax/format + focused repository self-check
msrv  - full Rust test suite + repository self-check (for Rust 1.87)
full  - host acceptance: format + strict clippy + full tests + self-check

A full host pass is necessary but not sufficient for platform-specific changes.
Railway/container and Android/Termux changes require their platform gates too.";

const DEFAULT_TIMEOUT_SECONDS: u64 = 3600;

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
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(64);
        }
    };
    if args.len() > 1 {
        eprintln!("{USAGE}");
        return ExitCode::from(64);
    }
    let limit = match timeout_from_env() {
        Ok(limit) => limit,
        Err(message) => {
            eprintln!("repair-gate: {message}");
            return ExitCode::from(64);
        }
    };
    let root = repository_root();
    match execute(mode, &root, limit) {
        Ok(()) => {
            println!(
                "repair-gate: PASS mode={} timeout={}s",
                mode.name(),
                limit.as_secs()
            );
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("repair-gate: FAIL: {message}");
            ExitCode::from(1)
        }
    }
}

/// `REPAIR_GATE_TIMEOUT_SECONDS`, read as the shell did: unset or empty means the default, and
/// anything but whole seconds of at least one is a usage error.
fn timeout_from_env() -> Result<Duration, String> {
    let raw = match std::env::var("REPAIR_GATE_TIMEOUT_SECONDS") {
        Ok(value) if !value.is_empty() => value,
        _ => return Ok(Duration::from_secs(DEFAULT_TIMEOUT_SECONDS)),
    };
    if !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!("invalid REPAIR_GATE_TIMEOUT_SECONDS={raw}"));
    }
    let seconds: u64 = raw
        .parse()
        .map_err(|_| format!("invalid REPAIR_GATE_TIMEOUT_SECONDS={raw}"))?;
    if seconds < 1 {
        return Err("REPAIR_GATE_TIMEOUT_SECONDS must be >= 1".to_owned());
    }
    Ok(Duration::from_secs(seconds))
}

/// The repository root: this crate lives in `<root>/xtask`.
fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}

fn execute(mode: Mode, root: &Path, limit: Duration) -> Result<(), String> {
    if mode == Mode::Msrv {
        check_msrv_toolchain(root)?;
    }
    let before = snapshot(root)?;

    for script in tracked_shell_scripts(root)? {
        if script == "scripts/railway-entrypoint.sh" {
            step(root, limit, "sh", &["-n", &script])?;
        } else {
            step(root, limit, "bash", &["-n", &script])?;
        }
    }
    if matches!(mode, Mode::Fast | Mode::Full) {
        step(root, limit, "cargo", &["fmt", "--check"])?;
    }
    if mode == Mode::Full {
        step(
            root,
            limit,
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
        step(root, limit, "cargo", &["test", "--locked", "--workspace"])?;
    } else {
        for test in [
            "functional_code_contract",
            "directive_lock",
            "deployment_targets",
            "repair_contract",
        ] {
            step(root, limit, "cargo", &["test", "--locked", "--test", test])?;
        }
        step(root, limit, "cargo", &["test", "--locked", "-p", "xtask"])?;
    }
    step(root, limit, "cargo", &["run", "--locked", "--", "check"])?;

    let after = snapshot(root)?;
    if before != after {
        let _ = Command::new("git")
            .args(["status", "--short", "--untracked-files=all"])
            .current_dir(root)
            .status();
        return Err("verification mutated tracked or untracked repository content".to_owned());
    }
    Ok(())
}

/// `msrv` checks the crate on the toolchain it declares. A newer rustc would accept code that
/// the declared floor rejects, so the mode refuses to run on any other compiler.
fn check_msrv_toolchain(root: &Path) -> Result<(), String> {
    let manifest = fs::read_to_string(root.join("Cargo.toml"))
        .map_err(|error| format!("cannot read Cargo.toml: {error}"))?;
    let declared = manifest
        .lines()
        .find_map(|line| {
            line.strip_prefix("rust-version = \"")
                .and_then(|rest| rest.strip_suffix('"'))
        })
        .ok_or("Cargo.toml declares no rust-version")?;
    let output = Command::new("rustc")
        .arg("--version")
        .output()
        .map_err(|error| format!("cannot run rustc: {error}"))?;
    let version = String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_owned();
    let major_minor = version
        .rsplit_once('.')
        .map_or(version.as_str(), |(head, _)| head);
    if major_minor != declared {
        return Err(format!(
            "msrv needs the declared rust-version {declared}, but rustc is {version}. Run: rustup run {declared} cargo run --locked -p xtask -- gate msrv"
        ));
    }
    Ok(())
}

/// The shell scripts git tracks, so every one of them must still parse.
fn tracked_shell_scripts(root: &Path) -> Result<Vec<String>, String> {
    let listing = git_stdout(root, &["ls-files", "-z", "--", "*.sh"])?;
    let mut scripts: Vec<String> = listing
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
        .map(|path| String::from_utf8_lossy(path).into_owned())
        .collect();
    scripts.sort();
    Ok(scripts)
}

/// The repository content verification must leave unchanged: the tracked diff against HEAD,
/// then every untracked file (by path, in byte order) with its bytes, or its link target.
fn snapshot(root: &Path) -> Result<Vec<u8>, String> {
    let mut out = git_stdout(root, &["diff", "--binary", "--no-ext-diff", "HEAD", "--"])?;
    let listing = git_stdout(root, &["ls-files", "--others", "--exclude-standard", "-z"])?;
    let mut paths: Vec<&[u8]> = listing
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
        .collect();
    paths.sort_unstable();
    for path in paths {
        out.extend_from_slice(b"\0untracked\0");
        out.extend_from_slice(path);
        out.push(0);
        let full = root.join(std::ffi::OsStr::from_bytes(path));
        let metadata = fs::symlink_metadata(&full)
            .map_err(|error| format!("cannot inspect {}: {error}", full.display()))?;
        if metadata.file_type().is_symlink() {
            let target = fs::read_link(&full)
                .map_err(|error| format!("cannot read link {}: {error}", full.display()))?;
            out.extend_from_slice(target.as_os_str().as_bytes());
        } else {
            let bytes = fs::read(&full)
                .map_err(|error| format!("cannot read {}: {error}", full.display()))?;
            out.extend_from_slice(&bytes);
        }
    }
    Ok(out)
}

fn git_stdout(root: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .map_err(|error| format!("cannot run git: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "`git {}` failed: {}",
            args.join(" "),
            output.status
        ));
    }
    Ok(output.stdout)
}

/// Runs one command in the root under `limit`. A command still running at the limit is killed,
/// and the step fails. Its output goes to the gate's own output, as it did under the shell.
fn step(root: &Path, limit: Duration, program: &str, args: &[&str]) -> Result<(), String> {
    let shown = std::iter::once(program)
        .chain(args.iter().copied())
        .collect::<Vec<_>>()
        .join(" ");
    println!("repair-gate: RUN: {shown}");
    let mut child = Command::new(program)
        .args(args)
        .current_dir(root)
        .spawn()
        .map_err(|error| format!("cannot start `{shown}`: {error}"))?;
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(()),
            Ok(Some(status)) => return Err(format!("`{shown}` exited with {status}")),
            Ok(None) => {}
            Err(error) => return Err(format!("cannot wait for `{shown}`: {error}")),
        }
        if started.elapsed() >= limit {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("`{shown}` timed out after {}s", limit.as_secs()));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
            "commit",
            "-q",
            "-m",
            "base",
        ]);
        dir
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
}
