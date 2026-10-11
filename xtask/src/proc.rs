//! Process helpers the xtask commands share: the repository root, git output, and a command
//! that runs under a time limit and is killed when the limit passes.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::error::{Error, Result};

/// The repository root. This crate lives in `<root>/xtask`.
#[must_use]
pub fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}

/// The standard output of `git ARGS` in ROOT. A git failure is an error, never empty output.
pub fn git_stdout(root: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let shown = format!("git {}", args.join(" "));
    let output = Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .map_err(|source| Error::Command {
            shown: shown.clone(),
            reason: format!("could not start: {source}"),
        })?;
    if !output.status.success() {
        return Err(Error::Command {
            shown,
            reason: format!("exited with {}", output.status),
        });
    }
    Ok(output.stdout)
}

/// Runs PROGRAM with ARGS in ROOT, printing the command first. A run still going at LIMIT is
/// killed, and the step fails. The command's output goes to this process's output.
pub fn run_step(root: &Path, limit: Duration, program: &str, args: &[&str]) -> Result<()> {
    let shown = std::iter::once(program)
        .chain(args.iter().copied())
        .collect::<Vec<_>>()
        .join(" ");
    println!("xtask: RUN: {shown}");
    let mut child = Command::new(program)
        .args(args)
        .current_dir(root)
        .stdin(Stdio::null())
        .spawn()
        .map_err(|source| Error::Command {
            shown: shown.clone(),
            reason: format!("could not start: {source}"),
        })?;
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(()),
            Ok(Some(status)) => {
                return Err(Error::Command {
                    shown,
                    reason: format!("exited with {status}"),
                });
            }
            Ok(None) => {}
            Err(source) => {
                return Err(Error::Command {
                    shown,
                    reason: format!("could not be waited for: {source}"),
                });
            }
        }
        if started.elapsed() >= limit {
            let _ = child.kill();
            let _ = child.wait();
            return Err(Error::Command {
                shown,
                reason: format!("timed out after {}s", limit.as_secs()),
            });
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}
