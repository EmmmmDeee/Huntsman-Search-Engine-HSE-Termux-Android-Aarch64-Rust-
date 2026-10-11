//! Capture of the agent's change as a patch. It writes OUT_DIR/change.patch, a binary git patch of
//! everything the working tree changes against BASE, new files included. Later jobs apply that
//! patch and check it. They never use the agent's repository, whose configuration and hooks the
//! agent could have written. An unchanged tree is refused.
//!
//! The capture runs from the trusted xtask, as the guard does, and every git command runs with the
//! same overrides and with the repository's .git/info/attributes removed first. So no filter or
//! program that the agent's repository names can change what the patch carries.

use std::fs;
use std::path::Path;
use std::process::ExitCode;

use super::guard::git;
use crate::error::{self, EX_REFUSED, Error, Result};

const USAGE: &str = "usage: xtask issue-fix capture BASE OUT_DIR";

/// `issue-fix capture BASE OUT_DIR`: writes OUT_DIR/change.patch and prints its size, or refuses
/// with status 1 when the tree is unchanged or git fails.
pub fn run(args: &[String]) -> ExitCode {
    let [base, out] = args else {
        return error::usage(USAGE);
    };
    if base.is_empty() || out.is_empty() {
        return error::usage(USAGE);
    }
    match capture(base, Path::new(out)) {
        Ok(size) => {
            println!("capture: wrote {size} bytes to {out}/change.patch");
            ExitCode::SUCCESS
        }
        Err(problem) => {
            eprintln!("capture: {problem}");
            ExitCode::from(EX_REFUSED)
        }
    }
}

/// Writes the patch of the working tree against BASE into OUT, and returns its size.
fn capture(base: &str, out: &Path) -> Result<usize> {
    fs::create_dir_all(out).map_err(|source| Error::Io {
        path: out.to_path_buf(),
        source,
    })?;
    git::detach_attributes()?;
    git::add_all()?;
    match git::staged_change_status(base)? {
        Some(0) => {
            return Err(Error::Refused(format!(
                "the agent left no changes against {base}"
            )));
        }
        Some(1) => {}
        other => {
            return Err(Error::Refused(format!(
                "git diff failed (exit {}) against {base}",
                exit_text(other)
            )));
        }
    }
    let patch = git::staged_patch(base)?;
    if !patch.status.success() {
        return Err(Error::Refused(format!(
            "git diff failed (exit {}) against {base}",
            exit_text(patch.status.code())
        )));
    }
    let target = out.join("change.patch");
    fs::write(&target, &patch.stdout).map_err(|source| Error::Io {
        path: target.clone(),
        source,
    })?;
    Ok(patch.stdout.len())
}

/// A git exit status for a message. A git stopped by a signal has none, so it reads as unknown.
fn exit_text(code: Option<i32>) -> String {
    code.map_or_else(|| "unknown".to_owned(), |code| code.to_string())
}
