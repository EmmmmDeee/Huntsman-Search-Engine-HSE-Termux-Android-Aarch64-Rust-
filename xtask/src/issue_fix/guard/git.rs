//! The git commands of the path guard and the capture. Every command runs with the same
//! overrides, so a program or a filter that the agent's repository names never runs, and no
//! .gitattributes in the change takes part in a diff.

use std::fs;
use std::io;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

use crate::error::{Error, Result};

/// The empty tree. Passed as the attribute source, it means that no attribute file in the
/// change applies to a command.
const EMPTY_TREE: &str = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";

/// Runs `git ARGS` with the overrides and returns its output, whatever its status, so the caller
/// decides what a status means. Standard error is shown unless QUIET. A command that cannot
/// start is an error.
pub(crate) fn run(args: &[&str], quiet: bool) -> Result<Output> {
    let mut command = Command::new("git");
    command
        .args([
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
        ])
        .args(["-c", "core.attributesFile=/dev/null"])
        .arg(format!("--attr-source={EMPTY_TREE}"))
        .args(args)
        .stdin(Stdio::null())
        .stderr(if quiet {
            Stdio::null()
        } else {
            Stdio::inherit()
        });
    command.output().map_err(|source| Error::Command {
        shown: format!("git {}", args.join(" ")),
        reason: format!("could not start: {source}"),
    })
}

/// Removes the repository's .git/info/attributes. Git reads that file even with --attr-source,
/// so it is removed before any command that reads attributes. Resolving its path only reads the
/// repository layout, so it is the one command that runs before the removal.
pub(crate) fn detach_attributes() -> Result<()> {
    let located = run(&["rev-parse", "--git-path", "info/attributes"], false)?;
    if !located.status.success() {
        return Ok(());
    }
    let text = String::from_utf8(located.stdout)
        .map_err(|_| Error::Refused("the attributes path is not UTF-8".to_owned()))?;
    let path = text.trim_end_matches('\n');
    if path.is_empty() {
        return Ok(());
    }
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(Error::Io {
            path: PathBuf::from(path),
            source,
        }),
    }
}

/// True when BASE names a commit. A git that cannot run also means no.
pub(crate) fn is_commit(base: &str) -> bool {
    let spec = format!("{base}^{{commit}}");
    run(&["rev-parse", "--verify", "--quiet", &spec], true)
        .is_ok_and(|output| output.status.success())
}

/// The raw diff of the working tree against BASE, NUL-separated, with renames detected.
pub(crate) fn raw_diff(base: &str) -> Result<Vec<u8>> {
    let output = run(
        &["diff", "--raw", "-z", "-M", "--no-ext-diff", base, "--"],
        false,
    )?;
    if !output.status.success() {
        return Err(Error::Refused(format!("git diff failed against {base}")));
    }
    Ok(output.stdout)
}

/// The unified diff of PATH against BASE with no context lines, read as text. None when git
/// fails, so the caller refuses the change rather than passing it.
pub(crate) fn hunks(base: &str, path: &str) -> Option<Vec<u8>> {
    let output = run(
        &["diff", "-U0", "--text", "--no-ext-diff", base, "--", path],
        false,
    )
    .ok()?;
    output.status.success().then_some(output.stdout)
}

/// Every path under src/ that BASE tracks as a file: a blob, and a symbolic link is one too. A
/// submodule is an entry of BASE that is not a file, so it is left out.
pub(crate) fn src_paths(base: &str) -> Result<Vec<String>> {
    let output = run(&["ls-tree", "-r", "-z", base, "--", "src"], false)?;
    if !output.status.success() {
        return Err(Error::Refused(format!("git ls-tree failed against {base}")));
    }
    let mut paths = Vec::new();
    for entry in output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
    {
        // Each entry is `MODE TYPE OBJECT TAB PATH`, so the path follows the first tab.
        let Some(tab) = entry.iter().position(|byte| *byte == b'\t') else {
            return Err(Error::Refused(format!(
                "malformed tree listing against {base}"
            )));
        };
        let meta = entry.get(..tab).unwrap_or_default();
        let is_blob = std::str::from_utf8(meta)
            .is_ok_and(|meta| meta.split_whitespace().nth(1) == Some("blob"));
        if is_blob {
            let path = entry.get(tab + 1..).unwrap_or_default();
            paths.extend(names(path)?);
        }
    }
    Ok(paths)
}

/// The untracked files of the working tree that the ignore rules do not hide.
pub(crate) fn untracked() -> Result<Vec<String>> {
    let output = run(&["ls-files", "-z", "--others", "--exclude-standard"], false)?;
    if !output.status.success() {
        return Err(Error::Refused("git ls-files failed".to_owned()));
    }
    names(&output.stdout)
}

/// The content of PATH at BASE, or None when BASE has no such file. A file that exists but
/// cannot be read is an error.
pub(crate) fn blob(base: &str, path: &str) -> Result<Option<Vec<u8>>> {
    let spec = format!("{base}:{path}");
    let exists = run(&["cat-file", "-e", &spec], true).is_ok_and(|out| out.status.success());
    if !exists {
        return Ok(None);
    }
    let output = run(&["cat-file", "blob", &spec], false)?;
    if !output.status.success() {
        return Err(Error::Refused(format!("cannot read {path} at {base}")));
    }
    Ok(Some(output.stdout))
}

/// Stages every change in the working tree, new files included.
pub(crate) fn add_all() -> Result<()> {
    let output = run(&["add", "-A"], false)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(Error::Refused("git add -A failed".to_owned()))
    }
}

/// The exit status of `git diff --cached --quiet` against BASE: 0 for no change, 1 for a
/// change, and None when git stopped by a signal.
pub(crate) fn staged_change_status(base: &str) -> Result<Option<i32>> {
    let output = run(
        &["diff", "--cached", "--quiet", "--no-ext-diff", base, "--"],
        false,
    )?;
    Ok(output.status.code())
}

/// The staged change against BASE as a binary git patch, with full object names.
pub(crate) fn staged_patch(base: &str) -> Result<Output> {
    run(
        &[
            "diff",
            "--cached",
            "--binary",
            "--full-index",
            "--no-ext-diff",
            "--no-textconv",
            base,
            "--",
        ],
        false,
    )
}

/// Splits NUL-separated git output into names. A name that is not UTF-8 refuses the listing,
/// since a name that cannot be read cannot be checked.
fn names(bytes: &[u8]) -> Result<Vec<String>> {
    bytes
        .split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
        .map(|name| {
            String::from_utf8(name.to_vec())
                .map_err(|_| Error::Refused("a path is not UTF-8".to_owned()))
        })
        .collect()
}
