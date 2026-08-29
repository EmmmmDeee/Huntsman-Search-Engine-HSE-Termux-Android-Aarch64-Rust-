//! Git plumbing: everything shells out to the real `git` binary, matching
//! the Python original rather than reimplementing pack-file reading.

use std::path::Path;
use std::process::Command;

pub fn repo_root() -> Result<String, String> {
    Ok(run_git(&["rev-parse", "--show-toplevel"], None)?
        .trim()
        .to_string())
}

pub fn git_tracked_files(root: &str) -> Result<Vec<String>, String> {
    let mut cmd = Command::new("git");
    cmd.args(["ls-files", "-z"]).current_dir(root);
    let out = cmd
        .output()
        .map_err(|e| format!("running git ls-files: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "git ls-files failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let text =
        String::from_utf8(out.stdout).map_err(|e| format!("git ls-files output not UTF-8: {e}"))?;
    Ok(text
        .split('\0')
        .filter(|p| !p.is_empty())
        .map(str::to_owned)
        .collect())
}

fn run_git(args: &[&str], cwd: Option<&str>) -> Result<String, String> {
    let mut cmd = Command::new("git");
    cmd.args(args);
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    let out = cmd
        .output()
        .map_err(|e| format!("running git {args:?}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    String::from_utf8(out.stdout).map_err(|e| format!("git {args:?} output not UTF-8: {e}"))
}

/// Reduce a remote URL to its `owner/repo` slug, dropping any embedded
/// credentials or local-proxy host (a sandbox may rewrite `origin` through a
/// `local_proxy@127.0.0.1:PORT` URL that must not be baked into the artifact).
pub fn sanitize_remote(url: &str) -> String {
    let mut u = url.to_string();
    if let Some(idx) = u.find("://") {
        u = u[idx + 3..].to_string();
    }
    if let Some(idx) = u.rfind('@') {
        u = u[idx + 1..].to_string();
    }
    if let Some(idx) = u.find("/git/") {
        u = u[idx + 5..].to_string();
    }
    if let Some(stripped) = u.strip_suffix(".git") {
        u = stripped.to_string();
    }
    if u.is_empty() {
        "(unknown)".to_string()
    } else {
        u
    }
}

pub struct GitInfo {
    pub commit: String,
    pub branch: String,
    pub date: String,
    pub subject: String,
    pub remote: String,
}

/// Each field is best-effort: a non-zero `git` exit (e.g. a shallow clone
/// with no remote configured) yields `"(unknown)"` for that one field rather
/// than failing the whole pack. `git` itself not being on `PATH` is a real
/// error and propagates.
pub fn git_info(root: &Path) -> Result<GitInfo, String> {
    let g = |args: &[&str]| -> Result<String, String> {
        let mut cmd = Command::new("git");
        cmd.args(args).current_dir(root);
        let out = cmd.output().map_err(|e| format!("running git: {e}"))?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
        } else {
            Ok("(unknown)".to_string())
        }
    };
    let remote_raw = g(&["config", "--get", "remote.origin.url"])?;
    Ok(GitInfo {
        commit: g(&["rev-parse", "HEAD"])?,
        branch: g(&["rev-parse", "--abbrev-ref", "HEAD"])?,
        date: g(&["log", "-1", "--format=%cd", "--date=iso-strict"])?,
        subject: g(&["log", "-1", "--format=%s"])?,
        remote: sanitize_remote(&remote_raw),
    })
}

#[cfg(test)]
mod tests {
    include!("gitinfo_tests.rs");
}
