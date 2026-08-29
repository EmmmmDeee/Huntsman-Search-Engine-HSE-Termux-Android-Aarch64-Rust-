//! Small formatting and filesystem-path helpers with no other natural home:
//! thousands-separator number formatting (Python's `f"{n:,}"`, which Rust's
//! `format!` has no equivalent for), a human byte-size formatter, a
//! Python-`repr`-style string-list renderer for diagnostic output, a
//! symlink-non-resolving path normalizer (for a not-yet-created output
//! path, where `std::fs::canonicalize` would fail), and a minimal
//! self-cleaning temp directory (standing in for Python's
//! `tempfile.TemporaryDirectory`, without adding a dependency for the one
//! call site that needs it).

use std::path::{Path, PathBuf};

/// Insert `,` every 3 digits from the right, in a plain ASCII-digit string.
fn commas(digits: &str) -> String {
    let bytes = digits.as_bytes();
    let n = bytes.len();
    let mut out = String::with_capacity(n + n / 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 && (n - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(*b as char);
    }
    out
}

/// `f"{n:,}"` for a non-negative integer.
pub fn commas_int(n: u64) -> String {
    commas(&n.to_string())
}

/// `f"{f:,.1f}"`: one decimal place, then thousands-separate the integer part.
fn commas_1f(f: f64) -> String {
    let s = format!("{f:.1}");
    match s.split_once('.') {
        Some((int_part, frac_part)) => format!("{}.{frac_part}", commas(int_part)),
        None => commas(&s),
    }
}

/// Human byte size: `B` (comma-grouped integer, no decimal) below 1024,
/// `KiB`/`MiB` with one decimal below the next threshold, `GiB` (one
/// decimal) for everything at or above that — matching the Python
/// original's loop exactly, including that `GiB` is the unconditional last
/// step (no further `TiB` tier).
pub fn human(n: u64) -> String {
    let mut f = n as f64;
    if f < 1024.0 {
        return format!("{} B", commas_int(n));
    }
    f /= 1024.0;
    for unit in ["KiB", "MiB"] {
        if f < 1024.0 {
            return format!("{} {unit}", commas_1f(f));
        }
        f /= 1024.0;
    }
    format!("{} GiB", commas_1f(f))
}

/// Renders like Python's `print(...)` of a `list[str]`: `['a', 'b']`. Real
/// file paths never contain a single quote, so no escaping is implemented.
pub fn py_list_repr(items: &[String]) -> String {
    let quoted: Vec<String> = items.iter().map(|s| format!("'{s}'")).collect();
    format!("[{}]", quoted.join(", "))
}

/// `os.path.abspath`: join with the cwd if relative, then collapse `.`/`..`
/// lexically. Deliberately does NOT resolve symlinks or require the path to
/// exist (unlike `std::fs::canonicalize`) — needed for an output path that
/// is about to be created, not one that exists yet.
pub fn abspath(p: &Path) -> Result<PathBuf, String> {
    let joined = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| format!("getting current directory: {e}"))?
            .join(p)
    };
    let mut out = PathBuf::new();
    for comp in joined.components() {
        match comp {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    Ok(out)
}

/// `os.path.relpath(target_abs, root)` for the one shape this tool needs:
/// `target_abs` normally lives under `root`. Falls back to the absolute
/// path when it doesn't — the caller only uses this to build an exclusion
/// set matched against `git ls-files` output (always root-relative, never
/// `../`-prefixed), so a path outside the tree simply never matches
/// anything either way.
pub fn relpath_under(root: &Path, target_abs: &Path) -> String {
    match target_abs.strip_prefix(root) {
        Ok(rel) => rel.to_string_lossy().replace('\\', "/"),
        Err(_) => target_abs.to_string_lossy().to_string(),
    }
}

/// A self-deleting temp directory, standing in for Python's
/// `tempfile.TemporaryDirectory()` for the one call site (`verify`) that
/// needs one — not worth a new dependency for.
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    pub fn new(prefix: &str) -> Result<Self, String> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let path = std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&path)
            .map_err(|e| format!("creating temp dir {}: {e}", path.display()))?;
        Ok(Self { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[cfg(test)]
mod tests {
    include!("format_util_tests.rs");
}
