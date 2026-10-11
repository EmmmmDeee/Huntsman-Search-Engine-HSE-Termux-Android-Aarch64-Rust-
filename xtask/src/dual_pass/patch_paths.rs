//! The paths a unified diff touches, read from every header a patch can carry.
//!
//! A pure rename or copy has no ---/+++ lines, so those alone would miss it. Every path a git
//! header names is returned. A `diff --git` header that cannot be split, such as one whose path
//! contains a space, is an error, so the caller refuses the patch rather than guessing its paths.
//!
//! Lines are split on LF and CR. Git writes LF, and a header is never split by CR, so this reads
//! a superset of the headers git applies, and no header that git applies can go unread.

use std::collections::BTreeSet;
use std::io::Read;
use std::process::ExitCode;

use crate::error::{self, Error, Result};

const USAGE: &str = "usage: xtask dual-pass patch-paths < PATCH";

/// The paths PATCH names in its headers, without the `a/` and `b/` prefixes, sorted.
pub fn touched_paths(diff: &str) -> Result<BTreeSet<String>> {
    let mut paths = BTreeSet::new();
    for line in diff.split(['\n', '\r']) {
        if let Some(rest) = line.strip_prefix("diff --git ") {
            match rest.split(' ').collect::<Vec<_>>().as_slice() {
                [old, new] if old.starts_with("a/") && new.starts_with("b/") => {
                    paths.insert(strip(old).to_owned());
                    paths.insert(strip(new).to_owned());
                }
                _ => {
                    return Err(Error::Invalid(format!("cannot read the paths in: {line}")));
                }
            }
        } else if line.starts_with("--- ") || line.starts_with("+++ ") {
            let name = line
                .get(4..)
                .unwrap_or_default()
                .split('\t')
                .next()
                .unwrap_or_default()
                .trim();
            let name = strip(name);
            if !name.is_empty() {
                paths.insert(name.to_owned());
            }
        } else if let Some(path) = ["rename from ", "rename to ", "copy from ", "copy to "]
            .iter()
            .find_map(|prefix| line.strip_prefix(prefix))
        {
            paths.insert(path.to_owned());
        }
    }
    paths.remove("");
    Ok(paths)
}

/// The name without its `a/` or `b/` prefix. `/dev/null`, the side of an added or removed file,
/// names no path, and is returned empty.
fn strip(name: &str) -> &str {
    if name == "/dev/null" {
        return "";
    }
    name.strip_prefix("a/")
        .or_else(|| name.strip_prefix("b/"))
        .unwrap_or(name)
}

/// `dual-pass patch-paths`: reads a patch on standard input and prints the paths it touches,
/// one per line. A header that cannot be read refuses the patch with status 64.
pub fn run(args: &[String]) -> ExitCode {
    if !args.is_empty() {
        return error::usage(USAGE);
    }
    let mut diff = String::new();
    if let Err(source) = std::io::stdin().read_to_string(&mut diff) {
        return error::report(
            "dual-pass patch-paths",
            &Error::Invalid(format!("cannot read the patch: {source}")),
        );
    }
    match touched_paths(&diff) {
        Ok(paths) => {
            for path in paths {
                println!("{path}");
            }
            ExitCode::SUCCESS
        }
        Err(problem) => error::report("dual-pass patch-paths", &problem),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(diff: &str) -> Vec<String> {
        touched_paths(diff)
            .expect("the headers are readable")
            .into_iter()
            .collect()
    }

    #[test]
    fn a_modified_file_names_its_path_once() {
        let diff = "diff --git a/src/lib.rs b/src/lib.rs\nindex 1..2 100644\n--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1 +1 @@\n-a\n+b\n";
        assert_eq!(paths(diff), ["src/lib.rs"]);
    }

    #[test]
    fn a_pure_rename_is_read_from_its_rename_headers() {
        let diff = "diff --git a/src/old.rs b/src/new.rs\nsimilarity index 100%\nrename from src/old.rs\nrename to src/new.rs\n";
        assert_eq!(paths(diff), ["src/new.rs", "src/old.rs"]);
    }

    #[test]
    fn a_new_file_names_no_path_for_dev_null() {
        let diff = "diff --git a/tests/new.rs b/tests/new.rs\nnew file mode 100644\n--- /dev/null\n+++ b/tests/new.rs\n";
        assert_eq!(paths(diff), ["tests/new.rs"]);
    }

    #[test]
    fn a_tab_after_the_name_ends_the_path() {
        let diff = "--- a/src/lib.rs\t2026-01-01\n+++ b/src/lib.rs\t2026-01-01\n";
        assert_eq!(paths(diff), ["src/lib.rs"]);
    }

    #[test]
    fn a_header_that_cannot_be_split_refuses_the_patch() {
        let diff = "diff --git a/src/my file.rs b/src/my file.rs\n";
        let problem = touched_paths(diff).expect_err("a path with a space is refused");
        assert!(
            problem.to_string().starts_with("cannot read the paths in:"),
            "{problem}"
        );
    }

    #[test]
    fn a_carriage_return_still_starts_a_header_line() {
        let diff = "x\r--- a/src/lib.rs\r+++ b/src/lib.rs\r";
        assert_eq!(paths(diff), ["src/lib.rs"]);
    }
}
