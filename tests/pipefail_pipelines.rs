//! Early-exit pipelines under `pipefail`. `producer | grep -q` lets grep exit at
//! its first match; the producer then takes SIGPIPE and the pipeline reports
//! failure (141) even though the match succeeded. That made the release identity
//! check fail on a 216 KB `strings` stream, and it made the dual-pass runner miss
//! `cannot find` in a large red log. Capture the output first, or use a here-string.

use std::fs;
use std::path::{Path, PathBuf};

const ROOTS: [&str; 3] = [".github/workflows", ".github/scripts", "scripts"];

fn workflow_and_script_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            workflow_and_script_files(&path, out);
        } else if matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("sh" | "yml" | "yaml")
        ) {
            out.push(path);
        }
    }
}

/// True when a `|` segment of this line runs `grep` with a short flag that
/// contains `q` (`-q`, `-Fq`, `-qx`, `-Eq`). Comment lines never count.
fn pipes_into_grep_quiet(line: &str) -> bool {
    if line.trim_start().starts_with('#') {
        return false;
    }
    line.split('|').skip(1).any(|segment| {
        let mut words = segment.split_whitespace();
        if words.next() != Some("grep") {
            return false;
        }
        for word in words {
            if !word.starts_with('-') || word.starts_with("--") {
                break;
            }
            if word[1..].contains('q') {
                return true;
            }
        }
        false
    })
}

#[test]
fn detector_flags_quiet_grep_pipes_and_nothing_else() {
    assert!(pipes_into_grep_quiet("strings -a x | grep -Fq \"$SHA\""));
    assert!(pipes_into_grep_quiet(
        "  printf '%s' \"$log\" | grep -q 'cannot find'; then"
    ));
    assert!(pipes_into_grep_quiet("a | grep -qx y"));
    assert!(!pipes_into_grep_quiet("grep -q 'cannot find' <<< \"$log\""));
    assert!(!pipes_into_grep_quiet(
        "usage=\"$(strings x | grep -o -m1 y || true)\""
    ));
    assert!(!pipes_into_grep_quiet("cmd | grep -e queue"));
    assert!(!pipes_into_grep_quiet("# readelf | grep -q is the hazard"));
    assert!(!pipes_into_grep_quiet("a || b"));
}

#[test]
fn no_pipeline_feeds_grep_quiet_under_pipefail() {
    let mut files = Vec::new();
    for root in ROOTS {
        workflow_and_script_files(Path::new(root), &mut files);
    }
    assert!(!files.is_empty(), "workflow and script roots must exist");
    files.sort();

    let mut hits = Vec::new();
    for file in &files {
        let text = fs::read_to_string(file).expect("readable workflow or script");
        for (number, line) in text.lines().enumerate() {
            if pipes_into_grep_quiet(line) {
                hits.push(format!(
                    "{}:{}: {}",
                    file.display(),
                    number + 1,
                    line.trim()
                ));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "producer | grep -q can report SIGPIPE under pipefail; capture the output or use a here-string:\n{}",
        hits.join("\n")
    );
}
