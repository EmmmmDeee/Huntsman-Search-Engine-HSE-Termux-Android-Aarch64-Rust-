//! Early-exit pipelines under `pipefail`. `producer | grep -q` lets grep exit at
//! its first match; the producer then takes SIGPIPE and the pipeline reports
//! failure (141) even though the match succeeded. That made the release identity
//! check fail on a 216 KB `strings` stream, and it made the dual-pass runner miss
//! `cannot find` in a large red log. Capture the output first, or use a here-string.

use std::fs;
use std::path::{Path, PathBuf};

/// Recursively collects the workflow and shell files under DIR.
fn workflow_and_script_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("readable directory entry").path();
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

/// Every workflow, action, and script the repository runs: `.github`, `scripts`, and
/// the shell scripts at the repository root (install.sh among them).
fn files_to_scan() -> Vec<PathBuf> {
    let mut files = Vec::new();
    for root in [".github", "scripts"] {
        workflow_and_script_files(Path::new(root), &mut files);
    }
    for entry in fs::read_dir(".").expect("the repository root must be readable") {
        let path = entry.expect("readable directory entry").path();
        if path.is_file() && path.extension().and_then(|e| e.to_str()) == Some("sh") {
            files.push(path);
        }
    }
    files.sort();
    files
}

/// Joins a line that ends in a pipe, or in a backslash, with the line after it, so a
/// pipeline split across lines is checked as one. Each entry keeps its first line's
/// number.
fn logical_lines(text: &str) -> Vec<(usize, String)> {
    let mut out: Vec<(usize, String)> = Vec::new();
    let mut joining = false;
    for (number, line) in text.lines().enumerate() {
        if joining {
            if let Some((_, joined)) = out.last_mut() {
                joined.push(' ');
                joined.push_str(line.trim());
            }
        } else {
            out.push((number + 1, line.to_owned()));
        }
        let trimmed = line.trim_end();
        joining = !trimmed.trim_start().starts_with('#')
            && ((trimmed.ends_with('|') && !trimmed.ends_with("||")) || trimmed.ends_with('\\'));
    }
    out
}

/// True when a pipe segment of this line runs grep, egrep, or fgrep with a quiet
/// flag: a short flag group that contains `q`, or `--quiet` or `--silent`, anywhere
/// among its arguments. `||` is logical OR, not a pipe, and a pipeline ends at `;`,
/// `&&`, or `||`. Comment lines never count.
fn pipes_into_grep_quiet(line: &str) -> bool {
    if line.trim_start().starts_with('#') {
        return false;
    }
    // Placeholder for `||`, so the single-pipe split leaves logical OR alone.
    let text = line.replace("||", "\u{1}").replace("|&", "|");
    text.split('|').skip(1).any(|segment| {
        let command = segment.split([';', '\u{1}', '&']).next().unwrap_or("");
        let mut words = command.split_whitespace();
        let mut first = words.next();
        if first == Some("command") {
            first = words.next();
        }
        if !matches!(first, Some("grep" | "egrep" | "fgrep")) {
            return false;
        }
        words.any(|word| {
            word == "--quiet"
                || word == "--silent"
                || (word.starts_with('-') && !word.starts_with("--") && word[1..].contains('q'))
        })
    })
}

#[test]
fn detector_flags_quiet_grep_pipes_and_nothing_else() {
    assert!(pipes_into_grep_quiet("strings -a x | grep -Fq \"$SHA\""));
    assert!(pipes_into_grep_quiet(
        "  printf '%s' \"$log\" | grep -q 'cannot find'; then"
    ));
    assert!(pipes_into_grep_quiet("a | grep -qx y"));
    assert!(pipes_into_grep_quiet("a | egrep -q y"));
    assert!(pipes_into_grep_quiet("a | fgrep -Fq y"));
    assert!(pipes_into_grep_quiet("a | grep 'x' -q"));
    assert!(pipes_into_grep_quiet("a | grep --quiet x"));
    assert!(pipes_into_grep_quiet("a | command grep -q x"));
    assert!(pipes_into_grep_quiet("a |& grep -q x"));
    assert!(!pipes_into_grep_quiet("grep -q 'cannot find' <<< \"$log\""));
    assert!(!pipes_into_grep_quiet(
        "usage=\"$(strings x | grep -o -m1 y || true)\""
    ));
    assert!(!pipes_into_grep_quiet("cmd | grep -e queue"));
    assert!(!pipes_into_grep_quiet("# readelf | grep -q is the hazard"));
    assert!(!pipes_into_grep_quiet("a || b"));
    assert!(!pipes_into_grep_quiet(
        "if grep -q 'x' \"$f\" || grep -q 'y' \"$f\"; then"
    ));
}

#[test]
fn a_pipe_continued_on_the_next_line_is_one_pipeline() {
    let text = "if curl --fail --silent \"$url\" |\n  grep -q '\"status\"'; then\n  :\nfi\n";
    let flagged: Vec<usize> = logical_lines(text)
        .into_iter()
        .filter(|(_, line)| pipes_into_grep_quiet(line))
        .map(|(number, _)| number)
        .collect();
    assert_eq!(flagged, [1], "the pipeline starts on line 1");
}

#[test]
fn no_pipeline_feeds_grep_quiet_under_pipefail() {
    let files = files_to_scan();
    assert!(
        files.iter().any(|f| f.starts_with(".github"))
            && files.iter().any(|f| f.starts_with("scripts")),
        "the workflow and script roots must contain files"
    );

    let mut hits = Vec::new();
    for file in &files {
        let text = fs::read_to_string(file).expect("readable workflow or script");
        for (number, line) in logical_lines(&text) {
            if pipes_into_grep_quiet(&line) {
                hits.push(format!("{}:{}: {}", file.display(), number, line.trim()));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "producer | grep -q can report SIGPIPE under pipefail; capture the output or use a here-string:\n{}",
        hits.join("\n")
    );
}
