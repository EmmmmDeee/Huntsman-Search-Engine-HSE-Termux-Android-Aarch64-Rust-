//! `scripts/hse-baseline.sh` is the bounded, read-only baseline the HSE upgrade pass runs on a
//! Termux handset: clone, cut a local-only branch off `origin/main`, run the workspace checks, and
//! always leave a `SUMMARY.txt`. Its safety value is entirely in what it does *not* do, so that
//! invariant is locked here: a future edit that teaches it to push, commit, merge, deploy, or
//! install the app fails this test rather than silently turning a diagnostic into a mutation.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

const SCRIPT: &str = "scripts/hse-baseline.sh";

fn script_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(SCRIPT)
}

fn script_text() -> String {
    fs::read_to_string(script_path()).expect("scripts/hse-baseline.sh must exist")
}

/// The script with every comment and quoted string removed, so the scan for destructive commands
/// below sees only the words the shell would actually run. A `#` starts a comment only after
/// whitespace or at the start of a line; a `#` inside `$#`/`${#...}` or a string is kept.
fn executable_words(text: &str) -> String {
    let mut out = String::new();
    for line in text.lines() {
        let mut in_single = false;
        let mut in_double = false;
        let mut prev_is_space = true;
        for ch in line.chars() {
            if !in_single && !in_double && ch == '#' && prev_is_space {
                break; // comment to end of line
            }
            match ch {
                '\'' if !in_double => in_single = !in_single,
                '"' if !in_single => in_double = !in_double,
                _ if !in_single && !in_double => out.push(ch),
                _ => {}
            }
            prev_is_space = ch.is_whitespace();
        }
        out.push('\n');
    }
    out
}

/// Whitespace-and-punctuation split, with each token's leading dashes dropped so `--workspace`
/// becomes `workspace` and `-C` becomes `C`. Hyphens inside a word are kept, so `cherry-pick`
/// and `rev-parse` stay whole.
fn tokens(words: &str) -> Vec<String> {
    words
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
        .map(|t| t.trim_start_matches('-').to_ascii_lowercase())
        .filter(|t| !t.is_empty())
        .collect()
}

#[test]
fn hse_baseline_parses_as_bash() {
    let status = Command::new("bash")
        .arg("-n")
        .arg(script_path())
        .status()
        .expect("bash must be available to syntax-check the baseline");
    assert!(status.success(), "{SCRIPT} must parse as bash");
}

#[test]
fn hse_baseline_keeps_its_read_only_contract() {
    let words = executable_words(&script_text());
    let toks = tokens(&words);

    // No command the script runs may push to a remote, write history, deploy, or install the app.
    const FORBIDDEN: &[&str] = &[
        "push",
        "commit",
        "merge",
        "rebase",
        "reset",
        "cherry-pick",
        "revert",
        "format-patch",
        "tag",
        "deploy",
        "publish",
        "gh",
    ];
    for bad in FORBIDDEN {
        assert!(
            !toks.iter().any(|t| t == bad),
            "{SCRIPT} must stay read-only, but runs a `{bad}` command"
        );
    }

    // `cargo install` / `cargo publish` would mutate the host or a registry; `pkg install` of the
    // toolchain is allowed, but installing the app or an install.sh is not.
    for (i, t) in toks.iter().enumerate() {
        if t == "cargo" {
            if let Some(next) = toks.get(i + 1) {
                assert!(
                    next != "install" && next != "publish",
                    "{SCRIPT} must not run `cargo {next}`"
                );
            }
        }
    }
    assert!(
        !words.contains("install.sh"),
        "{SCRIPT} must not invoke the app installer"
    );
}

#[test]
fn hse_baseline_is_termux_first_and_self_documenting() {
    let text = script_text();
    for required in [
        "#!/data/data/com.termux/files/usr/bin/bash",
        "${REF:-origin/main}",
        "trap finish EXIT",
        "SUMMARY.txt",
        "nothing was pushed, merged, installed, or deployed",
    ] {
        assert!(
            text.contains(required),
            "{SCRIPT} must contain {required:?}"
        );
    }
}

#[test]
fn hse_baseline_runs_the_full_workspace_check_set() {
    let text = script_text();
    for check in [
        "cargo fmt --all -- --check",
        "cargo check --workspace --all-targets --locked",
        "cargo clippy --workspace --all-targets --locked -- -D warnings",
        "cargo test --workspace --locked",
    ] {
        assert!(
            text.contains(check),
            "{SCRIPT} must run the baseline check {check:?}"
        );
    }
}
