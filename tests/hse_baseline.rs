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

/// The script with comments and the contents of quoted strings removed, leaving only the words the
/// shell would run as commands and arguments. A command substitution `$( … )` restores an unquoted
/// context — so a `"…"` nested inside it is its own string, exactly as the shell treats it — and
/// backslash line continuations are joined so a wrapped command stays one logical line. A `#`
/// starts a comment only outside quotes and at the start of a line or after whitespace.
fn executable_words(raw: &str) -> String {
    let joined = raw.replace("\\\n", " ");
    #[derive(PartialEq, Clone, Copy)]
    enum Quote {
        None,
        Single,
        Double,
    }
    let mut stack = vec![Quote::None];
    let mut out = String::new();
    let mut prev_space = true;
    let mut chars = joined.chars().peekable();
    while let Some(c) = chars.next() {
        match *stack.last().expect("stack is never empty") {
            Quote::Single => {
                if c == '\'' {
                    *stack.last_mut().unwrap() = Quote::None;
                }
                if c == '\n' {
                    out.push('\n');
                }
                prev_space = c == '\n';
            }
            Quote::Double => {
                if c == '$' && chars.peek() == Some(&'(') {
                    chars.next();
                    stack.push(Quote::None);
                } else if c == '"' {
                    *stack.last_mut().unwrap() = Quote::None;
                } else if c == '\n' {
                    out.push('\n');
                }
                prev_space = c == '\n';
            }
            Quote::None => match c {
                '#' if prev_space => {
                    while let Some(&n) = chars.peek() {
                        if n == '\n' {
                            break;
                        }
                        chars.next();
                    }
                }
                '\'' => {
                    *stack.last_mut().unwrap() = Quote::Single;
                    prev_space = false;
                }
                '"' => {
                    *stack.last_mut().unwrap() = Quote::Double;
                    prev_space = false;
                }
                '$' if chars.peek() == Some(&'(') => {
                    chars.next();
                    stack.push(Quote::None);
                    prev_space = false;
                }
                ')' if stack.len() > 1 => {
                    stack.pop();
                    prev_space = false;
                }
                '\n' => {
                    out.push('\n');
                    prev_space = true;
                }
                _ => {
                    out.push(c);
                    prev_space = c.is_whitespace();
                }
            },
        }
    }
    out
}

/// A line's whitespace-separated words, each trimmed of surrounding shell punctuation but keeping
/// internal characters, so `push;` becomes `push` while `rev-parse` and `HEAD^{commit}` stay whole
/// (and `HEAD^{commit}` never reduces to the bare word `commit`).
fn words_on_line(line: &str) -> Vec<String> {
    line.split_whitespace()
        .map(|w| {
            w.trim_matches(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
                .to_string()
        })
        .filter(|w| !w.is_empty())
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

    // A git invocation (direct or through the run_git wrapper) may only name read-only or local
    // subcommands — never one that writes history or publishes to a remote.
    const DESTRUCTIVE_GIT: &[&str] = &[
        "push",
        "commit",
        "merge",
        "rebase",
        "reset",
        "revert",
        "cherry-pick",
        "tag",
        "format-patch",
        "am",
    ];
    for line in words.lines() {
        let toks = words_on_line(line);
        if toks.iter().any(|t| t == "git" || t == "run_git") {
            for bad in DESTRUCTIVE_GIT {
                assert!(
                    !toks.iter().any(|t| t == bad),
                    "{SCRIPT} must stay read-only, but a git command runs `{bad}`: {line:?}"
                );
            }
        }
        // `cargo install` / `cargo publish` would mutate the host or a registry; `pkg install` of
        // the toolchain is on its own line and allowed.
        if toks.iter().any(|t| t == "cargo") {
            for bad in ["install", "publish"] {
                assert!(
                    !toks.iter().any(|t| t == bad),
                    "{SCRIPT} must not run `cargo {bad}`: {line:?}"
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

/// Runs the baseline with `HOME` and `WORK` in a fresh scratch directory and `REPO_URL` pointing
/// at a path that does not exist, so the run reaches the lock, then stops fast at the clone with
/// no network. `seed_lock` optionally pre-creates `$WORK/.baseline.lock` holding that PID string
/// (empty = a lock directory with no pid file). Returns whether the run exited 0 and the text the
/// run left behind (its `run.log` and `SUMMARY.txt`).
fn run_against_missing_repo(tag: &str, seed_lock: Option<&str>) -> (bool, String) {
    let base = std::env::temp_dir().join(format!("hse-baseline-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    let work = base.join("work");
    fs::create_dir_all(&work).expect("scratch work dir");
    if let Some(pid) = seed_lock {
        let lock = work.join(".baseline.lock");
        fs::create_dir_all(&lock).expect("seed lock dir");
        if !pid.is_empty() {
            fs::write(lock.join("pid"), pid).expect("seed lock pid");
        }
    }
    let out = Command::new("bash")
        .arg(script_path())
        .env("HOME", &base)
        .env("WORK", &work)
        .env("REPO_URL", base.join("no-such-repo"))
        .env("REF", "origin/main")
        .env("SKIP_TESTS", "1")
        .env_remove("RUN_RELEASE")
        .output()
        .expect("bash runs the baseline");
    let mut text = String::new();
    if let Ok(reports) = fs::read_dir(work.join("reports")) {
        let mut dirs: Vec<_> = reports.flatten().map(|e| e.path()).collect();
        dirs.sort();
        if let Some(dir) = dirs.last() {
            text.push_str(&fs::read_to_string(dir.join("run.log")).unwrap_or_default());
            text.push_str(&fs::read_to_string(dir.join("SUMMARY.txt")).unwrap_or_default());
        }
    }
    let ok = out.status.success();
    let _ = fs::remove_dir_all(&base);
    (ok, text)
}

#[test]
fn hse_baseline_reclaims_a_stale_lock() {
    // A lock left behind by a run whose owner is gone (here, a PID that is not a live process)
    // must be reclaimed, not wedge every later run forever.
    let (ok, text) = run_against_missing_repo("stale", Some("not-a-live-pid"));
    assert!(
        text.contains("Reclaiming a stale lock"),
        "a stale lock must be reclaimed; output was:\n{text}"
    );
    assert!(
        !text.contains("is using"),
        "a stale lock must not block the run; output was:\n{text}"
    );
    // The run still stops at the missing repo — the lock is not what failed it.
    assert!(
        !ok,
        "the run exits non-zero at the missing clone, not at the lock"
    );
}

#[test]
fn hse_baseline_blocks_on_a_live_lock() {
    // A lock whose owner is alive (this test process) must block, naming the owner.
    let pid = std::process::id().to_string();
    let (ok, text) = run_against_missing_repo("live", Some(&pid));
    assert!(!ok, "a blocked run exits non-zero");
    assert!(
        text.contains(&format!("another run (pid {pid}) is using")),
        "a live lock must block and name its owner; output was:\n{text}"
    );
    assert!(
        !text.contains("Reclaiming a stale lock"),
        "a live lock must never be reclaimed; output was:\n{text}"
    );
}
