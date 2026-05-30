//! CLI stream-hygiene tests: stdout must carry only command output, with
//! diagnostic logs confined to stderr. Regression guard for the bug where
//! `tracing_subscriber::fmt()` defaulted to stdout and prepended log lines
//! to `--output json`, breaking every downstream JSON parser.

use std::process::Command;

/// Monotonic, process-wide counter so every spawned `hse` invocation — across
/// both helpers and all parallel test threads — gets a unique HOME (and thus a
/// unique scan DB), avoiding "database is locked" contention.
static HOME_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn unique_home() -> std::path::PathBuf {
    let n = HOME_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let home = std::env::temp_dir().join(format!("hse-cli-io-{}-{n}", std::process::id()));
    let _ = std::fs::create_dir_all(&home);
    home
}

/// Run the built `hse` binary with a hermetic `HOME` (so the scan DB lands in
/// a throwaway dir) and return `(stdout, stderr)`.
fn run_hse(args: &[&str]) -> (String, String) {
    let home = unique_home();
    let out = Command::new(env!("CARGO_BIN_EXE_hse"))
        .args(args)
        .env("HOME", &home)
        // Force the default filter regardless of the ambient environment.
        .env_remove("RUST_LOG")
        .output()
        .expect("failed to spawn hse binary");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Like `run_hse` but also returns the process exit code (clap arg-parse
/// failures exit non-zero before the scan ever runs).
fn run_hse_status(args: &[&str]) -> (i32, String, String) {
    let home = unique_home();
    let out = Command::new(env!("CARGO_BIN_EXE_hse"))
        .args(args)
        .env("HOME", &home)
        .env_remove("RUST_LOG")
        .output()
        .expect("failed to spawn hse binary");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn scan_accepts_leading_negative_coordinate_value() {
    // Regression: clap treated a `--value` beginning with `-` (e.g. a
    // southern-hemisphere latitude) as an unknown flag and aborted with
    // "unexpected argument '-2' found" (exit 2) before the scan ran. The
    // `allow_hyphen_values` flag fixes it. `-27.47,153.02` is Brisbane — a
    // core GEOINT input for this Australia-focused tool.
    let (code, stdout, stderr) = run_hse_status(&[
        "scan",
        "--kind",
        "coords",
        "--value",
        "-27.47,153.02",
        "--depth",
        "0",
        "--passive-only",
        "--output",
        "json",
    ]);

    assert_eq!(
        code, 0,
        "leading-negative coords must parse and scan; exited {code}. stderr: {stderr:?}"
    );
    assert!(
        !stderr.contains("unexpected argument"),
        "must not be rejected as an unknown flag; stderr: {stderr:?}"
    );
    // The negative latitude must survive into the scan target verbatim.
    assert!(
        stdout.contains("-27.47"),
        "the southern-hemisphere latitude must reach the scan target; got: {}",
        &stdout[..stdout.len().min(300)]
    );
}

#[test]
fn scan_json_stdout_is_clean_and_parseable() {
    // Offline, deterministic module only — no network needed.
    let (stdout, stderr) = run_hse(&[
        "scan",
        "--kind",
        "name",
        "--value",
        "Jordan Meyer",
        "--modules",
        "name_to_username",
        "--depth",
        "0",
        "--output",
        "json",
    ]);

    let trimmed = stdout.trim_start();
    assert!(
        trimmed.starts_with('{'),
        "stdout must begin with the JSON object, not a log line; got: {:?}",
        &stdout[..stdout.len().min(120)]
    );
    assert!(
        stdout.trim_end().ends_with('}'),
        "stdout must end with the closing JSON brace"
    );
    // Structural sanity: the scan record is present.
    assert!(
        stdout.contains("\"entity_count\""),
        "stdout JSON must contain the scan record"
    );

    // Logs must still be emitted — just on stderr, not stdout.
    assert!(
        stderr.contains("name_to_username"),
        "the per-module INFO log line must appear on stderr; got: {stderr:?}"
    );
}
