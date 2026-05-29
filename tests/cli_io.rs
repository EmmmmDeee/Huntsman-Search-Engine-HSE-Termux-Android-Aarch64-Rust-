//! CLI stream-hygiene tests: stdout must carry only command output, with
//! diagnostic logs confined to stderr. Regression guard for the bug where
//! `tracing_subscriber::fmt()` defaulted to stdout and prepended log lines
//! to `--output json`, breaking every downstream JSON parser.

use std::process::Command;

/// Run the built `hse` binary with a hermetic `HOME` (so the scan DB lands in
/// a throwaway dir) and return `(stdout, stderr)`.
fn run_hse(args: &[&str]) -> (String, String) {
    let home = std::env::temp_dir().join(format!("hse-cli-io-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&home);
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
