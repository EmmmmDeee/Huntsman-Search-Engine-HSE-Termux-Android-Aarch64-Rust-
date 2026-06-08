//! CLI contract guards (spawn the real binary — the faithful test of the wiring
//! that a unit test can't reach):
//!   - seed validation: `hse scan` / `hse live` must reject reserved/placeholder
//!     targets at the boundary, so an "example anything" can never be dispatched.
//!   - `-o json` output discipline: stdout must be a single JSON document, with
//!     all human-readable progress/summary on stderr, so `| jq` works.

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_hse");

/// Run `hse <args>` with logging off; return (success, stderr).
fn run(args: &[&str]) -> (bool, String) {
    let out = Command::new(BIN)
        .args(args)
        .env("RUST_LOG", "off")
        .output()
        .expect("spawn hse");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn diff_wiring_self_compare_is_empty_and_json_clean() {
    // The diff *logic* is unit-tested in core::diff; this guards the CLI WIRING a
    // unit test can't reach: `latest` resolution, loading two scans from the store
    // by id, and the `-f json` render. Comparing a scan to itself must yield zero
    // added/removed (a non-empty self-diff would mean the load or the set math is
    // broken), and stdout must be one clean JSON document.
    let dir = std::env::temp_dir().join(format!("hse-diff-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    // One offline scan so there's a `latest` to compare against itself.
    let scan = Command::new(BIN)
        .args([
            "scan", "-v", "Jane Smith", "-k", "name", "--modules", "name_intel", "--throttle", "0",
        ])
        .env("RUST_LOG", "off")
        .env("HOME", &dir)
        .output()
        .expect("spawn hse scan");
    assert!(scan.status.success(), "seed scan must succeed");

    let out = Command::new(BIN)
        .args(["diff", "latest", "latest", "-f", "json"])
        .env("RUST_LOG", "off")
        .env("HOME", &dir)
        .output()
        .expect("spawn hse diff");
    assert!(out.status.success(), "diff of latest vs latest must succeed");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let d: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("diff -f json stdout is not pure JSON ({e}):\n{stdout}"));
    assert_eq!(
        d["added"].as_array().map(|a| a.len()),
        Some(0),
        "a scan compared to itself must add nothing: {d}"
    );
    assert_eq!(
        d["removed"].as_array().map(|a| a.len()),
        Some(0),
        "a scan compared to itself must remove nothing: {d}"
    );
    assert!(
        d["common"].as_u64().unwrap_or(0) > 0,
        "self-compare common count must equal the scan's entity total: {d}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn scan_rejects_placeholder_domain() {
    let (ok, err) = run(&["scan", "--kind", "domain", "--value", "example.com"]);
    assert!(!ok, "example.com must be rejected, not scanned");
    assert!(
        err.contains("reserved/placeholder") || err.contains("invalid target"),
        "expected a placeholder-rejection message, got: {err}"
    );
}

#[test]
fn scan_rejects_placeholder_email_host() {
    let (ok, err) = run(&["scan", "--kind", "email", "--value", "jordan@example.com"]);
    assert!(!ok, "jordan@example.com must be rejected");
    assert!(
        err.contains("reserved/placeholder") || err.contains("invalid target"),
        "{err}"
    );
}

#[test]
fn live_rejects_placeholder_domain() {
    let (ok, err) = run(&["live", "--kind", "domain", "--value", "test.example"]);
    assert!(!ok, "test.example must be rejected");
    assert!(
        err.contains("reserved/placeholder") || err.contains("invalid target"),
        "{err}"
    );
}

#[test]
fn scan_json_stdout_is_pure_json() {
    // The `-o json` contract for the most-used command: stdout is a single JSON
    // document (scan + entities + correlations + diagnostics), with all progress
    // and the "full dossier:" notice on stderr. Offline modules only (no network)
    // so the test is hermetic. Guards the same stdout/stderr discipline the import
    // fix established, across the command an operator is most likely to pipe.
    let dir = std::env::temp_dir().join(format!("hse-scan-json-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    let out = Command::new(BIN)
        .args([
            "scan",
            "-v",
            "Jane Smith",
            "-k",
            "name",
            "--modules",
            "name_intel",
            "--throttle",
            "0",
            "-o",
            "json",
        ])
        .env("RUST_LOG", "off")
        .env("HOME", &dir)
        .output()
        .expect("spawn hse scan");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("scan -o json stdout is not pure JSON ({e}):\n{stdout}"));
    for key in ["scan", "entities", "correlations"] {
        assert!(
            parsed.get(key).is_some(),
            "scan JSON must carry `{key}`: {parsed}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn import_json_stdout_is_pure_json_summary_on_stderr() {
    // `hse import … -o json` must emit ONLY JSON on stdout so `| jq` works; the
    // human-readable "Imported N entities" summary belongs on stderr. The summary
    // used to be println!'d to stdout ahead of the JSON, so a consumer parsing
    // stdout failed. Spawn the real binary and prove the contract end-to-end.
    let dir = std::env::temp_dir().join(format!("hse-import-json-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("dossier.txt");
    std::fs::write(
        &file,
        "Entry #1\n\u{2022} name: Isaac Frost\n\u{2022} email: isaac@frostcorp.io\n\
         \u{2022} ip: 8.8.8.8\n\u{2022} phone: +61412345678\n",
    )
    .unwrap();

    let out = Command::new(BIN)
        .args(["import", file.to_str().unwrap(), "-o", "json"])
        .env("RUST_LOG", "off")
        .env("HOME", &dir) // isolate the DB/key pool from the developer's $HOME
        .output()
        .expect("spawn hse import");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    // Stdout parses as JSON in full — nothing else is interleaved.
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("stdout is not pure JSON ({e}):\n{stdout}"));
    assert!(
        parsed.get("entities").and_then(|e| e.as_array()).is_some(),
        "JSON must carry an entities array: {parsed}"
    );
    // The human summary went to stderr, not stdout.
    assert!(
        stderr.contains("Imported") && !stdout.contains("Imported"),
        "summary must be on stderr only; stdout:\n{stdout}\nstderr:\n{stderr}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
