//! Offline CLI acceptance for the streaming domain-list importer.

use std::fs;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::Value;

static NEXT: AtomicUsize = AtomicUsize::new(0);

fn with_feed(
    input: &[u8],
    run: impl FnOnce(&std::path::Path) -> std::process::Output,
) -> std::process::Output {
    let dir = std::env::temp_dir().join(format!(
        "huntsman-domain-feed-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&dir).unwrap();
    let file = dir.join("domains.txt");
    fs::write(&file, input).unwrap();
    let output = run(&file);
    fs::remove_dir_all(dir).unwrap();
    output
}

fn match_file(path: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
        .args(["domain-feed", "match", "full"])
        .arg(path)
        .args(["--as-of", "2025-07-06"])
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn command_reports_membership_hash_and_explicit_unknowns() {
    let output = with_feed(b"EXAMPLE.COM\nexample.com\nother.com\n", |path| {
        match_file(path, &["example.com", "missing.test"])
    });
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["source_claim"], "domains-monitor.com");
    assert_eq!(result["source_authenticated"], Value::Bool(false));
    assert_eq!(result["dataset"], "full");
    assert_eq!(result["as_of"], "2025-07-06");
    assert_eq!(result["valid_rows"], 3);
    assert_eq!(result["file_parse_complete"], Value::Bool(true));
    assert_eq!(result["matches"][0]["occurrences"], 2);
    assert_eq!(result["matches"][1]["listed"], Value::Bool(false));
    assert_eq!(
        result["matches"][1]["status"],
        "not_observed_in_supplied_file"
    );
    assert_eq!(result["registration_status"], "unknown");
    assert_eq!(result["ownership"], "unknown");
    assert_eq!(result["site_active"], "unknown");
    assert_eq!(result["file_sha256"].as_str().unwrap().len(), 64);
}

#[test]
fn malformed_rows_leave_absence_unresolved_in_cli_json() {
    let output = with_feed(b"example.com\nnot/a/domain\n", |path| {
        match_file(path, &["example.com", "missing.example"])
    });
    assert!(output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["file_parse_complete"], Value::Bool(false));
    assert_eq!(
        report["matches"][1]["status"],
        "unresolved_due_to_invalid_rows"
    );
    assert_eq!(report["matches"][1]["listed"], Value::Null);
    assert_eq!(report["matches"][0]["status"], "present");
    assert_eq!(report["matches"][0]["listed"], Value::Bool(true));
}

#[test]
fn empty_and_non_domain_feeds_fail_without_negative_evidence() {
    for bytes in [
        &b""[..],
        &b"# header\n\n"[..],
        &b"<html>Access denied</html>\n"[..],
    ] {
        let output = with_feed(bytes, |path| match_file(path, &["example.com"]));
        assert_eq!(output.status.code(), Some(65));
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn trusted_sha256_pin_accepts_exact_bytes_and_rejects_mismatch() {
    const EXPECTED: &str =
        "391196688aa55d3321deffa736f8d103b4813470952b748e9c2c9deb17fa60f5";
    let input = b"example.com\n";
    let matching = with_feed(input, |path| {
        Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
            .args(["domain-feed", "match", "full"])
            .arg(path)
            .args(["--as-of", "2025-07-06", "--expect-sha256"])
            .arg(EXPECTED.to_ascii_uppercase())
            .arg("example.com")
            .output()
            .unwrap()
    });
    assert!(
        matching.status.success(),
        "{}",
        String::from_utf8_lossy(&matching.stderr)
    );
    let result: Value = serde_json::from_slice(&matching.stdout).unwrap();
    assert_eq!(result["file_sha256"], EXPECTED);
    let mismatching = with_feed(input, |path| {
        Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
            .args(["domain-feed", "match", "full"])
            .arg(path)
            .args(["--as-of", "2025-07-06", "--expect-sha256"])
            .arg("0".repeat(64))
            .arg("example.com")
            .output()
            .unwrap()
    });
    assert_eq!(mismatching.status.code(), Some(65));
    assert!(mismatching.stdout.is_empty());
    let invalid = with_feed(input, |path| {
        Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
            .args(["domain-feed", "match", "full"])
            .arg(path)
            .args(["--as-of", "2025-07-06", "--expect-sha256", "not-a-sha"])
            .arg("example.com")
            .output()
            .unwrap()
    });
    assert_eq!(invalid.status.code(), Some(64));
    assert!(invalid.stdout.is_empty());
}

#[test]
fn invalid_snapshot_date_refuses_before_printing_json() {
    let output = with_feed(b"example.com\n", |path| {
        Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
            .args(["domain-feed", "match", "full"])
            .arg(path)
            .args(["--as-of", "2025-02-29", "example.com"])
            .output()
            .unwrap()
    });
    assert_eq!(output.status.code(), Some(65));
    assert!(output.stdout.is_empty());
}

#[test]
fn zip_input_never_becomes_a_false_zero_match() {
    let output = with_feed(b"PK\x03\x04more-archive-data", |path| {
        match_file(path, &["example.com"])
    });
    assert_eq!(output.status.code(), Some(65));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("ZIP archive"));
}

#[test]
fn invalid_kind_is_rejected() {
    let output = with_feed(b"example.com\n", |path| {
        Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
            .args(["domain-feed", "match", "bogus"])
            .arg(path)
            .args(["--as-of", "2025-07-06", "example.com"])
            .output()
            .unwrap()
    });
    assert_eq!(output.status.code(), Some(64));
    assert!(output.stdout.is_empty());
}

#[cfg(unix)]
#[test]
fn symlinked_feed_is_refused() {
    use std::os::unix::fs::symlink;
    let output = with_feed(b"example.com\n", |path| {
        let link = path.with_extension("link");
        symlink(path, &link).unwrap();
        match_file(&link, &["example.com"])
    });
    assert_eq!(output.status.code(), Some(66));
    assert!(output.stdout.is_empty());
}
