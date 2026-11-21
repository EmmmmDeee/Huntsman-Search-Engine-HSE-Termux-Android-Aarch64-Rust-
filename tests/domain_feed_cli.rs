//! Offline CLI acceptance for the streaming domain-list importer.

use std::fs;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::Value;

static NEXT: AtomicUsize = AtomicUsize::new(0);

fn with_feed(input: &[u8], run: impl FnOnce(&std::path::Path) -> std::process::Output) -> std::process::Output {
    let dir = std::env::temp_dir().join(format!(
        "huntsman-domain-feed-{}-{}", std::process::id(),
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
    let output = with_feed(b"EXAMPLE.COM\nexample.com\nother.com\n",
        |path| match_file(path, &["example.com", "missing.test"]));
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["source_claim"], "domains-monitor.com");
    assert_eq!(result["source_authenticated"], Value::Bool(false));
    assert_eq!(result["dataset"], "full");
    assert_eq!(result["as_of"], "2025-07-06");
    assert_eq!(result["valid_rows"], 3);
    assert_eq!(result["matches"][0]["occurrences"], 2);
    assert_eq!(result["matches"][1]["listed"], Value::Bool(false));
    assert_eq!(result["registration_status"], "unknown");
    assert_eq!(result["ownership"], "unknown");
    assert_eq!(result["site_active"], "unknown");
    assert_eq!(result["file_sha256"].as_str().unwrap().len(), 64);
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
    let output = with_feed(b"PK\x03\x04more-archive-data",
        |path| match_file(path, &["example.com"]));
    assert_eq!(output.status.code(), Some(65));
    assert!(output.stdout.is_empty());
}

#[test]
fn invalid_kind_is_rejected() {
    let output = with_feed(b"example.com\n", |path| {
        Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
            .args(["domain-feed", "match", "bogus"])
            .arg(path)
            .args(["--as-of", "2025-07-06", "example.com"])
            .output().unwrap()
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
