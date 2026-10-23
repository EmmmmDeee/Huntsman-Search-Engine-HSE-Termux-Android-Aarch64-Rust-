//! CLI/Web API contract for the shared provenance register.
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

fn executable() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_huntsman-recon"))
}

fn home() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "hse-evidence-register-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&path).expect("temp home");
    path
}

fn run(home: &std::path::Path, args: &[&str]) -> Output {
    Command::new(executable())
        .args(args)
        .env("HOME", home)
        .env_remove("HUNTSMAN_HOME")
        .output()
        .expect("run huntsman-recon")
}

fn scan(home: &std::path::Path) -> String {
    let out = run(
        home,
        &["scans", "run", "+61412345678", "-u", "passive", "--json"],
    );
    assert!(
        out.status.success(),
        "scan failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let parsed: serde_json::Value = serde_json::from_slice(&out.stdout).expect("scan JSON");
    parsed["id"].as_str().expect("scan id").to_owned()
}

#[test]
fn evidence_export_preserves_raw_and_supports_delta() {
    let home = home();
    let first = scan(&home);
    let second = scan(&home);

    let raw = run(&home, &["scans", "evidence", &first]);
    assert!(
        raw.status.success(),
        "raw evidence: {}",
        String::from_utf8_lossy(&raw.stderr)
    );
    let text = String::from_utf8(raw.stdout).expect("utf8 evidence");
    assert!(text.starts_with("[HUNTSMAN_EVIDENCE]"));
    assert!(text.contains("RAW_DATA:"));
    assert!(text.contains("UNCERTAINTY_REGISTER:"));
    assert!(text.contains("[END_RECORD]"));

    let report = run(&home, &["scans", "evidence", &second, "--json"]);
    assert!(
        report.status.success(),
        "JSON evidence: {}",
        String::from_utf8_lossy(&report.stderr)
    );
    let parsed: serde_json::Value = serde_json::from_slice(&report.stdout).expect("evidence JSON");
    assert_eq!(parsed["status"], "FULL_REGISTER");
    assert_eq!(parsed["truncated"], false);
    assert!(parsed["uncertainty_register"]["items"].is_array());
    assert!(parsed["current_record_count"].as_u64().unwrap_or(0) > 0);
    assert!(
        parsed["records"]
            .as_array()
            .expect("records")
            .iter()
            .all(|r| r.get("RAW_SHA256").is_some())
    );

    let delta = run(
        &home,
        &[
            "scans", "evidence", &second, "--delta", &first, "-f", "json",
        ],
    );
    assert!(
        delta.status.success(),
        "delta failed: {}",
        String::from_utf8_lossy(&delta.stderr)
    );
    let parsed: serde_json::Value = serde_json::from_slice(&delta.stdout).expect("delta JSON");
    assert_eq!(parsed["baseline"], first);
    assert!(matches!(
        parsed["status"].as_str(),
        Some("MATERIAL_CHANGE" | "NO_MATERIAL_CHANGE")
    ));
    assert_eq!(parsed["truncated"], false);

    let matrix = run(&home, &["scans", "matrix", &second, "--json"]);
    assert!(
        matrix.status.success(),
        "matrix JSON: {}",
        String::from_utf8_lossy(&matrix.stderr)
    );
    let matrix: serde_json::Value =
        serde_json::from_slice(&matrix.stdout).expect("matrix JSON");
    assert_eq!(matrix["format"], "huntsman_sparse_evidence_matrix");
    assert_eq!(matrix["truncated"], false);
    assert!(matrix["rows"].is_array());
    assert!(matrix["columns"].is_array());
    assert!(matrix["uncertainty_register"]["items"].is_array());
    assert!(
        matrix["summary"]["recorded_elements"].as_u64().unwrap_or(0)
            >= matrix["rows"].as_array().expect("rows").len() as u64
    );

    let matrix_raw = run(&home, &["scans", "matrix", &second, "-f", "raw"]);
    assert!(
        matrix_raw.status.success(),
        "matrix raw: {}",
        String::from_utf8_lossy(&matrix_raw.stderr)
    );
    let output = String::from_utf8(matrix_raw.stdout).expect("raw matrix utf8");
    assert!(output.starts_with("[HUNTSMAN_MATRIX]"));
    assert!(output.contains("[END_HUNTSMAN_MATRIX]"));

    let invalid = run(&home, &["scans", "matrix", &second, "-f", "bad"]);
    assert!(!invalid.status.success());

    fs::remove_dir_all(home).expect("cleanup");
}
