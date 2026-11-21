//! End-to-end offline CLI acceptance for the breach CI planner and ranker.

use std::fs;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::Value;

static NEXT: AtomicUsize = AtomicUsize::new(0);

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
        .args(args)
        .output()
        .unwrap()
}

fn with_file(input: &str, f: impl FnOnce(&std::path::Path) -> Output) -> Output {
    let dir = std::env::temp_dir().join(format!(
        "huntsman-breach-ci-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("evidence.json");
    fs::write(&path, input).unwrap();
    let result = f(&path);
    fs::remove_dir_all(&dir).unwrap();
    result
}

#[test]
fn full_name_plan_preserves_all_name_tokens_without_breach_requests() {
    let output = run(&[
        "breach-ci",
        "plan",
        "name",
        "Jane Mary Smith",
        "--purpose",
        "authorized-engagement",
    ]);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["field"], "full_name");
    assert_eq!(report["candidate_count"], 1);
    assert_eq!(report["evidence_status"], "not_queried");
    for check in report["checks"].as_array().unwrap() {
        assert_eq!(check["selector"], "Jane Mary Smith");
        assert_eq!(check["state"], "not_queried");
        assert!(check["confidence_index"].is_null());
        assert_ne!(check["provider"], "DeHashed");
    }
}

#[test]
fn all_full_names_batch_retains_names_and_deduplicates_casefolds() {
    let input = "# authorised scope\nJordan Avery Example\nJane Mary Smith\njordan avery example\n";
    let output = with_file(input, |path| {
        run(&[
            "breach-ci",
            "names",
            path.to_str().unwrap(),
            "--purpose",
            "authorized-engagement",
        ])
    });
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["name_count"], 2);
    assert_eq!(report["duplicate_names"], 1);
    assert_eq!(report["plans"][0]["checks"][0]["selector"], "Jordan Avery Example");
    assert_eq!(report["plans"][1]["checks"][0]["selector"], "Jane Mary Smith");
}

#[test]
fn full_names_refuse_unvalidated_or_unscoped_identifiers() {
    let invalid = with_file("Jane Mary Smith\nJohn\n", |path| {
        run(&[
            "breach-ci",
            "names",
            path.to_str().unwrap(),
            "--purpose",
            "authorized-engagement",
        ])
    });
    assert_eq!(invalid.status.code(), Some(65));
    assert!(invalid.stdout.is_empty());

    let no_scope = run(&[
        "breach-ci",
        "plan",
        "name",
        "Jane Mary Smith",
        "--purpose",
        "security-research",
    ]);
    assert_eq!(no_scope.status.code(), Some(65));
    assert!(no_scope.stdout.is_empty());
}

#[test]
fn plan_is_offline_and_every_source_is_unqueried() {
    let output = run(&[
        "breach-ci",
        "plan",
        "username",
        "John.Doe",
        "--purpose",
        "authorized-engagement",
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let plan: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(plan["field"], "username");
    assert_eq!(plan["evidence_status"], "not_queried");
    assert!(plan["candidate_count"].as_u64().unwrap() > 1);
    for step in plan["checks"].as_array().unwrap() {
        assert_eq!(step["state"], "not_queried");
        assert!(step["confidence_index"].is_null());
        assert!(!step["selector"].as_str().unwrap().contains('*'));
    }
}

#[test]
fn security_research_cannot_plan_account_target() {
    let output = run(&[
        "breach-ci",
        "plan",
        "email",
        "alice@example.org",
        "--purpose",
        "security-research",
    ]);
    assert_eq!(output.status.code(), Some(65));
    assert!(output.stdout.is_empty());
}

#[test]
fn ranked_metadata_is_sorted_without_exposing_credentials() {
    let json = r#"[
        {
            "id":"case-b",
            "exact_identifier":false,
            "fuzzy_match":true,
            "primary_record":false,
            "original_dataset_ids":["root-a"],
            "temporal_consistency":false,
            "contradicted":false
        },
        {
            "id":"case-a",
            "exact_identifier":true,
            "fuzzy_match":false,
            "primary_record":true,
            "original_dataset_ids":["root-a","root-b","root-a"],
            "temporal_consistency":true,
            "contradicted":false
        }
    ]"#;
    let output = with_file(json, |path| {
        run(&["breach-ci", "rank", path.to_str().unwrap()])
    });
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["findings"][0]["id"], "case-a");
    assert_eq!(report["findings"][0]["confidence_index"], 76);
    assert_eq!(report["findings"][0]["distinct_claimed_origins"], 2);
    assert_eq!(report["findings"][1]["id"], "case-b");
    assert!(!String::from_utf8_lossy(&output.stdout).contains("password"));
}

#[test]
fn unknown_json_fields_are_rejected_without_echoing_values() {
    let input = r#"[{
        "id":"case-a",
        "exact_identifier":true,
        "fuzzy_match":false,
        "primary_record":true,
        "original_dataset_ids":["root-a"],
        "temporal_consistency":true,
        "contradicted":false,
        "password":"never-echo-me"
    }]"#;
    let output = with_file(input, |path| {
        run(&["breach-ci", "rank", path.to_str().unwrap()])
    });
    assert_eq!(output.status.code(), Some(65));
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("never-echo-me"));
}
