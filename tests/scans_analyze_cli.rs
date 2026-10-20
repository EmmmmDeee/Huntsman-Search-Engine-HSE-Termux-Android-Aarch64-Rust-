//! End-to-end bridge from a persisted scan to the shared offline analysis.
//! The binary reads exactly the store seeded by this test; no provider or network calls run.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

use huntsman_recon::entity::{Entity, EntityKind, Evidence, EvidenceProvenance};
use huntsman_recon::scan_store::{
    FORMAT_VERSION, RiskCounts, ScanOptions, ScanRecord, ScanResults, ScanStatus, ScanStore, new_id,
};
use huntsman_recon::source_outcome::SourceExecutionOutcome;

fn fixture() -> (PathBuf, String, Vec<u8>) {
    let dir = std::env::temp_dir().join(format!(
        "hse-scan-analysis-cli-{}-{}",
        std::process::id(),
        NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let store = ScanStore::open(&dir).unwrap();
    let id = new_id("example.com", 1919, 0);
    store
        .create(&ScanRecord {
            format_version: FORMAT_VERSION,
            id: id.clone(),
            name: "offline fixture".into(),
            target: "example.com".into(),
            target_type: "INTERNET_NAME".into(),
            kind: "domain".into(),
            options: ScanOptions {
                usecase: "passive".into(),
                ..ScanOptions::default()
            },
            status: ScanStatus::Finished,
            created: 1919,
            started: Some(1920),
            ended: Some(1921),
            elements: 1,
            unique: 1,
            correlations: RiskCounts::default(),
            errors: 0,
            modules_run: vec!["dns".into()],
            owner: None,
        })
        .unwrap();
    let evidence = Evidence::new(EvidenceProvenance::for_scan("dns", id.as_str()), "A record")
        .with_attr("ip", "192.0.2.4");
    let entity = Entity::builder(EntityKind::Domain, "example.com", 0.9, id.as_str())
        .evidence(evidence)
        .build();
    let elements = huntsman_recon::sf_elements::elements(
        huntsman_recon::sf_elements::Target {
            value: "example.com",
            kind: "INTERNET_NAME",
        },
        std::slice::from_ref(&entity),
        1919,
    );
    store
        .save_results(&ScanResults {
            format_version: FORMAT_VERSION,
            scan_id: id.clone(),
            text: "fixture".into(),
            entities: vec![entity],
            outcomes: vec![SourceExecutionOutcome::success("dns", 1, 1)],
            elements,
            correlations: Vec::new(),
            lineage: Vec::new(),
            termination: None,
        })
        .unwrap();
    let saved = std::fs::read(dir.join(&id).join("results.json")).unwrap();
    (dir, id, saved)
}

fn run(dir: &Path, id: &str, json: bool) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_huntsman-recon"));
    command
        .args(["scans", "analyze", id, "--dir"])
        .arg(dir)
        .env("HOME", dir);
    if json {
        command.arg("--json");
    }
    command.output().unwrap()
}

#[test]
fn analyze_saved_scan_round_trips_evidence_and_prints_explicit_limits() {
    let (dir, id, before) = fixture();
    let json = run(&dir, &id, true);
    assert!(json.status.success(), "{:?}", json.stderr);
    let value: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(value["scan"]["id"], id);
    assert_eq!(value["counts"]["saved_entities"], 1);
    assert_eq!(value["counts"]["source_outcomes"], 1);
    assert_eq!(
        value["limitations"]["provider_coverage"],
        "not_reconstructed"
    );
    assert_eq!(
        value["limitations"]["evidence_ancestry"],
        "not_reconstructed"
    );
    assert_eq!(value["limitations"]["scan_complete"], true);
    assert_eq!(
        value["limitations"]["false_positive_annotations"],
        "not_applied_to_entity_analysis"
    );
    assert_eq!(value["counts"]["flagged_elements"], 0);
    assert!(value["report"].is_object());

    let text = run(&dir, &id, false);
    assert!(text.status.success(), "{:?}", text.stderr);
    let printed = String::from_utf8(text.stdout).unwrap();
    assert!(printed.contains("saved_entities=1"));
    assert!(printed.contains("provider_coverage=not_reconstructed"));
    assert!(printed.contains("evidence_ancestry=not_reconstructed"));
    assert_eq!(
        std::fs::read(dir.join(&id).join("results.json")).unwrap(),
        before
    );

    let missing = run(&dir, "aaaaaaaaaaaaaaaa", true);
    assert!(!missing.status.success());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn analyze_cli_rejects_flagged_evidence_without_making_an_artifact_change() {
    let (dir, id, _) = fixture();
    let store = ScanStore::open(&dir).unwrap();
    let mut results = store.results(&id).unwrap().unwrap();
    let flagged = results
        .elements
        .iter_mut()
        .find(|element| element.entity.is_some() && element.kind != "ROOT")
        .unwrap();
    flagged.fp = true;
    store.save_results(&results).unwrap();

    let path = dir.join(&id).join("results.json");
    let before = std::fs::read(&path).unwrap();
    let output = run(&dir, &id, true);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("false-positive"),
        "{:?}",
        output.stderr
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert_eq!(store.results(&id).unwrap(), Some(results));

    std::fs::remove_dir_all(dir).unwrap();
}
