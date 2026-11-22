//! Real CLI-path contract for the opt-in, network-free Brisbane geographic view.

use std::path::PathBuf;
use std::process::Command;

#[test]
fn brisbane_geo_case_cli_keeps_overseas_records_as_unverified_leads() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/brisbane-geo-demo.json");
    let output = Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
        .arg("osint")
        .arg("geo-case")
        .arg(fixture)
        .output()
        .expect("run huntsman-recon");

    assert!(
        output.status.success(),
        "CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("geo-case JSON output");
    assert_eq!(report["anchor"]["city"], "Brisbane");
    assert_eq!(report["anchor"]["state"], "Queensland");
    assert_eq!(report["anchor"]["country"], "Australia");
    assert_eq!(report["anchor"]["timezone"], "Australia/Brisbane");
    assert_eq!(report["geographic_leads"].as_array().unwrap().len(), 4);
    assert_eq!(
        report["geographic_leads"][0]["category"],
        "brisbane_anchor"
    );
    assert_eq!(
        report["possible_cross_border_label_matches"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        report["possible_cross_border_label_matches"][0]["interpretation"],
        "same_label_only_not_identity_migration_or_family_proof"
    );
    assert_eq!(
        report["case"]["evidence_status"],
        "unverified_source_assertions_not_independent_corroboration"
    );
}
