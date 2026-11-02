//! End-to-end CLI contract for evidence-limited Rhinser schema mapping.
use std::process::Command;

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
        .args(args)
        .output()
        .expect("real Huntsman binary must execute")
}

#[test]
fn native_entities_preview_does_not_promote_sensor_claims_to_facts() {
    let path = std::env::temp_dir().join(format!(
        "hse-rhinser-schema-{}.json",
        std::process::id()
    ));
    let fixture = br#"{"schema_version":1,"captured_unix_ms":1730000000000,"operator_consented":true,"events":[{"kind":"ndef","hex":"D101055402656E4869"},{"kind":"bluetooth","transport":"ble","rssi_dbm":-66,"bonded":false,"randomized_address":true}]}"#;
    std::fs::write(&path, fixture).unwrap();
    let output = run(&["osint", "native", "--entities", path.to_str().unwrap()]);
    let unmodified = run(&["osint", "native", path.to_str().unwrap()]);
    std::fs::remove_file(&path).unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(unmodified.status.success());
    let mapped: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(mapped["source"], "rhinser_native");
    assert_eq!(mapped["evidence_role"], "operator_submitted_unverified");
    assert_eq!(mapped["relationships_inferred"], false);
    assert_eq!(mapped["device_attested"], false);
    assert_eq!(mapped["radio_access"], false);
    assert_eq!(mapped["entities"].as_array().unwrap().len(), 2);
    assert_eq!(mapped["entities"][0]["kind"], "other");
    assert_eq!(mapped["entities"][0]["confidence"], 0.25);
    assert_eq!(
        mapped["entities"][0]["evidence"][0]["attributes"]["evidence_role"],
        "seed_not_external_verification"
    );
    assert_eq!(
        mapped["entities"][1]["evidence"][0]["attributes"]["signal_class"],
        "medium"
    );
    let result = String::from_utf8_lossy(&output.stdout);
    assert!(!result.contains("D101055402656E4869"));
    assert!(!result.contains("owns"));
    let original: serde_json::Value = serde_json::from_slice(&unmodified.stdout).unwrap();
    assert_eq!(original["observations"].as_array().unwrap().len(), 2);
    assert!(original.get("entities").is_none());
}

#[test]
fn native_entities_preview_still_requires_valid_input_and_consent() {
    let path = std::env::temp_dir().join(format!(
        "hse-rhinser-schema-bad-{}.json",
        std::process::id()
    ));
    let fixture = br#"{"schema_version":1,"captured_unix_ms":1730000000000,"operator_consented":false,"events":[{"kind":"bluetooth","transport":"ble","rssi_dbm":-66,"bonded":false,"randomized_address":true}]}"#;
    std::fs::write(&path, fixture).unwrap();
    let output = run(&["osint", "native", "--entities", path.to_str().unwrap()]);
    std::fs::remove_file(&path).unwrap();
    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("entities"));
}
