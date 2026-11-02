//! Native Rhinser fixture bridge: CLI integration and negative controls.
use std::process::Command;

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
        .args(args)
        .output()
        .expect("binary executable")
}

#[test]
fn fixture_from_operator_is_classified_without_claiming_live_hardware() {
    let path = std::env::temp_dir().join(format!(
        "hse-rhinser-native-{}-{}.json",
        std::process::id(),
        "fixture"
    ));
    let fixture = br#"{"schema_version":1,"captured_unix_ms":1730000000000,"operator_consented":true,"events":[{"kind":"ndef","hex":"D101055402656E4869"},{"kind":"bluetooth","transport":"ble","rssi_dbm":-60,"bonded":false,"randomized_address":true}]}"#;
    std::fs::write(&path, fixture).unwrap();
    let shown = run(&["osint", "native", path.to_str().unwrap()]);
    std::fs::remove_file(&path).unwrap();
    assert!(shown.status.success(), "{}", String::from_utf8_lossy(&shown.stderr));
    let report: serde_json::Value = serde_json::from_slice(&shown.stdout).unwrap();
    assert_eq!(report["evidence_role"], "operator_submitted_unverified");
    assert_eq!(report["radio_access"], false);
    assert_eq!(report["device_attested"], false);
    assert_eq!(report["observations"].as_array().unwrap().len(), 2);
    assert_eq!(report["observations"][1]["signal_class"], "medium");
    assert!(!shown.stdout.windows(9).any(|window| window == b"D10105540"));
}

#[test]
fn prank_simulator_outputs_unmistakable_non_evidence() {
    let shown = run(&["osint", "demo", "42"]);
    assert!(shown.status.success());
    let report: serde_json::Value = serde_json::from_slice(&shown.stdout).unwrap();
    assert_eq!(report["mode"], "simulation_only");
    assert_eq!(report["evidence_role"], "not_evidence");
    assert_eq!(report["sensor_observation"], false);
    assert!(!run(&["osint", "demo", "not_an_integer"]).status.success());
}
