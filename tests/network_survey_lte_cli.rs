//! End-to-end offline Network Survey LTE CSV import acceptance.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use huntsman_recon::exit::{EX_DATAERR, EX_NOINPUT, EX_UNAVAILABLE, EX_USAGE};

const HEADER: &str = "# Created by Network Survey version=2.0\n# CSV Version=0.5.0\ndeviceTime,latitude,longitude,accuracy,recordNumber,groupNumber,plmn,tac,eci,pci,rsrp,ta,servingCell,locationAge,deviceSerialNumber\n";

fn file(suffix: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "huntsman-survey-lte-{}-{suffix}.csv",
        std::process::id()
    ))
}

fn command(path: &PathBuf) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
        .args(["radar", "survey-lte", "--file"])
        .arg(path)
        .arg("--json")
        .output()
        .unwrap()
}

#[test]
fn offline_csv_is_wired_to_cli_without_disclosing_device_identity() {
    let path = file("valid");
    let csv = format!(
        "{HEADER}2025-10-10T13:58:27.603261-04:00,37.7749,-122.4194,22,1,2,310-01,12345,12345678,36,-112.0,39,true,4916,PRIVATE-SERIAL\n"
    );
    fs::write(&path, csv).unwrap();
    let output = command(&path);
    fs::remove_file(path).unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["source"], "unverified_network_survey_csv_file");
    assert_eq!(report["status"], "historical_unverified");
    assert_eq!(report["observed"], 1);
    assert_eq!(
        report["observations"][0]["observation"]["sighting"]["network_id"],
        "lte:310-01-12345-12345678"
    );
    assert_eq!(
        report["observations"][0]["observation"]["sighting"]["latitude"],
        serde_json::Value::Null
    );
    assert_eq!(report["observations"][0]["reported_accuracy_m"], 22.0);
    assert!(!String::from_utf8_lossy(&output.stdout).contains("PRIVATE-SERIAL"));
}

#[test]
fn malformed_versions_and_rejected_only_inputs_fail_closed() {
    let path = file("invalid");
    fs::write(&path, HEADER.replace("0.5.0", "0.6.0")).unwrap();
    let output = command(&path);
    assert_eq!(output.status.code(), Some(i32::from(EX_DATAERR)));
    fs::write(
        &path,
        format!("{HEADER}2025-10-10T13:58:27Z,1,2,5,1,1,310-1,1,2,3,-110,0,false,100,x\n"),
    )
    .unwrap();
    let output = command(&path);
    fs::remove_file(path).unwrap();
    assert_eq!(output.status.code(), Some(i32::from(EX_UNAVAILABLE)));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["observed"], 0);
    assert_eq!(report["rejected"], 1);
}

#[test]
fn missing_file_and_missing_required_flag_are_distinct() {
    let path = file("missing");
    let _ = fs::remove_file(&path);
    assert_eq!(command(&path).status.code(), Some(i32::from(EX_NOINPUT)));
    let output = Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
        .args(["radar", "survey-lte"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(i32::from(EX_USAGE)));
}
