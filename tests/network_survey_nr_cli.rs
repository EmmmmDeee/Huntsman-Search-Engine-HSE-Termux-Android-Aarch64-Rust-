//! End-to-end offline Network Survey NR/5G CSV import acceptance.
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use huntsman_recon::exit::{EX_DATAERR, EX_NOINPUT, EX_UNAVAILABLE, EX_USAGE};

const PREFIX: &str = "# Created by Network Survey version=2.0\n# CSV Version=0.4.0\ndeviceTime,latitude,longitude,altitude,speed,accuracy,missionId,recordNumber,groupNumber,mcc,mnc,plmn,tac,nci,narfcn,pci,ssRsrp,ssRsrq,ssSinr,csiRsrp,csiRsrq,csiSinr,ta,servingCell,provider,slot,deviceSerialNumber,locationAge\n";
const ROW: &str = "2025-10-10T13:58:27Z,1,2,0,0,15,PRIVATE-MISSION,1,2,310,1,310-01,42,68719476735,12345,100,-110,-10,20,-110,-12,15,0,true,Example,0,PRIVATE-SERIAL,50\n";

fn path(suffix: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "huntsman-survey-nr-{}-{suffix}.csv",
        std::process::id()
    ))
}
fn run(path: &PathBuf) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
        .args(["radar", "survey-nr", "--file"])
        .arg(path)
        .arg("--json")
        .output()
        .unwrap()
}

#[test]
fn nr_csv_is_reachable_without_leaking_identifiers_or_claiming_live_capture() {
    let file = path("valid");
    fs::write(&file, format!("{PREFIX}{ROW}")).unwrap();
    let output = run(&file);
    fs::remove_file(file).unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["observed"], 1);
    assert_eq!(value["status"], "historical_unverified");
    assert_eq!(
        value["observations"][0]["observation"]["sighting"]["network_id"],
        "nr:310-01-42-68719476735"
    );
    assert_eq!(
        value["observations"][0]["observation"]["sighting"]["latitude"],
        serde_json::Value::Null
    );
    assert_eq!(value["observations"][0]["reported_accuracy_m"], 15.0);
    let out = String::from_utf8_lossy(&output.stdout);
    assert!(!out.contains("PRIVATE-MISSION"));
    assert!(!out.contains("PRIVATE-SERIAL"));
}

#[test]
fn unknown_versions_and_rejected_rows_have_distinct_exit_codes() {
    let file = path("invalid");
    fs::write(&file, PREFIX.replace("0.4.0", "0.9.0")).unwrap();
    assert_eq!(run(&file).status.code(), Some(i32::from(EX_DATAERR)));
    fs::write(&file, format!("{PREFIX}{}", ROW.replace("310-01", "310-1"))).unwrap();
    let output = run(&file);
    fs::remove_file(file).unwrap();
    assert_eq!(output.status.code(), Some(i32::from(EX_UNAVAILABLE)));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["rejected"], 1);
    assert_eq!(value["observed"], 0);
}

#[test]
fn absent_file_and_absent_file_flag_are_distinct() {
    let file = path("missing");
    let _ = fs::remove_file(&file);
    assert_eq!(run(&file).status.code(), Some(i32::from(EX_NOINPUT)));
    let output = Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
        .args(["radar", "survey-nr"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(i32::from(EX_USAGE)));
}
