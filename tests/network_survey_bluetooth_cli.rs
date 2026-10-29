//! End-to-end offline Bluetooth CSV import acceptance, without Android permissions.
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use huntsman_recon::exit::{EX_DATAERR, EX_NOINPUT, EX_UNAVAILABLE, EX_USAGE};

const PREFIX: &str = "# Created by Network Survey version=2.0\n# CSV Version=0.3.0\ndeviceTime,latitude,longitude,altitude,speed,accuracy,missionId,recordNumber,sourceAddress,destinationAddress,signalStrength,txPower,technology,supportedTechnologies,otaDeviceName,channel,deviceSerialNumber,locationAge,addressType,deviceClass,serviceUuids,companyId,mfgData\n";
const ROW: &str = "2025-10-10T13:58:27Z,37.7,-122.4,10,0,22,PRIVATE-MISSION,1,C3:12:34:56:78:9A,PRIVATE-DEST,-57,-10,LE,DUAL,Survey Beacon,37,PRIVATE-SERIAL,4916,RANDOM,5A0C,180D;180F,004C,4C00AABB\n";

fn path(suffix: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "huntsman-survey-bluetooth-{}-{suffix}.csv",
        std::process::id()
    ))
}

fn run(path: &PathBuf) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
        .args(["radar", "survey-bluetooth", "--file"])
        .arg(path)
        .arg("--json")
        .output()
        .unwrap()
}

#[test]
fn bluetooth_csv_is_reachable_and_never_claims_live_capture() {
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
    assert_eq!(
        value["source"],
        "unverified_network_survey_bluetooth_csv_file"
    );
    assert_eq!(value["status"], "historical_unverified");
    assert_eq!(value["observations"][0]["address"], "c3:12:34:56:78:9a");
    assert_eq!(
        value["observations"][0]["identity_stability"],
        "randomized_or_ephemeral"
    );
    assert_eq!(value["observations"][0]["technology"], "LE");
    assert_eq!(value["observations"][0]["reported_accuracy_m"], 22.0);
    let text = String::from_utf8_lossy(&output.stdout);
    for secret in [
        "PRIVATE-MISSION",
        "PRIVATE-DEST",
        "PRIVATE-SERIAL",
        "4C00AABB",
    ] {
        assert!(!text.contains(secret));
    }
    assert!(!text.contains("BluetoothRadar"));
    assert!(!text.contains("follower"));
}

#[test]
fn malformed_version_and_invalid_rows_have_distinct_exit_codes() {
    let file = path("invalid");
    fs::write(&file, PREFIX.replace("0.3.0", "0.9.0")).unwrap();
    assert_eq!(run(&file).status.code(), Some(i32::from(EX_DATAERR)));
    fs::write(
        &file,
        format!(
            "{PREFIX}{}",
            ROW.replace("C3:12:34:56:78:9A", "02:00:00:00:00:00")
        ),
    )
    .unwrap();
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
        .args(["radar", "survey-bluetooth"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(i32::from(EX_USAGE)));
}
