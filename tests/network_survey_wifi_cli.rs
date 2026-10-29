//! End-to-end offline Wi-Fi survey CSV import acceptance, without Android permissions.
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use huntsman_recon::exit::{EX_DATAERR, EX_NOINPUT, EX_UNAVAILABLE, EX_USAGE};

const PREFIX: &str = "# Created by Network Survey version=2.0\n# CSV Version=0.4.0\ndeviceTime,latitude,longitude,altitude,speed,accuracy,missionId,recordNumber,sourceAddress,destinationAddress,bssid,beaconInterval,serviceSetType,ssid,supportedRates,extendedSupportedRates,cipherSuites,akmSuites,encryptionType,wps,channel,frequencyMhz,signalStrength,snr,nodeType,standard,passpoint,bandwidth,deviceSerialNumber,locationAge\n";
const ROW: &str = "2025-10-10T13:58:27Z,37.7,-122.4,10,0,22,PRIVATE-MISSION,1,PRIVATE-SOURCE,PRIVATE-DEST,3C:5A:B4:11:22:33,100,ESS,SurveyAP,6;12,24,CCMP,PSK,WPA2,true,1,2412,-57,20,AP,IEEE80211AX,false,MHZ_20,PRIVATE-SERIAL,4916\n";

fn path(suffix: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "huntsman-survey-wifi-{}-{suffix}.csv",
        std::process::id()
    ))
}

fn run(path: &PathBuf) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
        .args(["radar", "survey-wifi", "--file"])
        .arg(path)
        .arg("--json")
        .output()
        .unwrap()
}

#[test]
fn offline_wifi_import_preserves_provenance_and_drops_device_identifiers() {
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
    assert_eq!(value["source"], "unverified_network_survey_wifi_csv_file");
    assert_eq!(value["status"], "historical_unverified");
    assert_eq!(value["observations"][0]["bssid"], "3c:5a:b4:11:22:33");
    assert_eq!(value["observations"][0]["reported_accuracy_m"], 22.0);
    assert_eq!(value["observations"][0]["signal_dbm"], -57.0);
    let text = String::from_utf8_lossy(&output.stdout);
    for secret in [
        "PRIVATE-MISSION",
        "PRIVATE-SOURCE",
        "PRIVATE-DEST",
        "PRIVATE-SERIAL",
    ] {
        assert!(!text.contains(secret));
    }
    assert!(!text.contains("mitm_assessment"));
    assert!(!text.contains("os_cached"));
}

#[test]
fn schema_errors_and_empty_valid_import_have_distinct_exit_codes() {
    let file = path("invalid");
    fs::write(&file, PREFIX.replace("0.4.0", "0.9.0")).unwrap();
    assert_eq!(run(&file).status.code(), Some(i32::from(EX_DATAERR)));
    fs::write(
        &file,
        format!(
            "{PREFIX}{}",
            ROW.replace("3C:5A:B4:11:22:33", "02:00:00:00:00:00")
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
        .args(["radar", "survey-wifi"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(i32::from(EX_USAGE)));
}
