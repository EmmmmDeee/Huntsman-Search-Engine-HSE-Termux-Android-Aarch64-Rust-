//! End-to-end acceptance for the local MITM Wi-Fi evidence gate.

use std::{fs, path::PathBuf, process::Command};

fn temp(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("huntsman-mitm-{}-{name}", std::process::id()))
}

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
}

#[test]
fn baseline_requires_confirmation_and_assessment_is_evidence_gated() {
    let good = temp("trusted-scan.json");
    let suspect = temp("suspect-scan.json");
    let baseline = temp("trusted-baseline.json");
    let _ = fs::remove_file(&baseline);
    fs::write(
        &good,
        r#"[{"bssid":"a0:11:22:33:44:55","ssid":"MyLab","rssi":-57,"capabilities":"[WPA2-PSK-CCMP][ESS]"}]"#,
    )
    .unwrap();
    fs::write(
        &suspect,
        r#"[{"bssid":"a0:11:22:33:44:66","ssid":"MyLab","rssi":-41,"capabilities":"[ESS]"}]"#,
    )
    .unwrap();
    let denied = bin()
        .arg("mitm")
        .arg("baseline")
        .arg("MyLab")
        .arg("--file")
        .arg(&good)
        .arg("--output")
        .arg(&baseline)
        .output()
        .unwrap();
    assert!(!denied.status.success());
    assert!(!baseline.exists());

    let enrolled = bin()
        .arg("mitm")
        .arg("baseline")
        .arg("MyLab")
        .arg("--file")
        .arg(&good)
        .arg("--output")
        .arg(&baseline)
        .arg("--confirmed")
        .output()
        .unwrap();
    assert!(
        enrolled.status.success(),
        "{}",
        String::from_utf8_lossy(&enrolled.stderr)
    );
    let repeated = bin()
        .arg("mitm")
        .arg("baseline")
        .arg("MyLab")
        .arg("--file")
        .arg(&good)
        .arg("--output")
        .arg(&baseline)
        .arg("--confirmed")
        .output()
        .unwrap();
    assert!(!repeated.status.success());

    let assessed = bin()
        .arg("mitm")
        .arg("assess")
        .arg("--baseline")
        .arg(&baseline)
        .arg("--file")
        .arg(&suspect)
        .output()
        .unwrap();
    assert!(
        assessed.status.success(),
        "{}",
        String::from_utf8_lossy(&assessed.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&assessed.stdout).unwrap();
    assert_eq!(report["status"], "suspected");
    assert_eq!(report["findings"][0]["kind"], "unrecognized_open_ap");
    assert_eq!(report["source"], "unverified_json_file");

    let _ = fs::remove_file(good);
    let _ = fs::remove_file(suspect);
    let _ = fs::remove_file(baseline);
}

#[test]
fn empty_capture_is_inconclusive_not_proof_of_no_attack() {
    let good = temp("trusted-empty-good.json");
    let empty = temp("empty.json");
    let baseline = temp("trusted-empty-baseline.json");
    let _ = fs::remove_file(&baseline);
    fs::write(
        &good,
        r#"[{"bssid":"a0:11:22:33:44:55","ssid":"Home","rssi":-45,"capabilities":"[WPA2-PSK][ESS]"}]"#,
    )
    .unwrap();
    fs::write(&empty, "[]").unwrap();
    assert!(
        bin()
            .arg("mitm")
            .arg("baseline")
            .arg("Home")
            .arg("--file")
            .arg(&good)
            .arg("--output")
            .arg(&baseline)
            .arg("--confirmed")
            .status()
            .unwrap()
            .success()
    );
    let report = bin()
        .arg("mitm")
        .arg("assess")
        .arg("--baseline")
        .arg(&baseline)
        .arg("--file")
        .arg(&empty)
        .output()
        .unwrap();
    assert!(report.status.success());
    let json: serde_json::Value = serde_json::from_slice(&report.stdout).unwrap();
    assert_eq!(json["status"], "inconclusive");
    let _ = fs::remove_file(good);
    let _ = fs::remove_file(empty);
    let _ = fs::remove_file(baseline);
}
