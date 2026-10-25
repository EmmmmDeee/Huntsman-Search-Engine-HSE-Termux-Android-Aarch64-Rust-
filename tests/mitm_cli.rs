//! MITM guard CLI regression tests use synthetic fixtures, never live radio.
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
}

fn fixture(label: &str, extension: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "hse-mitm-{}-{}-{label}.{extension}",
        std::process::id(),
        std::thread::current().name().unwrap_or("test")
    ))
}

#[test]
fn wigle_mixed_security_is_review_only() {
    let file = fixture("wigle", "jsonl");
    fs::write(&file, concat!(
        "{\"type\":\"WIFI\",\"name\":\"LabNet\",\"network_id\":\"02:11:22:33:44:55\",\"encryption\":\"WPA2\"}\n",
        "{\"type\":\"WIFI\",\"name\":\"LabNet\",\"network_id\":\"02:22:33:44:55:66\",\"encryption\":\"WPA3\"}\n",
        "{\"type\":\"BLE\",\"name\":\"ignored\",\"network_id\":\"10:11:22:33:44:55\"}\n"
    )).unwrap();
    let out = bin()
        .args(["mitm", "audit", "--json", "--file"])
        .arg(&file)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["mitm_confirmed"], false);
    assert_eq!(report["evaluated_access_points"], 2);
    assert_eq!(
        report["findings"][0]["code"],
        "unverified_ssid_security_variation"
    );
    fs::remove_file(file).unwrap();
}

#[test]
fn trusted_baseline_flags_unenrolled_and_downgraded_ap() {
    let file = fixture("radar", "json");
    let baseline = fixture("baseline", "json");
    fs::write(&file, br#"[{"bssid":"3c:5a:b4:22:33:44","ssid":"Office","rssi":-42,"capabilities":"[WPA2-PSK][ESS]"}]"#).unwrap();
    fs::write(&baseline, br#"{"networks":[{"ssid":"Office","bssids":["3c:5a:b4:11:22:33"],"minimum_security":"WPA3"}]}"#).unwrap();
    let out = bin()
        .args(["mitm", "audit", "--file"])
        .arg(&file)
        .args(["--baseline"])
        .arg(&baseline)
        .arg("--json")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["status"], "historical_unconfirmed_indicators");
    assert_eq!(
        report["findings"][0]["code"],
        "security_below_trusted_floor"
    );
    assert_eq!(report["findings"][0]["severity"], "high");
    assert_eq!(report["mitm_confirmed"], false);
    fs::remove_file(file).unwrap();
    fs::remove_file(baseline).unwrap();
}

#[test]
fn invalid_baseline_is_rejected() {
    let file = fixture("bad-scan", "json");
    let baseline = fixture("bad-baseline", "json");
    fs::write(&file, b"[]").unwrap();
    fs::write(&baseline, br#"{"networks":[{"ssid":"Office","bssids":["02:00:00:00:00:00"],"minimum_security":"WPA3"}]}"#).unwrap();
    let out = bin()
        .args(["mitm", "audit", "--file"])
        .arg(&file)
        .args(["--baseline"])
        .arg(&baseline)
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert_eq!(out.stdout, [] as [u8; 0]);
    fs::remove_file(file).unwrap();
    fs::remove_file(baseline).unwrap();
}

#[test]
fn baseline_requires_explicit_confirmation_and_never_overwrites() {
    use std::os::unix::fs::PermissionsExt as _;

    let output = fixture("operator-baseline", "json");
    let path = output.to_str().expect("temporary path is UTF-8");
    let args = [
        "mitm",
        "baseline",
        "--ssid",
        "LabNet",
        "--bssid",
        "02:11:22:33:44:55",
        "--minimum-security",
        "WPA2",
        "--output",
        path,
    ];
    let missing_confirmation = bin().args(args).output().unwrap();
    assert!(!missing_confirmation.status.success());
    assert!(!output.exists());

    let created = bin().args(args).arg("--confirmed").output().unwrap();
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    let original = fs::read(&output).unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&original).unwrap();
    assert_eq!(parsed["networks"][0]["ssid"], "LabNet");
    assert_eq!(parsed["networks"][0]["bssids"][0], "02:11:22:33:44:55");
    assert_eq!(parsed["networks"][0]["minimum_security"], "WPA2");
    assert_eq!(
        fs::metadata(&output).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let overwrite = bin().args(args).arg("--confirmed").output().unwrap();
    assert!(!overwrite.status.success());
    assert_eq!(fs::read(&output).unwrap(), original);
    fs::remove_file(output).unwrap();
}

#[test]
fn baseline_rejects_invalid_and_duplicate_operator_bssids() {
    let output = fixture("invalid-operator-baseline", "json");
    let path = output.to_str().expect("temporary path is UTF-8");
    for bssid in ["00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "not-a-mac"] {
        let result = bin()
            .args([
                "mitm",
                "baseline",
                "--ssid",
                "LabNet",
                "--bssid",
                bssid,
                "--minimum-security",
                "WPA2",
                "--output",
                path,
                "--confirmed",
            ])
            .output()
            .unwrap();
        assert!(!result.status.success(), "accepted invalid BSSID: {bssid}");
        assert!(!output.exists());
    }
    let duplicate = bin()
        .args([
            "mitm",
            "baseline",
            "--ssid",
            "LabNet",
            "--bssid",
            "02:11:22:33:44:55",
            "--bssid",
            "02:11:22:33:44:55",
            "--minimum-security",
            "WPA2",
            "--output",
            path,
            "--confirmed",
        ])
        .output()
        .unwrap();
    assert!(!duplicate.status.success());
    assert!(!output.exists());
}
