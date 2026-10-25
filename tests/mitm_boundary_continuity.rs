//! Synthetic end-to-end contracts for the CLI, native evaluator and Web UI radar payload.
//! No network, Android sensor, or trusted baseline enrollment is required.

use std::fs;
use std::process::Command;

use huntsman_recon::{mitm_guard, wifi_radar};

#[test]
fn offline_cli_and_embedded_radar_report_use_the_same_evidence_contract() {
    let raw = br#"[{"bssid":"3C:5A:B4:11:22:33","ssid":"Office","rssi":-55,"timestamp":980000000,"capabilities":"[WPA2-PSK][ESS]"},{"bssid":"3c:5a:b4:11:22:33","ssid":"Office","rssi":-54,"timestamp":980000000,"capabilities":"[WPA2-PSK][ESS]"},{"bssid":"02:11:22:33:44:55","ssid":"Office","rssi":-60,"timestamp":980000000,"capabilities":"[RSN-SAE-CCMP][ESS]"}]"#;

    // The Web UI embeds the native scan assessment, never a separate JS classifier.
    let current = wifi_radar::parse_scan(raw, Some(1000.0)).unwrap();
    let embedded = current.mitm_assessment.as_ref().unwrap();
    assert_eq!(embedded, &mitm_guard::from_wifi_scan(&current, None));
    assert_eq!(embedded.evaluated_access_points, 2);
    assert_eq!(embedded.status, "unconfirmed_indicators");
    assert!(!embedded.mitm_confirmed);

    // A disk replay does not inherit the live capture's boot-clock provenance.
    let replay = wifi_radar::parse_replay(raw).unwrap();
    let replay_embedded = replay.mitm_assessment.as_ref().unwrap();
    assert_eq!(
        replay_embedded,
        &mitm_guard::from_wifi_replay(&replay, None)
    );
    assert_eq!(replay_embedded.status, "historical_unconfirmed_indicators");

    let file = std::env::temp_dir().join(format!(
        "hse-mitm-boundary-{}.json",
        std::process::id()
    ));
    fs::write(&file, raw).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
        .args(["mitm", "audit", "--file"])
        .arg(&file)
        .arg("--json")
        .output()
        .unwrap();
    fs::remove_file(&file).unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let cli_json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let embedded_json = serde_json::to_value(replay_embedded).unwrap();
    assert_eq!(cli_json, embedded_json);
    assert_eq!(cli_json["evaluated_access_points"], 2);
    assert_eq!(cli_json["mitm_confirmed"], false);
}

#[test]
fn wigle_import_uses_the_same_bssid_identity_as_native_radar() {
    let raw = concat!(
        "{\"type\":\"WIFI\",\"name\":\"Office\",\"network_id\":\"3C:5A:B4:11:22:33\",\"encryption\":\"WPA2\"}\n",
        "{\"type\":\"WIFI\",\"name\":\"Office\",\"network_id\":\"3c:5a:b4:11:22:33\",\"encryption\":\"WPA2\"}\n",
        "{\"type\":\"WIFI\",\"name\":\"Office\",\"network_id\":\"02:11:22:33:44:55\",\"encryption\":\"WPA3\"}\n"
    );
    let report = mitm_guard::from_wigle_jsonl(raw.as_bytes(), None).unwrap();
    assert_eq!(report.evaluated_access_points, 2);
    assert_eq!(report.findings.len(), 1);
    assert_eq!(
        report.findings[0].code,
        "unverified_ssid_security_variation"
    );
    assert!(!report.mitm_confirmed);
}
