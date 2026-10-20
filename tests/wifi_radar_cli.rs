//! End-to-end CLI acceptance for offline/replayed Termux Wi-Fi cache data.
//! Live radio hardware tests are not faked by these deterministic fixtures.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use huntsman_recon::exit::{EX_DATAERR, EX_NOINPUT, EX_UNAVAILABLE, EX_USAGE};

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
}

fn path(suffix: &str) -> PathBuf {
    std::env::temp_dir().join(format!("huntsman-wifi-radar-{}-{suffix}.json", std::process::id()))
}

#[test]
fn termux_json_replays_as_real_rf_sightings_without_fabricated_location() {
    let input = path("valid");
    fs::write(
        &input,
        br#"[{"bssid":"3C:5A:B4:11:22:33","ssid":"MyLab","rssi":-48,"frequency_mhz":5180,"capabilities":"[WPA2-PSK]"}]"#,
    )
    .unwrap();
    let out = bin()
        .args(["radar", "wifi", "--json", "--file"])
        .arg(&input)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let parsed: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(parsed["source"], "termux-wifi-scaninfo");
    assert_eq!(parsed["acquisition"], "android_cached_scan_results_not_active_scan");
    assert_eq!(parsed["status"], "freshness_unknown");
    assert_eq!(parsed["observed"], 1);
    assert_eq!(parsed["observations"][0]["sighting"]["network_id"], "3c:5a:b4:11:22:33");
    assert_eq!(parsed["observations"][0]["band"], "5GHz");
    assert!(parsed["observations"][0]["sighting"]["latitude"].is_null());
    assert!(parsed["observations"][0]["sighting"]["observed_epoch"].is_null());
    fs::remove_file(input).unwrap();
}

#[test]
fn empty_android_os_cache_cannot_be_reported_as_success() {
    let input = path("empty");
    fs::write(&input, b"[]").unwrap();
    let out = bin()
        .args(["radar", "wifi", "--json", "--file"])
        .arg(&input)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(i32::from(EX_UNAVAILABLE)));
    let parsed: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(parsed["status"], "inconclusive");
    assert_eq!(parsed["observed"], 0);
    fs::remove_file(input).unwrap();
}

#[test]
fn termux_api_error_is_reported_as_failure_not_empty_results() {
    let input = path("error");
    fs::write(&input, br#"{"API_ERROR":"Location needs to be enabled"}"#).unwrap();
    let out = bin()
        .args(["radar", "wifi", "--file"])
        .arg(&input)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(i32::from(EX_DATAERR)));
    assert!(String::from_utf8_lossy(&out.stderr).contains("Location needs to be enabled"));
    assert!(out.stdout.is_empty());
    fs::remove_file(input).unwrap();
}

#[test]
fn the_cli_refuses_bad_arguments_and_missing_capture_files() {
    for args in [
        vec!["radar"],
        vec!["radar", "wifi", "--file"],
        vec!["radar", "wifi", "--json", "--json"],
        vec!["radar", "ble"],
    ] {
        let out = bin().args(args).output().unwrap();
        assert_eq!(out.status.code(), Some(i32::from(EX_USAGE)));
    }
    let missing = path("missing");
    let _ = fs::remove_file(&missing);
    let out = bin()
        .args(["radar", "wifi", "--file"])
        .arg(&missing)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(i32::from(EX_NOINPUT)));
}
