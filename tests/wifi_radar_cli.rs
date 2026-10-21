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
    std::env::temp_dir().join(format!(
        "huntsman-wifi-radar-{}-{suffix}.json",
        std::process::id()
    ))
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
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let parsed: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(parsed["source"], "unverified_json_file");
    assert_eq!(parsed["acquisition"], "offline_replay_no_boot_provenance");
    assert_eq!(parsed["status"], "freshness_unknown");
    assert_eq!(parsed["observed"], 1);
    assert_eq!(
        parsed["observations"][0]["sighting"]["network_id"],
        "3c:5a:b4:11:22:33"
    );
    assert_eq!(parsed["observations"][0]["band"], "5GHz");
    assert!(parsed["observations"][0]["sighting"]["latitude"].is_null());
    assert!(parsed["observations"][0]["sighting"]["observed_epoch"].is_null());
    fs::remove_file(input).unwrap();
}

#[test]
fn a_replayed_foreign_boot_timestamp_is_never_called_fresh() {
    // An imported file can have an Android boot timestamp that happens to
    // match the host uptime. The old CLI incorrectly labelled it recent.
    let uptime_text = fs::read_to_string("/proc/uptime").unwrap();
    let seconds: u64 = uptime_text
        .split_whitespace()
        .next()
        .unwrap()
        .split('.')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let timestamp = seconds.checked_mul(1_000_000).unwrap();
    let input = path("foreign-boot");
    fs::write(
        &input,
        format!(
            r#"[{{"bssid":"3C:5A:B4:11:22:33","ssid":"archived","rssi":-52,"timestamp":{timestamp}}}]"#
        ),
    )
    .unwrap();
    let out = bin()
        .args(["radar", "wifi", "--json", "--file"])
        .arg(&input)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let parsed: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(parsed["status"], "freshness_unknown");
    assert_eq!(parsed["source"], "unverified_json_file");
    assert_eq!(parsed["acquisition"], "offline_replay_no_boot_provenance");
    assert_eq!(
        parsed["observations"][0]["age_secs"],
        serde_json::Value::Null
    );
    assert_eq!(parsed["observations"][0]["freshness"], "unknown");
    assert_eq!(parsed["observations"][0]["os_timestamp_us"], timestamp);
    fs::remove_file(input).unwrap();
}

#[test]
fn redacted_and_group_bssids_are_not_exported_as_devices() {
    let input = path("invalid-identities");
    fs::write(
        &input,
        br#"[{"bssid":"02:00:00:00:00:00","ssid":"privacy-sentinel","rssi":-20},{"bssid":"01:00:5e:00:00:01","rssi":-45},{"bssid":"ff:ff:ff:ff:ff:ff","rssi":-49},{"bssid":"00:00:00:00:00:00","rssi":-40},{"bssid":"36:32:62:36:31:33","ssid":"randomized-valid","rssi":-60}]"#,
    )
    .unwrap();
    let out = bin()
        .args(["radar", "wifi", "--json", "--file"])
        .arg(&input)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let parsed: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(parsed["observed"], 1);
    assert_eq!(parsed["rejected"], 4);
    assert_eq!(parsed["status"], "freshness_unknown");
    assert_eq!(
        parsed["observations"][0]["sighting"]["network_id"],
        "36:32:62:36:31:33"
    );
    assert_eq!(parsed["observations"][0]["freshness"], "unknown");
    fs::remove_file(input).unwrap();
}

#[test]
fn only_redacted_bssid_is_inconclusive_not_zero_devices_detected() {
    let input = path("only-redacted");
    fs::write(&input, br#"[{"bssid":"02:00:00:00:00:00","rssi":-25}]"#).unwrap();
    let out = bin()
        .args(["radar", "wifi", "--json", "--file"])
        .arg(&input)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(i32::from(EX_UNAVAILABLE)));
    let parsed: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(parsed["observed"], 0);
    assert_eq!(parsed["rejected"], 1);
    assert_eq!(parsed["status"], "inconclusive");
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
    assert_eq!(out.stdout.len(), 0);
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

#[cfg(unix)]
#[test]
fn a_descendant_holding_sensor_stdout_cannot_hang_the_radar_command() {
    use std::ffi::OsString;
    use std::os::unix::fs::PermissionsExt;
    use std::time::{Duration, Instant};

    // Recreate the dangerous case: the direct sensor process returns, but a
    // grandchild inherited its stdout pipe. Previously reader.join() waited
    // for that grandchild indefinitely, bypassing the 15-second watchdog.
    let directory = std::env::temp_dir().join(format!(
        "huntsman-sensor-stdout-{}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).unwrap();
    let mut search_path = OsString::from(directory.as_os_str());
    search_path.push(":");
    search_path.push(std::env::var_os("PATH").unwrap_or_default());

    for (sensor, selector) in [
        ("termux-wifi-scaninfo", "wifi"),
        ("termux-telephony-cellinfo", "cells"),
    ] {
        let shim = directory.join(sensor);
        fs::write(&shim, b"#!/bin/sh\n(sleep 8) &\nprintf '[]\\n'\n").unwrap();
        let mut permissions = fs::metadata(&shim).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&shim, permissions).unwrap();

        let started = Instant::now();
        let result = bin()
            .args(["radar", selector])
            .env("PATH", &search_path)
            .output()
            .unwrap();
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{sensor} hung after its direct process exited"
        );
        assert_eq!(result.status.code(), Some(i32::from(EX_UNAVAILABLE)));
        assert!(
            String::from_utf8_lossy(&result.stderr)
                .contains("sensor stdout was not closed"),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        fs::remove_file(shim).unwrap();
    }
    fs::remove_dir(directory).unwrap();
}

#[test]
fn replay_file_option_requires_a_real_filename_for_both_radio_types() {
    for kind in ["wifi", "cells"] {
        let out = bin()
            .args(["radar", kind, "--file", "--json"])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(i32::from(EX_USAGE)), "{kind}");
    }
}
