//! End-to-end CLI coverage for `radar track`: a Wi-Fi sweep placed at the serving cell, added to
//! the private sweep log, and the log read back for recurring devices and followers. These
//! synthetic captures do not substitute for an on-device acceptance test.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use huntsman_recon::exit::{EX_NOINPUT, EX_UNAVAILABLE, EX_USAGE};

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
}

fn scratch(tag: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("huntsman-radar-track-{}-{tag}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

const WIFI: &[u8] = br#"[{"bssid":"3C:5A:B4:11:22:33","ssid":"tail","rssi":-48},{"bssid":"36:32:62:36:31:33","ssid":"randomized","rssi":-60},{"bssid":"00:11:22:33:44:55","ssid":"home\tforged=1\nfollower","rssi":-40}]"#;
const CELLS: &[u8] =
    br#"[{"type":"gsm","mcc":505,"mnc":1,"lac":17,"cid":91,"dbm":-84,"registered":true}]"#;

/// A device heard in two earlier places and now a third, over half an hour, is a follower; the
/// randomized address is never logged; the sweep is added to the log, which stays private.
#[test]
fn a_sweep_is_logged_at_its_cell_and_a_device_that_followed_is_flagged() {
    let dir = scratch("follow");
    let (wifi, cells, log) = (
        dir.join("wifi.json"),
        dir.join("cells.json"),
        dir.join("sweeps.jsonl"),
    );
    fs::write(&wifi, WIFI).unwrap();
    fs::write(&cells, CELLS).unwrap();
    let start = now() - 1_800;
    fs::write(
        &log,
        format!(
            "{{\"ts\":{start},\"cell\":\"lte:505-01-19-100\",\"devices\":[{{\"mac\":\"3c:5a:b4:11:22:33\"}}]}}\n\
             not a sweep\n\
             {{\"ts\":{},\"cell\":\"lte:505-01-19-200\",\"devices\":[{{\"mac\":\"3c:5a:b4:11:22:33\"}}]}}\n",
            start + 900
        ),
    )
    .unwrap();
    let out = bin()
        .args(["radar", "track", "--json", "--wifi-file"])
        .arg(&wifi)
        .arg("--cells-file")
        .arg(&cells)
        .arg("--log")
        .arg(&log)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["sweeps"], 3);
    assert_eq!(report["distinct_cells"], 3);
    assert_eq!(report["skipped_lines"], 1);
    assert_eq!(report["followers"].as_array().unwrap().len(), 1, "{report}");
    assert_eq!(report["followers"][0]["mac"], "3c:5a:b4:11:22:33");
    assert_eq!(report["followers"][0]["distinct_cells"], 3);

    let kept = fs::read_to_string(&log).unwrap();
    assert_eq!(
        kept.lines().count(),
        3,
        "the damaged line is not kept: {kept}"
    );
    let newest: serde_json::Value = serde_json::from_str(kept.lines().last().unwrap()).unwrap();
    assert_eq!(newest["cell"], "gsm:505-01-17-91");
    let macs: Vec<&str> = newest["devices"]
        .as_array()
        .unwrap()
        .iter()
        .map(|device| device["mac"].as_str().unwrap())
        .collect();
    assert_eq!(macs, ["3c:5a:b4:11:22:33", "00:11:22:33:44:55"]);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&log).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let _ = fs::remove_dir_all(&dir);
}

/// With no `--log`, the sweep goes to the private state directory, made 0700 when missing.
#[test]
fn the_default_log_lives_in_the_private_state_directory() {
    let dir = scratch("default");
    let (wifi, cells) = (dir.join("wifi.json"), dir.join("cells.json"));
    fs::write(&wifi, WIFI).unwrap();
    fs::write(&cells, CELLS).unwrap();
    let home = dir.join("state");
    let out = bin()
        .env("HUNTSMAN_HOME", &home)
        .args(["radar", "track", "--wifi-file"])
        .arg(&wifi)
        .arg("--cells-file")
        .arg(&cells)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(
        text.starts_with("track\tsweeps=1\tlocated=1\tcells=1\tfollowers=0"),
        "{text}"
    );
    // A second sweep makes the home access point recur; its SSID, a third party's text, is
    // escaped so it cannot forge a column or a row.
    let again = bin()
        .env("HUNTSMAN_HOME", &home)
        .args(["radar", "track", "--wifi-file"])
        .arg(&wifi)
        .arg("--cells-file")
        .arg(&cells)
        .output()
        .unwrap();
    let text = String::from_utf8(again.stdout).unwrap();
    assert!(text.contains("ssid=home\\tforged=1\\nfollower\t"), "{text}");
    assert!(
        !text.lines().any(|line| line.starts_with("follower")),
        "{text}"
    );
    let log = home.join("radar").join("sweeps.jsonl");
    assert_eq!(fs::read_to_string(&log).unwrap().lines().count(), 2);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |path: &PathBuf| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&home.join("radar")), 0o700);
        assert_eq!(mode(&log), 0o600);
    }
    let _ = fs::remove_dir_all(&dir);
}

/// An empty scan logs nothing, a missing cell replay is an error, and a bad flag is usage.
#[test]
fn a_sweep_that_cannot_be_trusted_is_not_logged() {
    let dir = scratch("refuse");
    let (wifi, empty, log) = (
        dir.join("wifi.json"),
        dir.join("empty.json"),
        dir.join("sweeps.jsonl"),
    );
    fs::write(&wifi, WIFI).unwrap();
    fs::write(&empty, b"[]").unwrap();
    let run =
        |args: &[&std::ffi::OsStr]| bin().args(["radar", "track"]).args(args).output().unwrap();
    let inconclusive = run(&[
        "--wifi-file".as_ref(),
        empty.as_os_str(),
        "--log".as_ref(),
        log.as_os_str(),
    ]);
    assert_eq!(inconclusive.status.code(), Some(i32::from(EX_UNAVAILABLE)));
    let missing = run(&[
        "--wifi-file".as_ref(),
        wifi.as_os_str(),
        "--cells-file".as_ref(),
        dir.join("absent.json").as_os_str(),
        "--log".as_ref(),
        log.as_os_str(),
    ]);
    assert_eq!(missing.status.code(), Some(i32::from(EX_NOINPUT)));
    assert!(!log.exists(), "nothing was logged");
    let usage = run(&[
        "--log".as_ref(),
        log.as_os_str(),
        "--log".as_ref(),
        log.as_os_str(),
    ]);
    assert_eq!(usage.status.code(), Some(i32::from(EX_USAGE)));
    let _ = fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn missing_scan_timestamps_do_not_create_a_live_track_log() {
    use std::ffi::OsString;
    use std::os::unix::fs::PermissionsExt;

    let dir = scratch("missing-live-timestamps");
    let log = dir.join("sweeps.jsonl");
    let shim = dir.join("termux-wifi-scaninfo");
    // Android may provide BSSID and RSSI while withholding a usable
    // boot-relative timestamp. Those rows must never be recorded as live.
    fs::write(
        &shim,
        br#"#!/bin/sh
printf '[{"bssid":"00:11:22:33:44:55","ssid":"unknown-age","rssi":-51}]'
"#,
    )
    .unwrap();
    let mut perms = fs::metadata(&shim).unwrap().permissions();
    perms.set_mode(0o700);
    fs::set_permissions(&shim, perms).unwrap();
    let mut search_path = OsString::from(dir.as_os_str());
    search_path.push(":");
    search_path.push(std::env::var_os("PATH").unwrap_or_default());

    let output = bin()
        .args(["radar", "track", "--json", "--log"])
        .arg(&log)
        .env("PATH", search_path)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(i32::from(EX_UNAVAILABLE)));
    assert!(String::from_utf8_lossy(&output.stderr).contains("no current-age observations"));
    assert!(!log.exists(), "unknown-age records created a tracking log");
    let _ = fs::remove_dir_all(dir);
}

#[cfg(unix)]
#[test]
fn live_randomized_only_cache_must_not_append_a_sweep() {
    use std::ffi::OsString;
    use std::os::unix::fs::PermissionsExt;

    let dir = scratch("randomized-only-live");
    let log = dir.join("sweeps.jsonl");
    let shim = dir.join("termux-wifi-scaninfo");
    fs::write(
        &shim,
        br#"#!/bin/sh
awk '{printf "[{\"bssid\":\"02:11:22:33:44:55\",\"ssid\":\"random\",\"rssi\":-51,\"timestamp\":%.0f}]\n", $1*1000000}' /proc/uptime
"#,
    )
    .unwrap();
    let mut perms = fs::metadata(&shim).unwrap().permissions();
    perms.set_mode(0o700);
    fs::set_permissions(&shim, perms).unwrap();
    let mut search_path = OsString::from(dir.as_os_str());
    search_path.push(":");
    search_path.push(std::env::var_os("PATH").unwrap_or_default());

    let output = bin()
        .args(["radar", "track", "--json", "--log"])
        .arg(&log)
        .env("PATH", search_path)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(i32::from(EX_UNAVAILABLE)));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("trackable access points"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !log.exists(),
        "randomized-only capture created an empty sweep"
    );
    let _ = fs::remove_dir_all(dir);
}

/// The CLI reports only persisted, capacity-bounded sweeps.
#[test]
fn cli_report_matches_stored_history_under_byte_capacity_pressure() {
    let dir = scratch("capacity-consistency");
    let wifi = dir.join("wifi.json");
    let cells = dir.join("cells.json");
    let log = dir.join("sweeps.jsonl");
    fs::write(&wifi, WIFI).unwrap();
    fs::write(&cells, CELLS).unwrap();
    let bound = usize::try_from(huntsman_recon::radar::MAX_TRACK_LOG_BYTES).unwrap();
    let huge = serde_json::json!({
        "ts": now().saturating_sub(900),
        "cell": "lte:505-01-1-19",
        "devices": [{
            "mac": "3c:5a:b4:11:22:33",
            "name": "x".repeat(bound - 150)
        }]
    });
    let mut original = serde_json::to_vec(&huge).unwrap();
    original.push(b'\n');
    assert!(original.len() <= bound);
    // Independently prove this fixture forces the byte cap to discard the
    // prior sweep, regardless of JSON field ordering or current clock value.
    let scan = huntsman_recon::wifi_radar::parse_replay(WIFI).unwrap();
    let serving = huntsman_recon::cell_radar::parse_replay(CELLS)
        .unwrap()
        .serving_cell();
    let incoming = scan.logged_sweep(now(), serving);
    assert!(original.len() + serde_json::to_vec(&incoming).unwrap().len() + 1 > bound);
    fs::write(&log, original).unwrap();

    let result = bin()
        .args(["radar", "track", "--json", "--wifi-file"])
        .arg(&wifi)
        .arg("--cells-file")
        .arg(&cells)
        .arg("--log")
        .arg(&log)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    let bytes = fs::read(&log).unwrap();
    let (stored, skipped) = huntsman_recon::radar::parse_track_log(&bytes);
    assert_eq!(skipped, 0);
    assert_eq!(stored.len(), 1);
    assert_eq!(report["sweeps"], 1);
    assert_eq!(report["recurring"].as_array().unwrap().len(), 0);
    assert_eq!(report["followers"].as_array().unwrap().len(), 0);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn ambiguous_registered_cell_replay_is_logged_without_a_place() {
    let dir = scratch("ambiguous-cells");
    let wifi = dir.join("wifi.json");
    let cells = dir.join("cells.json");
    let log = dir.join("sweeps.jsonl");
    fs::write(&wifi, WIFI).unwrap();
    fs::write(
        &cells,
        br#"[{"type":"gsm","mcc":505,"mnc":1,"lac":17,"cid":91,"registered":true},{"type":"lte","mcc":505,"mnc":1,"tac":19,"ci":1234,"registered":true}]"#,
    )
    .unwrap();
    let output = bin()
        .args(["radar", "track", "--json", "--wifi-file"])
        .arg(&wifi)
        .arg("--cells-file")
        .arg(&cells)
        .arg("--log")
        .arg(&log)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("no unique registered serving cell"));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["sweeps"], 1);
    assert_eq!(report["located_sweeps"], 0);
    assert_eq!(report["distinct_cells"], 0);
    let saved = fs::read(&log).unwrap();
    let (sweeps, malformed) = huntsman_recon::radar::parse_track_log(&saved);
    assert_eq!(malformed, 0);
    assert_eq!(sweeps.len(), 1);
    assert!(sweeps[0].cell.is_none());
    assert_eq!(sweeps[0].devices.len(), 2);
    fs::remove_dir_all(dir).unwrap();
}

/// Legacy JSONL group/sentinel identifiers remain readable and preserved as
/// evidence, but may never appear as recurring devices or follower candidates.
#[test]
fn historical_group_mac_rows_do_not_create_cli_recurrence_or_followers() {
    let dir = scratch("group-mac-history");
    let wifi = dir.join("wifi.json");
    let cells = dir.join("cells.json");
    let log = dir.join("sweeps.jsonl");
    fs::write(&wifi, WIFI).unwrap();
    fs::write(&cells, CELLS).unwrap();
    let start = now().saturating_sub(1_800);
    let mut old = String::new();
    for (index, cell) in ["lte:505-01-1-1", "lte:505-01-1-2", "lte:505-01-1-3"]
        .iter()
        .enumerate()
    {
        let row = serde_json::json!({
            "ts": start + u64::try_from(index).unwrap() * 600,
            "cell": cell,
            "devices": [
                {"mac": "01:00:5e:00:00:fb"},
                {"mac": "00:00:00:00:00:00"}
            ]
        });
        old.push_str(&row.to_string());
        old.push('\n');
    }
    fs::write(&log, old).unwrap();

    let out = bin()
        .args(["radar", "track", "--json", "--wifi-file"])
        .arg(&wifi)
        .arg("--cells-file")
        .arg(&cells)
        .arg("--log")
        .arg(&log)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["sweeps"], 4);
    assert_eq!(report["recurring"].as_array().unwrap().len(), 0);
    assert_eq!(report["followers"].as_array().unwrap().len(), 0);
    let stored = fs::read_to_string(&log).unwrap();
    assert_eq!(stored.lines().count(), 4);
    let first: serde_json::Value = serde_json::from_str(stored.lines().next().unwrap()).unwrap();
    assert_eq!(first["devices"].as_array().unwrap().len(), 2);
    assert_eq!(first["devices"][0]["mac"], "01:00:5e:00:00:fb");
    let _ = fs::remove_dir_all(dir);
}
