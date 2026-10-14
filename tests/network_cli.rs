//! The `network` lookup end to end through the binary, with no WiGLE credentials so no request
//! is made: `network`, `scan` inference and `scan -k network` reach the same front-end, the
//! offline OUI classification runs, the WiGLE leg reports `auth_required` rather than a zero,
//! and `--save` writes a ledger that `verify` reloads.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

const BSSID: &str = "3c:5a:b4:01:02:03";

fn bin() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_huntsman-recon"));
    command
        .env_remove("HUNTSMAN_WIGLE_USER")
        .env_remove("HUNTSMAN_WIGLE_TOKEN");
    command
}

fn run(args: &[&str]) -> Output {
    bin().args(args).output().unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn a_bssid_is_classified_offline_and_wigle_without_credentials_makes_no_request() {
    let out = run(&["network", "3C-5A-B4-01-02-03"]);
    assert!(out.status.success(), "{out:?}");
    let text = stdout(&out);
    assert!(text.contains("\noui\tsuccess\tfound=1"), "{text}");
    assert!(
        text.contains("\nwigle\tauth_required\tfound=none"),
        "{text}"
    );
    assert!(text.contains("HUNTSMAN_WIGLE_USER"), "{text}");
    assert!(text.ends_with("wigle_networks=none\n"), "{text}");
}

#[test]
fn scan_infers_a_bssid_or_a_coordinate_pair_and_takes_an_ssid_when_told() {
    for (args, selector) in [
        (vec!["scan", BSSID], BSSID),
        (vec!["scan", "-27.4698,153.0251"], "-27.469800,153.025100"),
        (vec!["scan", "Cafe Guest", "-k", "ssid"], "Cafe Guest"),
    ] {
        let out = run(&args);
        assert!(out.status.success(), "{args:?}: {out:?}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("scan_route=network"), "{args:?}: {stderr}");
        let text = stdout(&out);
        assert!(text.contains(selector), "{args:?}: {text}");
        assert!(text.contains("\nwigle\tauth_required"), "{args:?}: {text}");
    }
}

#[test]
fn bad_selectors_are_data_errors_and_bad_usage_is_a_usage_error() {
    assert_eq!(run(&["network", "ssid:"]).status.code(), Some(65));
    assert_eq!(run(&["network", &"x".repeat(33)]).status.code(), Some(65));
    assert_eq!(run(&["network"]).status.code(), Some(64));
    assert_eq!(run(&["network", BSSID, "--bogus"]).status.code(), Some(64));
}

#[test]
fn a_saved_network_report_verifies() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("network-cli-save");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let ledger = dir.join("network.json");
    let out = run(&["network", BSSID, "--save", ledger.to_str().unwrap()]);
    assert!(out.status.success(), "{out:?}");
    assert!(stdout(&out).contains("saved="), "{out:?}");
    let verify = run(&["verify", ledger.to_str().unwrap()]);
    assert!(verify.status.success(), "{verify:?}");
}
