//! End-to-end CLI coverage for rootless Android cellular OS-cache evidence.
//! These synthetic captures do not substitute for an on-device acceptance test.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use huntsman_recon::exit::{EX_DATAERR, EX_NOINPUT, EX_UNAVAILABLE, EX_USAGE};

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
}

fn path(suffix: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "huntsman-cell-radar-{}-{suffix}.json",
        std::process::id()
    ))
}

#[test]
fn cell_info_cli_keeps_android_rat_identity_and_unknown_time() {
    let input = path("mixed");
    fs::write(
        &input,
        br#"[{"type":"gsm","mcc":505,"mnc":1,"lac":17,"cid":91,"dbm":-84,"registered":true},{"type":"lte","mcc":505,"mnc":1,"tac":19,"ci":12345,"dbm":-101},{"type":"nr","mcc":"505","mnc":"01","tac":20,"nci":68719476735},{"type":"cdma","system":1,"network":2,"basestation":3}]"#,
    )
    .unwrap();
    let out = bin()
        .args(["radar", "cells", "--file"])
        .arg(&input)
        .arg("--json")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let data: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(data["source"], "unverified_json_file");
    assert_eq!(data["acquisition"], "offline_replay_no_capture_provenance");
    assert_eq!(data["status"], "freshness_unknown");
    assert_eq!(data["observed"], 3);
    assert_eq!(data["rejected"], 1);
    assert_eq!(
        data["observations"][0]["sighting"]["network_id"],
        "gsm:505-01-17-91"
    );
    assert_eq!(
        data["observations"][2]["sighting"]["network_id"],
        "nr:505-01-20-68719476735"
    );
    assert_eq!(data["observations"][0]["registered"], true);
    assert_eq!(data["observations"][0]["freshness"], "unknown");
    assert!(data["observations"][0]["sighting"]["latitude"].is_null());
    assert!(data["observations"][0]["sighting"]["observed_epoch"].is_null());
    fs::remove_file(input).unwrap();
}

#[test]
fn redacted_or_empty_cell_cache_is_inconclusive_not_absence() {
    let input = path("redacted");
    fs::write(
        &input,
        br#"[{"type":"lte","mcc":505,"mnc":1,"tac":2147483647,"ci":17}]"#,
    )
    .unwrap();
    let out = bin()
        .args(["radar", "cells", "--json", "--file"])
        .arg(&input)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(i32::from(EX_UNAVAILABLE)));
    let data: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(data["status"], "inconclusive");
    assert_eq!(data["observed"], 0);
    assert_eq!(data["rejected"], 1);
    fs::remove_file(input).unwrap();
}

#[test]
fn corrupt_cell_info_and_missing_input_fail_closed() {
    let input = path("bad");
    fs::write(&input, br#"{"API_ERROR":"permission denied"}"#).unwrap();
    let out = bin()
        .args(["radar", "cells", "--file"])
        .arg(&input)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(i32::from(EX_DATAERR)));
    assert!(String::from_utf8_lossy(&out.stderr).contains("permission denied"));
    fs::remove_file(input).unwrap();

    let missing = path("missing");
    let _ = fs::remove_file(&missing);
    let out = bin()
        .args(["radar", "cells", "--file"])
        .arg(&missing)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(i32::from(EX_NOINPUT)));
    let out = bin()
        .args(["radar", "cells", "--json", "--json"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(i32::from(EX_USAGE)));
}
