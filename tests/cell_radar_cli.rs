//! Cell radio CLI replay acceptance with representative upstream Termux:API JSON.
//! A deterministic fixture is not a real handset acquisition receipt.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use huntsman_recon::exit::{EX_DATAERR, EX_NOINPUT, EX_UNAVAILABLE, EX_USAGE};

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
}

fn fixture_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "huntsman-cell-radar-{}-{name}.json",
        std::process::id()
    ))
}

#[test]
fn lte_nr_and_wcdma_replay_emit_typed_cell_identity_not_location() {
    let file = fixture_path("mixed");
    fs::write(
        &file,
        br#"[{"type":"lte","registered":true,"mcc":505,"mnc":1,"tac":222,"ci":45678,"dbm":-99},{"type":"nr","registered":false,"mcc":"505","mnc":"01","tac":130000,"nci":68719476734,"dbm":-95},{"type":"wcdma","registered":false,"mcc":505,"mnc":2,"lac":124,"cid":3220,"dbm":-81}]"#,
    )
    .unwrap();
    let out = bin()
        .args(["radar", "cell", "--json", "--file"])
        .arg(&file)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(json["source"], "unverified_json_file");
    assert_eq!(json["status"], "os_cached_freshness_unknown");
    assert_eq!(json["observed"], 3);
    assert_eq!(json["rejected"], 0);
    assert_eq!(
        json["observations"][0]["sighting"]["network_id"],
        "lte:505:1:222:45678"
    );
    assert_eq!(
        json["observations"][1]["sighting"]["network_id"],
        "nr:505:01:130000:68719476734"
    );
    assert_eq!(json["observations"][0]["sighting"]["radio"], "Cellular");
    assert_eq!(json["observations"][0]["sighting"]["source"], "CellRadar");
    for row in json["observations"].as_array().unwrap() {
        assert_eq!(row["freshness"], "unknown");
        assert!(row["sighting"]["latitude"].is_null());
        assert!(row["sighting"]["longitude"].is_null());
        assert!(row["sighting"]["observed_epoch"].is_null());
    }
    fs::remove_file(file).unwrap();
}

#[test]
fn cdma_tower_metadata_never_becomes_handset_location() {
    let file = fixture_path("cdma");
    fs::write(
        &file,
        br#"[{"type":"cdma","registered":true,"system":11,"network":22,"basestation":33,"latitude":900000,"longitude":300000,"dbm":-83}]"#,
    )
    .unwrap();
    let out = bin()
        .args(["radar", "cell", "--json", "--file"])
        .arg(&file)
        .output()
        .unwrap();
    assert!(out.status.success());
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        json["observations"][0]["sighting"]["network_id"],
        "cdma:11:22:33"
    );
    assert!(json["observations"][0]["sighting"]["latitude"].is_null());
    fs::remove_file(file).unwrap();
}

#[test]
fn empty_cell_cache_does_not_corroborate_absence_of_towers() {
    let file = fixture_path("empty");
    fs::write(&file, b"[]").unwrap();
    let out = bin()
        .args(["radar", "cell", "--json", "--file"])
        .arg(&file)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(i32::from(EX_UNAVAILABLE)));
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(json["status"], "inconclusive");
    assert_eq!(json["observed"], 0);
    fs::remove_file(file).unwrap();
}

#[test]
fn missing_identity_and_api_error_never_become_zero_result_successes() {
    let file = fixture_path("invalid");
    fs::write(&file, br#"[{"type":"nr","mcc":"505","mnc":"01","tac":1}]"#).unwrap();
    let out = bin()
        .args(["radar", "cell", "--json", "--file"])
        .arg(&file)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(i32::from(EX_UNAVAILABLE)));
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(json["rejected"], 1);
    fs::write(&file, br#"{"API_ERROR":"location permission denied"}"#).unwrap();
    let out = bin()
        .args(["radar", "cell", "--file"])
        .arg(&file)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(i32::from(EX_DATAERR)));
    fs::remove_file(file).unwrap();
}

#[test]
fn missing_capture_and_bad_arguments_fail_loudly() {
    for words in [
        vec!["radar", "cell", "--json", "--json"],
        vec!["radar", "cell", "--file"],
        vec!["radar", "cell", "--unknown"],
    ] {
        let out = bin().args(words).output().unwrap();
        assert_eq!(out.status.code(), Some(i32::from(EX_USAGE)));
    }
    let missing = fixture_path("missing");
    let _ = fs::remove_file(&missing);
    let out = bin()
        .args(["radar", "cell", "--file"])
        .arg(&missing)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(i32::from(EX_NOINPUT)));
}
