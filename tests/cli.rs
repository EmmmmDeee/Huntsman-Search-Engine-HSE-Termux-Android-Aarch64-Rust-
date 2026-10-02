//! Binary acceptance. `check` runs in a scratch directory so the repo is not touched.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
}

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("huntsman-cli-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn check_reproduces_committed_artifacts() {
    let dir = scratch("check");
    let out = bin().arg("check").current_dir(&dir).output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(stdout, "accepted techniques=0\nbrisbane_sydney_m=732379\n");
    let committed = Path::new(env!("CARGO_MANIFEST_DIR")).join("var");
    for name in ["ledger.json", "navigator.json", "stix-bundle.json"] {
        assert_eq!(
            fs::read(dir.join("var").join(name)).unwrap(),
            fs::read(committed.join(name)).unwrap(),
            "var/{name} differs from `check` output; re-run `cargo run -- check`"
        );
    }
    let verify = bin()
        .args(["verify", "var/ledger.json"])
        .current_dir(&dir)
        .output()
        .unwrap();
    assert!(verify.status.success());
    assert!(String::from_utf8_lossy(&verify.stdout).contains("admitted=0"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn failures_exit_nonzero() {
    let dir = scratch("fail");
    let missing = dir.join("missing");
    let out = bin()
        .args(["search", "port"])
        .arg(&missing)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(66), "unreadable dir is not hits=0");
    fs::write(dir.join("ledger.json"), b"[{\"prev\":\"x\"}]").unwrap();
    let out = bin()
        .arg("verify")
        .arg(dir.join("ledger.json"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(65));
    assert_eq!(bin().arg("nope").output().unwrap().status.code(), Some(64));
    assert_eq!(
        bin()
            .args(["geo", "91,0", "0,0"])
            .output()
            .unwrap()
            .status
            .code(),
        Some(65)
    );
    let _ = fs::remove_dir_all(&dir);
}
