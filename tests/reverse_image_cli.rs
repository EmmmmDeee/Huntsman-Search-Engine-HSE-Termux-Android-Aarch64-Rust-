//! End-to-end reverse-image CLI contract exercised against the real Huntsman binary.
//! No provider credentials or network access are required.

use std::fs;
use std::process::Command;

fn image_fixture() -> Vec<u8> {
    // A minimal 1x1 GIF with a global palette and a single image frame.
    b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;".to_vec()
}

fn scratch(tag: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "huntsman-reverse-image-cli-{tag}-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).expect("scratch directory");
    path
}

#[test]
fn offline_reverse_image_runs_real_binary_and_reports_no_external_queries() {
    let home = scratch("offline");
    let image_path = home.join("photo.gif");
    fs::write(&image_path, image_fixture()).expect("image fixture");
    let out = Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
        .args(["reverse-image", image_path.to_str().expect("path"), "--json"])
        .env("HOME", &home)
        .output()
        .expect("run image search");
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).expect("report JSON");
    assert_eq!(report["bytes"], image_fixture().len());
    assert_eq!(report["live_requested"], false);
    assert_eq!(report["image_sha256"].as_str().unwrap().len(), 64);
    assert!(report["matches"].as_array().unwrap().is_empty());
    assert_eq!(report["statuses"].as_array().unwrap().len(), 3);
    assert!(report["statuses"].as_array().unwrap().iter().all(|s| s["state"] == "not_requested"));
    let help = Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
        .args(["reverse-image", "--help"])
        .env("HOME", &home)
        .output()
        .expect("run offline help");
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("IMAGE-FILE"));
    fs::remove_dir_all(home).expect("clean scratch");
}

#[cfg(unix)]
#[test]
fn reverse_image_cli_refuses_symlink_input_without_following_it() {
    use std::os::unix::fs::symlink;
    let home = scratch("symlink");
    let image_path = home.join("original.gif");
    let linked = home.join("linked.gif");
    fs::write(&image_path, image_fixture()).expect("fixture");
    symlink(&image_path, &linked).expect("create symlink");
    let out = Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
        .args(["reverse-image", linked.to_str().expect("path"), "--json"])
        .env("HOME", &home)
        .output()
        .expect("run command");
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).contains("unreadable"));
    fs::remove_dir_all(home).expect("clean scratch");
}
