//! The `reverse-image` command against the real binary. Every case is offline: a live search is
//! only exercised where it must stop before any request (no provider named, no key configured).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use huntsman_recon::environment::{GOOGLE_VISION_KEY_ENV, LENSO_KEY_ENV, SAUCENAO_KEY_ENV};
use huntsman_recon::exit::{EX_NOINPUT, EX_USAGE};

/// A minimal 1x1 GIF with a global palette and a single image frame.
const GIF: &[u8] = b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;";

fn scratch(tag: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("reverse-image-cli-{tag}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("scratch directory");
    dir
}

/// Runs the binary in `home` with no provider key anywhere: not in the environment, and no keys
/// file in the home directory.
fn run(home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
        .args(args)
        .current_dir(home)
        .env("HOME", home)
        .env("HUNTSMAN_HOME", home.join(".huntsman"))
        .env_remove(GOOGLE_VISION_KEY_ENV)
        .env_remove(LENSO_KEY_ENV)
        .env_remove(SAUCENAO_KEY_ENV)
        .output()
        .expect("run huntsman-recon")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn offline_reports_the_file_and_says_no_search_ran() {
    let home = scratch("offline");
    fs::write(home.join("photo.gif"), GIF).expect("image fixture");
    let out = run(&home, &["reverse-image", "photo.gif", "--json"]);
    assert!(out.status.success(), "stderr: {}", text(&out.stderr));
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).expect("report JSON");
    assert_eq!(report["file_bytes"].as_u64(), Some(GIF.len() as u64));
    assert_eq!(report["file_sha256"].as_str().map(str::len), Some(64));
    assert_eq!(report["format"], "GIF");
    assert_eq!(report["search"], "not_run");
    assert_eq!(report["provider"], serde_json::Value::Null);
    // No search ran, so there is no list of matches to read as "no matches".
    assert_eq!(report["matches"], serde_json::Value::Null);

    let plain = run(&home, &["reverse-image", "photo.gif"]);
    assert!(plain.status.success());
    assert!(
        text(&plain.stdout).contains("no search ran: nothing was sent"),
        "{}",
        text(&plain.stdout)
    );
    assert!(!text(&plain.stdout).contains("no matches"));

    let help = run(&home, &["reverse-image", "--help"]);
    assert!(help.status.success());
    assert!(text(&help.stdout).contains("--live --provider"));
    fs::remove_dir_all(home).expect("clean scratch");
}

#[test]
fn live_needs_one_named_provider_and_sends_nothing_without_it() {
    let home = scratch("provider");
    fs::write(home.join("photo.gif"), GIF).expect("image fixture");
    for args in [
        &["reverse-image", "photo.gif", "--live"][..],
        &["reverse-image", "photo.gif", "--live", "--json"][..],
        &["reverse-image", "photo.gif", "--provider", "lenso"][..],
        &["reverse-image", "photo.gif", "--live", "--provider", "all"][..],
    ] {
        let out = run(&home, args);
        assert_eq!(out.status.code(), Some(i32::from(EX_USAGE)), "{args:?}");
        assert_eq!(text(&out.stdout), "", "{args:?}");
        assert!(text(&out.stderr).contains("usage: huntsman-recon reverse-image"));
    }
    let bare = run(&home, &["reverse-image", "photo.gif", "--live"]);
    assert!(
        text(&bare.stderr).contains("--live needs --provider"),
        "{}",
        text(&bare.stderr)
    );
    fs::remove_dir_all(home).expect("clean scratch");
}

#[test]
fn a_named_provider_without_a_key_is_asked_nothing() {
    let home = scratch("no-key");
    fs::write(home.join("photo.gif"), GIF).expect("image fixture");
    let out = run(
        &home,
        &[
            "reverse-image",
            "photo.gif",
            "--live",
            "--provider",
            "saucenao",
            "--json",
        ],
    );
    assert_eq!(out.status.code(), Some(i32::from(EX_NOINPUT)));
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).expect("report JSON");
    assert_eq!(report["provider"], "saucenao");
    assert_eq!(report["search"], "not_run");
    assert_eq!(report["outcome"]["kind"], "not_configured");
    assert_eq!(report["matches"], serde_json::Value::Null);
    assert!(text(&out.stderr).contains(SAUCENAO_KEY_ENV));
    fs::remove_dir_all(home).expect("clean scratch");
}

#[cfg(unix)]
#[test]
fn a_linked_image_is_refused_without_following_it() {
    use std::os::unix::fs::symlink;
    let home = scratch("symlink");
    fs::write(home.join("original.gif"), GIF).expect("fixture");
    symlink(home.join("original.gif"), home.join("linked.gif")).expect("create symlink");
    let out = run(&home, &["reverse-image", "linked.gif", "--json"]);
    assert_eq!(out.status.code(), Some(i32::from(EX_NOINPUT)));
    assert_eq!(out.stdout.len(), 0);
    assert!(text(&out.stderr).contains("unreadable"));
    fs::remove_dir_all(home).expect("clean scratch");
}
