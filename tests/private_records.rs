//! What a lookup or an investigation finds is written mode 600. A ledger names the addresses,
//! phones and handles a lookup found and a session holds an investigation's seeds and
//! findings, so on a shared host (the Railway container, any multi-user Linux) another
//! account must not read them. Replacing an older, world-readable file leaves it private.
#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

fn scratch(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("private-records-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path)
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()))
        .permissions()
        .mode()
        & 0o777
}

fn recon(dir: &Path, args: &[&str]) {
    let out = Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn a_ledger_is_private_even_over_an_older_readable_one() {
    let dir = scratch("ledger");
    let ledger = dir.join("var/ledger.json");
    fs::create_dir_all(ledger.parent().unwrap()).unwrap();
    fs::write(&ledger, "[]").unwrap();
    fs::set_permissions(&ledger, fs::Permissions::from_mode(0o644)).unwrap();
    recon(&dir, &["check"]);
    assert_eq!(mode(&ledger), 0o600, "{}", ledger.display());
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_saved_session_and_its_current_marker_are_private() {
    let dir = scratch("session");
    recon(
        &dir,
        &["plan", "--session-dir", "store", "alice@example.com"],
    );
    let sessions: Vec<PathBuf> = fs::read_dir(dir.join("store/sessions"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(sessions.len(), 1, "{sessions:?}");
    assert_eq!(mode(&sessions[0]), 0o600, "{}", sessions[0].display());
    assert_eq!(mode(&dir.join("store/current.txt")), 0o600);
    fs::remove_dir_all(dir).unwrap();
}
