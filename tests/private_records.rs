//! What a lookup or an investigation finds is written mode 600. A ledger names the addresses,
//! phones and handles a lookup found and a session holds an investigation's seeds and
//! findings, so on a shared host (a self-hosted Linux container, any multi-user Linux) another
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

/// Run the binary under `umask 022`. The test runner's own umask is not known: under `umask
/// 077` (Android app processes, the container entrypoint) a plain write also comes out 0600, and
/// the assertions below would hold without the private writer.
fn recon(dir: &Path, args: &[&str]) {
    let out = Command::new("sh")
        .arg("-c")
        .arg("umask 022 && exec \"$0\" \"$@\"")
        .arg(env!("CARGO_BIN_EXE_huntsman-recon"))
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
    // The control: `check` also writes the navigator layer through the ordinary writer, and
    // under the pinned umask that file is readable. So the 0600 above came from the ledger's
    // writer, not from the environment.
    let navigator = dir.join("var/navigator.json");
    assert_eq!(mode(&navigator), 0o644, "{}", navigator.display());
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_saved_session_is_private() {
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
    fs::remove_dir_all(dir).unwrap();
}
