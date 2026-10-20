//! Credential-management CLI: only piped stdin supplies a new value, and
//! diagnostics never echo credential material or modify another slot.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const SLOT: &str = "HUNTSMAN_TEST_API_KEY";
const SECRET: &str = "TEST_ONLY_VALUE_SAMPLE_4e2b9c";

fn home(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "hse-key-manage-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn command(home: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_huntsman-recon"));
    cmd.env("HOME", home);
    cmd
}

fn set(home: &Path, slot: &str, bytes: &[u8]) -> Output {
    let mut child = command(home)
        .args(["keys", "set", slot, "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(bytes).unwrap();
    child.wait_with_output().unwrap()
}

#[cfg(unix)]
#[test]
fn piped_key_round_trips_in_private_file_without_leaking_to_output() {
    use std::os::unix::fs::PermissionsExt;
    let dir = home("roundtrip");
    let path = dir.join(".huntsman.env");
    let result = set(&dir, SLOT, format!("{SECRET}\n").as_bytes());
    assert!(result.status.success(), "stderr={:?}", result.stderr);
    let output = format!(
        "{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(!output.contains(SECRET));
    assert!(output.contains("stored"));
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let saved = huntsman_recon::keys::Keys::load(&path).unwrap();
    assert_eq!(saved.get(SLOT).unwrap().expose(), SECRET);

    let removed = command(&dir).args(["keys", "remove", SLOT]).output().unwrap();
    assert!(removed.status.success(), "{:?}", removed.stderr);
    assert!(!std::fs::read_to_string(&path).unwrap().contains(SECRET));
    assert!(huntsman_recon::keys::Keys::load(&path).unwrap().get(SLOT).is_none());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn malformed_input_refuses_without_mutating_an_existing_key() {
    let dir = home("badinput");
    let original = set(&dir, SLOT, SECRET.as_bytes());
    assert!(original.status.success(), "{:?}", original.stderr);
    let before = std::fs::read(dir.join(".huntsman.env")).unwrap();

    for invalid in [
        Vec::new(),
        b"changeme\n".to_vec(),
        b"line1\nline2".to_vec(),
        vec![b'x'; huntsman_recon::keys::MAX_KEY_BYTES + 1],
        vec![0xff],
    ] {
        let output = set(&dir, SLOT, &invalid);
        assert!(!output.status.success(), "accepted invalid credential");
        assert!(!String::from_utf8_lossy(&output.stderr).contains(SECRET));
        assert_eq!(std::fs::read(dir.join(".huntsman.env")).unwrap(), before);
    }

    let invalid_name = set(&dir, "not_a_slot", b"another-test-value");
    assert_eq!(invalid_name.status.code(), Some(64));
    assert_eq!(std::fs::read(dir.join(".huntsman.env")).unwrap(), before);

    let bad_usage = command(&dir)
        .args(["keys", "set", SLOT, SECRET])
        .output()
        .unwrap();
    assert_eq!(bad_usage.status.code(), Some(64));
    assert!(!String::from_utf8_lossy(&bad_usage.stderr).contains(SECRET));

    std::fs::remove_dir_all(dir).unwrap();
}

#[cfg(unix)]
#[test]
fn symlinked_default_file_is_refused_without_following() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let dir = home("symlink");
    let target = dir.join("target.env");
    std::fs::write(&target, "HUNTSMAN_UNRELATED_KEY='another-value'\n").unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
    symlink(&target, dir.join(".huntsman.env")).unwrap();

    let output = set(&dir, SLOT, SECRET.as_bytes());
    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stderr).contains(SECRET));
    assert_eq!(
        std::fs::read_to_string(&target).unwrap(),
        "HUNTSMAN_UNRELATED_KEY='another-value'\n"
    );
    std::fs::remove_dir_all(dir).unwrap();
}
