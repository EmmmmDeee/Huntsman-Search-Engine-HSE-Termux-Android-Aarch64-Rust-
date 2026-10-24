//! A reader that stops early, as `head` does, must not cost a saved file or end in a panic.
//! Rust ignores SIGPIPE, so a failed print panics with status 101. `stdio_failure` turns that
//! into an exit status, and the commands that save write their files before they print.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use huntsman_recon::exit::{EX_IOERR, EX_PIPE};

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "huntsman-closed-output-{tag}-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// `program` run in `dir` with `HOME` there, so no keys file or user state is read.
fn command(program: &str, dir: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(program);
    command
        .args(args)
        .current_dir(dir)
        .env("HOME", dir)
        .env_remove("RUST_BACKTRACE");
    command
}

/// Runs `command` with standard output on a pipe whose reader has already gone.
fn run_with_closed_stdout(mut command: Command) -> Output {
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    command
        .stdout(Stdio::from(writer))
        .stderr(Stdio::piped())
        .output()
        .unwrap()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn a_lookup_saves_its_ledger_and_exits_141_when_the_reader_has_gone() {
    let dir = scratch("lookup");
    let ledger = dir.join("phone.json");
    let out = run_with_closed_stdout(command(
        env!("CARGO_BIN_EXE_huntsman-recon"),
        &dir,
        &["phone", "+61412345678", "--save", ledger.to_str().unwrap()],
    ));
    assert_eq!(
        out.status.code(),
        Some(i32::from(EX_PIPE)),
        "{}",
        stderr(&out)
    );
    assert_eq!(
        stderr(&out),
        "",
        "a closed reader is not an error to report"
    );
    let verify = command(
        env!("CARGO_BIN_EXE_huntsman-recon"),
        &dir,
        &["verify", ledger.to_str().unwrap()],
    )
    .output()
    .unwrap();
    assert_eq!(verify.status.code(), Some(0), "{}", stderr(&verify));
    // Three outcomes, one per numbering plan (the plan that does not hold the number answers too),
    // one not-configured row for each keyed phone leg this keyless run skipped (numverify and the
    // keyed indicator source), the entity, and one evidence record for each module that found the
    // number. The second module's record is the one a first-record-only save used to drop.
    assert!(
        String::from_utf8_lossy(&verify.stdout).contains("entries=8"),
        "{}",
        String::from_utf8_lossy(&verify.stdout)
    );
    let saved = fs::read_to_string(&ledger).unwrap();
    assert!(saved.contains("src/phone_cli.rs"), "{saved}");
    let _ = fs::remove_dir_all(&dir);
}

/// The skipped-keys-file warning is written while the lookup collects, before it saves. A stderr
/// whose reader has gone must not end the lookup there.
#[cfg(unix)]
#[test]
fn a_keys_file_warning_on_a_closed_stderr_does_not_cost_the_ledger() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = scratch("warning");
    let keys = dir.join(".huntsman.env");
    fs::write(&keys, "# no keys\n").unwrap();
    // Readable by others, so the default-file gate skips it and names it on stderr.
    fs::set_permissions(&keys, fs::Permissions::from_mode(0o644)).unwrap();
    let ledger = dir.join("phone.json");
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    let out = command(
        env!("CARGO_BIN_EXE_huntsman-recon"),
        &dir,
        &["phone", "+61412345678", "--save", ledger.to_str().unwrap()],
    )
    .stdout(Stdio::piped())
    .stderr(Stdio::from(writer))
    .output()
    .unwrap();
    assert!(
        ledger.exists(),
        "the ledger was not saved: status {:?}",
        out.status
    );
    assert!(
        !matches!(out.status.code(), Some(code) if code == i32::from(EX_PIPE) || code == i32::from(EX_IOERR)),
        "the warning's failed write ended the lookup: {:?}",
        out.status
    );
    let _ = fs::remove_dir_all(&dir);
}

/// `scan` names its route on stderr before it hands over to the lookup that saves.
#[test]
fn a_scan_route_line_on_a_closed_stderr_does_not_cost_the_ledger() {
    let dir = scratch("scan-route");
    let ledger = dir.join("phone.json");
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    let out = command(
        env!("CARGO_BIN_EXE_huntsman-recon"),
        &dir,
        &["scan", "+61412345678", "--save", ledger.to_str().unwrap()],
    )
    .stdout(Stdio::piped())
    .stderr(Stdio::from(writer))
    .output()
    .unwrap();
    assert!(
        ledger.exists(),
        "the ledger was not saved: status {:?}",
        out.status
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn plan_saves_its_session_and_exits_141_when_the_reader_has_gone() {
    let dir = scratch("plan");
    let sessions = dir.join("sessions");
    let out = run_with_closed_stdout(command(
        env!("CARGO_BIN_EXE_huntsman-recon"),
        &dir,
        &[
            "plan",
            "--session-dir",
            sessions.to_str().unwrap(),
            "ada@example.com",
        ],
    ));
    assert_eq!(
        out.status.code(),
        Some(i32::from(EX_PIPE)),
        "{}",
        stderr(&out)
    );
    assert_eq!(stderr(&out), "");
    let saved: Vec<_> = fs::read_dir(sessions.join("sessions"))
        .expect("the session directory was written")
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(saved.len(), 1, "one saved session: {saved:?}");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_full_output_device_is_an_output_error_named_in_one_line() {
    let full = Path::new("/dev/full");
    if !full.exists() {
        eprintln!("skipped: no /dev/full on this host");
        return;
    }
    let dir = scratch("full");
    let out = command(env!("CARGO_BIN_EXE_huntsman-recon"), &dir, &["--version"])
        .stdout(Stdio::from(fs::File::create(full).unwrap()))
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(i32::from(EX_IOERR)),
        "{}",
        stderr(&out)
    );
    assert_eq!(
        stderr(&out),
        "output write failed: No space left on device (os error 28)\n"
    );
    let _ = fs::remove_dir_all(&dir);
}
