//! `huntsman-recon plan`: the offline investigation spine, and its sessions. It was a separate
//! `investigate` binary, which the prebuilt release did not ship.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

use huntsman_recon::exit::{EX_DATAERR, EX_IOERR, EX_NOINPUT, EX_USAGE};

fn plan(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
        .arg("plan")
        .args(args)
        .output()
        .expect("run huntsman-recon plan")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn scratch(tag: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("plan-cli-{tag}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn help_is_available() {
    let out = plan(&["--help"]);
    assert!(out.status.success());
    assert!(stdout(&out).contains("plan [--session-dir DIR] SEED [SEED ...]"));
}

#[test]
fn offline_cli_executes_shared_runtime() {
    let out = plan(&["ada@example.com", "example.com"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("accepted=2"));
    assert!(text.contains("entities=2"));
    assert!(text.contains("termination=FixedPoint"));
    assert!(text.contains("truncated=false"));
}

#[test]
fn unsupported_only_input_fails_explicitly() {
    let out = plan(&["not-a-supported-single-token"]);
    assert_eq!(out.status.code(), Some(i32::from(EX_DATAERR)));
    assert!(stderr(&out).contains("no actionable seeds"));
}

#[test]
fn a_saved_session_reloads() {
    let dir = scratch("reload");
    let sessions = dir.to_str().unwrap();
    let out = plan(&["--session-dir", sessions, "ada@example.com"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let text = stdout(&out);
    let id = text
        .lines()
        .find_map(|line| line.strip_prefix("session="))
        .and_then(|rest| rest.split_whitespace().next())
        .unwrap_or_else(|| panic!("no session= line in {text}"));

    let reloaded = plan(&["--load-session", sessions, id]);
    assert!(reloaded.status.success(), "{}", stderr(&reloaded));
    let summary = stdout(&reloaded);
    assert!(summary.starts_with(&format!("session={id} ")), "{summary}");
    assert!(summary.contains("terminated=true"), "{summary}");

    let missing = plan(&["--load-session", sessions, "no-such-session"]);
    assert_eq!(missing.status.code(), Some(i32::from(EX_NOINPUT)));
    let _ = fs::remove_dir_all(&dir);
}

/// A session file that is read but does not hold a session is bad data (65), as a malformed
/// ledger is for `verify`; only a file that cannot be read is unreadable input (66). The message
/// names the file and what is wrong with it. A session an older build wrote, which lacks a field
/// this build needs, is the second case.
#[test]
fn a_malformed_session_file_is_bad_data_not_unreadable_input() {
    let dir = scratch("malformed");
    let sessions = dir.join("sessions");
    fs::create_dir_all(&sessions).unwrap();
    for body in ["{\"id\": \"broken\"", "{\"id\": \"broken\"}"] {
        fs::write(sessions.join("broken.json"), body).unwrap();
        let out = plan(&["--load-session", dir.to_str().unwrap(), "broken"]);
        let text = stderr(&out);
        assert_eq!(
            out.status.code(),
            Some(i32::from(EX_DATAERR)),
            "{body}: {text}"
        );
        assert!(out.stdout.is_empty(), "{body}: {}", stdout(&out));
        assert!(
            text.contains("broken.json") && text.contains("not a session"),
            "{body}: {text}"
        );
    }
    let _ = fs::remove_dir_all(&dir);
}

/// A request to save that cannot be honoured stops the run before it starts. The old binary
/// dropped a `--session-dir` with no value, and took a mistyped option for a seed; either way it
/// exited 0 without saving.
#[test]
fn a_request_to_save_is_refused_rather_than_dropped() {
    for args in [
        &["ada@example.com", "--session-dir"][..],
        &[
            "--session-dir",
            "a",
            "--session-dir",
            "b",
            "ada@example.com",
        ][..],
        &["--sesion-dir", "a", "ada@example.com"][..],
        &["ada@example.com", "--load-session", "a", "b"][..],
        &["--load-session", "only-a-dir"][..],
    ] {
        let out = plan(args);
        assert_eq!(out.status.code(), Some(i32::from(EX_USAGE)), "{args:?}");
        assert!(out.stdout.is_empty(), "{args:?}");
        assert!(
            stderr(&out).contains("usage: huntsman-recon plan"),
            "{args:?}"
        );
    }
}

#[test]
fn a_session_that_cannot_be_written_is_an_output_error() {
    let dir = scratch("unwritable");
    let file = dir.join("a-file");
    fs::write(&file, "not a directory").unwrap();
    let out = plan(&["--session-dir", file.to_str().unwrap(), "ada@example.com"]);
    assert_eq!(
        out.status.code(),
        Some(i32::from(EX_IOERR)),
        "{}",
        stderr(&out)
    );
    let _ = fs::remove_dir_all(&dir);
}
