#![cfg(unix)]

use std::fs;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn verify_refuses_fifo_without_waiting_for_a_writer() {
    let dir = std::env::temp_dir().join(format!("huntsman-fifo-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let fifo = dir.join("ledger.json");
    assert!(Command::new("mkfifo").arg(&fifo).status().unwrap().success());
    let mut child = Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
        .arg("verify")
        .arg(&fifo)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    let timed_out = loop {
        if child.try_wait().unwrap().is_some() {
            break false;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            break true;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let output = child.wait_with_output().unwrap();
    fs::remove_dir_all(&dir).unwrap();
    assert!(!timed_out, "verify blocked while opening a FIFO");
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("not a regular file"),
        "unexpected stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
