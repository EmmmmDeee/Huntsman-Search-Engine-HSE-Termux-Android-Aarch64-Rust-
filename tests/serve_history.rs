//! `serve --history DIR`: the web UI's offline analysis bridges its seeds to the saved scans in DIR,
//! as `correlate --history` does for one artifact, and reports the bridges as `cross_scan`.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

use huntsman_recon::entity::{Entity, EntityKind};
use huntsman_recon::scan_artifact::{self, ScanArtifact};

const SEED: &str = "alex.demo@example.org";

/// A fresh history directory holding one saved scan per `(scan_id, email)` pair.
fn history(tag: &str, scans: &[(&str, &str)]) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("serve-history-{tag}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    for (scan_id, email) in scans {
        let artifact = ScanArtifact::new(
            *scan_id,
            vec![Entity::new(EntityKind::Email, *email, 0.9, *scan_id)],
            Vec::new(),
        );
        scan_artifact::write(&dir.join(format!("{scan_id}.json")), &artifact).unwrap();
    }
    dir
}

/// `serve` on a free loopback port with the inherited environment cleared, as `serve_analyze`.
fn start(extra: &[&str]) -> (Child, String) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_huntsman-recon"));
    command.args(["serve", "--bind", "127.0.0.1:0"]).args(extra);
    for name in [
        "HSE_BIND",
        "HSE_AUTH_TOKEN",
        "PORT",
        "RAILWAY_ENVIRONMENT",
        "RAILWAY_ENVIRONMENT_ID",
        "RAILWAY_PROJECT_ID",
        "RAILWAY_SERVICE_ID",
        "TERMUX_VERSION",
        "PREFIX",
    ] {
        command.env_remove(name);
    }
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut first = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut first)
        .unwrap();
    let addr = first
        .trim()
        .strip_prefix("serving=http://")
        .and_then(|rest| rest.strip_suffix('/'))
        .unwrap_or_else(|| panic!("no serving= line: {first:?}"))
        .to_owned();
    (child, addr)
}

fn get(addr: &str, path: &str) -> String {
    let mut stream = TcpStream::connect(addr).unwrap();
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: {addr}\r\nSec-Fetch-Site: same-origin\r\n\r\n"
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

/// The analysis of the seed, as the page requests it.
fn analysis_of(addr: &str) -> serde_json::Value {
    let response = get(addr, "/api/analyze?seeds=alex.demo%40example.org");
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    let body = &response[response.find("\r\n\r\n").unwrap() + 4..];
    serde_json::from_str(body).unwrap()
}

#[test]
fn serve_history_bridges_the_seed_to_the_saved_scan_that_saw_it() {
    let dir = history("bridges", &[("scan-old", SEED)]);
    let (mut child, addr) = start(&["--history", dir.to_str().unwrap()]);
    let view = analysis_of(&addr);
    child.kill().unwrap();
    child.wait().unwrap();

    let matches = &view["cross_scan"]["Historical"]["matches"];
    assert_eq!(matches.as_array().map(Vec::len), Some(1), "{view}");
    assert_eq!(
        matches[0]["overlapping_scans"],
        serde_json::json!(["scan-old"]),
        "{view}"
    );
}

#[test]
fn serve_history_without_an_overlap_reports_none_not_null() {
    let dir = history("no-overlap", &[("scan-other", "bob@example.org")]);
    let (mut child, addr) = start(&["--history", dir.to_str().unwrap()]);
    let view = analysis_of(&addr);
    child.kill().unwrap();
    child.wait().unwrap();

    assert_eq!(view["cross_scan"], serde_json::json!("None"), "{view}");
}

#[test]
fn serve_without_history_reports_a_null_cross_scan() {
    let (mut child, addr) = start(&[]);
    let view = analysis_of(&addr);
    child.kill().unwrap();
    child.wait().unwrap();

    assert_eq!(
        view.get("cross_scan"),
        Some(&serde_json::Value::Null),
        "{view}"
    );
}

#[test]
fn serve_refuses_a_history_directory_it_cannot_read() {
    let missing = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("serve-history-missing-dir");
    let _ = fs::remove_dir_all(&missing);
    let out = Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
        .args(["serve", "--bind", "127.0.0.1:0", "--history"])
        .arg(&missing)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert_eq!(out.status.code(), Some(66), "{stderr}");
    assert!(stderr.contains("serve --history"), "{stderr}");
}

#[test]
fn serve_refuses_a_malformed_history_artifact_and_names_it() {
    let dir = history("malformed", &[]);
    fs::write(dir.join("broken.json"), b"{ not a scan artifact").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
        .args(["serve", "--bind", "127.0.0.1:0", "--history"])
        .arg(&dir)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert_eq!(out.status.code(), Some(65), "{stderr}");
    assert!(stderr.contains("broken.json"), "{stderr}");
}
