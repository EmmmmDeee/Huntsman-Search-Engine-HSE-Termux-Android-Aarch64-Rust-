//! A server that starts over scans a previous process left active marks them `ABORTED` before it
//! answers anything, so after Android kills `serve` mid-scan and Termux starts it again the page
//! never shows a `RUNNING` scan nobody can stop or delete. The store's own tests cover the sweep
//! itself; this one locks that `serve` runs it, over a row with no owner recorded (one written
//! before the worker recorded itself) and one whose owner's pid is gone.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;

use huntsman_recon::scan_service::{ScanService, ServiceError};
use huntsman_recon::scan_store::{
    FORMAT_VERSION, RiskCounts, ScanOptions, ScanRecord, ScanResults, ScanStatus, ScanStore, new_id,
};
use serde_json::Value;

/// A fresh home whose `~/.huntsman/scans` holds the rows in `left`, each `RUNNING` with the
/// owner given; answers the home and the ids, in `left`'s order.
fn home_with(tag: &str, left: &[Option<u32>]) -> (PathBuf, Vec<String>) {
    let home = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("serve-recovery-{tag}"));
    let _ = fs::remove_dir_all(&home);
    fs::create_dir_all(&home).unwrap();
    let ids = create_rows(&home, left);
    (home, ids)
}

/// Add abandoned rows to a disposable store, in creation order.
fn create_rows(home: &Path, left: &[Option<u32>]) -> Vec<String> {
    let store = ScanStore::open(&home.join(".huntsman").join("scans")).unwrap();
    left.iter()
        .enumerate()
        .map(|(sequence, owner)| {
            let id = new_id("example.org", 1, u64::try_from(sequence).unwrap());
            store
                .create(&ScanRecord {
                    format_version: FORMAT_VERSION,
                    id: id.clone(),
                    name: format!("left running {sequence}"),
                    target: "example.org".into(),
                    target_type: "INTERNET_NAME".into(),
                    kind: "domain".into(),
                    options: ScanOptions {
                        usecase: "all".into(),
                        ..ScanOptions::default()
                    },
                    status: ScanStatus::Running,
                    created: 1,
                    started: Some(1),
                    ended: None,
                    elements: 0,
                    unique: 0,
                    correlations: RiskCounts::default(),
                    errors: 0,
                    modules_run: Vec::new(),
                    owner: *owner,
                    owner_started: None,
                })
                .unwrap();
            id
        })
        .collect()
}

/// `serve` on a free loopback port with `home` as its `HOME` and the inherited environment
/// cleared, as the Termux service starts it after a restart.
fn start(home: &Path) -> (Child, String) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_huntsman-recon"));
    command
        .args(["serve", "--bind", "127.0.0.1:0"])
        .env("HOME", home)
        .env_remove("HUNTSMAN_HOME");
    for name in [
        "HSE_BIND",
        "HSE_AUTH_TOKEN",
        "PORT",
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

/// One request as the page sends it, with the lookup header every scan call carries; answers the
/// status line and the JSON body.
fn call(addr: &str, method: &str, path: &str) -> (String, Value) {
    let mut stream = TcpStream::connect(addr).unwrap();
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nSec-Fetch-Site: same-origin\r\nX-Huntsman-Lookup: 1\r\nContent-Length: 0\r\n\r\n"
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    let (head, body) = response
        .split_once("\r\n\r\n")
        .unwrap_or_else(|| panic!("no body: {response}"));
    let status = head.lines().next().unwrap_or_default().to_owned();
    let body = serde_json::from_str(body).unwrap_or_else(|_| panic!("not JSON: {response}"));
    (status, body)
}

#[test]
fn a_restarted_server_marks_what_it_left_running_aborted_before_it_answers() {
    // No owner recorded, and an owner no process has.
    let (home, ids) = home_with("aborts", &[None, Some(u32::MAX)]);
    let (mut child, addr) = start(&home);
    let (status, list) = call(&addr, "GET", "/api/scans");
    assert_eq!(status, "HTTP/1.1 200 OK", "{list}");
    let rows = list.as_array().unwrap();
    assert_eq!(rows.len(), ids.len(), "{list}");
    for id in &ids {
        let row = rows
            .iter()
            .find(|row| row["id"] == id.as_str())
            .unwrap_or_else(|| panic!("{id} not listed: {list}"));
        assert_eq!(row["status"], "ABORTED", "{row}");
        assert!(row["ended"].is_u64(), "{row}");
        let (status, shown) = call(&addr, "GET", &format!("/api/scans/{id}"));
        assert_eq!(status, "HTTP/1.1 200 OK", "{shown}");
        assert_eq!(shown["status"], "ABORTED", "{shown}");
        let (_, log) = call(&addr, "GET", &format!("/api/scans/{id}/log"));
        let newest = log.as_array().and_then(|entries| entries.last()).cloned();
        let message = newest
            .as_ref()
            .and_then(|entry| entry["message"].as_str())
            .unwrap_or_default();
        assert!(
            message.contains("the server stopped while this scan was RUNNING; marked ABORTED")
                && message.contains("it had saved nothing yet"),
            "{log}"
        );
        assert_eq!(
            newest.map(|entry| entry["level"].clone()),
            Some("WARNING".into())
        );
        // Settled, the row takes the actions a finished scan takes.
        assert_eq!(
            call(&addr, "POST", &format!("/api/scans/{id}/stop")).0,
            "HTTP/1.1 409 Conflict"
        );
        assert_eq!(
            call(&addr, "POST", &format!("/api/scans/{id}/delete")).0,
            "HTTP/1.1 200 OK"
        );
    }
    let (_, list) = call(&addr, "GET", "/api/scans");
    assert_eq!(list, Value::Array(Vec::new()));
    child.kill().unwrap();
    child.wait().unwrap();
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn one_scan_with_an_unwritable_log_does_not_disable_saved_scan_routes() {
    let (home, mut ids) = home_with("isolated-log", &[None, None]);
    // Both rows have the same creation time. Recovery visits them in ID order.
    ids.sort();
    let scans = home.join(".huntsman").join("scans");
    let store = ScanStore::open(&scans).unwrap();
    let checkpoint = &ids[1];
    store
        .save_results(&ScanResults {
            format_version: FORMAT_VERSION,
            scan_id: checkpoint.clone(),
            text: "saved recovery fixture".into(),
            entities: Vec::new(),
            outcomes: Vec::new(),
            elements: Vec::new(),
            correlations: Vec::new(),
            lineage: Vec::new(),
            termination: None,
        })
        .unwrap();
    let results_path = scans.join(checkpoint).join("results.json");
    let original_results = fs::read(&results_path).unwrap();
    fs::create_dir(scans.join(&ids[0]).join("log-overflow.jsonl")).unwrap();

    let (mut child, addr) = start(&home);
    let (status, rows) = call(&addr, "GET", "/api/scans");
    child.kill().unwrap();
    child.wait().unwrap();

    assert_eq!(status, "HTTP/1.1 200 OK", "{rows}");
    for id in &ids {
        assert_eq!(row_status(&rows, id), "ABORTED", "{rows}");
    }
    assert_eq!(fs::read(results_path).unwrap(), original_results);
    let entries = store.log(checkpoint).unwrap();
    assert!(
        entries.last().is_some_and(|entry| entry
            .message
            .contains("what it had found by its last checkpoint is kept")),
        "{entries:?}"
    );
    let _ = fs::remove_dir_all(home);
}

fn row_status<'a>(rows: &'a Value, id: &str) -> &'a str {
    rows.as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == id)
        .and_then(|row| row["status"].as_str())
        .unwrap_or_else(|| panic!("scan {id} has no status in {rows}"))
}

#[test]
fn a_reconciliation_failure_is_visible_without_hiding_the_other_rows() {
    let (home, _) = home_with("isolated-list", &[]);
    let (mut child, addr) = start(&home);
    // Add two abandoned rows after startup, as another Huntsman process could.
    let mut ids = create_rows(&home, &[Some(u32::MAX), Some(u32::MAX)]);
    ids.sort();
    let scans = home.join(".huntsman").join("scans");
    fs::create_dir(scans.join(&ids[0]).join("log-overflow.jsonl")).unwrap();

    let (status, rows) = call(&addr, "GET", "/api/scans");
    child.kill().unwrap();
    child.wait().unwrap();

    assert_eq!(status, "HTTP/1.1 200 OK", "{rows}");
    assert_eq!(row_status(&rows, &ids[0]), "ERROR-FAILED", "{rows}");
    assert_eq!(row_status(&rows, &ids[1]), "ABORTED", "{rows}");
    let _ = fs::remove_dir_all(home);
}

#[test]
fn retention_input_still_fails_when_reconciliation_cannot_be_persisted() {
    let (home, ids) = home_with("strict-records", &[Some(u32::MAX)]);
    let scans = home.join(".huntsman").join("scans");
    fs::create_dir(scans.join(&ids[0]).join("log-overflow.jsonl")).unwrap();
    let store = ScanStore::open(&scans).unwrap();
    let service = ScanService::new(store, Arc::new(|_, _, _| panic!("unexpected lookup")));

    let error = service.records().unwrap_err();
    assert!(
        matches!(&error, ServiceError::Store(message) if message.contains("not a regular overflow log")),
        "{error:?}"
    );
    let _ = fs::remove_dir_all(home);
}
