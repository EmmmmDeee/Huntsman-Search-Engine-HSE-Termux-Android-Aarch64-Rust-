//! The web UI's offline multi-hop analysis, served by the shipped binary. `GET /api/analyze` runs
//! the investigation spine on the seeds and answers with what it found: the entities, the links
//! between them, the next pivots, the correlations, the gaps and the planned sources.
//!
//! It is offline by construction: the spine is handed no transport and only plans its dispatches,
//! and `tests/architecture_boundaries.rs` keeps every module but `src/http.rs` and
//! `src/web_server.rs` from opening a socket.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};

/// `serve` on a free loopback port, with no inherited bind, token, external host or Termux setting.
fn start() -> (Child, String) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_huntsman-recon"));
    command.args(["serve", "--bind", "127.0.0.1:0"]);
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

#[test]
fn serve_runs_the_offline_multi_hop_analysis_its_page_offers() {
    let (mut child, addr) = start();
    let page = get(&addr, "/");
    let analysis = get(
        &addr,
        "/api/analyze?seeds=alex.demo%40example.org%0A%40alexdemo%0Aexample.org%0A%2B15555550123",
    );
    child.kill().unwrap();
    child.wait().unwrap();

    assert!(page.starts_with("HTTP/1.1 200"), "{page}");
    // The analysis form, whatever other attributes its tag carries.
    let form = page
        .find(r#" id="analyze""#)
        .map(|at| &page[page[..at].rfind('<').unwrap()..at]);
    assert_eq!(
        form.map(|tag| tag.split(' ').next()),
        Some(Some("<form")),
        "the page offers no analysis"
    );
    assert!(analysis.starts_with("HTTP/1.1 200"), "{analysis}");
    let body = &analysis[analysis.find("\r\n\r\n").unwrap() + 4..];
    let view: serde_json::Value = serde_json::from_str(body).unwrap();
    assert_eq!(view["accepted"].as_array().unwrap().len(), 4, "{view}");
    assert!(!view["relations"].as_array().unwrap().is_empty(), "{view}");
    assert!(!view["pivots"].as_array().unwrap().is_empty(), "{view}");
    let rules: Vec<&str> = view["correlations"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|correlation| correlation["rule_id"].as_str())
        .collect();
    assert!(rules.contains(&"AU-063"), "{rules:?}");
    assert_eq!(view["gaps"]["orphans"][0]["kind"], "phone", "{view}");
    assert!(!view["planned"].as_array().unwrap().is_empty(), "{view}");
}
