//! `serve` keeps answering after the process runs short of file descriptors. Termux gives an
//! app a modest descriptor limit, and every open connection holds a few (the socket, the copy
//! that lets the server close an idle one, the copy that answers when a thread cannot start),
//! so a burst of connections makes `accept` fail with EMFILE. That failure lasts only until
//! those connections finish; it must not end the server.
#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// `serve` on a free loopback port under `ulimit -n limit`; returns the child and its address.
fn serve_with_descriptor_limit(limit: u32) -> (Child, String) {
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "ulimit -n {limit} && exec \"$0\" serve --bind 127.0.0.1:0"
        ))
        .arg(env!("CARGO_BIN_EXE_huntsman-recon"))
        .env_remove("HSE_BIND")
        .env_remove("HSE_AUTH_TOKEN")
        .env_remove("PORT")
        .env_remove("RAILWAY_ENVIRONMENT")
        .env_remove("TERMUX_VERSION")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
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

fn health(addr: &str) -> Option<String> {
    let mut stream = TcpStream::connect(addr).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    write!(stream, "GET /api/health HTTP/1.1\r\nHost: {addr}\r\n\r\n").ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    Some(response)
}

#[test]
fn running_out_of_descriptors_pauses_serve_instead_of_ending_it() {
    // Standard streams, the listener and a few the runtime opens leave room for about two
    // connections, so the burst below must make `accept` fail with EMFILE.
    let (mut child, addr) = serve_with_descriptor_limit(12);
    assert!(health(&addr).is_some_and(|r| r.starts_with("HTTP/1.1 200")));

    let burst: Vec<TcpStream> = (0..16)
        .filter_map(|_| TcpStream::connect(&addr).ok())
        .collect();
    assert!(!burst.is_empty());
    // Long enough for the accept loop to reach the EMFILE and, before the fix, exit on it.
    std::thread::sleep(Duration::from_millis(500));
    drop(burst);

    let exited = child.try_wait().unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut answered = None;
    while exited.is_none() && Instant::now() < deadline {
        if let Some(response) = health(&addr) {
            if response.starts_with("HTTP/1.1 200") {
                answered = Some(response);
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let still_running = child.try_wait().unwrap().is_none();
    let _ = child.kill();
    let _ = child.wait();
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert_eq!(
        exited, None,
        "serve exited after running short of descriptors"
    );
    assert!(
        still_running,
        "serve exited after running short of descriptors"
    );
    assert!(
        answered.is_some(),
        "serve stopped answering after the burst"
    );
    // The operator is told why requests waited.
    assert!(
        stderr.contains("serve accept: ")
            && stderr.contains("waiting for open connections to finish"),
        "{stderr}"
    );
}
