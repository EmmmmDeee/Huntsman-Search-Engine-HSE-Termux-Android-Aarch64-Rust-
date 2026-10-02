//! Real sockets, loopback only: the transport against a throwaway local server.
//! No external network is touched.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use huntsman_recon::egress::EgressPolicy;
use huntsman_recon::fetch::{FetchOptions, fetch};
use huntsman_recon::http::{Request, Transport, TransportConfig, UreqTransport};
use huntsman_recon::source_outcome::SourceOutcomeKind;

/// Serve `responses` (raw HTTP) to successive connections, then stop.
fn serve(responses: Vec<Vec<u8>>) -> (u16, thread::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let handle = thread::spawn(move || {
        let mut requests = Vec::new();
        for raw in responses {
            let (mut sock, _) = listener.accept().expect("accept");
            requests.push(read_request(&mut sock));
            let _ = sock.write_all(&raw);
        }
        requests
    });
    (port, handle)
}

fn read_request(sock: &mut TcpStream) -> String {
    sock.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    let mut buf = Vec::new();
    let mut chunk = [0u8; 512];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        match sock.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

fn ok(body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\nX-Test: yes\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn lab_transport(max_body: usize) -> UreqTransport {
    UreqTransport::new(&TransportConfig {
        timeout: Duration::from_secs(5),
        max_body,
        egress: EgressPolicy::Unrestricted,
        ..TransportConfig::default()
    })
}

#[test]
fn loopback_is_blocked_by_default_and_nothing_is_sent() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.set_nonblocking(true).expect("nonblocking");
    let port = listener.local_addr().expect("addr").port();
    let t = UreqTransport::default();
    for host in ["127.0.0.1", "localhost", "[::1]"] {
        let failure = t
            .send(&Request::get(format!("http://{host}:{port}/")))
            .expect_err("loopback must be refused");
        assert!(failure.blocked, "{host}: {failure:?}");
    }
    assert!(
        listener.accept().is_err(),
        "a connection reached the listener"
    );
}

#[test]
fn a_local_server_is_reachable_when_the_operator_allows_it() {
    let (port, server) = serve(vec![ok("hello")]);
    let t = lab_transport(1024);
    let r = t
        .send(&Request::get(format!("http://127.0.0.1:{port}/p?q=1")).header("X-Probe", "1"))
        .expect("send");
    assert_eq!(
        (r.status, r.text().as_str(), r.truncated),
        (200, "hello", false)
    );
    assert_eq!(r.header_value("x-test"), Some("yes"));
    let seen = server.join().expect("server");
    assert!(seen[0].starts_with("GET /p?q=1 HTTP/1.1"));
    assert!(seen[0].to_ascii_lowercase().contains("x-probe: 1"));
    assert!(
        seen[0]
            .to_ascii_lowercase()
            .contains("user-agent: huntsman-recon/")
    );
}

#[test]
fn oversized_bodies_are_cut_and_flagged() {
    let (port, server) = serve(vec![ok(&"a".repeat(5000))]);
    let r = lab_transport(100)
        .send(&Request::get(format!("http://127.0.0.1:{port}/")))
        .expect("send");
    assert_eq!((r.body.len(), r.truncated), (100, true));
    drop(server.join());
}

#[test]
fn error_statuses_are_responses_not_transport_errors() {
    let raw = b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 7\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec();
    let (port, server) = serve(vec![raw]);
    let fetched = fetch(
        &lab_transport(1024),
        Request::get(format!("http://127.0.0.1:{port}/")),
        None,
        &FetchOptions::default(),
        "local",
        1,
    )
    .expect("fetch");
    assert_eq!(fetched.outcome.kind, SourceOutcomeKind::RateLimited);
    assert_eq!(fetched.outcome.retry_after_secs, Some(7));
    drop(server.join());
}

#[test]
fn redirects_are_followed_by_the_fetch_layer_not_the_transport() {
    let redirect = |to: &str| {
        format!(
            "HTTP/1.1 302 Found\r\nLocation: {to}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .into_bytes()
    };
    let (port, server) = serve(vec![redirect("/next"), ok("landed")]);
    let fetched = fetch(
        &lab_transport(1024),
        Request::get(format!("http://127.0.0.1:{port}/start")),
        None,
        &FetchOptions::default(),
        "local",
        1,
    )
    .expect("fetch");
    assert_eq!(fetched.redirects, 1);
    assert_eq!(fetched.response.expect("response").text(), "landed");
    let seen = server.join().expect("server");
    assert!(seen[1].starts_with("GET /next "));
}

#[test]
fn a_closed_port_is_a_connect_failure_with_a_cause() {
    let port = {
        let l = TcpListener::bind("127.0.0.1:0").expect("bind");
        l.local_addr().expect("addr").port()
    };
    let fetched = fetch(
        &lab_transport(1024),
        Request::get(format!("http://127.0.0.1:{port}/")),
        None,
        &FetchOptions::default(),
        "local",
        1,
    )
    .expect("fetch");
    assert_eq!(fetched.outcome.kind, SourceOutcomeKind::ConnectFailure);
    assert!(fetched.response.is_none());
}

#[test]
fn a_silent_server_times_out() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let hold = thread::spawn(move || {
        let (sock, _) = listener.accept().expect("accept");
        thread::sleep(Duration::from_millis(1500));
        drop(sock);
    });
    let t = UreqTransport::new(&TransportConfig {
        timeout: Duration::from_millis(400),
        egress: EgressPolicy::Unrestricted,
        ..TransportConfig::default()
    });
    let failure = t
        .send(&Request::get(format!("http://127.0.0.1:{port}/")))
        .expect_err("timeout");
    assert_eq!(failure.kind, SourceOutcomeKind::TtfbTimeout, "{failure:?}");
    hold.join().expect("holder");
}
