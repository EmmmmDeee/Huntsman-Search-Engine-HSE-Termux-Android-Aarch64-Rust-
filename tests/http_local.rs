//! Real sockets, loopback only: the transport against a throwaway local server.
//! No external network is touched.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use huntsman_recon::deadline::{Deadline, SystemClock};
use huntsman_recon::egress::EgressPolicy;
use huntsman_recon::fetch::{FetchOptions, fetch, fetch_within};
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
fn public_only_refuses_private_target_with_proxy_environment() {
    const CHILD: &str = "HSE_PROXY_GUARD_TEST_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let transport = UreqTransport::new(&TransportConfig {
            timeout: Duration::from_secs(1),
            ..TransportConfig::default()
        });
        let failure = transport
            .send(&Request::get("http://[::1]:9/"))
            .expect_err("non-public destination must be refused");
        assert!(failure.blocked, "{failure:?}");
        return;
    }

    let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
    proxy.set_nonblocking(true).unwrap();
    let proxy_url = format!("http://{}", proxy.local_addr().unwrap());
    let mut child = std::process::Command::new(std::env::current_exe().unwrap());
    child
        .args([
            "--exact",
            "public_only_refuses_private_target_with_proxy_environment",
            "--nocapture",
        ])
        .env(CHILD, "1");
    for key in [
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
    ] {
        child.env(key, &proxy_url);
    }
    child.env("NO_PROXY", "").env("no_proxy", "");
    let result = child.output().unwrap();
    assert!(
        result.status.success(),
        "{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        proxy.accept().is_err(),
        "non-public request reached environment proxy"
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

/// A server that accepts and then says nothing for `hold`.
fn silent(hold: Duration) -> (u16, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let handle = thread::spawn(move || {
        let (sock, _) = listener.accept().expect("accept");
        thread::sleep(hold);
        drop(sock);
    });
    (port, handle)
}

#[test]
fn a_request_cap_cuts_the_transport_timeout_short() {
    let (port, hold) = silent(Duration::from_secs(3));
    let t = UreqTransport::new(&TransportConfig {
        timeout: Duration::from_secs(10),
        egress: EgressPolicy::Unrestricted,
        ..TransportConfig::default()
    });
    let started = std::time::Instant::now();
    let failure = t
        .send(
            &Request::get(format!("http://127.0.0.1:{port}/"))
                .with_timeout(Duration::from_millis(300)),
        )
        .expect_err("capped");
    assert_eq!(failure.kind, SourceOutcomeKind::TtfbTimeout, "{failure:?}");
    assert!(
        started.elapsed() < Duration::from_millis(2500),
        "{:?}",
        started.elapsed()
    );
    hold.join().expect("holder");
}

#[test]
fn a_request_cap_never_raises_the_transport_timeout() {
    let (port, hold) = silent(Duration::from_secs(3));
    let t = UreqTransport::new(&TransportConfig {
        timeout: Duration::from_millis(300),
        egress: EgressPolicy::Unrestricted,
        ..TransportConfig::default()
    });
    let started = std::time::Instant::now();
    let failure = t
        .send(
            &Request::get(format!("http://127.0.0.1:{port}/"))
                .with_timeout(Duration::from_secs(60)),
        )
        .expect_err("transport timeout still applies");
    assert_eq!(failure.kind, SourceOutcomeKind::TtfbTimeout, "{failure:?}");
    assert!(
        started.elapsed() < Duration::from_millis(2500),
        "{:?}",
        started.elapsed()
    );
    hold.join().expect("holder");
}

#[test]
fn a_request_cap_also_bounds_a_stalled_body() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let hold = thread::spawn(move || {
        let (mut sock, _) = listener.accept().expect("accept");
        read_request(&mut sock);
        let _ = sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\npartial");
        let _ = sock.flush();
        thread::sleep(Duration::from_secs(3));
    });
    let t = UreqTransport::new(&TransportConfig {
        timeout: Duration::from_secs(10),
        egress: EgressPolicy::Unrestricted,
        ..TransportConfig::default()
    });
    let started = std::time::Instant::now();
    let failure = t
        .send(
            &Request::get(format!("http://127.0.0.1:{port}/"))
                .with_timeout(Duration::from_millis(300)),
        )
        .expect_err("body read capped");
    // The status line and headers arrived; the cap fired while reading the body.
    assert_eq!(failure.kind, SourceOutcomeKind::BodyTimeout, "{failure:?}");
    assert!(
        started.elapsed() < Duration::from_millis(2500),
        "{:?}",
        started.elapsed()
    );
    hold.join().expect("holder");
}

/// A redirect chain far longer than the redirect limit, each hop answering `302`
/// to the next after `delay`. Returns the port and the request lines seen. The
/// server thread is left in `accept` when the test ends.
fn slow_redirect_chain(delay: Duration) -> (u16, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = seen.clone();
    thread::spawn(move || {
        for (hop, stream) in listener.incoming().enumerate() {
            let Ok(mut sock) = stream else { continue };
            let head = read_request(&mut sock);
            log.lock()
                .expect("log")
                .push(head.lines().next().unwrap_or_default().to_owned());
            thread::sleep(delay);
            let _ = sock.write_all(
                format!(
                    "HTTP/1.1 302 Found\r\nLocation: /hop{}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    hop + 1
                )
                .as_bytes(),
            );
        }
    });
    (port, seen)
}

/// Security review on 5f446416: every redirect hop used to be sent with the full
/// request cap again, so five slow hops could run five caps. The cap now bounds
/// the whole fetch. 400 ms hops under a 1 s cap: the third hop gets 200 ms and
/// times out at the cap, instead of six hops taking 2.4 s.
#[test]
fn a_slow_redirect_chain_stops_at_the_request_cap() {
    let (port, seen) = slow_redirect_chain(Duration::from_millis(400));
    let cap = Duration::from_secs(1);
    let started = std::time::Instant::now();
    let fetched = fetch(
        &lab_transport(1024),
        Request::get(format!("http://127.0.0.1:{port}/hop0")).with_timeout(cap),
        None,
        &FetchOptions::default(),
        "local",
        1,
    )
    .expect("fetch");
    let elapsed = started.elapsed();
    assert!(elapsed <= cap + Duration::from_millis(500), "{elapsed:?}");
    assert_eq!(
        fetched.outcome.kind,
        SourceOutcomeKind::TtfbTimeout,
        "{fetched:?}"
    );
    assert!(fetched.response.is_none());
    assert_eq!(fetched.redirects, 2);
    assert_eq!(seen.lock().expect("log").len(), 3);
}

/// The same chain inside a caller's deadline (how stolen.tax spends its lookup
/// budget): an uncapped request still stops when the deadline does.
#[test]
fn a_slow_redirect_chain_stops_at_the_deadline() {
    let (port, seen) = slow_redirect_chain(Duration::from_millis(400));
    let budget = Duration::from_secs(1);
    let clock = SystemClock;
    let deadline = Deadline::start(&clock, budget);
    let fetched = fetch_within(
        &lab_transport(1024),
        Request::get(format!("http://127.0.0.1:{port}/hop0")),
        None,
        &FetchOptions::default(),
        &deadline,
        "local",
        1,
    )
    .expect("fetch");
    let elapsed = deadline.elapsed();
    assert!(
        elapsed <= budget + Duration::from_millis(500),
        "{elapsed:?}"
    );
    assert_eq!(
        fetched.outcome.kind,
        SourceOutcomeKind::TtfbTimeout,
        "{fetched:?}"
    );
    assert!(fetched.response.is_none());
    assert!(fetched.redirects <= 2, "{}", fetched.redirects);
    assert!(seen.lock().expect("log").len() <= 3);
}
