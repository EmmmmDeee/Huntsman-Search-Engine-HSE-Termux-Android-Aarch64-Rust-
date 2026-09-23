//! Loopback HTTP server for module tests.
//!
//! Answers each connection with the next canned response, so a module's REAL
//! request path — URL building, headers, status classification, body decoding —
//! runs against a status the test chooses, with no network and no mock of the
//! HTTP client. A plain `reqwest::Client::new()` reaches it (the engine's
//! `build_client()` filters loopback by design, so tests must not use that).
//!
//! Every module test that needed this hand-rolled its own `TcpListener` loop;
//! this is the one copy for the ones written since.

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// One canned answer.
pub(crate) struct Canned {
    pub(crate) status: u16,
    pub(crate) content_type: &'static str,
    pub(crate) body: String,
    /// Extra response headers (`Retry-After`, …), written after `Content-Type`.
    pub(crate) headers: Vec<(&'static str, String)>,
}

impl Canned {
    /// A JSON answer.
    pub(crate) fn json(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            content_type: "application/json",
            body: body.into(),
            headers: Vec::new(),
        }
    }

    /// A plain-text answer (an error page, an empty body).
    pub(crate) fn text(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            content_type: "text/plain",
            body: body.into(),
            headers: Vec::new(),
        }
    }

    /// An HTML document — a provider's error template, a bot-challenge
    /// interstitial or a login page served where JSON was expected.
    pub(crate) fn html(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            content_type: "text/html; charset=UTF-8",
            body: body.into(),
            headers: Vec::new(),
        }
    }

    /// Add a response header — a provider's `Retry-After` on a 429, say — so a
    /// module's header-reading path runs against the value the test chooses.
    pub(crate) fn header(mut self, name: &'static str, value: impl Into<String>) -> Self {
        self.headers.push((name, value.into()));
        self
    }
}

/// Bind a loopback listener that answers connections in order from `answers`
/// and return its base URL (`http://127.0.0.1:PORT`). A connection past the end
/// of the queue gets a `599` with a message, so a test sees an unexpected extra
/// request as a failure rather than a hang.
pub(crate) async fn serve(answers: Vec<Canned>) -> String {
    serve_recording(answers).await.0
}

/// The request heads a [`serve_recording`] listener received, in arrival order.
pub(crate) type Requests = std::sync::Arc<std::sync::Mutex<Vec<String>>>;

/// [`serve`], also handing back every request head it receives: the request
/// line and headers, as text. A module's result shows what it did with the
/// answer; the head shows what it sent, so a test can assert WHERE a module put
/// something, such as a credential in a header and not in the URL
/// (REQ-CRED-001).
///
/// A head is what one `read` returned, up to 8 KiB. A small loopback GET
/// arrives in one read, and nothing here is meant for large requests.
pub(crate) async fn serve_recording(answers: Vec<Canned>) -> (String, Requests) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let requests = Requests::default();
    let seen = requests.clone();
    tokio::spawn(async move {
        let mut queue = answers.into_iter();
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            // The request head is all that is needed; the body (a POST's JSON)
            // is never inspected.
            let mut buf = vec![0u8; 8192];
            let n = sock.read(&mut buf).await.unwrap_or(0);
            seen.lock()
                .expect("request log")
                .push(String::from_utf8_lossy(&buf[..n]).into_owned());
            let (status, content_type, body, headers) = match queue.next() {
                Some(c) => (c.status, c.content_type, c.body, c.headers),
                None => (
                    599,
                    "text/plain",
                    "test_server: no canned answer left for this request".to_string(),
                    Vec::new(),
                ),
            };
            let reason = match status {
                200 => "OK",
                401 => "Unauthorized",
                403 => "Forbidden",
                404 => "Not Found",
                422 => "Unprocessable Entity",
                429 => "Too Many Requests",
                500 => "Internal Server Error",
                503 => "Service Unavailable",
                _ => "Status",
            };
            let extra: String = headers
                .iter()
                .map(|(name, value)| format!("{name}: {value}\r\n"))
                .collect();
            let head = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n{extra}Connection: close\r\n\r\n",
                body.len()
            );
            let _ = sock.write_all(head.as_bytes()).await;
            let _ = sock.write_all(body.as_bytes()).await;
            let _ = sock.shutdown().await;
        }
    });
    (format!("http://{addr}"), requests)
}

/// A loopback address nothing listens on, held for as long as this value
/// lives. The port is bound but never listened on, so a connect is refused at
/// once, and no other socket (another test's server included) can be given
/// it meanwhile. Binding a listener to find a free port and dropping it hands
/// that port back for the next `bind("127.0.0.1:0")`, which under the parallel
/// test harness can be another test's server: the "refused" probe then
/// connects.
pub(crate) struct ClosedPort {
    _held: tokio::net::TcpSocket,
    addr: std::net::SocketAddr,
}

impl ClosedPort {
    pub(crate) fn new() -> Self {
        let held = tokio::net::TcpSocket::new_v4().expect("tcp socket");
        held.set_reuseaddr(false).expect("no address reuse");
        held.bind(([127, 0, 0, 1], 0).into())
            .expect("bind loopback");
        let addr = held.local_addr().expect("local addr");
        Self { _held: held, addr }
    }

    pub(crate) fn addr(&self) -> std::net::SocketAddr {
        self.addr
    }
}

#[test]
fn a_closed_port_refuses_and_cannot_be_taken_while_held() {
    let closed = ClosedPort::new();
    let refused = std::net::TcpStream::connect(closed.addr()).map_err(|e| e.kind());
    assert_eq!(refused.err(), Some(std::io::ErrorKind::ConnectionRefused));
    assert!(
        std::net::TcpListener::bind(closed.addr()).is_err(),
        "a held port must not be bindable by another listener"
    );
}
