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
}

impl Canned {
    /// A JSON answer.
    pub(crate) fn json(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            content_type: "application/json",
            body: body.into(),
        }
    }

    /// A plain-text answer (an error page, an empty body).
    pub(crate) fn text(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            content_type: "text/plain",
            body: body.into(),
        }
    }

    /// An HTML document — a provider's error template, a bot-challenge
    /// interstitial or a login page served where JSON was expected.
    pub(crate) fn html(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            content_type: "text/html; charset=UTF-8",
            body: body.into(),
        }
    }
}

/// Bind a loopback listener that answers connections in order from `answers`
/// and return its base URL (`http://127.0.0.1:PORT`). A connection past the end
/// of the queue gets a `599` with a message, so a test sees an unexpected extra
/// request as a failure rather than a hang.
pub(crate) async fn serve(answers: Vec<Canned>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        let mut queue = answers.into_iter();
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            // The request head is all that is needed; the body (a POST's JSON)
            // is never inspected.
            let mut buf = vec![0u8; 8192];
            let _ = sock.read(&mut buf).await;
            let (status, content_type, body) = match queue.next() {
                Some(c) => (c.status, c.content_type, c.body),
                None => (
                    599,
                    "text/plain",
                    "test_server: no canned answer left for this request".to_string(),
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
            let head = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = sock.write_all(head.as_bytes()).await;
            let _ = sock.write_all(body.as_bytes()).await;
            let _ = sock.shutdown().await;
        }
    });
    format!("http://{addr}")
}
