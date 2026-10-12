//! Minimal embedded Web UI and HTTP API for Huntsman Recon.
//!
//! The default bind is loopback-only. Explicit non-loopback binds require a
//! non-empty bearer token supplied by the caller. The server is dependency-free,
//! blocking, bounded per request, and exposes only read-only metadata endpoints.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::engineering_command;
use crate::error::Error;
use crate::module::reachable_modules;

pub const DEFAULT_BIND: &str = "127.0.0.1:8080";

/// Resolve the implicit server bind without weakening the explicit bind contract.
///
/// Local/Termux runs stay loopback-only. Railway runs use the platform-provided
/// PORT on all interfaces so Railway routing and health checks reach the server.
/// `HSE_BIND` always wins and an explicit CLI `--bind` still wins later.
///
/// # Errors
/// Railway mode fails closed when PORT is absent, malformed, or zero.
pub fn resolve_serve_bind(
    hse_bind: Option<&str>,
    railway_port: Option<&str>,
    railway: bool,
) -> Result<String, Error> {
    if let Some(bind) = hse_bind {
        return Ok(bind.to_owned());
    }
    if !railway {
        return Ok(DEFAULT_BIND.to_owned());
    }

    let raw = railway_port.ok_or_else(|| Error::Invalid("Railway PORT is missing".into()))?;
    let port = raw
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| Error::Invalid(format!("invalid Railway PORT {raw:?}")))?;
    Ok(format!("0.0.0.0:{port}"))
}
const MAX_REQUEST_BYTES: usize = 16 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(5);
/// Whole-request wall-clock budget. The per-read `IO_TIMEOUT` restarts on every successful
/// read, so it alone cannot bound a client that dribbles a byte at a time; this absolute
/// deadline caps the total time spent reading one request.
const REQUEST_DEADLINE: Duration = Duration::from_secs(10);
/// Connections served at once. A phone browser opens several for one page, and some are speculative
/// and idle, so each connection gets its own thread: one that sends nothing holds up only itself.
/// A connection past the cap is answered `503` at once.
const MAX_CONNECTIONS: usize = 32;
/// The handler formats short strings, so a small stack is enough, and it keeps a full set of
/// connection threads cheap on a phone.
const HANDLER_STACK_BYTES: usize = 256 * 1024;

#[derive(Clone, PartialEq, Eq)]
pub struct ServeConfig {
    pub bind: SocketAddr,
    pub bearer_token: Option<String>,
}

impl ServeConfig {
    /// Build and validate server configuration.
    ///
    /// # Errors
    /// Rejects malformed bind addresses, empty supplied tokens, and explicit
    /// non-loopback binds without a token.
    pub fn parse(bind: &str, bearer_token: Option<String>) -> Result<Self, Error> {
        let bind = normalize_bind(bind)?;
        let bearer_token = match bearer_token {
            Some(token) => {
                let token = token.trim().to_owned();
                if token.is_empty() {
                    return Err(Error::missing_credential(
                        "HSE_AUTH_TOKEN must not be empty",
                    ));
                }
                Some(token)
            }
            None => None,
        };

        if !bind.ip().is_loopback() && bearer_token.is_none() {
            return Err(Error::missing_credential(
                "non-loopback serve bind requires HSE_AUTH_TOKEN",
            ));
        }

        Ok(Self { bind, bearer_token })
    }
}

fn normalize_bind(raw: &str) -> Result<SocketAddr, Error> {
    let trimmed = raw.trim();
    let normalized = if let Some(port) = trimmed.strip_prefix("localhost:") {
        format!("127.0.0.1:{port}")
    } else {
        trimmed.to_owned()
    };
    normalized
        .parse::<SocketAddr>()
        .map_err(|error| Error::Invalid(format!("invalid serve bind {trimmed:?}: {error}")))
}

pub struct Server {
    listener: TcpListener,
    config: ServeConfig,
}

impl Server {
    /// Bind the configured address.
    ///
    /// # Errors
    /// Returns a storage-class I/O error when the listener cannot bind.
    pub fn bind(config: ServeConfig) -> Result<Self, Error> {
        let listener = TcpListener::bind(config.bind)
            .map_err(|error| Error::Store(format!("serve bind {}: {error}", config.bind)))?;
        Ok(Self { listener, config })
    }

    /// Actual bound address, useful when port 0 was requested.
    ///
    /// # Errors
    /// Returns an I/O error if the listener address cannot be read.
    pub fn local_addr(&self) -> Result<SocketAddr, Error> {
        self.listener
            .local_addr()
            .map_err(|error| Error::Store(format!("serve local address: {error}")))
    }

    /// Run until the listener returns an unrecoverable error. Each connection is served on its
    /// own thread, up to [`MAX_CONNECTIONS`] at a time.
    ///
    /// # Errors
    /// Returns the listener error that stops the loop.
    pub fn run(&self) -> Result<(), Error> {
        let config = Arc::new(self.config.clone());
        let live = Arc::new(AtomicUsize::new(0));
        loop {
            let (stream, _) = self
                .listener
                .accept()
                .map_err(|error| Error::Store(format!("serve accept: {error}")))?;
            serve_on_a_thread(&config, &live, stream);
        }
    }

    #[cfg(test)]
    fn run_n(&self, count: usize) -> Result<(), Error> {
        for _ in 0..count {
            let (stream, _) = self
                .listener
                .accept()
                .map_err(|error| Error::Store(format!("serve accept: {error}")))?;
            handle_stream(&self.config, stream)?;
        }
        Ok(())
    }
}

/// One of the [`MAX_CONNECTIONS`] places. Dropping it, including when the handler panics, frees it.
struct Slot(Arc<AtomicUsize>);

impl Slot {
    fn take(live: &Arc<AtomicUsize>) -> Option<Self> {
        if live.fetch_add(1, Ordering::AcqRel) >= MAX_CONNECTIONS {
            live.fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        Some(Self(Arc::clone(live)))
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

fn serve_on_a_thread(config: &Arc<ServeConfig>, live: &Arc<AtomicUsize>, stream: TcpStream) {
    let Some(slot) = Slot::take(live) else {
        refuse_busy(stream);
        return;
    };
    // The thread owns the stream; this copy lets a failed spawn still answer the client.
    let fallback = stream.try_clone().ok();
    let config = Arc::clone(config);
    let spawned = thread::Builder::new()
        .name("serve-connection".into())
        .stack_size(HANDLER_STACK_BYTES)
        .spawn(move || {
            let _slot = slot;
            let _handled = handle_stream(&config, stream);
        });
    if spawned.is_err() {
        if let Some(stream) = fallback {
            refuse_busy(stream);
        }
    }
}

fn refuse_busy(mut stream: TcpStream) {
    let _ = stream.set_write_timeout(Some(Duration::from_secs(1)));
    let busy = response(503, "text/plain; charset=utf-8", "busy\n", false);
    let _ = stream.write_all(busy.as_bytes());
}

fn handle_stream(config: &ServeConfig, mut stream: TcpStream) -> Result<(), Error> {
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|error| Error::Store(format!("serve read timeout: {error}")))?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|error| Error::Store(format!("serve write timeout: {error}")))?;

    let deadline = Instant::now() + REQUEST_DEADLINE;
    let request = read_request(&mut stream, deadline)?;
    let response = response_for_request(&request, config.bearer_token.as_deref());
    stream
        .write_all(response.as_bytes())
        .map_err(|error| Error::Store(format!("serve write: {error}")))?;
    stream
        .flush()
        .map_err(|error| Error::Store(format!("serve flush: {error}")))
}

fn read_request(stream: &mut TcpStream, deadline: Instant) -> Result<String, Error> {
    let mut bytes = Vec::with_capacity(1024);
    let mut chunk = [0_u8; 1024];

    while bytes.len() < MAX_REQUEST_BYTES {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok("REQUEST_TIMEOUT".into());
        }
        // Bound each read by the time left in the whole-request budget (never longer than the
        // per-read timeout), so a client that dribbles bytes cannot hold the connection open
        // past the deadline.
        stream
            .set_read_timeout(Some(remaining.min(IO_TIMEOUT)))
            .map_err(|error| Error::Store(format!("serve read timeout: {error}")))?;
        let read = match stream.read(&mut chunk) {
            Ok(read) => read,
            // A client that sends nothing, or stalls past its budget, has run out of time: it gets
            // the 408 that the timeout sentinel renders, not a dropped connection.
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Ok("REQUEST_TIMEOUT".into());
            }
            Err(error) => return Err(Error::Store(format!("serve read: {error}"))),
        };
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..read]);
        if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }

    if bytes.len() >= MAX_REQUEST_BYTES && !bytes.windows(4).any(|window| window == b"\r\n\r\n") {
        return Ok("REQUEST_TOO_LARGE".into());
    }

    // Header values may carry bytes outside ASCII (RFC 9110 obs-text). Decoding them lossily keeps
    // such a request answerable instead of refusing it with no reply.
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Method {
    Get,
    Head,
    Other,
}

#[derive(Debug)]
struct ParsedRequest<'a> {
    method: Method,
    path: &'a str,
    authorization: Option<&'a str>,
}

fn parse_request(request: &str) -> Option<ParsedRequest<'_>> {
    let mut lines = request.split("\r\n");
    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();
    let method = match parts.next()? {
        "GET" => Method::Get,
        "HEAD" => Method::Head,
        _ => Method::Other,
    };
    let raw_path = parts.next()?;
    let path = raw_path.split('?').next().unwrap_or(raw_path);
    let mut authorization = None;

    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("authorization") {
            authorization = Some(value.trim());
        }
    }

    Some(ParsedRequest {
        method,
        path,
        authorization,
    })
}

#[derive(Debug, Serialize)]
struct Health<'a> {
    status: &'a str,
    name: &'a str,
    version: &'a str,
}

fn response_for_request(request: &str, bearer_token: Option<&str>) -> String {
    if request == "REQUEST_TOO_LARGE" {
        return response(
            413,
            "text/plain; charset=utf-8",
            "request too large\n",
            false,
        );
    }

    if request == "REQUEST_TIMEOUT" {
        return response(408, "text/plain; charset=utf-8", "request timeout\n", false);
    }

    let Some(parsed) = parse_request(request) else {
        return response(400, "text/plain; charset=utf-8", "bad request\n", false);
    };

    if parsed.method == Method::Other {
        return response(
            405,
            "text/plain; charset=utf-8",
            "method not allowed\n",
            false,
        );
    }

    let head = parsed.method == Method::Head;
    let protected = matches!(parsed.path, "/api/modules" | "/api/command");
    if protected
        && bearer_token.is_some_and(|expected| !bearer_matches(parsed.authorization, expected))
    {
        return response(
            401,
            "application/json; charset=utf-8",
            "{\"error\":\"unauthorized\"}\n",
            head,
        );
    }

    match parsed.path {
        "/" | "/index.html" => response(200, "text/html; charset=utf-8", INDEX_HTML, head),
        "/api/health" => {
            let body = serde_json::to_string_pretty(&Health {
                status: "ok",
                name: "huntsman-recon",
                version: env!("CARGO_PKG_VERSION"),
            })
            .unwrap_or_else(|_| "{\"status\":\"error\"}".into());
            response(
                200,
                "application/json; charset=utf-8",
                &format!("{body}\n"),
                head,
            )
        }
        "/api/modules" => {
            let body = serde_json::to_string_pretty(&serde_json::json!({
                "count": reachable_modules().len(),
                "modules": reachable_modules(),
            }))
            .unwrap_or_else(|_| "{\"count\":0,\"modules\":[]}".into());
            response(
                200,
                "application/json; charset=utf-8",
                &format!("{body}\n"),
                head,
            )
        }
        "/api/command" => match engineering_command::render_json() {
            Ok(body) => response(
                200,
                "application/json; charset=utf-8",
                &format!("{body}\n"),
                head,
            ),
            Err(_) => response(
                500,
                "application/json; charset=utf-8",
                "{\"error\":\"command contract unavailable\"}\n",
                head,
            ),
        },
        "/favicon.ico" => response(204, "image/x-icon", "", head),
        _ => response(404, "text/plain; charset=utf-8", "not found\n", head),
    }
}

fn bearer_matches(header: Option<&str>, expected: &str) -> bool {
    let Some(header) = header else {
        return false;
    };
    let mut parts = header.split_whitespace();
    let Some(scheme) = parts.next() else {
        return false;
    };
    let Some(actual) = parts.next() else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("bearer") || parts.next().is_some() {
        return false;
    }
    fixed_time_eq(actual.as_bytes(), expected.as_bytes())
}

fn fixed_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0_u8;
    for (a, b) in left.iter().zip(right.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

fn response(status: u16, content_type: &str, body: &str, head: bool) -> String {
    let reason = match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        413 => "Payload Too Large",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Error",
    };
    let retry_after = if status == 503 {
        "Retry-After: 1\r\n"
    } else {
        ""
    };
    let content_length = body.len();
    let rendered_body = if head { "" } else { body };
    format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {content_length}\r\n{retry_after}Cache-Control: no-store\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\n\r\n{rendered_body}"
    )
}

const INDEX_HTML: &str = r#"<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Huntsman Recon</title>
<style>
:root{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;color-scheme:dark}
body{max-width:960px;margin:0 auto;padding:24px;background:#111;color:#eee}
h1{font-size:20px;margin:0 0 16px}button,input{font:inherit;padding:8px}
section{border:1px solid #444;padding:12px;margin:12px 0}pre{white-space:pre-wrap;overflow-wrap:anywhere}
.row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
small{color:#aaa}
</style>
<h1>Huntsman Recon</h1>
<div class="row"><input id="token" type="password" autocomplete="off" placeholder="token (only if configured)"><button id="refresh">Refresh</button></div>
<small>Read-only status, module catalogue, and engineering command contract.</small>
<section><b>Health</b><pre id="health">loading…</pre></section>
<section><b>Reachable modules</b><pre id="modules">loading…</pre></section>
<section><b>Command contract</b><pre id="command">loading…</pre></section>
<script>
const token=()=>document.getElementById('token').value;
async function get(path){
  const headers={}; const t=token(); if(t) headers.Authorization='Bearer '+t;
  const r=await fetch(path,{headers,cache:'no-store'}); return await r.text();
}
async function refresh(){
  for(const [id,path] of [['health','/api/health'],['modules','/api/modules'],['command','/api/command']]){
    try{document.getElementById(id).textContent=await get(path)}catch(e){document.getElementById(id).textContent=String(e)}
  }
}
document.getElementById('refresh').onclick=refresh; refresh();
</script>
</html>
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn implicit_bind_is_loopback_locally_and_railway_port_on_railway() {
        assert_eq!(resolve_serve_bind(None, None, false).unwrap(), DEFAULT_BIND);
        assert_eq!(
            resolve_serve_bind(Some("127.0.0.1:9000"), Some("1234"), true).unwrap(),
            "127.0.0.1:9000"
        );
        assert_eq!(
            resolve_serve_bind(None, Some("43210"), true).unwrap(),
            "0.0.0.0:43210"
        );
        assert!(resolve_serve_bind(None, None, true).is_err());
        assert!(resolve_serve_bind(None, Some("0"), true).is_err());
        assert!(resolve_serve_bind(None, Some("not-a-port"), true).is_err());
    }

    #[test]
    fn config_defaults_and_public_token_requirement_are_explicit() {
        let local = ServeConfig::parse(DEFAULT_BIND, None).unwrap();
        assert!(local.bind.ip().is_loopback());
        assert!(ServeConfig::parse("0.0.0.0:8080", None).is_err());
        assert!(ServeConfig::parse(DEFAULT_BIND, Some("   ".into())).is_err());
        assert!(ServeConfig::parse("0.0.0.0:8080", Some("token".into())).is_ok());
        assert_eq!(
            ServeConfig::parse("localhost:9000", None).unwrap().bind,
            "127.0.0.1:9000".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn pure_router_serves_health_and_protected_metadata() {
        let health = response_for_request("GET /api/health HTTP/1.1\r\n\r\n", Some("secret"));
        assert!(health.starts_with("HTTP/1.1 200"));
        assert!(health.contains("\"status\": \"ok\""));

        let denied = response_for_request("GET /api/modules HTTP/1.1\r\n\r\n", Some("secret"));
        assert!(denied.starts_with("HTTP/1.1 401"));

        let allowed = response_for_request(
            "GET /api/modules HTTP/1.1\r\nAuthorization: bearer secret\r\n\r\n",
            Some("secret"),
        );
        assert!(allowed.starts_with("HTTP/1.1 200"));
        assert!(allowed.contains("\"modules\""));
    }

    #[test]
    fn head_has_get_content_length_but_no_body() {
        let get = response_for_request("GET /api/health HTTP/1.1\r\n\r\n", None);
        let head = response_for_request("HEAD /api/health HTTP/1.1\r\n\r\n", None);
        let get_len = get
            .lines()
            .find(|line| line.starts_with("Content-Length:"))
            .unwrap();
        let head_len = head
            .lines()
            .find(|line| line.starts_with("Content-Length:"))
            .unwrap();
        assert_eq!(get_len, head_len);
        assert!(head.ends_with("\r\n\r\n"));
    }

    #[test]
    fn loopback_server_handles_one_real_request() {
        let server = Server::bind(ServeConfig::parse("127.0.0.1:0", None).unwrap()).unwrap();
        let addr = server.local_addr().unwrap();
        let handle = thread::spawn(move || server.run_n(1).unwrap());

        let mut client = TcpStream::connect(addr).unwrap();
        client
            .write_all(b"GET /api/health HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        handle.join().unwrap();

        assert!(response.starts_with("HTTP/1.1 200"));
        assert!(response.contains("huntsman-recon"));
    }

    fn serve_in_background() -> SocketAddr {
        let server = Server::bind(ServeConfig::parse("127.0.0.1:0", None).unwrap()).unwrap();
        let addr = server.local_addr().unwrap();
        thread::spawn(move || {
            let _ = server.run();
        });
        addr
    }

    fn get_within(addr: SocketAddr, path: &str, wait: Duration) -> std::io::Result<String> {
        let mut client = TcpStream::connect(addr)?;
        client.set_read_timeout(Some(wait))?;
        client.write_all(format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes())?;
        let mut response = String::new();
        match client.read_to_string(&mut response) {
            // A refused connection is closed with the request unread, which resets it after the
            // reply has been delivered.
            Err(error)
                if error.kind() == std::io::ErrorKind::ConnectionReset && !response.is_empty() => {}
            outcome => {
                outcome?;
            }
        }
        Ok(response)
    }

    #[test]
    fn an_idle_connection_does_not_hold_up_the_next_request() {
        // A browser opens speculative connections and sends nothing on them. The accept loop used
        // to serve one connection at a time, so each of these stalled the page for IO_TIMEOUT.
        let addr = serve_in_background();
        let _idle = [
            TcpStream::connect(addr).unwrap(),
            TcpStream::connect(addr).unwrap(),
        ];
        let started = Instant::now();
        let response = get_within(addr, "/api/health", Duration::from_secs(3))
            .expect("the request was answered while other connections sat idle");
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(
            started.elapsed() < IO_TIMEOUT,
            "the request waited for the idle connections"
        );
    }

    #[test]
    fn connections_past_the_cap_are_answered_busy_and_their_places_come_back() {
        let addr = serve_in_background();
        let idle: Vec<TcpStream> = (0..MAX_CONNECTIONS)
            .map(|_| TcpStream::connect(addr).unwrap())
            .collect();
        let refused = get_within(addr, "/api/health", Duration::from_secs(3)).unwrap();
        assert!(
            refused.starts_with("HTTP/1.1 503 Service Unavailable"),
            "{refused}"
        );
        assert!(refused.contains("Retry-After: 1\r\n"), "{refused}");

        drop(idle);
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let response = get_within(addr, "/api/health", Duration::from_secs(3)).unwrap();
            if response.starts_with("HTTP/1.1 200") {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "the places never came back: {response}"
            );
            thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn statuses_carry_their_reason_phrases() {
        for (status, phrase) in [(408, "Request Timeout"), (503, "Service Unavailable")] {
            let rendered = response(status, "text/plain; charset=utf-8", "x\n", false);
            assert!(
                rendered.starts_with(&format!("HTTP/1.1 {status} {phrase}\r\n")),
                "{rendered}"
            );
        }
        assert!(
            response_for_request("REQUEST_TIMEOUT", None)
                .starts_with("HTTP/1.1 408 Request Timeout")
        );
    }

    #[test]
    fn a_request_past_its_deadline_times_out_without_blocking() {
        // A deadline already in the past makes read_request stop on the first iteration and
        // return the timeout sentinel, before any blocking read. This is the whole-request
        // bound that a per-read socket timeout alone does not give against a dribbling client.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let _client = TcpStream::connect(addr).unwrap(); // connects, sends nothing
        let (mut server, _) = listener.accept().unwrap();
        // A deadline captured now is already elapsed when read_request re-reads the clock,
        // so `remaining` saturates to zero on the first iteration.
        let deadline = Instant::now();
        assert_eq!(
            read_request(&mut server, deadline).unwrap(),
            "REQUEST_TIMEOUT",
            "an elapsed deadline must stop the read, not block on the silent client"
        );
        assert!(
            response_for_request("REQUEST_TIMEOUT", None).starts_with("HTTP/1.1 408"),
            "the timeout sentinel renders as 408 Request Timeout"
        );
    }

    #[test]
    fn fixed_time_compare_requires_exact_bytes() {
        assert!(fixed_time_eq(b"abc", b"abc"));
        assert!(!fixed_time_eq(b"abc", b"abd"));
        assert!(!fixed_time_eq(b"abc", b"ab"));
    }

    #[test]
    fn bind_parser_accepts_ipv4_and_ipv6_socket_addresses() {
        assert_eq!(
            normalize_bind("127.0.0.1:8080").unwrap().ip(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        );
        assert_eq!(
            normalize_bind("[::1]:8080").unwrap().ip(),
            std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
        );
    }

    #[test]
    fn a_client_that_sends_nothing_gets_a_408_when_its_read_times_out() {
        // A connection that never sends a byte used to be dropped without a reply, so the 408
        // that the timeout sentinel renders never reached the client.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();
        let config = ServeConfig::parse("127.0.0.1:0", None).unwrap();
        let handle = thread::spawn(move || handle_stream(&config, server));
        client
            .set_read_timeout(Some(Duration::from_secs(15)))
            .unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert!(handle.join().unwrap().is_ok());
        assert!(
            response.starts_with("HTTP/1.1 408 Request Timeout"),
            "{response}"
        );
    }

    #[test]
    fn opaque_header_bytes_do_not_refuse_a_valid_request() {
        // RFC 9110 allows bytes outside ASCII in field values (obs-text). Refusing the whole
        // request for one such byte left a valid client with no reply at all.
        let addr = serve_in_background();
        let mut client = TcpStream::connect(addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        client
            .write_all(b"GET /api/health HTTP/1.1\r\nHost: localhost\r\nX-Note: caf\xe9\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    }
}
