//! Minimal embedded Web UI and HTTP API for Huntsman Recon.
//!
//! The default bind is loopback-only. Explicit non-loopback binds require a
//! non-empty bearer token supplied by the caller. The server is dependency-free,
//! blocking and bounded per request. It exposes read-only metadata endpoints and, when the
//! binary installs a [`LookupHandler`], `GET /api/lookup`, which runs one lookup through the
//! same front-ends as the CLI. A lookup spends network egress and operator keys, so it needs
//! the `X-Huntsman-Lookup` header (a page on another origin cannot send it without a CORS
//! preflight this server never approves) and is refused when the browser marks it cross-site.
//! A loopback bind answers only requests whose `Host` is a loopback authority,
//! which blocks a browser DNS-rebinding attack from reaching the local API.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::engineering_command;
use crate::entity::Entity;
use crate::error::Error;
use crate::module::reachable_modules;
use crate::source_outcome::SourceExecutionOutcome;

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
/// Lookups running at once. Each one holds sockets to several providers for up to two minutes,
/// so a phone gets a small, fixed number; one past the cap is answered `503`.
const MAX_LOOKUPS: usize = 2;
/// A lookup does TLS and JSON decoding, which the small connection stack is not sized for, so it
/// runs on its own thread with this stack.
const LOOKUP_STACK_BYTES: usize = 4 * 1024 * 1024;
/// Longest decoded `q` accepted by `/api/lookup`.
const MAX_SELECTOR_BYTES: usize = 512;
/// The header a lookup request must carry. Its presence forces a CORS preflight from any other
/// origin, and this server answers no preflight.
pub const LOOKUP_HEADER: &str = "x-huntsman-lookup";

/// One `/api/lookup` request: `kind` is `auto` unless the caller named one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupQuery {
    pub kind: String,
    pub selector: String,
}

/// A finished lookup, as the CLI would print and save it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct LookupReport {
    pub route: &'static str,
    pub text: String,
    pub entities: Vec<Entity>,
    pub outcomes: Vec<SourceExecutionOutcome>,
}

/// Why a lookup produced no report: the HTTP status and a message safe to show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupError {
    pub status: u16,
    pub message: String,
}

/// Runs one lookup. Installed by the binary, which owns transport construction.
pub type LookupHandler =
    Arc<dyn Fn(&LookupQuery) -> Result<LookupReport, LookupError> + Send + Sync>;

#[derive(Clone)]
struct Lookups {
    handler: LookupHandler,
    live: Arc<AtomicUsize>,
}

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
    lookups: Option<Lookups>,
}

impl Server {
    /// Bind the configured address.
    ///
    /// # Errors
    /// Returns a storage-class I/O error when the listener cannot bind.
    pub fn bind(config: ServeConfig) -> Result<Self, Error> {
        let listener = TcpListener::bind(config.bind)
            .map_err(|error| Error::Store(format!("serve bind {}: {error}", config.bind)))?;
        Ok(Self {
            listener,
            config,
            lookups: None,
        })
    }

    /// Serve `GET /api/lookup` through `handler`. Without this the route answers `404`.
    #[must_use]
    pub fn with_lookup(mut self, handler: LookupHandler) -> Self {
        self.lookups = Some(Lookups {
            handler,
            live: Arc::new(AtomicUsize::new(0)),
        });
        self
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
        let shared = Arc::new((self.config.clone(), self.lookups.clone()));
        let live = Arc::new(AtomicUsize::new(0));
        loop {
            let (stream, _) = self
                .listener
                .accept()
                .map_err(|error| Error::Store(format!("serve accept: {error}")))?;
            serve_on_a_thread(&shared, &live, stream);
        }
    }

    #[cfg(test)]
    fn run_n(&self, count: usize) -> Result<(), Error> {
        for _ in 0..count {
            let (stream, _) = self
                .listener
                .accept()
                .map_err(|error| Error::Store(format!("serve accept: {error}")))?;
            handle_stream_with(&self.config, self.lookups.as_ref(), stream)?;
        }
        Ok(())
    }
}

/// One of a bounded number of places. Dropping it, including when the holder panics, frees it.
struct Slot(Arc<AtomicUsize>);

impl Slot {
    fn take(live: &Arc<AtomicUsize>) -> Option<Self> {
        Self::take_of(live, MAX_CONNECTIONS)
    }

    fn take_of(live: &Arc<AtomicUsize>, cap: usize) -> Option<Self> {
        if live.fetch_add(1, Ordering::AcqRel) >= cap {
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

type Shared = (ServeConfig, Option<Lookups>);

fn serve_on_a_thread(shared: &Arc<Shared>, live: &Arc<AtomicUsize>, stream: TcpStream) {
    let Some(slot) = Slot::take(live) else {
        refuse_busy(stream);
        return;
    };
    // The thread owns the stream; this copy lets a failed spawn still answer the client.
    let fallback = stream.try_clone().ok();
    let shared = Arc::clone(shared);
    let spawned = thread::Builder::new()
        .name("serve-connection".into())
        .stack_size(HANDLER_STACK_BYTES)
        .spawn(move || {
            let _slot = slot;
            let _handled = handle_stream_with(&shared.0, shared.1.as_ref(), stream);
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

#[cfg(test)]
fn handle_stream(config: &ServeConfig, stream: TcpStream) -> Result<(), Error> {
    handle_stream_with(config, None, stream)
}

fn handle_stream_with(
    config: &ServeConfig,
    lookups: Option<&Lookups>,
    mut stream: TcpStream,
) -> Result<(), Error> {
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|error| Error::Store(format!("serve read timeout: {error}")))?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|error| Error::Store(format!("serve write timeout: {error}")))?;

    let deadline = Instant::now() + REQUEST_DEADLINE;
    let request = read_request(&mut stream, deadline)?;
    let response = respond(
        &request,
        config.bearer_token.as_deref(),
        config.bind,
        lookups,
    );
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
    query: &'a str,
    host: Option<&'a str>,
    authorization: Option<&'a str>,
    lookup_header: bool,
    sec_fetch_site: Option<&'a str>,
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
    let (path, query) = raw_path.split_once('?').unwrap_or((raw_path, ""));
    let mut host = None;
    let mut authorization = None;
    let mut lookup_header = false;
    let mut sec_fetch_site = None;

    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("host") {
            // First Host wins; a second one is malformed and is ignored rather than
            // allowed to override the first.
            if host.is_none() {
                host = Some(value.trim());
            }
        } else if name.eq_ignore_ascii_case("authorization") {
            authorization = Some(value.trim());
        } else if name.trim().eq_ignore_ascii_case(LOOKUP_HEADER) {
            lookup_header = value.trim() == "1";
        } else if name.eq_ignore_ascii_case("sec-fetch-site") {
            sec_fetch_site = Some(value.trim());
        }
    }

    Some(ParsedRequest {
        method,
        path,
        query,
        host,
        authorization,
        lookup_header,
        sec_fetch_site,
    })
}

/// Whether a loopback server should answer a request carrying this `Host`.
///
/// A DNS-rebinding attack reaches a loopback bind from a page whose origin is a
/// public name rebound to a loopback address, so the browser sends that public
/// name in `Host`. Accepting only loopback authorities refuses the rebound
/// request while real local clients (which send `localhost`, `127.0.0.1`, or
/// `[::1]`) are unaffected. A missing or empty `Host` is allowed: a browser never
/// omits it, so its absence is not a rebinding vector and a raw client stays
/// answerable.
fn host_is_allowed_for_loopback(host: Option<&str>) -> bool {
    let Some(host) = host else {
        return true;
    };
    let host = host.trim();
    if host.is_empty() {
        return true;
    }
    let name = if let Some(rest) = host.strip_prefix('[') {
        // IPv6 literal in brackets: `[::1]` or `[::1]:port`.
        match rest.split_once(']') {
            Some((inner, _)) => inner,
            None => return false,
        }
    } else {
        // `host` or `host:port`; strip only a trailing port.
        host.rsplit_once(':').map_or(host, |(name, _)| name)
    };
    if name.eq_ignore_ascii_case("localhost") {
        return true;
    }
    name.parse::<std::net::IpAddr>()
        .is_ok_and(|ip| ip.is_loopback())
}

#[derive(Debug, Serialize)]
struct Health<'a> {
    status: &'a str,
    name: &'a str,
    version: &'a str,
}

#[cfg(test)]
fn response_for_request(request: &str, bearer_token: Option<&str>, bind: SocketAddr) -> String {
    respond(request, bearer_token, bind, None)
}

fn respond(
    request: &str,
    bearer_token: Option<&str>,
    bind: SocketAddr,
    lookups: Option<&Lookups>,
) -> String {
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

    // DNS-rebinding guard. A loopback server is reached from a page whose origin is
    // a public name rebound to a loopback address, so the browser sends that public
    // name in `Host`. Answer only loopback authorities (or an absent `Host`). A
    // non-loopback bind is intentionally public, gated by the bearer token, and its
    // legitimate `Host` is not known here, so the guard skips it.
    if bind.ip().is_loopback() && !host_is_allowed_for_loopback(parsed.host) {
        return response(
            403,
            "text/plain; charset=utf-8",
            "host not allowed\n",
            parsed.method == Method::Head,
        );
    }

    if parsed.method == Method::Other {
        return response(
            405,
            "text/plain; charset=utf-8",
            "method not allowed\n",
            false,
        );
    }

    let head = parsed.method == Method::Head;
    let protected = matches!(parsed.path, "/api/modules" | "/api/command" | "/api/lookup");
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
        "/api/lookup" => lookup_response(&parsed, lookups),
        "/favicon.ico" => response(204, "image/x-icon", "", head),
        _ => response(404, "text/plain; charset=utf-8", "not found\n", head),
    }
}

fn json_error(status: u16, message: &str) -> String {
    let body = serde_json::json!({ "error": message }).to_string();
    response(
        status,
        "application/json; charset=utf-8",
        &format!("{body}\n"),
        false,
    )
}

fn lookup_response(parsed: &ParsedRequest<'_>, lookups: Option<&Lookups>) -> String {
    let Some(lookups) = lookups else {
        return json_error(404, "lookups are not enabled on this server");
    };
    if parsed.method != Method::Get {
        return json_error(405, "lookup needs GET");
    }
    // `none` is a typed URL or bookmark; `same-origin` is this page. Anything else came from
    // another site, which must not spend this operator's egress or keys.
    if parsed
        .sec_fetch_site
        .is_some_and(|site| !matches!(site, "same-origin" | "none"))
    {
        return json_error(403, "cross-site lookup refused");
    }
    if !parsed.lookup_header {
        return json_error(403, "lookup needs the X-Huntsman-Lookup: 1 header");
    }
    let query = match parse_lookup_query(parsed.query) {
        Ok(query) => query,
        Err(message) => return json_error(400, message),
    };
    let Some(slot) = Slot::take_of(&lookups.live, MAX_LOOKUPS) else {
        return json_error(503, "lookup capacity in use; retry shortly");
    };
    let handler = Arc::clone(&lookups.handler);
    let worker = thread::Builder::new()
        .name("serve-lookup".into())
        .stack_size(LOOKUP_STACK_BYTES)
        .spawn(move || {
            let _slot = slot;
            handler(&query)
        });
    let outcome = match worker {
        Ok(worker) => worker.join(),
        Err(_) => return json_error(503, "could not start a lookup worker"),
    };
    match outcome {
        Ok(Ok(report)) => match serde_json::to_string(&report) {
            Ok(body) => response(
                200,
                "application/json; charset=utf-8",
                &format!("{body}\n"),
                false,
            ),
            Err(_) => json_error(500, "report could not be encoded"),
        },
        Ok(Err(error)) => json_error(error.status, &error.message),
        Err(_) => json_error(500, "lookup failed unexpectedly"),
    }
}

/// `kind` (default `auto`) and `q` from a query string. Unknown keys are ignored.
fn parse_lookup_query(raw: &str) -> Result<LookupQuery, &'static str> {
    let mut kind = None;
    let mut selector = None;
    for pair in raw.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let value = percent_decode(value).ok_or("query is not valid percent-encoded UTF-8")?;
        match key {
            "kind" => kind = Some(value),
            "q" => selector = Some(value),
            _ => {}
        }
    }
    let selector = selector.map(|q| q.trim().to_owned()).unwrap_or_default();
    if selector.is_empty() {
        return Err("lookup needs q");
    }
    if selector.len() > MAX_SELECTOR_BYTES {
        return Err("q is too long");
    }
    let kind = kind
        .map(|k| k.trim().to_ascii_lowercase())
        .filter(|k| !k.is_empty())
        .unwrap_or_else(|| "auto".into());
    Ok(LookupQuery { kind, selector })
}

/// `application/x-www-form-urlencoded` value decoding: `+` is a space and `%XX` a byte.
fn percent_decode(raw: &str) -> Option<String> {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => out.push(b' '),
            b'%' => {
                let hex = bytes.get(index + 1..index + 3)?;
                if !hex.iter().all(u8::is_ascii_hexdigit) {
                    return None;
                }
                out.push(u8::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()?);
                index += 2;
            }
            byte => out.push(byte),
        }
        index += 1;
    }
    String::from_utf8(out).ok()
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
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        413 => "Payload Too Large",
        422 => "Unprocessable Content",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
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
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="color-scheme" content="dark light">
<meta name="referrer" content="no-referrer">
<title>Huntsman Recon</title>
<style>
:root{--bg:#111;--fg:#eee;--dim:#aaa;--line:#444;--acc:#7cc4ff;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;color-scheme:dark}
@media (prefers-color-scheme:light){:root{--bg:#fafafa;--fg:#111;--dim:#555;--line:#ccc;--acc:#0b62a8;color-scheme:light}}
*{box-sizing:border-box}
body{max-width:960px;margin:0 auto;padding:max(12px,env(safe-area-inset-top)) 12px 24px;background:var(--bg);color:var(--fg);font-size:15px}
h1{font-size:18px;margin:0 0 12px}
button,input,select{font:inherit;min-height:44px;padding:8px 10px;border:1px solid var(--line);border-radius:6px;background:transparent;color:inherit}
button{cursor:pointer;border-color:var(--acc);color:var(--acc)}
button:disabled{opacity:.5}
form{display:grid;grid-template-columns:1fr;gap:8px}
@media (min-width:640px){form{grid-template-columns:9em 1fr auto}}
section,details{border:1px solid var(--line);border-radius:6px;padding:10px;margin:10px 0}
summary{cursor:pointer;min-height:32px}
pre{white-space:pre-wrap;overflow-wrap:anywhere;margin:6px 0 0}
table{width:100%;border-collapse:collapse}td,th{border-bottom:1px solid var(--line);padding:4px;text-align:left;vertical-align:top;overflow-wrap:anywhere}
small,.dim{color:var(--dim)}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
</style>
<h1>Huntsman Recon</h1>
<section>
<form id="lookup">
<select id="kind" aria-label="kind">
<option value="auto">auto</option><option value="people">people</option><option value="email">email</option>
<option value="exposure">exposure</option><option value="username">username</option><option value="phone">phone</option>
</select>
<input id="q" required maxlength="512" autocomplete="off" autocapitalize="off" spellcheck="false" enterkeyhint="search" placeholder="name, email, @handle or phone" aria-label="selector">
<button id="run" type="submit">Look up</button>
</form>
<small>Runs one lookup through the same front-ends as the CLI. It makes network requests; exposure spends operator keys.</small>
</section>
<section id="result" hidden>
<div class="row"><b id="route"></b><span id="status" class="dim"></span><button id="download" type="button">Download JSON</button></div>
<table><thead><tr><th>source</th><th>outcome</th><th>found</th></tr></thead><tbody id="outcomes"></tbody></table>
<pre id="text"></pre>
</section>
<details><summary>Server status and token</summary>
<div class="row"><input id="token" type="password" autocomplete="off" placeholder="token (only if configured)" aria-label="token"><button id="refresh" type="button">Refresh</button></div>
<b>Health</b><pre id="health">…</pre>
<b>Reachable modules</b><pre id="modules">…</pre>
<b>Command contract</b><pre id="command">…</pre>
</details>
<script>
const $=id=>document.getElementById(id);
let last=null;
try{$('token').value=sessionStorage.getItem('hse-token')||''}catch(_){}
$('token').onchange=()=>{try{sessionStorage.setItem('hse-token',$('token').value)}catch(_){}};
function headers(extra){const h=Object.assign({},extra);const t=$('token').value;if(t)h.Authorization='Bearer '+t;return h}
async function get(path){const r=await fetch(path,{headers:headers(),cache:'no-store'});return await r.text()}
async function refresh(){
  for(const [id,path] of [['health','/api/health'],['modules','/api/modules'],['command','/api/command']]){
    try{$(id).textContent=await get(path)}catch(e){$(id).textContent=String(e)}
  }
}
function cell(row,text){const td=document.createElement('td');td.textContent=text==null?'':String(text);row.appendChild(td)}
$('lookup').onsubmit=async ev=>{
  ev.preventDefault();
  const q=$('q').value.trim(); if(!q) return;
  const params=new URLSearchParams({kind:$('kind').value,q});
  $('run').disabled=true; $('result').hidden=false; $('route').textContent='';
  $('status').textContent='running…'; $('text').textContent=''; $('outcomes').replaceChildren(); last=null;
  const started=Date.now();
  try{
    const r=await fetch('/api/lookup?'+params,{headers:headers({'X-Huntsman-Lookup':'1'}),cache:'no-store'});
    const body=await r.json();
    const secs=((Date.now()-started)/1000).toFixed(1)+'s';
    if(!r.ok){$('status').textContent='HTTP '+r.status+' · '+secs;$('text').textContent=body.error||'';return}
    last=body; $('route').textContent=body.route;
    $('status').textContent=body.entities.length+' entities · '+secs;
    for(const o of body.outcomes){const tr=document.createElement('tr');cell(tr,o.module);cell(tr,o.kind);cell(tr,o.found);$('outcomes').appendChild(tr)}
    $('text').textContent=body.text;
  }catch(e){$('status').textContent=String(e)}finally{$('run').disabled=false}
};
$('download').onclick=()=>{
  if(!last) return;
  const a=document.createElement('a');
  a.href=URL.createObjectURL(new Blob([JSON.stringify(last,null,2)],{type:'application/json'}));
  a.download='huntsman-'+last.route+'-'+Date.now()+'.json'; a.click(); URL.revokeObjectURL(a.href);
};
$('refresh').onclick=refresh; refresh();
</script>
</html>
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    /// A loopback bind for the pure-router tests. The DNS-rebinding guard is active
    /// for loopback binds, so requests here carry a loopback `Host` or none at all.
    fn loopback_bind() -> SocketAddr {
        "127.0.0.1:8080".parse().unwrap()
    }

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
        let health = response_for_request(
            "GET /api/health HTTP/1.1\r\n\r\n",
            Some("secret"),
            loopback_bind(),
        );
        assert!(health.starts_with("HTTP/1.1 200"));
        assert!(health.contains("\"status\": \"ok\""));

        let denied = response_for_request(
            "GET /api/modules HTTP/1.1\r\n\r\n",
            Some("secret"),
            loopback_bind(),
        );
        assert!(denied.starts_with("HTTP/1.1 401"));

        let allowed = response_for_request(
            "GET /api/modules HTTP/1.1\r\nAuthorization: bearer secret\r\n\r\n",
            Some("secret"),
            loopback_bind(),
        );
        assert!(allowed.starts_with("HTTP/1.1 200"));
        assert!(allowed.contains("\"modules\""));
    }

    #[test]
    fn head_has_get_content_length_but_no_body() {
        let get = response_for_request("GET /api/health HTTP/1.1\r\n\r\n", None, loopback_bind());
        let head = response_for_request("HEAD /api/health HTTP/1.1\r\n\r\n", None, loopback_bind());
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
            response_for_request("REQUEST_TIMEOUT", None, loopback_bind())
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
            response_for_request("REQUEST_TIMEOUT", None, loopback_bind())
                .starts_with("HTTP/1.1 408"),
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

    #[test]
    fn host_allowlist_accepts_only_loopback_authorities() {
        for allowed in [
            "localhost",
            "LOCALHOST",
            "localhost:8080",
            "127.0.0.1",
            "127.0.0.1:8080",
            "127.0.0.5:8080",
            "[::1]",
            "[::1]:8080",
        ] {
            assert!(
                host_is_allowed_for_loopback(Some(allowed)),
                "{allowed} should be allowed"
            );
        }
        assert!(host_is_allowed_for_loopback(None));
        assert!(host_is_allowed_for_loopback(Some("")));
        for denied in [
            "rebind.example.com",
            "127.0.0.1.evil.com",
            "localhost.evil.com",
            "10.0.0.1:8080",
            "evil.com:127.0.0.1",
            "example.com",
        ] {
            assert!(
                !host_is_allowed_for_loopback(Some(denied)),
                "{denied} should be denied"
            );
        }
    }

    #[test]
    fn a_loopback_server_refuses_a_rebound_host_on_every_endpoint() {
        // A page on a public origin rebound to loopback makes the browser send that
        // public name in Host. No endpoint, authenticated or not, may answer it.
        let bind = loopback_bind();
        for path in [
            "/",
            "/index.html",
            "/api/health",
            "/api/modules",
            "/api/command",
        ] {
            let rebound = response_for_request(
                &format!("GET {path} HTTP/1.1\r\nHost: rebind.example.com\r\n\r\n"),
                None,
                bind,
            );
            assert!(
                rebound.starts_with("HTTP/1.1 403 Forbidden"),
                "{path}: {rebound}"
            );
        }
    }

    #[test]
    fn a_loopback_server_still_answers_loopback_and_hostless_requests() {
        let bind = loopback_bind();
        for host in [
            "localhost",
            "localhost:8080",
            "127.0.0.1:8080",
            "[::1]:8080",
        ] {
            let ok = response_for_request(
                &format!("GET /api/health HTTP/1.1\r\nHost: {host}\r\n\r\n"),
                None,
                bind,
            );
            assert!(ok.starts_with("HTTP/1.1 200"), "{host}: {ok}");
        }
        let hostless = response_for_request("GET /api/health HTTP/1.1\r\n\r\n", None, bind);
        assert!(hostless.starts_with("HTTP/1.1 200"), "{hostless}");
    }

    #[test]
    fn the_host_guard_runs_before_authentication() {
        // A rebound request to a protected endpoint is refused for its Host even with a
        // valid token, so the guard never reveals the 200/401 distinction to a
        // disallowed origin.
        let served = response_for_request(
            "GET /api/command HTTP/1.1\r\nHost: evil.example\r\nAuthorization: Bearer secret\r\n\r\n",
            Some("secret"),
            loopback_bind(),
        );
        assert!(served.starts_with("HTTP/1.1 403 Forbidden"), "{served}");
    }

    #[test]
    fn a_public_bind_is_not_subject_to_the_host_guard() {
        // A non-loopback bind is intentionally public and gated by the bearer token; its
        // real Host (a Railway hostname, say) is unknown here, so the guard must not
        // apply or it would refuse every real request.
        let public = "0.0.0.0:8080".parse::<SocketAddr>().unwrap();
        let served = response_for_request(
            "GET /api/health HTTP/1.1\r\nHost: huntsman.up.railway.app\r\n\r\n",
            Some("secret"),
            public,
        );
        assert!(served.starts_with("HTTP/1.1 200"), "{served}");
    }

    fn echo_lookups() -> Lookups {
        Lookups {
            handler: Arc::new(|query: &LookupQuery| {
                assert!(query.selector != "boom", "handler panicked");
                if query.selector == "refused" {
                    return Err(LookupError {
                        status: 422,
                        message: "no".into(),
                    });
                }
                Ok(LookupReport {
                    route: "email",
                    text: format!("{}|{}", query.kind, query.selector),
                    entities: Vec::new(),
                    outcomes: Vec::new(),
                })
            }),
            live: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn lookup(request: &str, token: Option<&str>, lookups: Option<&Lookups>) -> String {
        respond(request, token, loopback_bind(), lookups)
    }

    const HEADER: &str = "X-Huntsman-Lookup: 1\r\n";

    #[test]
    fn lookup_is_absent_until_the_binary_installs_a_handler() {
        let got = lookup(
            &format!("GET /api/lookup?q=a HTTP/1.1\r\nHost: localhost\r\n{HEADER}\r\n"),
            None,
            None,
        );
        assert!(got.starts_with("HTTP/1.1 404"), "{got}");
    }

    #[test]
    fn lookup_decodes_the_query_and_returns_the_report() {
        let lookups = echo_lookups();
        let got = lookup(
            &format!(
                "GET /api/lookup?kind=Email&q=ada%40example.com+x HTTP/1.1\r\nHost: localhost\r\nSec-Fetch-Site: same-origin\r\n{HEADER}\r\n"
            ),
            None,
            Some(&lookups),
        );
        assert!(got.starts_with("HTTP/1.1 200"), "{got}");
        assert!(got.contains(r#""text":"email|ada@example.com x""#), "{got}");
        let auto = lookup(
            &format!("GET /api/lookup?q=x HTTP/1.1\r\n{HEADER}\r\n"),
            None,
            Some(&lookups),
        );
        assert!(auto.contains(r#""text":"auto|x""#), "{auto}");
    }

    #[test]
    fn a_cross_site_or_headerless_lookup_never_reaches_the_handler() {
        let lookups = echo_lookups();
        for request in [
            "GET /api/lookup?q=boom HTTP/1.1\r\nHost: localhost\r\n\r\n".to_owned(),
            format!(
                "GET /api/lookup?q=boom HTTP/1.1\r\nHost: localhost\r\nSec-Fetch-Site: cross-site\r\n{HEADER}\r\n"
            ),
            format!(
                "GET /api/lookup?q=boom HTTP/1.1\r\nHost: localhost\r\nSec-Fetch-Site: same-site\r\n{HEADER}\r\n"
            ),
            "GET /api/lookup?q=boom HTTP/1.1\r\nHost: localhost\r\nX-Huntsman-Lookup: yes\r\n\r\n"
                .to_owned(),
        ] {
            let got = lookup(&request, None, Some(&lookups));
            assert!(got.starts_with("HTTP/1.1 403"), "{request:?} -> {got}");
        }
        let head = lookup(
            &format!("HEAD /api/lookup?q=boom HTTP/1.1\r\n{HEADER}\r\n"),
            None,
            Some(&lookups),
        );
        assert!(head.starts_with("HTTP/1.1 405"), "{head}");
    }

    #[test]
    fn a_configured_token_guards_lookup() {
        let lookups = echo_lookups();
        let request = format!("GET /api/lookup?q=a HTTP/1.1\r\n{HEADER}\r\n");
        assert!(lookup(&request, Some("secret"), Some(&lookups)).starts_with("HTTP/1.1 401"));
        let authed =
            format!("GET /api/lookup?q=a HTTP/1.1\r\nAuthorization: Bearer secret\r\n{HEADER}\r\n");
        assert!(lookup(&authed, Some("secret"), Some(&lookups)).starts_with("HTTP/1.1 200"));
    }

    #[test]
    fn lookup_errors_panics_and_capacity_are_answered_and_slots_are_freed() {
        let lookups = echo_lookups();
        let ask = |q: &str| {
            lookup(
                &format!("GET /api/lookup?q={q} HTTP/1.1\r\n{HEADER}\r\n"),
                None,
                Some(&lookups),
            )
        };
        assert!(ask("refused").starts_with("HTTP/1.1 422"));
        assert!(ask("boom").starts_with("HTTP/1.1 500"));
        assert_eq!(
            lookups.live.load(Ordering::Acquire),
            0,
            "a panic frees its slot"
        );
        assert!(ask("").starts_with("HTTP/1.1 400"));
        assert!(ask(&"a".repeat(MAX_SELECTOR_BYTES + 1)).starts_with("HTTP/1.1 400"));
        lookups.live.store(MAX_LOOKUPS, Ordering::Release);
        assert!(ask("a").starts_with("HTTP/1.1 503"));
        lookups.live.store(0, Ordering::Release);
        assert!(ask("a").starts_with("HTTP/1.1 200"));
    }

    #[test]
    fn percent_decoding_is_strict() {
        assert_eq!(percent_decode("a+b%40c").as_deref(), Some("a b@c"));
        assert_eq!(percent_decode("%C3%A9").as_deref(), Some("\u{e9}"));
        for bad in ["%+1", "%zz", "%4", "%", "%FF"] {
            assert_eq!(percent_decode(bad), None, "{bad}");
        }
    }

    #[test]
    fn the_page_never_writes_provider_text_as_markup() {
        assert!(!INDEX_HTML.contains("innerHTML"));
        assert!(!INDEX_HTML.contains("insertAdjacentHTML"));
        assert!(INDEX_HTML.contains("'X-Huntsman-Lookup':'1'"));
    }
}
