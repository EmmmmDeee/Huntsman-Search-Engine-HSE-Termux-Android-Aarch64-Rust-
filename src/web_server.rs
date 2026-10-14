//! Minimal embedded Web UI and HTTP API for Huntsman Recon.
//!
//! The default bind is loopback-only. Explicit non-loopback binds require a
//! non-empty bearer token supplied by the caller. The server is dependency-free,
//! blocking and bounded per request. It exposes read-only metadata endpoints and, when the
//! binary installs a [`LookupHandler`], `GET /api/lookup`, which runs one lookup through the
//! same front-ends as the CLI. A lookup spends network egress and operator keys, so it needs
//! the `X-Huntsman-Lookup` header (a page on another origin cannot send it without a CORS
//! preflight this server never approves) and is refused when the browser marks it cross-site.
//! When the binary installs an [`AnalyzeHandler`], `GET /api/analyze` runs the offline
//! investigation spine on a list of seeds and returns its multi-hop result: the entities, the
//! links between them, the next pivots, the correlations and the planned sources. It makes no
//! network request and spends no key, so it needs no lookup header, but it is still refused
//! cross-site and, on a public bind, needs the token.
//! A loopback bind answers only requests whose `Host` is a loopback authority,
//! which blocks a browser DNS-rebinding attack from reaching the local API.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::base64;
use crate::engineering_command;
use crate::entity::Entity;
use crate::error::Error;
use crate::module::reachable_modules;
use crate::sha256::sha256;
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
/// The seeds of the largest analysis the server admits, as they arrive: percent-encoded, three bytes
/// for each byte that is not ASCII, with `%0A` between them (24 KiB).
const LARGEST_ANALYSIS_SEEDS: usize =
    MAX_ANALYZE_SEEDS * MAX_SELECTOR_BYTES * 3 + (MAX_ANALYZE_SEEDS - 1) * 3;
/// What a request carries besides its analysis seeds: the rest of the request line, a browser's
/// headers and a bearer token.
const HEADER_ALLOWANCE: usize = 8 * 1024;
/// Request line and headers of one request (33 KiB). It is derived from the analysis limits, so the
/// largest analysis the server admits always fits, with the header allowance.
const MAX_REQUEST_BYTES: usize = (LARGEST_ANALYSIS_SEEDS + HEADER_ALLOWANCE).next_multiple_of(1024);
const IO_TIMEOUT: Duration = Duration::from_secs(5);
/// Whole-request wall-clock budget. The per-read `IO_TIMEOUT` restarts on every successful
/// read, so it alone cannot bound a client that dribbles a byte at a time; this absolute
/// deadline caps the total time spent reading one request.
const REQUEST_DEADLINE: Duration = Duration::from_secs(10);
/// Connections served at once. A phone browser opens several for one page, and some are speculative
/// and idle, so each connection gets its own thread: one that sends nothing holds up only itself.
/// A connection past the cap first closes the connection that has waited longest without a whole
/// request, if it has waited [`IDLE_GRACE`]; when none has, it is answered `503` at once.
const MAX_CONNECTIONS: usize = 32;
/// How long a connection may wait without a whole request before a connection that finds every
/// place taken may close it. A browser sends its request as soon as it connects, except on a
/// speculative connection, which it replaces when it needs one.
const IDLE_GRACE: Duration = Duration::from_secs(1);
/// The handler formats short strings, so a small stack is enough, and it keeps a full set of
/// connection threads cheap on a phone.
const HANDLER_STACK_BYTES: usize = 256 * 1024;
/// Lookups running at once. Each one holds sockets to several providers for up to two minutes,
/// so a phone gets a small, fixed number; one past the cap is answered `503`.
const MAX_LOOKUPS: usize = 2;
/// A lookup does TLS and JSON decoding, which the small connection stack is not sized for, so it
/// runs on its own thread with this stack.
const LOOKUP_STACK_BYTES: usize = 4 * 1024 * 1024;
/// Longest decoded `q` accepted by `/api/lookup`, and longest seed accepted by `/api/analyze`.
const MAX_SELECTOR_BYTES: usize = 512;
/// Seeds in one `/api/analyze` request. The spine is offline and bounded by its own limits; this
/// caps what one request can ask of a phone.
const MAX_ANALYZE_SEEDS: usize = 16;
/// An analysis builds the entity graph, runs the correlation rules and encodes the report, which
/// the small connection stack is not sized for, so, like a lookup, it runs on its own thread with
/// this stack. It holds no socket and finishes in milliseconds, so the connection cap bounds how
/// many run at once.
const ANALYZE_STACK_BYTES: usize = 4 * 1024 * 1024;
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

/// Runs the offline multi-hop analysis of the seeds and returns its report as JSON. Installed by
/// the binary, which owns the investigation spine; the error carries the HTTP status to answer.
pub type AnalyzeHandler =
    Arc<dyn Fn(&[String]) -> Result<serde_json::Value, LookupError> + Send + Sync>;

/// The routes a binary installs. A route whose handler is absent answers `404`.
#[derive(Clone, Default)]
struct Routes {
    lookups: Option<Lookups>,
    analyze: Option<AnalyzeHandler>,
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
    routes: Routes,
}

impl Server {
    /// Bind the configured address.
    ///
    /// # Errors
    /// Returns a storage-class I/O error when the listener cannot bind.
    pub fn bind(config: ServeConfig) -> Result<Self, Error> {
        let listener =
            TcpListener::bind(config.bind).map_err(|error| bind_failure(config.bind, &error))?;
        Ok(Self {
            listener,
            config,
            routes: Routes::default(),
        })
    }

    /// Serve `GET /api/lookup` through `handler`. Without this the route answers `404`.
    #[must_use]
    pub fn with_lookup(mut self, handler: LookupHandler) -> Self {
        self.routes.lookups = Some(Lookups {
            handler,
            live: Arc::new(AtomicUsize::new(0)),
        });
        self
    }

    /// Serve `GET /api/analyze` through `handler`. Without this the route answers `404`.
    #[must_use]
    pub fn with_analyze(mut self, handler: AnalyzeHandler) -> Self {
        self.routes.analyze = Some(handler);
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
    /// own thread, up to [`MAX_CONNECTIONS`] at a time. A failed `accept` that a later one can
    /// succeed after (no free file descriptor or memory, a connection reset before it was taken)
    /// pauses the loop instead of ending it; see [`AcceptFailure`]. `notice` hears the first
    /// failure of each such run, so the process boundary can say why requests are waiting.
    ///
    /// # Errors
    /// Returns the listener error that stops the loop.
    pub fn run(&self, mut notice: impl FnMut(&std::io::Error)) -> Result<(), Error> {
        let shared = Arc::new((self.config.clone(), self.routes.clone()));
        let live = Arc::new(AtomicUsize::new(0));
        let idle = Arc::new(Idle::default());
        let mut failures = AcceptFailures::default();
        loop {
            match self.listener.accept() {
                Ok((stream, _)) => {
                    failures.recovered();
                    serve_on_a_thread(&shared, &live, &idle, stream);
                }
                Err(error) => match AcceptFailure::of(&error) {
                    AcceptFailure::Fatal => {
                        return Err(Error::Store(format!("serve accept: {error}")));
                    }
                    AcceptFailure::Transient => {
                        if failures.is_first() {
                            notice(&error);
                        }
                        thread::sleep(failures.pause());
                    }
                },
            }
        }
    }

    #[cfg(test)]
    fn run_n(&self, count: usize) -> Result<(), Error> {
        for _ in 0..count {
            let (stream, _) = self
                .listener
                .accept()
                .map_err(|error| Error::Store(format!("serve accept: {error}")))?;
            handle_stream_with(&self.config, &self.routes, stream, None)?;
        }
        Ok(())
    }
}

/// What a failed `accept` means for the loop.
#[derive(Debug, PartialEq, Eq)]
enum AcceptFailure {
    /// The listener itself is unusable, so no later `accept` can succeed.
    Fatal,
    /// The process or system is short of something (file descriptors when every connection
    /// thread holds some, memory under Android's pressure) or the one pending connection went
    /// away. Connections finishing free what was short, so a later `accept` succeeds.
    Transient,
}

/// `EBADF`, the same number on Linux, Android, the BSDs and macOS.
const EBADF: i32 = 9;

impl AcceptFailure {
    fn of(error: &std::io::Error) -> Self {
        // An invalid or non-listening socket (EINVAL, ENOTSOCK, EOPNOTSUPP map to InvalidInput
        // or Unsupported) and a closed descriptor never recover; everything else is about the
        // moment, not the listener.
        match error.kind() {
            std::io::ErrorKind::InvalidInput | std::io::ErrorKind::Unsupported => Self::Fatal,
            _ if error.raw_os_error() == Some(EBADF) => Self::Fatal,
            _ => Self::Transient,
        }
    }
}

/// The pause after each failed `accept` in a row: it doubles from [`ACCEPT_PAUSE_FIRST`] to
/// [`ACCEPT_PAUSE_MOST`], so a shortage is not met with a busy loop.
#[derive(Default)]
struct AcceptFailures {
    in_a_row: u32,
}

const ACCEPT_PAUSE_FIRST: Duration = Duration::from_millis(10);
const ACCEPT_PAUSE_MOST: Duration = Duration::from_millis(500);

impl AcceptFailures {
    fn is_first(&self) -> bool {
        self.in_a_row == 0
    }

    fn pause(&mut self) -> Duration {
        let pause = ACCEPT_PAUSE_FIRST
            .saturating_mul(1 << self.in_a_row.min(16))
            .min(ACCEPT_PAUSE_MOST);
        self.in_a_row = self.in_a_row.saturating_add(1);
        pause
    }

    fn recovered(&mut self) {
        self.in_a_row = 0;
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

/// The connections still waiting for a whole request, in the order they arrived, each with a
/// handle that can close it. Connections that send nothing, a browser's speculative ones or a
/// local app's on purpose, would otherwise keep every request out for the whole read budget.
#[derive(Default)]
struct Idle {
    next: AtomicU64,
    waiting: Mutex<VecDeque<(u64, Instant, TcpStream)>>,
}

impl Idle {
    fn waiting(&self) -> MutexGuard<'_, VecDeque<(u64, Instant, TcpStream)>> {
        self.waiting.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Note a connection that is about to read its request; it is forgotten when the returned
    /// guard drops. A connection whose socket cannot be duplicated is never closed early.
    fn wait(self: &Arc<Self>, stream: &TcpStream) -> Option<Waiting> {
        let handle = stream.try_clone().ok()?;
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        self.waiting().push_back((id, Instant::now(), handle));
        Some(Waiting {
            idle: Arc::clone(self),
            id,
        })
    }

    /// Close the connection that has waited longest, if it has waited `grace`. Its read ends at
    /// once, and its thread lets its place go.
    fn close_longest_waiting(&self, grace: Duration) -> bool {
        let mut waiting = self.waiting();
        if waiting
            .front()
            .is_none_or(|(_, since, _)| since.elapsed() < grace)
        {
            return false;
        }
        waiting
            .pop_front()
            .is_some_and(|(_, _, handle)| handle.shutdown(Shutdown::Both).is_ok())
    }
}

/// A connection noted in [`Idle`]; dropping it, once the request is read, forgets the connection.
struct Waiting {
    idle: Arc<Idle>,
    id: u64,
}

impl Drop for Waiting {
    fn drop(&mut self) {
        self.idle.waiting().retain(|(id, _, _)| *id != self.id);
    }
}

/// The place a closed connection gives back, once its thread has let it go: at once, as a rule.
fn place_freed_by_closing(live: &Arc<AtomicUsize>) -> Option<Slot> {
    for _ in 0..50 {
        if let Some(slot) = Slot::take(live) {
            return Some(slot);
        }
        thread::sleep(Duration::from_millis(2));
    }
    None
}

type Shared = (ServeConfig, Routes);

fn serve_on_a_thread(
    shared: &Arc<Shared>,
    live: &Arc<AtomicUsize>,
    idle: &Arc<Idle>,
    stream: TcpStream,
) {
    let slot = match Slot::take(live) {
        Some(slot) => slot,
        None if idle.close_longest_waiting(IDLE_GRACE) => match place_freed_by_closing(live) {
            Some(slot) => slot,
            None => return refuse_busy(stream),
        },
        None => return refuse_busy(stream),
    };
    // The thread owns the stream; this copy lets a failed spawn still answer the client.
    let fallback = stream.try_clone().ok();
    let waiting = idle.wait(&stream);
    let shared = Arc::clone(shared);
    let spawned = thread::Builder::new()
        .name("serve-connection".into())
        .stack_size(HANDLER_STACK_BYTES)
        .spawn(move || {
            let _slot = slot;
            let _handled = handle_stream_with(&shared.0, &shared.1, stream, waiting);
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
    handle_stream_with(config, &Routes::default(), stream, None)
}

fn handle_stream_with(
    config: &ServeConfig,
    routes: &Routes,
    mut stream: TcpStream,
    waiting: Option<Waiting>,
) -> Result<(), Error> {
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|error| Error::Store(format!("serve read timeout: {error}")))?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|error| Error::Store(format!("serve write timeout: {error}")))?;

    let deadline = Instant::now() + REQUEST_DEADLINE;
    let request = read_request(&mut stream, deadline)?;
    // A whole request: the connection is busy now, not idle, and is no longer closed early.
    drop(waiting);
    let response = respond(
        &request,
        config.bearer_token.as_deref(),
        config.bind,
        routes,
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
        // Only the new bytes, and the three before them, can complete the blank line that ends
        // the head: scanning the whole buffer after every read was quadratic in its length.
        let scan_from = bytes.len().saturating_sub(3);
        bytes.extend_from_slice(&chunk[..read]);
        if bytes[scan_from..]
            .windows(4)
            .any(|window| window == b"\r\n\r\n")
        {
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
    respond(request, bearer_token, bind, &Routes::default())
}

fn respond(request: &str, bearer_token: Option<&str>, bind: SocketAddr, routes: &Routes) -> String {
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
    let protected = matches!(
        parsed.path,
        "/api/modules" | "/api/command" | "/api/lookup" | "/api/analyze"
    );
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
        "/api/lookup" => lookup_response(&parsed, routes.lookups.as_ref()),
        "/api/analyze" => analyze_response(&parsed, routes.analyze.as_ref()),
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

/// `GET /api/analyze?seeds=…`: the offline multi-hop analysis of up to [`MAX_ANALYZE_SEEDS`]
/// seeds, one per line. It is refused cross-site like a lookup, but needs no lookup header: it
/// makes no network request and spends no key.
fn analyze_response(parsed: &ParsedRequest<'_>, analyze: Option<&AnalyzeHandler>) -> String {
    let Some(analyze) = analyze else {
        return json_error(404, "analysis is not enabled on this server");
    };
    if parsed.method != Method::Get {
        return json_error(405, "analysis needs GET");
    }
    if parsed
        .sec_fetch_site
        .is_some_and(|site| !matches!(site, "same-origin" | "none"))
    {
        return json_error(403, "cross-site analysis refused");
    }
    let seeds = match parse_analyze_seeds(parsed.query) {
        Ok(seeds) => seeds,
        Err(message) => return json_error(400, &message),
    };
    let handler = Arc::clone(analyze);
    let worker = thread::Builder::new()
        .name("serve-analyze".into())
        .stack_size(ANALYZE_STACK_BYTES)
        .spawn(move || handler(&seeds));
    let outcome = match worker {
        Ok(worker) => worker.join(),
        Err(_) => return json_error(503, "could not start an analysis worker"),
    };
    match outcome {
        Ok(Ok(report)) => response(
            200,
            "application/json; charset=utf-8",
            &format!("{report}\n"),
            false,
        ),
        Ok(Err(error)) => json_error(error.status, &error.message),
        Err(_) => json_error(500, "analysis failed unexpectedly"),
    }
}

/// The seeds in a query's `seeds` value, one per line: each is trimmed and blank lines are
/// dropped. Unknown keys are ignored.
fn parse_analyze_seeds(raw: &str) -> Result<Vec<String>, String> {
    let mut text = String::new();
    for pair in raw.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if key == "seeds" {
            text = percent_decode(value)
                .ok_or_else(|| "query is not valid percent-encoded UTF-8".to_owned())?;
        }
    }
    let seeds: Vec<String> = text
        .lines()
        .map(str::trim)
        .filter(|seed| !seed.is_empty())
        .map(str::to_owned)
        .collect();
    if seeds.is_empty() {
        return Err("analysis needs seeds, one per line".to_owned());
    }
    if seeds.len() > MAX_ANALYZE_SEEDS {
        return Err(format!("analysis takes at most {MAX_ANALYZE_SEEDS} seeds"));
    }
    if seeds.iter().any(|seed| seed.len() > MAX_SELECTOR_BYTES) {
        return Err(format!("a seed is longer than {MAX_SELECTOR_BYTES} bytes"));
    }
    Ok(seeds)
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

/// Why `addr` could not be bound, and what to do about it. Port 8080 is also the default of other
/// servers people run in Termux, and Termux has no root for a port below 1024.
fn bind_failure(addr: SocketAddr, error: &std::io::Error) -> Error {
    let other_port = match addr {
        SocketAddr::V4(v4) => format!("{}:PORT", v4.ip()),
        SocketAddr::V6(v6) => format!("[{}]:PORT", v6.ip()),
    };
    let reason = match error.kind() {
        std::io::ErrorKind::AddrInUse => format!(
            "another program already listens there; stop it, or pass --bind {other_port} for another port (port 0 picks a free one)"
        ),
        std::io::ErrorKind::PermissionDenied if addr.port() < 1024 => format!(
            "a port below 1024 needs root, which Termux does not have; pass --bind {other_port} with a port of 1024 or more"
        ),
        _ => error.to_string(),
    };
    Error::Store(format!("serve bind {addr}: {reason}"))
}

/// The page's policy. Its one inline script and its one inline style run because their SHA-256
/// is listed, so injected markup cannot run script. Nothing loads from elsewhere, requests go
/// only to this server, and no other page may frame it. Without that last rule, a site open in
/// the same phone browser could lay this page under its own and turn taps into lookups that
/// spend the operator's keys.
static PAGE_POLICY: LazyLock<String> = LazyLock::new(|| {
    format!(
        "default-src 'none'; script-src '{}'; style-src '{}'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        hash_source(inline_block(INDEX_HTML, "script")),
        hash_source(inline_block(INDEX_HTML, "style")),
    )
});

/// Every other response loads nothing and may not be framed.
const OTHER_POLICY: &str = "default-src 'none'; frame-ancestors 'none'";

/// The text between `<tag>` and `</tag>`, the part a browser hashes for a CSP hash source.
fn inline_block<'a>(page: &'a str, tag: &str) -> &'a str {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    match (page.find(&open), page.find(&close)) {
        (Some(start), Some(end)) if start + open.len() <= end => &page[start + open.len()..end],
        _ => "",
    }
}

fn hash_source(content: &str) -> String {
    format!("sha256-{}", base64::standard(&sha256(content.as_bytes())))
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
    let policy = if content_type.starts_with("text/html") {
        PAGE_POLICY.as_str()
    } else {
        OTHER_POLICY
    };
    format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {content_length}\r\n{retry_after}Cache-Control: no-store\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nContent-Security-Policy: {policy}\r\n\r\n{rendered_body}"
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
button,input,select,textarea{font:inherit;min-height:44px;padding:8px 10px;border:1px solid var(--line);border-radius:6px;background:transparent;color:inherit}
button{cursor:pointer;border-color:var(--acc);color:var(--acc)}
button:disabled{opacity:.5}
form{display:grid;grid-template-columns:1fr;gap:8px}
@media (min-width:640px){form{grid-template-columns:9em 1fr auto}#analyze{grid-template-columns:1fr auto}}
textarea{width:100%;resize:vertical}
h2{font-size:15px;margin:12px 0 4px}
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
<section>
<form id="analyze">
<textarea id="seeds" required rows="4" maxlength="2048" autocomplete="off" autocapitalize="off" spellcheck="false" placeholder="a seed per line: name, email, @handle, phone or domain" aria-label="seeds"></textarea>
<button id="arun" type="submit">Analyze</button>
</form>
<small>Multi-hop analysis, offline: links the seeds, ranks the next pivots, names the gaps and plans the sources, with no network request and no key.</small>
</section>
<section id="aresult" hidden>
<div class="row"><b id="asummary"></b><span id="astatus" class="dim"></span><button id="adownload" type="button">Download JSON</button></div>
<h2>Entities</h2>
<table><thead><tr><th>kind</th><th>value</th><th>confidence</th></tr></thead><tbody id="aentities"></tbody></table>
<h2>Links</h2>
<table><thead><tr><th>from</th><th>relation</th><th>to</th></tr></thead><tbody id="arelations"></tbody></table>
<h2>Next pivots</h2>
<table><thead><tr><th>entity</th><th>links</th><th>reach</th><th>cut point</th></tr></thead><tbody id="apivots"></tbody></table>
<h2>Correlations</h2>
<table><thead><tr><th>rule</th><th>severity</th><th>finding</th><th>entities</th></tr></thead><tbody id="acorrelations"></tbody></table>
<small id="anote" class="dim"></small>
<h2>Gaps</h2>
<table><thead><tr><th>seed</th><th>isolation</th><th>next step</th></tr></thead><tbody id="agaps"></tbody></table>
<h2>Planned sources</h2>
<table><thead><tr><th>target</th><th>source</th><th>route</th><th>utility</th></tr></thead><tbody id="aplanned"></tbody></table>
<h2>Rejected seeds</h2>
<table><thead><tr><th>seed</th><th>reason</th></tr></thead><tbody id="arejected"></tbody></table>
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
async function call(path,extra){const r=await fetch(path,{headers:headers(extra),cache:'no-store'});const text=await r.text();let body=null;try{body=JSON.parse(text)}catch(_){}return {r,text,body}}
const reason=({text,body})=>(body&&body.error)||text.trim();
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
    const res=await call('/api/lookup?'+params,{'X-Huntsman-Lookup':'1'}),body=res.body;
    const secs=((Date.now()-started)/1000).toFixed(1)+'s';
    if(!res.r.ok||!body){$('status').textContent='HTTP '+res.r.status+' · '+secs;$('text').textContent=reason(res);return}
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
let alast=null;
const show=v=>v==null?'':typeof v==='object'?JSON.stringify(v):String(v);
function fill(id,items,cols){const tb=$(id);tb.replaceChildren();for(const it of items){const tr=document.createElement('tr');for(const c of cols(it))cell(tr,c);tb.appendChild(tr)}}
$('analyze').onsubmit=async ev=>{
  ev.preventDefault();
  const seeds=$('seeds').value.trim(); if(!seeds) return;
  $('arun').disabled=true; $('aresult').hidden=false; $('asummary').textContent=''; $('anote').textContent='';
  $('astatus').textContent='analyzing…'; alast=null;
  for(const id of ['aentities','arelations','apivots','acorrelations','agaps','aplanned','arejected']) $(id).replaceChildren();
  try{
    const res=await call('/api/analyze?'+new URLSearchParams({seeds})),body=res.body;
    if(!res.r.ok||!body){$('astatus').textContent='HTTP '+res.r.status+' · '+reason(res);return}
    alast=body;
    const names=new Map(body.entities.map(e=>[e.uid,show(e.kind)+': '+e.value]));
    const who=uid=>names.get(uid)||uid;
    $('asummary').textContent=body.accepted.length+' seeds · '+body.entities.length+' entities · '+body.relations.length+' links';
    $('astatus').textContent=body.gaps.linked_seeds+' of '+body.gaps.total_seeds+' seeds linked · '+show(body.termination);
    fill('aentities',body.entities,e=>[show(e.kind),e.value,Number(e.confidence).toFixed(2)]);
    fill('arelations',body.relations,x=>[who(x.from_uid),show(x.kind),who(x.to_uid)]);
    fill('apivots',body.pivots,p=>[who(p.uid),p.degree,p.reachable,p.articulation?'yes':'']);
    fill('acorrelations',body.correlations,c=>[c.rule_id+' '+c.rule_name,show(c.severity),c.description,c.entity_uids.map(who).join(', ')]);
    $('anote').textContent=body.correlations.length?'Correlations over entered seeds describe the links derived from them; each stays a hypothesis until a source corroborates it.':'No correlation: the seeds share no derived link.';
    fill('agaps',body.gaps.orphans,o=>[who(o.uid),show(o.isolation),o.action]);
    fill('aplanned',body.planned,p=>[show(p.kind)+': '+p.value,p.source,p.url||'',p.utility==null?'':Number(p.utility).toFixed(2)]);
    fill('arejected',body.rejected,x=>[x.seed,x.reason]);
  }catch(e){$('astatus').textContent=String(e)}finally{$('arun').disabled=false}
};
$('adownload').onclick=()=>{
  if(!alast) return;
  const a=document.createElement('a');
  a.href=URL.createObjectURL(new Blob([JSON.stringify(alast,null,2)],{type:'application/json'}));
  a.download='huntsman-analysis-'+Date.now()+'.json'; a.click(); URL.revokeObjectURL(a.href);
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

    /// Running out of descriptors or memory, or losing the pending connection, must not end
    /// `serve`; only a listener that can never accept again does.
    #[test]
    fn only_an_unusable_listener_ends_the_accept_loop() {
        use std::io::{Error as IoError, ErrorKind};
        // Linux and Android numbers: EMFILE, ENFILE, ENOMEM, ENOBUFS, ECONNABORTED, EPROTO, EPERM.
        for raw in [24, 23, 12, 105, 103, 71, 1] {
            assert_eq!(
                AcceptFailure::of(&IoError::from_raw_os_error(raw)),
                AcceptFailure::Transient,
                "errno {raw}"
            );
        }
        for kind in [
            ErrorKind::Interrupted,
            ErrorKind::ConnectionAborted,
            ErrorKind::WouldBlock,
            ErrorKind::OutOfMemory,
        ] {
            assert_eq!(
                AcceptFailure::of(&IoError::from(kind)),
                AcceptFailure::Transient
            );
        }
        assert_eq!(
            AcceptFailure::of(&IoError::from_raw_os_error(EBADF)),
            AcceptFailure::Fatal
        );
        // EINVAL: the socket is not listening.
        assert_eq!(
            AcceptFailure::of(&IoError::from_raw_os_error(22)),
            AcceptFailure::Fatal
        );
        assert_eq!(
            AcceptFailure::of(&IoError::from(ErrorKind::Unsupported)),
            AcceptFailure::Fatal
        );
    }

    #[test]
    fn accept_pauses_back_off_to_a_ceiling_and_reset_on_success() {
        let mut failures = AcceptFailures::default();
        assert!(failures.is_first());
        let pauses: Vec<_> = (0..12).map(|_| failures.pause()).collect();
        assert!(!failures.is_first());
        assert_eq!(pauses[0], ACCEPT_PAUSE_FIRST);
        assert!(pauses.windows(2).all(|pair| pair[0] <= pair[1]));
        assert_eq!(pauses[11], ACCEPT_PAUSE_MOST);
        failures.recovered();
        assert!(failures.is_first());
        assert_eq!(failures.pause(), ACCEPT_PAUSE_FIRST);
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
            let _ = server.run(|_| {});
        });
        addr
    }

    /// The largest analysis the server admits, every seed byte percent-encoded, sent with headers
    /// that fill the allowance: the whole request is read and answered. With the 16 KiB request
    /// cap it was refused `413`, and so was the page's own longest input (2,048 CJK characters).
    #[test]
    fn the_largest_admitted_analysis_is_read_whole() {
        use std::fmt::Write as _;

        let mut server = Server::bind(ServeConfig::parse("127.0.0.1:0", None).unwrap()).unwrap();
        server.routes = echo_seeds();
        let addr = server.local_addr().unwrap();
        thread::spawn(move || {
            let _ = server.run(|_| {});
        });
        let seed = "é".repeat(MAX_SELECTOR_BYTES / 2);
        assert_eq!(seed.len(), MAX_SELECTOR_BYTES);
        let encoded = seed.bytes().fold(String::new(), |mut encoded, byte| {
            write!(encoded, "%{byte:02X}").unwrap();
            encoded
        });
        let head = format!(
            "GET /api/analyze?seeds={} HTTP/1.1\r\nHost: localhost\r\nSec-Fetch-Site: same-origin\r\nX-Pad: ",
            vec![encoded; MAX_ANALYZE_SEEDS].join("%0A")
        );
        let bound = LARGEST_ANALYSIS_SEEDS + HEADER_ALLOWANCE;
        let request = format!("{head}{}\r\n\r\n", "p".repeat(bound - head.len() - 4));
        assert_eq!(request.len(), bound);
        assert!(request.len() > 16 * 1024);

        let mut client = TcpStream::connect(addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        client.write_all(request.as_bytes()).unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{}", &response[..80]);
        let body: serde_json::Value =
            serde_json::from_str(&response[response.find("\r\n\r\n").unwrap() + 4..]).unwrap();
        assert_eq!(
            body["seeds"],
            serde_json::json!(vec![seed; MAX_ANALYZE_SEEDS])
        );
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

    /// Connections that send nothing, in every place for longer than `IDLE_GRACE`, kept every
    /// request out for the whole read budget: `503` for 5 s, and for as long as someone renews
    /// them (any app on the phone can open loopback connections). A request that finds every
    /// place taken now closes the connection that has waited longest, and is served; the other
    /// idle connections keep their places.
    #[test]
    fn a_request_at_the_cap_closes_the_longest_waiting_connection() {
        let addr = serve_in_background();
        let mut idle: Vec<TcpStream> = (0..MAX_CONNECTIONS)
            .map(|_| TcpStream::connect(addr).unwrap())
            .collect();
        thread::sleep(IDLE_GRACE + Duration::from_millis(200));

        let started = Instant::now();
        let response = get_within(addr, "/api/health", Duration::from_secs(3)).unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(started.elapsed() < IDLE_GRACE, "{:?}", started.elapsed());

        let mut byte = [0_u8; 1];
        idle[0]
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        assert_eq!(
            idle[0].read(&mut byte).unwrap(),
            0,
            "the longest waiting connection is closed"
        );
        idle[1]
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let next = idle[1].read(&mut byte).unwrap_err().kind();
        assert!(
            matches!(
                next,
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ),
            "the next one still waits: {next:?}"
        );
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
        let routes = Routes {
            lookups: lookups.cloned(),
            analyze: None,
        };
        respond(request, token, loopback_bind(), &routes)
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

    fn header<'a>(response: &'a str, name: &str) -> Option<&'a str> {
        response
            .split("\r\n\r\n")
            .next()?
            .lines()
            .find_map(|line| line.strip_prefix(name)?.strip_prefix(": "))
    }

    #[test]
    fn a_bind_failure_names_its_cause_and_what_to_pass_instead() {
        use std::io::{Error as IoError, ErrorKind};
        let v4: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let low: SocketAddr = "0.0.0.0:80".parse().unwrap();
        let v6: SocketAddr = "[::1]:8080".parse().unwrap();
        assert_eq!(
            bind_failure(v4, &IoError::from(ErrorKind::AddrInUse)).to_string(),
            "store: serve bind 127.0.0.1:8080: another program already listens there; stop it, or pass --bind 127.0.0.1:PORT for another port (port 0 picks a free one)"
        );
        assert!(
            bind_failure(v6, &IoError::from(ErrorKind::AddrInUse))
                .to_string()
                .contains("pass --bind [::1]:PORT")
        );
        assert_eq!(
            bind_failure(low, &IoError::from(ErrorKind::PermissionDenied)).to_string(),
            "store: serve bind 0.0.0.0:80: a port below 1024 needs root, which Termux does not have; pass --bind 0.0.0.0:PORT with a port of 1024 or more"
        );
        // Above 1024 a refusal is not about root, and other failures keep the system's words.
        let refused = IoError::from(ErrorKind::PermissionDenied);
        assert_eq!(
            bind_failure(v4, &refused).to_string(),
            format!("store: serve bind 127.0.0.1:8080: {refused}")
        );
        let other = IoError::from(ErrorKind::AddrNotAvailable);
        assert_eq!(
            bind_failure(v4, &other).to_string(),
            format!("store: serve bind 127.0.0.1:8080: {other}")
        );
    }

    #[test]
    fn every_response_refuses_framing_and_outside_loads() {
        for request in [
            "GET / HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n",
            "HEAD / HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n",
            "GET /api/health HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n",
            "GET /api/modules HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n",
            "GET /missing HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: evil.example\r\n\r\n",
            "REQUEST_TOO_LARGE",
        ] {
            let response = response_for_request(request, None, loopback_bind());
            assert_eq!(
                header(&response, "X-Frame-Options"),
                Some("DENY"),
                "{request}"
            );
            let policy = header(&response, "Content-Security-Policy").unwrap_or_default();
            assert!(
                policy.starts_with("default-src 'none';"),
                "{request}: {policy}"
            );
            assert!(
                policy.ends_with("frame-ancestors 'none'"),
                "{request}: {policy}"
            );
        }
    }

    #[test]
    fn the_page_policy_allows_exactly_the_page_inline_script_and_style() {
        let response = response_for_request(
            "GET / HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n",
            None,
            loopback_bind(),
        );
        let policy = header(&response, "Content-Security-Policy").unwrap();
        // Hashes of what a browser hashes: the exact text inside each element.
        let between = |open: &str, close: &str| {
            let start = INDEX_HTML.find(open).unwrap() + open.len();
            let end = INDEX_HTML.find(close).unwrap();
            crate::base64::standard(&crate::sha256::sha256(&INDEX_HTML.as_bytes()[start..end]))
        };
        assert!(
            policy.contains(&format!(
                "script-src 'sha256-{}';",
                between("<script>", "</script>")
            )),
            "{policy}"
        );
        assert!(
            policy.contains(&format!(
                "style-src 'sha256-{}';",
                between("<style>", "</style>")
            )),
            "{policy}"
        );
        assert!(policy.contains("connect-src 'self';"), "{policy}");
        assert!(!policy.contains("unsafe"), "{policy}");
    }

    /// The hashes cover the two inline blocks and nothing else. A second block, an inline event
    /// handler, a `style` attribute or a `javascript:` URL would be blocked by the policy, and the
    /// page would break in the browser with nothing failing here.
    #[test]
    fn the_page_keeps_only_what_its_policy_allows() {
        assert_eq!(INDEX_HTML.matches("<script").count(), 1);
        assert_eq!(INDEX_HTML.matches("<style").count(), 1);
        assert!(INDEX_HTML.contains("<script>") && INDEX_HTML.contains("<style>"));
        let script = inline_block(INDEX_HTML, "script");
        let style = inline_block(INDEX_HTML, "style");
        assert!(!script.trim().is_empty() && !style.trim().is_empty());
        assert!(!INDEX_HTML.to_ascii_lowercase().contains("javascript:"));
        // The markup outside the two blocks: every attribute of every tag.
        let markup = INDEX_HTML.replace(script, "").replace(style, "");
        let attributes: Vec<String> = markup
            .split('<')
            .skip(1)
            .filter_map(|tag| tag.split('>').next())
            .flat_map(|tag| tag.split_whitespace().skip(1).map(str::to_ascii_lowercase))
            .collect();
        assert!(!attributes.is_empty());
        for attribute in &attributes {
            let name = attribute.split('=').next().unwrap_or_default();
            assert!(
                !(name.starts_with("on") && name.len() > 2) && name != "style",
                "the policy would block attribute {attribute:?}"
            );
        }
    }

    #[test]
    fn the_page_never_writes_provider_text_as_markup() {
        assert!(!INDEX_HTML.contains("innerHTML"));
        assert!(!INDEX_HTML.contains("insertAdjacentHTML"));
        assert!(INDEX_HTML.contains("'X-Huntsman-Lookup':'1'"));
    }

    /// Some refusals are plain text, not JSON: `503 busy` at the connection cap, `413` for an
    /// oversized request, `408`. The page parsed every answer as JSON before reading its status,
    /// so it showed a parser error instead of the refusal. It now reads each answer as text and
    /// parses JSON only when it can (checked in Chromium: a `413` reads `HTTP 413 · request too
    /// large`, where it read `SyntaxError: Unexpected token 'r'`).
    #[test]
    fn the_page_reads_a_plain_text_refusal() {
        let script = inline_block(INDEX_HTML, "script");
        assert!(
            !script.contains(".json()"),
            "an answer parsed as JSON before its status was read"
        );
        assert!(script.contains("try{body=JSON.parse(text)}catch(_){}"));
    }

    fn analyses(
        handler: impl Fn(&[String]) -> Result<serde_json::Value, LookupError> + Send + Sync + 'static,
    ) -> Routes {
        Routes {
            lookups: None,
            analyze: Some(Arc::new(handler)),
        }
    }

    /// Answers with the seeds it was given, so a test can see exactly what reached the spine.
    fn echo_seeds() -> Routes {
        analyses(|seeds| Ok(serde_json::json!({ "seeds": seeds })))
    }

    fn analyze(query: &str, extra: &str, token: Option<&str>, routes: &Routes) -> String {
        respond(
            &format!("GET /api/analyze?{query} HTTP/1.1\r\nHost: localhost\r\n{extra}\r\n"),
            token,
            loopback_bind(),
            routes,
        )
    }

    #[test]
    fn analysis_answers_404_until_the_binary_installs_it() {
        let response = analyze("seeds=a", "", None, &Routes::default());
        assert!(response.starts_with("HTTP/1.1 404"), "{response}");
    }

    #[test]
    fn analysis_takes_one_seed_per_line_trimmed_and_without_blank_lines() {
        let response = analyze(
            "seeds=+alex.demo%40example.org+%0A%0A%40alexdemo%0D%0Aexample.org",
            "Sec-Fetch-Site: same-origin\r\n",
            None,
            &echo_seeds(),
        );
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(
            response.contains(r#"{"seeds":["alex.demo@example.org","@alexdemo","example.org"]}"#),
            "{response}"
        );
    }

    /// A request the analysis cannot honour is refused before the spine runs.
    #[test]
    fn analysis_refuses_what_it_cannot_honour_before_it_runs() {
        let too_many = format!(
            "seeds={}",
            (0..=MAX_ANALYZE_SEEDS)
                .map(|n| format!("seed{n}.example"))
                .collect::<Vec<_>>()
                .join("%0A")
        );
        let too_long = format!("seeds={}", "a".repeat(MAX_SELECTOR_BYTES + 1));
        for (query, extra, status, fragment) in [
            ("seeds=", "", "400", "needs seeds"),
            ("seeds=+%0A+", "", "400", "needs seeds"),
            ("other=x", "", "400", "needs seeds"),
            (too_many.as_str(), "", "400", "at most 16 seeds"),
            (too_long.as_str(), "", "400", "longer than 512 bytes"),
            ("seeds=%ZZ", "", "400", "percent-encoded"),
            (
                "seeds=a",
                "Sec-Fetch-Site: cross-site\r\n",
                "403",
                "cross-site",
            ),
            (
                "seeds=a",
                "Sec-Fetch-Site: same-site\r\n",
                "403",
                "cross-site",
            ),
        ] {
            let response = analyze(query, extra, None, &echo_seeds());
            assert!(
                response.starts_with(&format!("HTTP/1.1 {status}")),
                "{query}: {response}"
            );
            assert!(response.contains(fragment), "{query}: {response}");
            assert!(!response.contains("\"seeds\":["), "{query} ran the spine");
        }
        let post = respond(
            "POST /api/analyze?seeds=a HTTP/1.1\r\nHost: localhost\r\n\r\n",
            None,
            loopback_bind(),
            &echo_seeds(),
        );
        assert!(post.starts_with("HTTP/1.1 405"), "{post}");
    }

    #[test]
    fn analysis_needs_the_token_when_one_is_configured() {
        let refused = analyze("seeds=a", "", Some("secret"), &echo_seeds());
        assert!(refused.starts_with("HTTP/1.1 401"), "{refused}");
        let allowed = analyze(
            "seeds=a",
            "Authorization: Bearer secret\r\n",
            Some("secret"),
            &echo_seeds(),
        );
        assert!(allowed.starts_with("HTTP/1.1 200"), "{allowed}");
    }

    #[test]
    fn analysis_answers_with_the_status_the_spine_reports() {
        let refusing = analyses(|_| {
            Err(LookupError {
                status: 422,
                message: "no actionable seeds".into(),
            })
        });
        let response = analyze("seeds=a", "", None, &refusing);
        assert!(response.starts_with("HTTP/1.1 422"), "{response}");
        assert!(response.contains("no actionable seeds"), "{response}");
    }

    /// About `depth` KiB of stack: a 1 KiB frame per call, kept live across the call below it.
    fn deep_stack(depth: usize) -> u64 {
        let frame = std::hint::black_box([1_u8; 1024]);
        let below = if depth == 0 { 0 } else { deep_stack(depth - 1) };
        below + u64::from(frame[depth % frame.len()])
    }

    /// The spine needs more stack than a connection thread has. Served from a thread with the
    /// connection stack, a handler that uses about 1 MiB of stack must still answer, because the
    /// analysis runs on its own thread. Run inline, it would overflow and abort the server.
    #[test]
    fn an_analysis_runs_off_the_small_connection_stack() {
        let deep = analyses(|_| Ok(serde_json::json!({ "sum": deep_stack(1024) })));
        let response = thread::Builder::new()
            .stack_size(HANDLER_STACK_BYTES)
            .spawn(move || analyze("seeds=a", "", None, &deep))
            .unwrap()
            .join()
            .unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.contains(r#"{"sum":1025}"#), "{response}");
    }

    /// Each correlation row says what the rule found, such as how many independent pathways
    /// corroborate a link or how many pairs only a shared handle connects, beside the rule and
    /// the entities it names. The page showed only the rule, its severity and the entities.
    #[test]
    fn the_page_shows_what_each_correlation_found() {
        let table = &INDEX_HTML[..INDEX_HTML.find(r#"<tbody id="acorrelations">"#).unwrap()];
        let header = &table[table.rfind("<thead>").unwrap()..];
        assert_eq!(
            header,
            "<thead><tr><th>rule</th><th>severity</th><th>finding</th><th>entities</th></tr></thead>"
        );
        let script = inline_block(INDEX_HTML, "script");
        let row = &script[script.find("fill('acorrelations'").unwrap()..];
        let row = &row[..row.find(';').unwrap()];
        assert!(
            row.ends_with(
                "c=>[c.rule_id+' '+c.rule_name,show(c.severity),c.description,\
                 c.entity_uids.map(who).join(', ')])"
            ),
            "{row}"
        );
    }

    /// The page drives the analysis through the same route, refused cross-site, with no lookup
    /// header: it makes no network request and spends no key.
    #[test]
    fn the_page_runs_the_offline_analysis() {
        assert!(INDEX_HTML.contains(r#"<form id="analyze">"#));
        assert!(INDEX_HTML.contains("call('/api/analyze?'"));
        let script = inline_block(INDEX_HTML, "script");
        let analyze_call = &script[script.find("call('/api/analyze?'").unwrap()..];
        let analyze_call = &analyze_call[..analyze_call.find(';').unwrap()];
        assert!(
            !analyze_call.contains("X-Huntsman-Lookup"),
            "{analyze_call}"
        );
    }
}
