//! Minimal embedded Web UI and HTTP API for Huntsman Recon.
//!
//! The default bind is loopback-only and needs no token. Explicit non-loopback binds require a
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
//! When the binary installs a [`ScanApi`], the saved scans answer under `/api/scans`,
//! `/api/eventtypes` and `/api/settings`, Spiderfoot's web API: reads are `GET`, state changes
//! (start, stop, delete, re-run, false positive) are `POST` with their parameters in the query
//! string, and every call is guarded as a lookup is. No other route takes `POST`.
//! A loopback bind answers only requests whose `Host` is a loopback authority,
//! which blocks a browser DNS-rebinding attack from reaching the local API.

use std::collections::{BTreeSet, VecDeque};
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{RecvTimeoutError, sync_channel};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::base64;
use crate::engineering_command;
use crate::entity::Entity;
use crate::error::Error;
use crate::key_import;
use crate::keys::{self, Keys};
use crate::module::reachable_modules;
use crate::provider_credentials::PROVIDERS;
use crate::scan_api::ScanApi;
use crate::scan_route::{self, ScanKind};
use crate::scan_service::{ScanRequest, ScanService};
use crate::scan_store::{LogLevel, ScanStatus};
use crate::sha256::sha256;
use crate::source_outcome::SourceExecutionOutcome;
use crate::value_syntax::form_pairs;
use crate::wifi_radar::WifiScan;

pub const DEFAULT_BIND: &str = "127.0.0.1:8080";

/// Use an explicit bind or the loopback-only default. External hosting platforms
/// do not change the bind implicitly; an operator must opt in to public listening.
#[must_use]
pub fn resolve_serve_bind(hse_bind: Option<&str>) -> String {
    hse_bind.unwrap_or(DEFAULT_BIND).to_owned()
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
/// Only one device-radio request at a time; Android's cached scan may take 15 seconds.
const MAX_RADAR_REQUESTS: usize = 1;
const RADAR_WAIT: Duration = Duration::from_secs(18);
/// A lookup does TLS and JSON decoding, which the small connection stack is not sized for, so it
/// runs on its own thread with this stack.
const LOOKUP_STACK_BYTES: usize = 4 * 1024 * 1024;
/// The longest `/api/lookup` waits for its lookup: the two minutes a lookup may hold its
/// providers, and time to wait for a place behind the scans already running. A lookup still
/// running then is answered `504` with the saved scan it runs as, which goes on and keeps what it
/// finds; a phone that reloads mid-lookup waits on that same scan instead of starting another.
const LOOKUP_WAIT: Duration = Duration::from_secs(150);
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
/// A scan API request reads a saved scan whole and encodes its elements, raw records and all, so,
/// like an analysis, it runs on its own thread with a stack sized for that. Starting a scan only
/// saves its row: the scan itself runs on the service's own thread.
const SCANS_STACK_BYTES: usize = 4 * 1024 * 1024;
/// The longest request body the server reads: a Settings page key save (`slot` and `value`) or
/// key import (`import`, a whole `SpiderFoot.cfg` or keys file), form-encoded, in what a request
/// leaves past its head (25 KiB). Every other route takes its parameters in the query string.
const MAX_FORM_BYTES: usize = MAX_REQUEST_BYTES - HEADER_ALLOWANCE;
/// The Settings page's provider keys: which may be saved, and one save.
const KEYS_PATH: &str = "/api/settings/keys";
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
    /// The saved scan the lookup ran as, which `/api/scans/ID` reads again; absent when the
    /// server keeps no saved scans.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scan: Option<String>,
    /// How that scan ended: `FINISHED`, or `ABORTED` when it was stopped under Scans, so the
    /// report holds what it had found by then.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<&'static str>,
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
    /// [`LOOKUP_WAIT`], shorter in tests.
    wait: Duration,
}

/// Runs the offline multi-hop analysis of the seeds and returns its report as JSON. Installed by
/// the binary, which owns the investigation spine; the error carries the HTTP status to answer.
pub type AnalyzeHandler =
    Arc<dyn Fn(&[String]) -> Result<serde_json::Value, LookupError> + Send + Sync>;

/// One bounded, no-root Android OS-cached Wi-Fi observation read.
/// Installed by the process boundary; the server library owns no sensor subprocess.
pub type RadarHandler = Arc<dyn Fn() -> Result<WifiScan, LookupError> + Send + Sync>;

#[derive(Clone)]
struct Radar {
    handler: RadarHandler,
    live: Arc<AtomicUsize>,
}

/// The routes a binary installs. A route whose handler is absent answers `404`.
#[derive(Clone, Default)]
struct Routes {
    lookups: Option<Lookups>,
    radar: Option<Radar>,
    analyze: Option<AnalyzeHandler>,
    scans: Option<Arc<ScanApi>>,
    /// The home whose keys file every lookup reads, for [`KEYS_PATH`].
    keys_home: Option<PathBuf>,
}

/// Where `serve` listens and the token its API needs. Only [`ServeConfig::parse`] builds one, so a
/// loopback bind can never carry a token.
#[derive(Clone, PartialEq, Eq)]
pub struct ServeConfig {
    pub bind: SocketAddr,
    bearer_token: Option<String>,
}

impl ServeConfig {
    /// Build and validate server configuration.
    ///
    /// A loopback bind never needs the token: the operator chose a page that asks for none on
    /// the phone (2026-10-14), so a token supplied for a loopback bind is not used. The `Host`
    /// guard and the lookup header still keep other websites out. A non-loopback bind is public
    /// and always needs it.
    ///
    /// # Errors
    /// Rejects malformed bind addresses, and a non-loopback bind without a non-empty token.
    pub fn parse(bind: &str, bearer_token: Option<String>) -> Result<Self, Error> {
        let bind = normalize_bind(bind)?;
        if bind.ip().is_loopback() {
            return Ok(Self {
                bind,
                bearer_token: None,
            });
        }
        match bearer_token.map(|token| token.trim().to_owned()) {
            Some(token) if !token.is_empty() => Ok(Self {
                bind,
                bearer_token: Some(token),
            }),
            Some(_) => Err(Error::missing_credential(
                "HSE_AUTH_TOKEN must not be empty",
            )),
            None => Err(Error::missing_credential(
                "non-loopback serve bind requires HSE_AUTH_TOKEN",
            )),
        }
    }

    /// Whether every endpoint but the page and health needs the bearer token: only on a public
    /// bind.
    #[must_use]
    pub fn needs_token(&self) -> bool {
        self.bearer_token.is_some()
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
            wait: LOOKUP_WAIT,
        });
        self
    }

    /// Serve `GET /api/radar/wifi` from the same Android cache adapter as the CLI.
    /// Nothing is read before an explicitly requested API call.
    #[must_use]
    pub fn with_radar(mut self, handler: RadarHandler) -> Self {
        self.routes.radar = Some(Radar {
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

    /// Serve the saved scans (`/api/scans...`, `/api/eventtypes`, `/api/settings`) through `api`.
    /// Without this those routes answer `404`.
    #[must_use]
    pub fn with_scans(mut self, api: Arc<ScanApi>) -> Self {
        self.routes.scans = Some(api);
        self
    }

    /// Serve `/api/settings/keys` over the keys file in `home` (`~/.huntsman.env`), the one every
    /// lookup reads. Without this the route answers `404`.
    #[must_use]
    pub fn with_keys_home(mut self, home: PathBuf) -> Self {
        self.routes.keys_home = Some(home);
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
    /// own thread, up to [`MAX_CONNECTIONS`] at a time. A failed `accept` that concerned only
    /// the one connection being taken (reset or aborted before it was accepted, a pending
    /// network error on it) is retried at once; one that a later `accept` can succeed after
    /// (no free file descriptor or memory) pauses the loop instead of ending it; see
    /// [`AcceptFailure`]. `notice` hears a shortage at most once every [`ACCEPT_NOTICE_EVERY`],
    /// so the process boundary can say why requests are waiting without flooding its log.
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
                    AcceptFailure::Retry if failures.retry_at_once() => {}
                    AcceptFailure::Retry | AcceptFailure::Transient => {
                        if failures.notice_due(Instant::now()) {
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
    /// The failure was the one connection being taken: it was reset or aborted before it was
    /// accepted, or Linux reported a network error pending on it (`accept(2)` lists them and
    /// says to retry). Nothing was short, so the next `accept` can succeed at once.
    Retry,
    /// The process or system is short of something (file descriptors when every connection
    /// thread holds some, memory under Android's pressure). Connections finishing free what
    /// was short, so a later `accept` succeeds.
    Transient,
}

/// `EBADF`, the same number on Linux, Android, the BSDs and macOS.
const EBADF: i32 = 9;

/// Errors that say the listener itself is unusable: a closed descriptor, and on Linux and
/// Android a descriptor that is not a socket (`ENOTSOCK`, 88), which std files under no named
/// `ErrorKind`.
#[cfg(any(target_os = "linux", target_os = "android"))]
const FATAL_ERRNOS: [i32; 2] = [EBADF, 88];
#[cfg(not(any(target_os = "linux", target_os = "android")))]
const FATAL_ERRNOS: [i32; 1] = [EBADF];

/// Errors `accept(2)` on Linux and Android reports for the one connection it dequeued, not
/// for the listener: `EPERM` (1, a firewall rule), `ENONET` (64), `EPROTO` (71),
/// `ENOPROTOOPT` (92), `EOPNOTSUPP` (95), `ENETDOWN` (100), `ENETUNREACH` (101),
/// `ECONNABORTED` (103), `ECONNRESET` (104), `EHOSTDOWN` (112) and `EHOSTUNREACH` (113). The
/// manual says to treat them like `EAGAIN` and retry. They are matched by number before any
/// `ErrorKind`, because std files `EOPNOTSUPP` under `Unsupported` from Rust 1.88, which would
/// otherwise end the server over one bad connection.
#[cfg(any(target_os = "linux", target_os = "android"))]
const RETRY_ERRNOS: [i32; 11] = [1, 64, 71, 92, 95, 100, 101, 103, 104, 112, 113];
#[cfg(not(any(target_os = "linux", target_os = "android")))]
const RETRY_ERRNOS: [i32; 0] = [];

impl AcceptFailure {
    fn of(error: &std::io::Error) -> Self {
        use std::io::ErrorKind;
        if let Some(raw) = error.raw_os_error() {
            if RETRY_ERRNOS.contains(&raw) {
                return Self::Retry;
            }
            if FATAL_ERRNOS.contains(&raw) {
                return Self::Fatal;
            }
        }
        // An invalid socket (EINVAL is `InvalidInput`) and an unsupported operation never
        // recover; a connection that went away or was interrupted costs nothing to retry;
        // everything else is about the moment, not the listener.
        match error.kind() {
            ErrorKind::InvalidInput | ErrorKind::Unsupported => Self::Fatal,
            ErrorKind::ConnectionAborted
            | ErrorKind::ConnectionReset
            | ErrorKind::Interrupted
            | ErrorKind::HostUnreachable
            | ErrorKind::NetworkUnreachable
            | ErrorKind::NetworkDown
            | ErrorKind::TimedOut => Self::Retry,
            _ => Self::Transient,
        }
    }
}

/// The pause after each failed `accept` in a row: it doubles from [`ACCEPT_PAUSE_FIRST`] to
/// [`ACCEPT_PAUSE_MOST`], so a shortage is not met with a busy loop. Per-connection failures
/// are retried without a pause, up to [`RETRY_BURST`] in a row: a longer run means something
/// is wrong beyond the one connection, and it is paused like a shortage.
#[derive(Default)]
struct AcceptFailures {
    in_a_row: u32,
    retried_in_a_row: u32,
    last_notice: Option<Instant>,
}

const ACCEPT_PAUSE_FIRST: Duration = Duration::from_millis(10);
const ACCEPT_PAUSE_MOST: Duration = Duration::from_millis(500);
/// How often the operator is told that `accept` is failing. One successful `accept` ends a
/// failure run, and at a descriptor limit runs end with every connection that finishes, so
/// a per-run notice would print once per request served for as long as the shortage lasts.
const ACCEPT_NOTICE_EVERY: Duration = Duration::from_secs(30);
const RETRY_BURST: u32 = 64;

impl AcceptFailures {
    /// Whether a per-connection failure is retried at once; a burst of them is paused instead.
    fn retry_at_once(&mut self) -> bool {
        self.retried_in_a_row = self.retried_in_a_row.saturating_add(1);
        self.retried_in_a_row <= RETRY_BURST
    }

    /// Whether to tell the operator now: the first failure of a run, and not within
    /// [`ACCEPT_NOTICE_EVERY`] of the last notice.
    fn notice_due(&mut self, now: Instant) -> bool {
        let due = self.in_a_row == 0
            && self
                .last_notice
                .is_none_or(|last| now.saturating_duration_since(last) >= ACCEPT_NOTICE_EVERY);
        if due {
            self.last_notice = Some(now);
        }
        due
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
        self.retried_in_a_row = 0;
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
    let response = respond(&request, config, routes);
    stream
        .write_all(&response)
        .map_err(|error| Error::Store(format!("serve write: {error}")))?;
    stream
        .flush()
        .map_err(|error| Error::Store(format!("serve flush: {error}")))
}

fn read_request(stream: &mut TcpStream, deadline: Instant) -> Result<String, Error> {
    let mut bytes = Vec::with_capacity(1024);
    let mut chunk = [0_u8; 1024];
    // Once the head is in: the whole request's length, the head and the form body it announces.
    let mut whole = None;

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
        if whole.is_none() {
            if let Some(at) = bytes[scan_from..]
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
            {
                let head = scan_from + at + 4;
                whole = Some(head + form_body_len(&bytes[..head]));
            }
        }
        if whole.is_some_and(|whole| bytes.len() >= whole) {
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

/// The body to read after a request's `head`: the `Content-Length` it announces, when that is at
/// most [`MAX_FORM_BYTES`]. A larger body is not read; the route answers without it.
fn form_body_len(head: &[u8]) -> usize {
    parse_request(&String::from_utf8_lossy(head))
        .and_then(|parsed| parsed.content_length)
        .filter(|length| *length <= MAX_FORM_BYTES)
        .unwrap_or(0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Method {
    Get,
    Head,
    /// A state change: the scan API's, with its parameters in the query string, and a key save,
    /// with its form in the body.
    Post,
    Other,
}

impl Method {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Post => "POST",
            Self::Other => "OTHER",
        }
    }
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
    /// A request body was announced: a non-zero `Content-Length` or any `Transfer-Encoding`.
    has_body: bool,
    /// The `Content-Length`, when it is a number.
    content_length: Option<usize>,
    /// What followed the head, as far as it was read.
    body: &'a str,
}

fn parse_request(request: &str) -> Option<ParsedRequest<'_>> {
    let mut lines = request.split("\r\n");
    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();
    let method = match parts.next()? {
        "GET" => Method::Get,
        "HEAD" => Method::Head,
        "POST" => Method::Post,
        _ => Method::Other,
    };
    let raw_path = parts.next()?;
    let (path, query) = raw_path.split_once('?').unwrap_or((raw_path, ""));
    let mut host = None;
    let mut authorization = None;
    let mut lookup_header = false;
    let mut sec_fetch_site = None;
    let mut has_body = false;
    let mut content_length = None;

    // The head ends at the first blank line; anything after it is body, never a header.
    for line in lines.take_while(|line| !line.is_empty()) {
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
        } else if name.eq_ignore_ascii_case("content-length") {
            has_body |= value.trim() != "0";
            content_length = value.trim().parse().ok();
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            has_body = true;
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
        has_body,
        content_length,
        body: request.split_once("\r\n\r\n").map_or("", |(_, body)| body),
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
    /// The page this server serves, as [`PAGE_ID`]. A tab whose page names another was loaded
    /// from an earlier build and asks to be reloaded.
    page: &'a str,
    /// `token` when every endpoint other than health and the page needs the bearer token, `none`
    /// otherwise. The page reads it to ask for the token before a call is refused.
    auth: &'a str,
}

/// The router for a server started with this bind and token, built the way `serve` builds it.
#[cfg(test)]
fn response_for_request(request: &str, bearer_token: Option<&str>, bind: SocketAddr) -> String {
    text(respond(
        request,
        &test_config(bind, bearer_token),
        &Routes::default(),
    ))
}

/// An answer that is text, as text.
#[cfg(test)]
fn text(answer: Vec<u8>) -> String {
    String::from_utf8(answer).unwrap_or_else(|error| panic!("an answer that is not text: {error}"))
}

#[cfg(test)]
fn test_config(bind: SocketAddr, bearer_token: Option<&str>) -> ServeConfig {
    ServeConfig::parse(&bind.to_string(), bearer_token.map(str::to_owned))
        .unwrap_or_else(|error| panic!("{bind} with {bearer_token:?}: {error}"))
}

/// The bytes to write for one request: text for every answer but a scan export that is a
/// workbook.
fn respond(request: &str, config: &ServeConfig, routes: &Routes) -> Vec<u8> {
    let (bind, bearer_token) = (config.bind, config.bearer_token.as_deref());
    if request == "REQUEST_TOO_LARGE" {
        return response(
            413,
            "text/plain; charset=utf-8",
            "request too large\n",
            false,
        )
        .into_bytes();
    }

    if request == "REQUEST_TIMEOUT" {
        return response(408, "text/plain; charset=utf-8", "request timeout\n", false).into_bytes();
    }

    let Some(parsed) = parse_request(request) else {
        return response(400, "text/plain; charset=utf-8", "bad request\n", false).into_bytes();
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
        )
        .into_bytes();
    }

    // Only the scan API and the key save change state, so only they take POST.
    if parsed.method == Method::Other
        || parsed.method == Method::Post
            && !(ScanApi::handles(parsed.path) || parsed.path == KEYS_PATH)
    {
        return response(
            405,
            "text/plain; charset=utf-8",
            "method not allowed\n",
            false,
        )
        .into_bytes();
    }

    let head = parsed.method == Method::Head;
    let protected = matches!(
        parsed.path,
        "/api/modules"
            | "/api/command"
            | "/api/lookup"
            | "/api/analyze"
            | "/api/radar/wifi"
            | KEYS_PATH
    ) || ScanApi::handles(parsed.path);
    if protected
        && bearer_token.is_some_and(|expected| !bearer_matches(parsed.authorization, expected))
    {
        return response(401, "application/json; charset=utf-8", UNAUTHORIZED, head).into_bytes();
    }

    if ScanApi::handles(parsed.path) {
        return scans_response(&parsed, routes.scans.as_ref());
    }
    let text = match parsed.path {
        "/" | "/index.html" => response(200, "text/html; charset=utf-8", &PAGE, head),
        "/api/health" => {
            let body = serde_json::to_string_pretty(&Health {
                status: "ok",
                name: "huntsman-recon",
                version: env!("CARGO_PKG_VERSION"),
                page: &PAGE_ID,
                auth: if bearer_token.is_some() {
                    "token"
                } else {
                    "none"
                },
            })
            .unwrap_or_else(|_| "{\"status\":\"error\"}".into());
            json_ok(&body, head)
        }
        "/api/modules" => {
            let body = serde_json::to_string_pretty(&serde_json::json!({
                "count": reachable_modules().len(),
                "modules": reachable_modules(),
            }))
            .unwrap_or_else(|_| "{\"count\":0,\"modules\":[]}".into());
            json_ok(&body, head)
        }
        "/api/command" => match engineering_command::render_json() {
            Ok(body) => json_ok(&body, head),
            Err(_) => response(
                500,
                "application/json; charset=utf-8",
                "{\"error\":\"command contract unavailable\"}\n",
                head,
            ),
        },
        "/api/lookup" => lookup_response(&parsed, routes.lookups.as_ref(), routes.scans.as_ref()),
        "/api/radar/wifi" => radar_response(&parsed, routes.radar.as_ref()),
        "/api/analyze" => analyze_response(&parsed, routes.analyze.as_ref()),
        KEYS_PATH => keys_response(&parsed, routes.keys_home.as_deref()),
        "/favicon.svg" => response(200, "image/svg+xml", FAVICON_SVG, head),
        "/favicon.ico" => response(204, "image/x-icon", "", head),
        _ => response(404, "text/plain; charset=utf-8", "not found\n", head),
    };
    text.into_bytes()
}

/// The answer to a protected request without the server's token. It names the remedy, because the
/// page shows it as it is and a bare `unauthorized` left the operator nowhere to go.
const UNAUTHORIZED: &str = "{\"error\":\"unauthorized: this server was started with HSE_AUTH_TOKEN set; enter that value in the token field under About\"}\n";

fn json_error(status: u16, message: &str) -> String {
    let body = serde_json::json!({ "error": message }).to_string();
    response(
        status,
        "application/json; charset=utf-8",
        &format!("{body}\n"),
        false,
    )
}

/// A `200 OK` answer carrying an already-rendered JSON `body`. It owns the one JSON success
/// contract the route handlers share, as [`json_error`] owns the failure one: the
/// `application/json; charset=utf-8` content type and the single trailing newline every answer
/// ends with. `head` drops the body for a `HEAD` request while keeping its `Content-Length`.
fn json_ok(body: &str, head: bool) -> String {
    response(
        200,
        "application/json; charset=utf-8",
        &format!("{body}\n"),
        head,
    )
}

/// Read Android's OS-cached Wi-Fi scan only after an explicitly initiated,
/// same-origin, lookup-header-bearing request. A missing sensor is an error,
/// never a fabricated empty scan. Each worker is time- and concurrency-bounded.
fn radar_response(parsed: &ParsedRequest<'_>, radar: Option<&Radar>) -> String {
    let Some(radar) = radar else {
        return json_error(404, "Wi-Fi radar is not enabled on this server");
    };
    if parsed.method != Method::Get {
        return json_error(405, "Wi-Fi radar needs GET");
    }
    if parsed
        .sec_fetch_site
        .is_some_and(|site| !matches!(site, "same-origin" | "none"))
    {
        return json_error(403, "cross-site Wi-Fi radar request refused");
    }
    if !parsed.lookup_header {
        return json_error(403, "Wi-Fi radar needs the X-Huntsman-Lookup: 1 header");
    }
    if !parsed.query.is_empty() {
        return json_error(400, "Wi-Fi radar takes no query parameters");
    }
    let Some(slot) = Slot::take_of(&radar.live, MAX_RADAR_REQUESTS) else {
        return json_error(503, "Wi-Fi radio request already in progress");
    };
    let handler = Arc::clone(&radar.handler);
    let (sender, receiver) = sync_channel(1);
    let worker = thread::Builder::new()
        .name("serve-wifi-radar".into())
        .stack_size(LOOKUP_STACK_BYTES)
        .spawn(move || {
            let result = catch_unwind(AssertUnwindSafe(|| handler()));
            drop(slot);
            let _ = sender.send(result);
        });
    if worker.is_err() {
        return json_error(503, "could not start a Wi-Fi radar worker");
    }
    match receiver.recv_timeout(RADAR_WAIT) {
        Ok(Ok(Ok(scan))) => match serde_json::to_string(&scan) {
            Ok(body) => json_ok(&body, false),
            Err(_) => json_error(500, "Wi-Fi observations could not be encoded"),
        },
        Ok(Ok(Err(error))) => json_error(error.status, &error.message),
        Ok(Err(_)) | Err(RecvTimeoutError::Disconnected) => {
            json_error(500, "Wi-Fi radar failed unexpectedly")
        }
        Err(RecvTimeoutError::Timeout) => json_error(504, "Wi-Fi radar did not answer in time"),
    }
}

/// `GET /api/lookup`: one lookup, answered with its report. With saved scans on, the lookup runs
/// as a saved scan, so it is kept, listed under Scans, can be stopped there, and reads `ABORTED`
/// after a server that stopped mid-lookup starts again; the answer names it. Without them the
/// installed handler runs it and nothing is kept, as there is nowhere to keep it. Either way the
/// request waits at most [`Lookups::wait`] and then answers `504`.
fn lookup_response(
    parsed: &ParsedRequest<'_>,
    lookups: Option<&Lookups>,
    scans: Option<&Arc<ScanApi>>,
) -> String {
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
    let until = Instant::now() + lookups.wait;
    if let Some(scans) = scans {
        let service = Arc::clone(scans.service());
        // Reading and encoding the saved report needs more stack than a connection has.
        let worker = thread::Builder::new()
            .name("serve-lookup".into())
            .stack_size(LOOKUP_STACK_BYTES)
            .spawn(move || saved_lookup(&service, &query, until));
        return match worker.map(thread::JoinHandle::join) {
            Ok(Ok(answer)) => answer,
            Ok(Err(_)) => json_error(500, "lookup failed unexpectedly"),
            Err(_) => json_error(503, "could not start a lookup worker"),
        };
    }
    let Some(slot) = Slot::take_of(&lookups.live, MAX_LOOKUPS) else {
        return json_error(503, "lookup capacity in use; retry shortly");
    };
    let handler = Arc::clone(&lookups.handler);
    let (sender, receiver) = sync_channel(1);
    let worker = thread::Builder::new()
        .name("serve-lookup".into())
        .stack_size(LOOKUP_STACK_BYTES)
        .spawn(move || {
            let outcome = catch_unwind(AssertUnwindSafe(|| handler(&query)));
            // Free the place before answering: a client that has its answer may ask again at
            // once, and must not find its own finished lookup still counted.
            drop(slot);
            let _ = sender.send(outcome);
        });
    if worker.is_err() {
        return json_error(503, "could not start a lookup worker");
    }
    match receiver.recv_timeout(until.saturating_duration_since(Instant::now())) {
        Ok(Ok(Ok(report))) => match serde_json::to_string(&report) {
            Ok(body) => json_ok(&body, false),
            Err(_) => json_error(500, "report could not be encoded"),
        },
        Ok(Ok(Err(error))) => json_error(error.status, &error.message),
        Ok(Err(_)) | Err(RecvTimeoutError::Disconnected) => {
            json_error(500, "lookup failed unexpectedly")
        }
        Err(RecvTimeoutError::Timeout) => json_error(
            504,
            "the lookup is still running and this server keeps no saved scans, so its result \
             will not be kept; set HOME or HUNTSMAN_HOME to keep lookups as saved scans",
        ),
    }
}

/// One `/api/lookup` as a saved scan of the target: started, or joined when the same lookup is
/// already under way, then waited on until `until`. A scan that has not ended by then is answered
/// `504` and runs on; one that ended with nothing saved is answered `502` with the reason its log
/// gives. Each answer names the scan.
fn saved_lookup(service: &Arc<ScanService>, query: &LookupQuery, until: Instant) -> String {
    let request = ScanRequest {
        target: query.selector.clone(),
        kind: Some(query.kind.clone()),
        ..ScanRequest::default()
    };
    let record = match service
        .start_or_join(&request)
        .and_then(|record| service.wait(&record.id, until))
    {
        Ok(record) => record,
        Err(failure) => return json_error(failure.status(), &failure.to_string()),
    };
    let failed = |status: u16, error: String| {
        let body = serde_json::json!({ "error": error, "scan": record.id });
        response(
            status,
            "application/json; charset=utf-8",
            &format!("{body}\n"),
            false,
        )
    };
    if record.status.is_active() {
        return failed(
            504,
            format!(
                "the lookup is still running as saved scan {}; it goes on and keeps what it finds \
                 at /api/scans/{} and under Scans",
                record.id, record.id
            ),
        );
    }
    let saved = match service.store().results(&record.id) {
        Ok(saved) => saved.filter(|_| record.status != ScanStatus::ErrorFailed),
        Err(failure) => return json_error(500, &failure.to_string()),
    };
    let Some(results) = saved else {
        let log = service.store().log(&record.id).unwrap_or_default();
        let why = log
            .iter()
            .rev()
            .find(|entry| entry.level == LogLevel::Error)
            .or_else(|| log.last())
            .map_or_else(
                || "the lookup saved nothing".to_owned(),
                |entry| entry.message.clone(),
            );
        return failed(502, why);
    };
    let report = LookupReport {
        route: scan_route::parse_kind(&record.kind).map_or("scan", ScanKind::command),
        text: results.text,
        entities: results.entities,
        outcomes: results.outcomes,
        scan: Some(record.id.clone()),
        status: Some(record.status.as_str()),
    };
    match serde_json::to_string(&report) {
        Ok(body) => json_ok(&body, false),
        Err(_) => json_error(500, "report could not be encoded"),
    }
}

/// The saved scans: Spiderfoot's scan list, scan views, exports and state changes, answered by the
/// binary's [`ScanApi`]. A scan makes network requests and spends keys, and its results are the
/// operator's, so every call is guarded as a lookup is: refused cross-site or same-site, it needs
/// the lookup header (which another origin cannot send without a preflight this server never
/// approves), and on a public bind the bearer token. Parameters travel in the query string, so a
/// request that sends a body is refused rather than half read.
fn scans_response(parsed: &ParsedRequest<'_>, scans: Option<&Arc<ScanApi>>) -> Vec<u8> {
    let Some(scans) = scans else {
        return json_error(404, "saved scans are not enabled on this server").into_bytes();
    };
    if parsed
        .sec_fetch_site
        .is_some_and(|site| !matches!(site, "same-origin" | "none"))
    {
        return json_error(403, "cross-site scan request refused").into_bytes();
    }
    if !parsed.lookup_header {
        return json_error(403, "the scan API needs the X-Huntsman-Lookup: 1 header").into_bytes();
    }
    if parsed.has_body {
        return json_error(400, "send the parameters in the query string, with no body")
            .into_bytes();
    }
    let head = parsed.method == Method::Head;
    let (api, method, path, query) = (
        Arc::clone(scans),
        parsed.method.as_str(),
        parsed.path.to_owned(),
        parsed.query.to_owned(),
    );
    let worker = thread::Builder::new()
        .name("serve-scans".into())
        .stack_size(SCANS_STACK_BYTES)
        .spawn(move || api.handle(method, &path, &query));
    let answer = match worker {
        Ok(worker) => worker.join(),
        Err(_) => return json_error(503, "could not start a scan API worker").into_bytes(),
    };
    match answer {
        Ok(answer) => {
            let disposition = answer.filename.as_deref().map(|name| {
                format!(
                    "Content-Disposition: attachment; filename=\"{}\"\r\n",
                    header_filename(name)
                )
            });
            response_bytes(
                answer.status,
                answer.content_type,
                &answer.body,
                head,
                disposition.as_deref().unwrap_or(""),
            )
        }
        Err(_) => json_error(500, "the scan API failed unexpectedly").into_bytes(),
    }
}

/// A file name safe inside a quoted header value: letters, digits, `.`, `-` and `_` kept, every
/// other character `_`, so a name can never end the header or start another.
fn header_filename(name: &str) -> String {
    let safe: String = name
        .chars()
        .take(128)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if safe.is_empty() {
        "export".to_owned()
    } else {
        safe
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

/// `GET` and `POST /api/settings/keys`: the provider keys the Settings page may save, and one save.
/// Spiderfoot keeps its modules' API keys in its settings. Here they live in the keys file every
/// lookup reads (`~/.huntsman.env`), so the next lookup uses a saved key without a restart. A save
/// sends `slot` and `value` as a form body, never in the URL, and an empty `value` removes the
/// slot. No answer carries a value: only whether each slot is set and whether the file sets it.
/// It changes what every lookup spends, so it is guarded as the scan API is: refused cross-site or
/// same-site, it needs the lookup header, and on a public bind the bearer token.
fn keys_response(parsed: &ParsedRequest<'_>, home: Option<&Path>) -> String {
    let Some(home) = home else {
        return json_error(
            404,
            "this server keeps no keys file: start it with HOME set to an absolute directory",
        );
    };
    if parsed
        .sec_fetch_site
        .is_some_and(|site| !matches!(site, "same-origin" | "none"))
    {
        return json_error(403, "cross-site key request refused");
    }
    if !parsed.lookup_header {
        return json_error(403, "the key settings need the X-Huntsman-Lookup: 1 header");
    }
    // A URL is kept in history and logs, so a key must not reach this route in one, even beside
    // a form that would be saved.
    if !parsed.query.is_empty() {
        return json_error(
            400,
            "the key settings take no query string: send a form body",
        );
    }
    if parsed.method == Method::Post {
        return match save_key(parsed, &home.join(keys::DEFAULT_KEYS_FILE)) {
            Ok(imported) => key_slots(home, false, imported.as_ref()),
            Err(refused) => refused,
        };
    }
    if parsed.has_body {
        return json_error(400, "only a key save sends a body");
    }
    key_slots(home, parsed.method == Method::Head, None)
}

/// What a key import saved: the slots, and what it left out, by name.
struct Imported {
    slots: Vec<&'static str>,
    unused: Vec<String>,
    settings: usize,
}

/// One key save from the form in `parsed`'s body: `slot`, a slot of a provider in the credential
/// catalogue, and `value`, the key, or empty to remove the slot; or a key import, `import`, the
/// text of a file holding keys. The refusal is the answer to send.
fn save_key(parsed: &ParsedRequest<'_>, file: &Path) -> Result<Option<Imported>, String> {
    if parsed.content_length != Some(parsed.body.len()) {
        return Err(json_error(
            400,
            &format!("send the form as a body of at most {MAX_FORM_BYTES} bytes"),
        ));
    }
    let Some(form) = form_pairs(parsed.body) else {
        return Err(json_error(
            400,
            "the form is not valid percent-encoded UTF-8",
        ));
    };
    let field = |name: &str| {
        form.iter()
            .rev()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    };
    if let Some(text) = field("import") {
        if field("slot").is_some() || field("value").is_some() {
            return Err(json_error(
                400,
                "send either slot and value, or import, not both",
            ));
        }
        return import_keys(file, text).map(Some);
    }
    let slot = field("slot").unwrap_or_default();
    if !PROVIDERS
        .iter()
        .any(|provider| provider.slots.contains(&slot))
    {
        return Err(json_error(400, "slot is not a provider key slot"));
    }
    let value = field("value").filter(|value| !value.trim().is_empty());
    keys::store_slot(file, slot, value).map_err(store_refusal)?;
    Ok(None)
}

/// Every key `text` holds that a Huntsman source takes, saved in one rewrite of the keys file:
/// the text of a Spiderfoot settings export (`SpiderFoot.cfg`) or of a keys file. A line that
/// cannot be read saves nothing, and neither does a file that sets no key a source takes.
fn import_keys(file: &Path, text: &str) -> Result<Imported, String> {
    let plan = key_import::plan(text);
    if !plan.refused.is_empty() {
        return Err(json_error(
            422,
            &format!("nothing was imported: {}", plan.refused.join("; ")),
        ));
    }
    if plan.saves.is_empty() {
        let unused = if plan.unused.is_empty() {
            String::new()
        } else {
            format!(" (no Huntsman source takes {})", plan.unused.join(", "))
        };
        return Err(json_error(
            422,
            &format!("the file sets no key a Huntsman source takes{unused}"),
        ));
    }
    let changes: Vec<(&str, Option<&str>)> = plan
        .saves
        .iter()
        .map(|(slot, secret)| (*slot, Some(secret.expose())))
        .collect();
    keys::store_slots(file, &changes).map_err(store_refusal)?;
    Ok(Imported {
        slots: plan.saves.iter().map(|(slot, _)| *slot).collect(),
        unused: plan.unused,
        settings: plan.settings,
    })
}

/// The answer to a key save the keys file refused: 422 for a value or file it cannot hold, 500
/// for one it cannot read or write.
fn store_refusal(error: Error) -> String {
    match error {
        Error::Invalid(message) => json_error(422, &message),
        other => json_error(500, &other.to_string()),
    }
}

/// Every provider key slot in the credential catalogue: its provider, whether a lookup would find
/// it set (in the keys file or the environment), and whether the keys file sets it. With the file,
/// and the warning a lookup would print when it cannot read the file. After an import, what it
/// saved and left out.
fn key_slots(home: &Path, head: bool, imported: Option<&Imported>) -> String {
    let resolved = Keys::for_lookup(Some(home.as_os_str()));
    let saved: BTreeSet<&str> = resolved.keys.slots().into_iter().collect();
    let slots: Vec<serde_json::Value> = PROVIDERS
        .iter()
        .flat_map(|provider| {
            provider.slots.iter().map(|slot| {
                serde_json::json!({
                    "provider": provider.name,
                    "slot": slot,
                    "set": resolved.keys.get(slot).is_some(),
                    "saved": saved.contains(slot),
                })
            })
        })
        .collect();
    let mut body = serde_json::json!({
        "file": home.join(keys::DEFAULT_KEYS_FILE).display().to_string(),
        "warning": resolved.warning,
        "slots": slots,
    });
    if let Some(imported) = imported {
        body["imported"] = serde_json::json!({
            "slots": imported.slots,
            "unused": imported.unused,
            "settings": imported.settings,
        });
    }
    json_ok(&body.to_string(), head)
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
        Ok(Ok(report)) => json_ok(&report.to_string(), false),
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
    response_with(status, content_type, body, head, "")
}

/// [`response`] with `extra`, whole `Name: value\r\n` header lines, after the standard ones.
fn response_with(status: u16, content_type: &str, body: &str, head: bool, extra: &str) -> String {
    let mut out = response_head(status, content_type, body.len(), extra);
    if !head {
        out.push_str(body);
    }
    out
}

/// [`response_with`] for a body of bytes, such as an Excel export.
fn response_bytes(
    status: u16,
    content_type: &str,
    body: &[u8],
    head: bool,
    extra: &str,
) -> Vec<u8> {
    let mut out = response_head(status, content_type, body.len(), extra).into_bytes();
    if !head {
        out.extend_from_slice(body);
    }
    out
}

/// The status line and headers of an answer whose body is `content_length` bytes, through the
/// blank line that ends them.
fn response_head(status: u16, content_type: &str, content_length: usize, extra: &str) -> String {
    let reason = match status {
        200 => "OK",
        202 => "Accepted",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        413 => "Payload Too Large",
        422 => "Unprocessable Content",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Error",
    };
    let status_header = match status {
        503 => "Retry-After: 1\r\n",
        401 => "WWW-Authenticate: Bearer realm=\"huntsman-recon\"\r\n",
        _ => "",
    };
    let policy = if content_type.starts_with("text/html") {
        PAGE_POLICY.as_str()
    } else {
        OTHER_POLICY
    };
    format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {content_length}\r\n{status_header}Cache-Control: no-store\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nContent-Security-Policy: {policy}\r\n{extra}\r\n"
    )
}

/// The page: one inline style and one inline script, so the policy can pin both by hash. It is
/// the HSE console's look (app bar, bottom tabs on a phone, panels), over this server's routes.
const INDEX_HTML: &str = include_str!("web_ui.html");

/// The empty page id [`PAGE`] fills in, in the page's head and outside its script and style, so
/// filling it leaves the hashes [`PAGE_POLICY`] lists unchanged.
const PAGE_ID_SLOT: &str = r#"<meta name="huntsman-page" content="">"#;

/// The first 16 hex digits of the SHA-256 of the page this build embeds. Every page an upgrade
/// changes gets a new id, a build without provenance metadata included.
static PAGE_ID: LazyLock<String> =
    LazyLock::new(|| crate::sha256::hex32(&sha256(INDEX_HTML.as_bytes()))[..16].to_owned());

/// The page as served: [`INDEX_HTML`] carrying its [`PAGE_ID`], which the page compares with
/// the one every health answer names.
static PAGE: LazyLock<String> = LazyLock::new(|| {
    INDEX_HTML.replacen(
        PAGE_ID_SLOT,
        &format!(r#"<meta name="huntsman-page" content="{}">"#, *PAGE_ID),
        1,
    )
});

/// The console's locator mark, as the tab icon. It is a file of its own because the page policy
/// loads images only from this server.
const FAVICON_SVG: &str = "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 32 32\"><rect width=\"32\" height=\"32\" rx=\"6\" fill=\"#0a0d11\"/><circle cx=\"16\" cy=\"16\" r=\"8\" fill=\"none\" stroke=\"#1cb8f5\" stroke-width=\"2\"/><circle cx=\"16\" cy=\"16\" r=\"2.4\" fill=\"#1cb8f5\"/><path d=\"M16 2v6M16 24v6M2 16h6M24 16h6\" stroke=\"#1cb8f5\" stroke-width=\"2\"/></svg>\n";

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    /// A loopback bind for the pure-router tests. The DNS-rebinding guard is active
    /// for loopback binds, so requests here carry a loopback `Host` or none at all.
    fn loopback_bind() -> SocketAddr {
        "127.0.0.1:8080".parse().unwrap()
    }

    /// A public bind, the only kind whose API needs the token.
    fn public_bind() -> SocketAddr {
        "0.0.0.0:8080".parse().unwrap()
    }

    /// The bind of a server started with `token`: a token is used only on a public bind.
    fn bind_for(token: Option<&str>) -> SocketAddr {
        if token.is_some() {
            public_bind()
        } else {
            loopback_bind()
        }
    }

    /// Running out of descriptors or memory must not end `serve`, and losing the pending
    /// connection must not even pause it; only a listener that can never accept again ends it.
    #[test]
    fn only_an_unusable_listener_ends_the_accept_loop() {
        use std::io::{Error as IoError, ErrorKind};
        // Linux and Android numbers: EMFILE, ENFILE, ENOMEM, ENOBUFS.
        for raw in [24, 23, 12, 105] {
            assert_eq!(
                AcceptFailure::of(&IoError::from_raw_os_error(raw)),
                AcceptFailure::Transient,
                "errno {raw}"
            );
        }
        for kind in [ErrorKind::WouldBlock, ErrorKind::OutOfMemory] {
            assert_eq!(
                AcceptFailure::of(&IoError::from(kind)),
                AcceptFailure::Transient
            );
        }
        // The one dequeued connection: EPERM, EPROTO, EOPNOTSUPP, ENETUNREACH, ECONNABORTED,
        // ECONNRESET, EHOSTUNREACH. EOPNOTSUPP is `Unsupported` from Rust 1.88, which must not
        // make it fatal.
        #[cfg(any(target_os = "linux", target_os = "android"))]
        for raw in [1, 71, 95, 101, 103, 104, 113] {
            assert_eq!(
                AcceptFailure::of(&IoError::from_raw_os_error(raw)),
                AcceptFailure::Retry,
                "errno {raw}"
            );
        }
        for kind in [
            ErrorKind::Interrupted,
            ErrorKind::ConnectionAborted,
            ErrorKind::ConnectionReset,
            ErrorKind::HostUnreachable,
        ] {
            assert_eq!(
                AcceptFailure::of(&IoError::from(kind)),
                AcceptFailure::Retry
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
        // ENOTSOCK: std leaves it `Uncategorized`, so it is named by number.
        #[cfg(any(target_os = "linux", target_os = "android"))]
        assert_eq!(
            AcceptFailure::of(&IoError::from_raw_os_error(88)),
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
        let pauses: Vec<_> = (0..12).map(|_| failures.pause()).collect();
        assert_eq!(pauses[0], ACCEPT_PAUSE_FIRST);
        assert!(pauses.windows(2).all(|pair| pair[0] <= pair[1]));
        assert_eq!(pauses[11], ACCEPT_PAUSE_MOST);
        failures.recovered();
        assert_eq!(failures.pause(), ACCEPT_PAUSE_FIRST);
    }

    /// At a descriptor limit every finishing connection lets one `accept` succeed and the next
    /// one fail again, so a notice per failure run would print once per request served.
    #[test]
    fn the_accept_notice_is_rate_limited_across_failure_runs() {
        let start = Instant::now();
        let mut failures = AcceptFailures::default();
        assert!(failures.notice_due(start), "the first failure is told");
        let _ = failures.pause();
        assert!(!failures.notice_due(start), "not again within the run");
        for seconds in [0, 1, 29] {
            failures.recovered();
            assert!(
                !failures.notice_due(start + Duration::from_secs(seconds)),
                "a new run {seconds} s later is not told again"
            );
            let _ = failures.pause();
        }
        failures.recovered();
        assert!(failures.notice_due(start + ACCEPT_NOTICE_EVERY));
    }

    /// Per-connection failures cost nothing to retry, until a run of them says the trouble is
    /// not one connection.
    #[test]
    fn per_connection_failures_retry_at_once_until_a_burst() {
        let mut failures = AcceptFailures::default();
        assert!((0..RETRY_BURST).all(|_| failures.retry_at_once()));
        assert!(!failures.retry_at_once());
        failures.recovered();
        assert!(failures.retry_at_once());
    }

    #[test]
    fn implicit_bind_stays_loopback_without_an_explicit_setting() {
        assert_eq!(resolve_serve_bind(None), DEFAULT_BIND);
        assert_eq!(resolve_serve_bind(Some("127.0.0.1:9000")), "127.0.0.1:9000");
        assert_eq!(resolve_serve_bind(Some("0.0.0.0:43210")), "0.0.0.0:43210");
    }

    #[test]
    fn config_defaults_and_public_token_requirement_are_explicit() {
        let local = ServeConfig::parse(DEFAULT_BIND, None).unwrap();
        assert!(local.bind.ip().is_loopback());
        assert!(!local.needs_token());
        assert!(ServeConfig::parse("0.0.0.0:8080", None).is_err());
        assert!(ServeConfig::parse("0.0.0.0:8080", Some("   ".into())).is_err());
        assert!(
            ServeConfig::parse("0.0.0.0:8080", Some("token".into()))
                .unwrap()
                .needs_token()
        );
        assert_eq!(
            ServeConfig::parse("localhost:9000", None).unwrap().bind,
            "127.0.0.1:9000".parse::<SocketAddr>().unwrap()
        );
    }

    /// The phone's web UI asked for a token on every load once the installer gave the service
    /// one (seen 2026-10-14, "remove these weird token requirements"). A loopback server now
    /// needs none, whatever `HSE_AUTH_TOKEN` holds: every endpoint answers without
    /// `Authorization`, and health tells the page not to ask.
    #[test]
    fn a_loopback_server_needs_no_token_even_when_one_is_supplied() {
        let lookups = echo_lookups();
        for bind in ["127.0.0.1:8080", "localhost:8080", "[::1]:8080"] {
            for token in [None, Some("phone-service-token"), Some("   ")] {
                let config = ServeConfig::parse(bind, token.map(str::to_owned)).unwrap();
                assert!(!config.needs_token(), "{bind} {token:?}");
                let routes = Routes {
                    lookups: Some(lookups.clone()),
                    radar: None,
                    analyze: echo_seeds().analyze,
                    scans: None,
                    keys_home: None,
                };
                let ask = |path: &str| {
                    text(respond(
                        &format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n{HEADER}\r\n"),
                        &config,
                        &routes,
                    ))
                };
                for path in [
                    "/",
                    "/api/modules",
                    "/api/command",
                    "/api/analyze?seeds=a",
                    "/api/lookup?q=a",
                ] {
                    let answer = ask(path);
                    assert!(
                        answer.starts_with("HTTP/1.1 200"),
                        "{bind} {token:?} {path}: {answer}"
                    );
                }
                assert!(ask("/api/health").contains("\"auth\": \"none\""));
            }
        }
    }

    #[test]
    fn pure_router_serves_health_and_protected_metadata() {
        let health = response_for_request(
            "GET /api/health HTTP/1.1\r\n\r\n",
            Some("secret"),
            public_bind(),
        );
        assert!(health.starts_with("HTTP/1.1 200"));
        assert!(health.contains("\"status\": \"ok\""));

        let denied = response_for_request(
            "GET /api/modules HTTP/1.1\r\n\r\n",
            Some("secret"),
            public_bind(),
        );
        assert!(denied.starts_with("HTTP/1.1 401"));

        let allowed = response_for_request(
            "GET /api/modules HTTP/1.1\r\nAuthorization: bearer secret\r\n\r\n",
            Some("secret"),
            public_bind(),
        );
        assert!(allowed.starts_with("HTTP/1.1 200"));
        assert!(allowed.contains("\"modules\""));
    }

    #[test]
    fn wifi_radar_requires_same_origin_lookup_header_and_public_bind_token() {
        let config = ServeConfig::parse("0.0.0.0:8080", Some("secret".into())).unwrap();
        let handler: RadarHandler = Arc::new(|| {
            crate::wifi_radar::parse_scan(
                br#"[{"bssid":"3C:5A:B4:11:22:33","ssid":"test","rssi":-58,"timestamp":100000000}]"#,
                Some(1000.0),
            )
            .map_err(|e| LookupError {
                status: 422,
                message: e.to_string(),
            })
        });
        let routes = Routes {
            radar: Some(Radar {
                handler,
                live: Arc::new(AtomicUsize::new(0)),
            }),
            ..Routes::default()
        };
        let request = |method: &str, headers: &str| {
            text(respond(
                &format!("{method} /api/radar/wifi HTTP/1.1\r\n{headers}\r\n"),
                &config,
                &routes,
            ))
        };
        let auth = "Authorization: Bearer secret\r\n";
        let lookup = "X-Huntsman-Lookup: 1\r\n";
        assert!(request("GET", lookup).starts_with("HTTP/1.1 401"));
        assert!(request("GET", auth).starts_with("HTTP/1.1 403"));
        assert!(
            request(
                "GET",
                &format!("{auth}{lookup}Sec-Fetch-Site: cross-site\r\n")
            )
            .starts_with("HTTP/1.1 403")
        );
        assert!(request("POST", &format!("{auth}{lookup}")).starts_with("HTTP/1.1 405"));
        assert!(request("HEAD", &format!("{auth}{lookup}")).starts_with("HTTP/1.1 405"));
        let result = request(
            "GET",
            &format!("{auth}{lookup}Sec-Fetch-Site: same-origin\r\n"),
        );
        assert!(result.starts_with("HTTP/1.1 200"), "{result}");
        let body: serde_json::Value =
            serde_json::from_str(result.split("\r\n\r\n").nth(1).unwrap_or_default()).unwrap();
        assert_eq!(body["source"], "termux-wifi-scaninfo");
        assert_eq!(body["status"], "stale_only");
        assert_eq!(body["observations"][0]["age_secs"], 900.0);
        assert!(body["observations"][0]["sighting"]["latitude"].is_null());

        // Without an installed sensor adapter the route refuses rather than
        // manufacturing a zero-observation success response.
        let missing = text(respond(
            &format!("GET /api/radar/wifi HTTP/1.1\r\n{auth}{lookup}\r\n"),
            &config,
            &Routes::default(),
        ));
        assert!(missing.starts_with("HTTP/1.1 404"), "{missing}");
    }

    #[test]
    fn wifi_radar_busy_and_adapter_error_are_failures_not_empty_scans() {
        let config = ServeConfig::parse("127.0.0.1:8080", None).unwrap();
        let live = Arc::new(AtomicUsize::new(1));
        let routes = Routes {
            radar: Some(Radar {
                handler: Arc::new(|| {
                    Err(LookupError {
                        status: 503,
                        message: "Termux:API unavailable".into(),
                    })
                }),
                live: Arc::clone(&live),
            }),
            ..Routes::default()
        };
        let ask = || {
            text(respond(
                "GET /api/radar/wifi HTTP/1.1\r\nHost: localhost\r\nX-Huntsman-Lookup: 1\r\n\r\n",
                &config,
                &routes,
            ))
        };
        assert!(ask().starts_with("HTTP/1.1 503"));
        live.store(0, Ordering::SeqCst);
        let error = ask();
        assert!(error.starts_with("HTTP/1.1 503"));
        assert!(error.contains("Termux:API unavailable"));
    }

    /// A tab open across an upgrade notices it: the page is served with the id of the page this
    /// build embeds, health names the same id, and filling it in leaves the policy's hashes valid.
    #[test]
    fn the_page_and_health_name_one_page_id_and_the_policy_still_matches() {
        assert!(
            PAGE_ID.len() == 16 && PAGE_ID.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "{}",
            *PAGE_ID
        );
        assert!(INDEX_HTML.contains(PAGE_ID_SLOT), "the page keeps the slot");
        let page = response_for_request("GET / HTTP/1.1\r\n\r\n", None, loopback_bind());
        let body = page.split("\r\n\r\n").nth(1).unwrap_or_default();
        assert!(
            body.contains(&format!(
                r#"<meta name="huntsman-page" content="{}">"#,
                *PAGE_ID
            )),
            "the served page carries its id"
        );
        assert_eq!(
            inline_block(body, "script"),
            inline_block(INDEX_HTML, "script")
        );
        assert_eq!(
            inline_block(body, "style"),
            inline_block(INDEX_HTML, "style")
        );
        let health =
            response_for_request("GET /api/health HTTP/1.1\r\n\r\n", None, loopback_bind());
        let health = health.split("\r\n\r\n").nth(1).unwrap_or_default();
        let health: serde_json::Value = serde_json::from_str(health.trim_end())
            .unwrap_or_else(|e| panic!("health is not JSON: {e}"));
        assert_eq!(health["page"], PAGE_ID.as_str());
    }

    /// Every `200 OK` JSON answer shares one content type and ends in exactly one newline,
    /// the contract [`json_ok`] now owns in one place (as [`json_error`] owns the failure one).
    /// Each route handler builds its own body, so a handler reverting to a hand-rolled
    /// `response(200, …)` could drift the content type or newline; this pins all three
    /// JSON success routes to the shared shape.
    #[test]
    fn every_json_ok_route_shares_one_content_type_and_a_single_trailing_newline() {
        for path in ["/api/health", "/api/modules", "/api/command"] {
            let answer = response_for_request(
                &format!("GET {path} HTTP/1.1\r\nAuthorization: Bearer secret\r\n\r\n"),
                Some("secret"),
                loopback_bind(),
            );
            assert!(answer.starts_with("HTTP/1.1 200"), "{path}: {answer}");
            assert_eq!(
                header(&answer, "Content-Type"),
                Some("application/json; charset=utf-8"),
                "{path} content type"
            );
            let body = answer.split("\r\n\r\n").nth(1).unwrap_or_default();
            assert!(
                body.ends_with('\n') && !body.ends_with("\n\n"),
                "{path} body must end in exactly one newline: {body:?}"
            );
            // The body before that newline is valid JSON.
            serde_json::from_str::<serde_json::Value>(body.trim_end_matches('\n'))
                .unwrap_or_else(|e| panic!("{path} body is not JSON: {e}"));
        }
    }

    /// A token-protected server said only `{"error":"unauthorized"}`, and health gave no sign a
    /// token was needed, so the page could not tell the operator what to do (seen on a phone,
    /// 2026-10-14). Health now says whether the token is needed, and a refusal names the remedy
    /// and carries the standard challenge.
    #[test]
    fn health_says_whether_a_token_is_needed_and_a_refusal_names_the_remedy() {
        let health = |token| {
            response_for_request("GET /api/health HTTP/1.1\r\n\r\n", token, bind_for(token))
        };
        assert!(health(Some("secret")).contains("\"auth\": \"token\""));
        assert!(health(None).contains("\"auth\": \"none\""));

        for path in ["/api/modules", "/api/command", "/api/analyze?seeds=a"] {
            let denied = response_for_request(
                &format!("GET {path} HTTP/1.1\r\nAuthorization: Bearer wrong\r\n\r\n"),
                Some("secret"),
                public_bind(),
            );
            assert!(denied.starts_with("HTTP/1.1 401"), "{path}: {denied}");
            assert_eq!(
                header(&denied, "WWW-Authenticate"),
                Some("Bearer realm=\"huntsman-recon\"")
            );
            let body = denied.split("\r\n\r\n").nth(1).unwrap_or_default();
            let error: serde_json::Value = serde_json::from_str(body).unwrap();
            let error = error["error"].as_str().unwrap_or_default();
            assert!(
                error.starts_with("unauthorized") && error.contains("HSE_AUTH_TOKEN"),
                "{error}"
            );
        }
    }

    /// The phone's page asked for a token on every load (2026-10-14). It now asks only when health
    /// says the server needs one, which only a public bind does: the token panel and the notice
    /// start hidden, a call carries `Authorization` only then, and a loopback answer clears a token
    /// an earlier page stored. A public bind still gets the field, the `#token=` fragment and the
    /// prompt on a refusal.
    #[test]
    fn the_page_asks_for_a_token_only_when_the_server_needs_one() {
        let script = inline_block(INDEX_HTML, "script");
        assert!(
            INDEX_HTML.contains(r#"<p class="alert warn" id="authnote" role="alert" hidden></p>"#)
        );
        assert!(INDEX_HTML.contains(r#"<div class="panel" id="tokenpanel" hidden>"#));
        assert!(script.contains("if(needsToken&&token)h.Authorization='Bearer '+token"));
        assert!(script.contains("if(b.auth==='token'){\n        needsToken=true;"));
        // A stored token is tried without fetching a body: HEAD answers 401 or 200 and nothing else.
        assert!(script.contains("refused(await call('/api/command',{},{method:'HEAD'}))"));
        assert!(script.contains("else{needsToken=false;token='';store.set('hse-token','');"));
        assert!(
            script.contains("const refused=res=>{if(res.r.status===401){askToken();return true}")
        );
        assert_eq!(script.matches("refused(res)").count(), 3);
        // Every request goes through `call`, which adds the header, except an export, which is
        // read as a file and sends the same headers: no bare `fetch` elsewhere.
        assert_eq!(script.matches("fetch(").count(), 2);
        assert!(script.contains("r=await fetch(path,{headers:headers(LH),"));
        assert!(script.contains("/(?:^#|&)token=([^&]*)/.exec(location.hash)"));
        assert!(script.contains("history.replaceState("));
    }

    /// The page is laid out as Spiderfoot 4.0's: an app bar with the locator mark, the theme switch
    /// and About, Spiderfoot's New Scan, Scans and Settings plus Analyze as tabs (a bottom tab bar
    /// on a phone, a top nav on a wider screen), one scan's sections under `#/scan/ID`, two scans
    /// compared under `#/compare/A/B`, and a view for each.
    #[test]
    fn the_page_is_the_console_shell_with_a_tab_per_view() {
        assert!(INDEX_HTML.contains(r#"<header class="appbar">"#));
        assert!(INDEX_HTML.contains(r#"<nav class="navbar" aria-label="Primary">"#));
        let script = inline_block(INDEX_HTML, "script");
        assert!(script.contains(
            "const VIEWS=['scans','newscan','scan','compare','analyze','radar','settings','about'];"
        ));
        for view in ["newscan", "scans", "analyze", "radar", "settings"] {
            assert!(
                INDEX_HTML.contains(&format!(
                    r##"<a class="navlink" data-view="{view}" href="#/{view}">"##
                )),
                "{view}"
            );
        }
        assert!(INDEX_HTML.contains(r##"<a class="iconbtn" id="nav-about" href="#/about""##));
        for view in [
            "scans", "newscan", "scan", "compare", "analyze", "radar", "settings", "about",
        ] {
            assert!(
                INDEX_HTML.contains(&format!(r#"<section id="view-{view}" hidden>"#)),
                "{view}"
            );
        }
        // Spiderfoot's sections of one scan, and the addresses an older page used.
        assert!(
            script.contains(
                "const TABS=['summary','correlations','browse','graph','settings','log'];"
            )
        );
        assert!(script.contains("({lookup:'newscan',status:'about'})[parts[0]]"));
        let style = inline_block(INDEX_HTML, "style");
        assert!(style.contains(".navbar{position:fixed;left:0;right:0;bottom:0;"));
        assert!(style.contains("@media (min-width:768px){\n.navbar{top:"));
        let icon = response_for_request(
            "GET /favicon.svg HTTP/1.1\r\nHost: localhost\r\n\r\n",
            None,
            loopback_bind(),
        );
        assert!(icon.starts_with("HTTP/1.1 200"), "{icon}");
        assert_eq!(header(&icon, "Content-Type"), Some("image/svg+xml"));
        assert!(
            INDEX_HTML.contains(r#"<link rel="icon" href="/favicon.svg" type="image/svg+xml">"#)
        );
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
    fn the_host_guard_refuses_a_rebound_host_whatever_it_carries() {
        // A loopback server needs no token, so the Host guard is what keeps a rebound page
        // out: a request with a disallowed Host is refused even when it carries a token.
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
        // real Host (a public hostname, say) is unknown here, so the guard must not
        // apply or it would refuse every real request.
        let public = "0.0.0.0:8080".parse::<SocketAddr>().unwrap();
        let served = response_for_request(
            "GET /api/health HTTP/1.1\r\nHost: huntsman.example.test\r\n\r\n",
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
                if query.selector == "slow" {
                    thread::sleep(Duration::from_secs(1));
                }
                Ok(LookupReport {
                    route: "email",
                    text: format!("{}|{}", query.kind, query.selector),
                    entities: Vec::new(),
                    outcomes: Vec::new(),
                    scan: None,
                    status: None,
                })
            }),
            live: Arc::new(AtomicUsize::new(0)),
            wait: Duration::from_secs(10),
        }
    }

    fn lookup(request: &str, token: Option<&str>, lookups: Option<&Lookups>) -> String {
        let routes = Routes {
            lookups: lookups.cloned(),
            radar: None,
            analyze: None,
            scans: None,
            keys_home: None,
        };
        text(respond(
            request,
            &test_config(bind_for(token), token),
            &routes,
        ))
    }

    const HEADER: &str = "X-Huntsman-Lookup: 1\r\n";

    #[test]
    fn the_page_offers_every_lookup_kind_the_cli_routes() {
        // New Scan's target type is how a phone user names a kind; a kind missing from it is
        // reachable only by `auto` inference, and an SSID never is.
        let picker = &INDEX_HTML[INDEX_HTML.find(r#"<select id="skind">"#).unwrap()..];
        let picker = &picker[..picker.find("</select>").unwrap()];
        assert!(picker.starts_with(r#"<select id="skind"><option value="auto">"#));
        for kind in crate::scan_route::ScanKind::ALL {
            let option = format!("<option value=\"{}\">", kind.command());
            assert!(picker.contains(&option), "missing {option}");
        }
        assert_eq!(
            picker.matches("<option ").count(),
            1 + crate::scan_route::ScanKind::ALL.len()
        );
    }

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
        assert!(ask("boom").starts_with("HTTP/1.1 500"));
        assert_eq!(
            lookups.live.load(Ordering::Acquire),
            0,
            "a panic frees its slot"
        );
        // A client that has its answer can ask again at once: the slot is free before the answer
        // is sent, never a moment after it.
        for round in 0..500 {
            for (q, status) in [("refused", "HTTP/1.1 422"), ("a", "HTTP/1.1 200")] {
                assert!(ask(q).starts_with(status));
                assert_eq!(
                    lookups.live.load(Ordering::Acquire),
                    0,
                    "the answered lookup {q:?} still held its slot in round {round}"
                );
            }
        }
        assert!(ask("").starts_with("HTTP/1.1 400"));
        assert!(ask(&"a".repeat(MAX_SELECTOR_BYTES + 1)).starts_with("HTTP/1.1 400"));
        lookups.live.store(MAX_LOOKUPS, Ordering::Release);
        assert!(ask("a").starts_with("HTTP/1.1 503"));
        lookups.live.store(0, Ordering::Release);
        assert!(ask("a").starts_with("HTTP/1.1 200"));
    }

    #[test]
    fn a_lookup_without_saved_scans_answers_504_when_its_wait_runs_out() {
        let lookups = Lookups {
            wait: Duration::from_millis(100),
            ..echo_lookups()
        };
        let got = lookup(
            &format!("GET /api/lookup?q=slow HTTP/1.1\r\n{HEADER}\r\n"),
            None,
            Some(&lookups),
        );
        assert!(got.starts_with("HTTP/1.1 504"), "{got}");
        assert!(got.contains("keeps no saved scans"), "{got}");
        // The request is answered; the lookup holds its place until it ends, then frees it.
        assert_eq!(lookups.live.load(Ordering::Acquire), 1);
        let freed = Instant::now() + Duration::from_secs(5);
        while lookups.live.load(Ordering::Acquire) != 0 {
            assert!(Instant::now() < freed, "the slot was never freed");
            thread::sleep(Duration::from_millis(10));
        }
    }

    /// A server with lookups and saved scans over `lookup` in a scratch store, waiting `wait`.
    fn saved_lookup_routes(
        tag: &str,
        lookup: crate::scan_service::ScanLookup,
        wait: Duration,
    ) -> (Routes, std::path::PathBuf) {
        use crate::scan_store::ScanStore;
        let dir =
            std::env::temp_dir().join(format!("hse-serve-lookup-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let api = ScanApi::new(
            ScanService::new(ScanStore::open(&dir).unwrap(), lookup),
            None,
        );
        let routes = Routes {
            lookups: Some(Lookups {
                wait,
                ..echo_lookups()
            }),
            radar: None,
            analyze: None,
            scans: Some(Arc::new(api)),
            keys_home: None,
        };
        (routes, dir)
    }

    fn found_phone(selector: &str) -> crate::scan_service::LookupOutput {
        crate::scan_service::LookupOutput {
            text: format!("report on {selector}"),
            entities: vec![
                crate::entity::Entity::builder(
                    crate::entity::EntityKind::Phone,
                    selector,
                    0.9,
                    "s",
                )
                .build(),
            ],
            outcomes: Vec::new(),
        }
    }

    fn scan_of(answer: &str) -> String {
        let body = &answer[answer.find("\r\n\r\n").unwrap() + 4..];
        let value: serde_json::Value = serde_json::from_str(body).unwrap();
        value["scan"].as_str().unwrap().to_owned()
    }

    const PHONE_LOOKUP: &str = "GET /api/lookup?kind=phone&q=%2B61412345678 HTTP/1.1\r\n";

    #[test]
    fn a_lookup_with_saved_scans_is_kept_as_a_scan_and_names_it() {
        let lookup: crate::scan_service::ScanLookup = Arc::new(
            |_kind, selector: &str, _: &crate::module_selection::Selection| {
                Ok(found_phone(selector))
            },
        );
        let (routes, dir) = saved_lookup_routes("kept", lookup, Duration::from_secs(10));
        let got = scans_request(&routes, None, &format!("{PHONE_LOOKUP}{HEADER}\r\n"));
        assert!(got.starts_with("HTTP/1.1 200"), "{got}");
        // The report the legacy handler gave, with the scan it ran as.
        for part in [
            r#""route":"phone""#,
            r#""value":"+61412345678""#,
            r#""text":"report on +61412345678""#,
            r#""status":"FINISHED""#,
        ] {
            assert!(got.contains(part), "{part} in {got}");
        }
        let id = scan_of(&got);
        let record = scans_request(
            &routes,
            None,
            &format!("GET /api/scans/{id} HTTP/1.1\r\n{HEADER}\r\n"),
        );
        assert!(record.starts_with("HTTP/1.1 200"), "{record}");
        assert!(record.contains(r#""status":"FINISHED""#), "{record}");
        let listed = scans_request(
            &routes,
            None,
            &format!("GET /api/scans HTTP/1.1\r\n{HEADER}\r\n"),
        );
        assert!(listed.contains(&id), "{listed}");
        // A target the scan cannot route is refused before any scan is kept.
        let bad = scans_request(
            &routes,
            None,
            &format!("GET /api/lookup?kind=ip&q=nope HTTP/1.1\r\n{HEADER}\r\n"),
        );
        assert!(bad.starts_with("HTTP/1.1 400"), "{bad}");
        let api = routes.scans.as_ref().unwrap();
        assert_eq!(api.service().store().list().unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_lookup_past_its_wait_answers_504_and_its_scan_runs_on_and_is_joined() {
        let gate = Arc::new(Mutex::new(()));
        let calls = Arc::new(AtomicUsize::new(0));
        let lookup: crate::scan_service::ScanLookup = {
            let (gate, calls) = (Arc::clone(&gate), Arc::clone(&calls));
            Arc::new(
                move |_kind, selector: &str, _: &crate::module_selection::Selection| {
                    calls.fetch_add(1, Ordering::AcqRel);
                    drop(gate.lock().unwrap_or_else(PoisonError::into_inner));
                    Ok(found_phone(selector))
                },
            )
        };
        let (routes, dir) = saved_lookup_routes("wait", lookup, Duration::from_millis(150));
        let held = gate.lock().unwrap();
        let ask = || scans_request(&routes, None, &format!("{PHONE_LOOKUP}{HEADER}\r\n"));
        let first = ask();
        assert!(first.starts_with("HTTP/1.1 504"), "{first}");
        let id = scan_of(&first);
        assert!(first.contains(&format!("/api/scans/{id}")), "{first}");
        // A reload while it runs waits on the same scan instead of starting another.
        let reload = ask();
        assert!(reload.starts_with("HTTP/1.1 504"), "{reload}");
        assert_eq!(scan_of(&reload), id);
        let service = Arc::clone(routes.scans.as_ref().unwrap().service());
        assert_eq!(service.store().list().unwrap().len(), 1);
        drop(held);
        let done = service
            .wait(&id, Instant::now() + Duration::from_secs(10))
            .unwrap();
        assert_eq!(done.status, ScanStatus::Finished);
        assert_eq!(
            calls.load(Ordering::Acquire),
            1,
            "one lookup ran for both requests"
        );
        let results = service.store().results(&id).unwrap().unwrap();
        assert_eq!(results.entities.len(), 1, "what it found was kept");
        // Once it has ended, the same lookup is a new scan, given the time to run this time.
        let mut routes = routes;
        routes.lookups.as_mut().unwrap().wait = Duration::from_secs(10);
        let again = scans_request(&routes, None, &format!("{PHONE_LOOKUP}{HEADER}\r\n"));
        assert!(again.starts_with("HTTP/1.1 200"), "{again}");
        assert_ne!(scan_of(&again), id);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_saved_lookup_that_finds_nothing_answers_502_with_its_reason_and_scan() {
        let lookup: crate::scan_service::ScanLookup = Arc::new(
            |_kind, _selector: &str, _: &crate::module_selection::Selection| {
                Err("every source failed".to_owned())
            },
        );
        let (routes, dir) = saved_lookup_routes("failed", lookup, Duration::from_secs(10));
        let got = scans_request(&routes, None, &format!("{PHONE_LOOKUP}{HEADER}\r\n"));
        assert!(got.starts_with("HTTP/1.1 502"), "{got}");
        assert!(got.contains("every source failed"), "{got}");
        let id = scan_of(&got);
        let api = routes.scans.as_ref().unwrap();
        assert_eq!(
            api.service().store().get(&id).unwrap().status,
            ScanStatus::ErrorFailed
        );
        let _ = std::fs::remove_dir_all(dir);
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
            radar: None,
            analyze: Some(Arc::new(handler)),
            scans: None,
            keys_home: None,
        }
    }

    /// Answers with the seeds it was given, so a test can see exactly what reached the spine.
    fn echo_seeds() -> Routes {
        analyses(|seeds| Ok(serde_json::json!({ "seeds": seeds })))
    }

    fn analyze(query: &str, extra: &str, token: Option<&str>, routes: &Routes) -> String {
        text(respond(
            &format!("GET /api/analyze?{query} HTTP/1.1\r\nHost: localhost\r\n{extra}\r\n"),
            &test_config(bind_for(token), token),
            routes,
        ))
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
        let post = text(respond(
            "POST /api/analyze?seeds=a HTTP/1.1\r\nHost: localhost\r\n\r\n",
            &test_config(loopback_bind(), None),
            &echo_seeds(),
        ));
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

    /// The bridges to saved scans reach a reader as a table, not only in the JSON. The page had no
    /// place for `cross_scan`, so `serve --history` had no visible effect.
    #[test]
    fn the_page_draws_the_bridges_to_saved_scans() {
        let table = &INDEX_HTML[..INDEX_HTML.find(r#"<tbody id="ascans">"#).unwrap()];
        let header = &table[table.rfind("<thead>").unwrap()..];
        assert_eq!(
            header,
            "<thead><tr><th>entity</th><th>tier</th><th>saved scans</th></tr></thead>"
        );
        let script = inline_block(INDEX_HTML, "script");
        assert!(script.contains("const cross=body.cross_scan"), "{script}");
        assert!(script.contains("fill('ascans',bridged,r=>r)"), "{script}");
    }

    /// The page drives the analysis through the same route, refused cross-site, with no lookup
    /// header: it makes no network request and spends no key.
    #[test]
    fn the_page_runs_the_offline_analysis() {
        assert!(INDEX_HTML.contains(r#"<form class="row" id="analyze">"#));
        assert!(INDEX_HTML.contains("call('/api/analyze?'"));
        let script = inline_block(INDEX_HTML, "script");
        let analyze_call = &script[script.find("call('/api/analyze?'").unwrap()..];
        let analyze_call = &analyze_call[..analyze_call.find(';').unwrap()];
        assert!(
            !analyze_call.contains("X-Huntsman-Lookup"),
            "{analyze_call}"
        );
    }

    /// A server with saved scans whose lookup finds the selector and nothing else, in a scratch
    /// store; the scan has run to its end before the first request.
    fn scan_routes(tag: &str) -> (Routes, String, std::path::PathBuf) {
        use crate::scan_service::{LookupOutput, ScanRequest, ScanService};
        use crate::scan_store::{ScanOptions, ScanStore};
        let dir =
            std::env::temp_dir().join(format!("hse-serve-scans-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let lookup = Arc::new(
            |_kind: crate::scan_route::ScanKind,
             selector: &str,
             _: &crate::module_selection::Selection| {
                Ok(LookupOutput {
                    text: "report".into(),
                    entities: vec![
                        crate::entity::Entity::builder(
                            crate::entity::EntityKind::Phone,
                            selector,
                            0.9,
                            "s",
                        )
                        .build(),
                    ],
                    outcomes: Vec::new(),
                })
            },
        );
        let api = ScanApi::new(
            ScanService::new(ScanStore::open(&dir).unwrap(), lookup),
            None,
        );
        let id = api
            .service()
            .run(&ScanRequest {
                target: "+61412345678".into(),
                name: None,
                kind: None,
                options: ScanOptions {
                    usecase: "all".into(),
                    modules: Vec::new(),
                    types: Vec::new(),
                    depth: 0,
                },
            })
            .unwrap()
            .id;
        let routes = Routes {
            scans: Some(Arc::new(api)),
            ..Routes::default()
        };
        (routes, id, dir)
    }

    fn scans_request(routes: &Routes, token: Option<&str>, request: &str) -> String {
        text(respond(
            request,
            &test_config(bind_for(token), token),
            routes,
        ))
    }

    /// An Excel export is bytes, sent whole after its headers, its length counted in bytes.
    #[test]
    fn an_excel_export_is_sent_as_bytes_with_its_exact_length() {
        let (routes, id, dir) = scan_routes("xlsx");
        let book = respond(
            &format!("GET /api/scans/{id}/export?format=xlsx HTTP/1.1\r\n{HEADER}\r\n"),
            &test_config(loopback_bind(), None),
            &routes,
        );
        let split = book.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let (head_bytes, body) = book.split_at(split);
        let head_text = String::from_utf8(head_bytes.to_vec()).unwrap();
        assert!(head_text.starts_with("HTTP/1.1 200"), "{head_text}");
        assert_eq!(
            header(&head_text, "Content-Type"),
            Some(crate::xlsx::CONTENT_TYPE)
        );
        assert_eq!(
            header(&head_text, "Content-Length"),
            Some(body.len().to_string().as_str())
        );
        assert!(
            header(&head_text, "Content-Disposition")
                .unwrap()
                .ends_with(".xlsx\""),
            "{head_text}"
        );
        assert!(body.starts_with(b"PK\x03\x04"));
        assert!(std::str::from_utf8(body).is_err(), "a workbook is not text");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The saved scans answer through serve with the same guards as a lookup: the header, never
    /// cross-site, the token on a public bind. Reads are GET or HEAD, changes are POST, and an
    /// export downloads under the name the API gives it.
    #[test]
    fn saved_scans_answer_through_serve_behind_the_lookup_guards() {
        let (routes, id, dir) = scan_routes("guards");
        let ask = |request: String| scans_request(&routes, None, &request);
        let list = ask(format!(
            "GET /api/scans HTTP/1.1\r\nHost: localhost\r\nSec-Fetch-Site: same-origin\r\n{HEADER}\r\n"
        ));
        assert!(list.starts_with("HTTP/1.1 200"), "{list}");
        assert!(list.contains(&format!("\"id\":\"{id}\"")), "{list}");
        let head = ask(format!("HEAD /api/scans HTTP/1.1\r\n{HEADER}\r\n"));
        assert!(
            head.starts_with("HTTP/1.1 200") && head.ends_with("\r\n\r\n"),
            "{head}"
        );
        for refused in [
            "GET /api/scans HTTP/1.1\r\n\r\n".to_owned(),
            format!("GET /api/scans HTTP/1.1\r\nSec-Fetch-Site: cross-site\r\n{HEADER}\r\n"),
            format!(
                "POST /api/scans?target=x HTTP/1.1\r\nSec-Fetch-Site: same-site\r\n{HEADER}\r\n"
            ),
            "POST /api/scans?target=x HTTP/1.1\r\nX-Huntsman-Lookup: yes\r\n\r\n".to_owned(),
        ] {
            assert!(
                ask(refused.clone()).starts_with("HTTP/1.1 403"),
                "{refused}"
            );
        }
        // A body is refused: the parameters travel in the query string.
        let body = ask(format!(
            "POST /api/scans/{id}/fp?ids=a&fp=1 HTTP/1.1\r\nContent-Length: 3\r\n{HEADER}\r\nx=1"
        ));
        assert!(body.starts_with("HTTP/1.1 400"), "{body}");
        // A header line after the blank line is body, not a header.
        let smuggled = ask("GET /api/scans HTTP/1.1\r\n\r\nX-Huntsman-Lookup: 1\r\n".to_owned());
        assert!(smuggled.starts_with("HTTP/1.1 403"), "{smuggled}");
        let export = ask(format!(
            "GET /api/scans/{id}/export?format=csv HTTP/1.1\r\n{HEADER}\r\n"
        ));
        assert!(export.starts_with("HTTP/1.1 200"), "{export}");
        assert_eq!(
            header(&export, "Content-Type"),
            Some("text/csv; charset=utf-8")
        );
        let disposition = header(&export, "Content-Disposition").unwrap();
        assert!(
            disposition.starts_with("attachment; filename=\"") && disposition.ends_with(".csv\""),
            "{disposition}"
        );
        assert!(
            export.contains("Updated,Type,Module,Source,F/P,Data"),
            "{export}"
        );
        let rerun = ask(format!(
            "POST /api/scans/{id}/rerun HTTP/1.1\r\nContent-Length: 0\r\n{HEADER}\r\n"
        ));
        assert!(rerun.starts_with("HTTP/1.1 202 Accepted"), "{rerun}");
        let read_as_post = ask(format!(
            "GET /api/scans/{id}/rerun HTTP/1.1\r\n{HEADER}\r\n"
        ));
        assert!(read_as_post.starts_with("HTTP/1.1 405"), "{read_as_post}");
        // Only the scan API takes POST.
        for path in [
            "/",
            "/api/health",
            "/api/modules",
            "/api/lookup?q=a",
            "/api/analyze?seeds=a",
        ] {
            let post = ask(format!("POST {path} HTTP/1.1\r\n{HEADER}\r\n"));
            assert!(post.starts_with("HTTP/1.1 405"), "{path}: {post}");
        }
        // A public bind needs the token for every scan route.
        let public = scans_request(
            &routes,
            Some("s3cret"),
            &format!("GET /api/eventtypes HTTP/1.1\r\n{HEADER}\r\n"),
        );
        assert!(public.starts_with("HTTP/1.1 401"), "{public}");
        let signed = scans_request(
            &routes,
            Some("s3cret"),
            &format!("GET /api/settings HTTP/1.1\r\nAuthorization: Bearer s3cret\r\n{HEADER}\r\n"),
        );
        assert!(signed.starts_with("HTTP/1.1 200"), "{signed}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn saved_scans_are_absent_until_the_binary_installs_them() {
        let got = response_for_request(
            &format!("GET /api/scans HTTP/1.1\r\nHost: localhost\r\n{HEADER}\r\n"),
            None,
            loopback_bind(),
        );
        assert!(got.starts_with("HTTP/1.1 404"), "{got}");
        assert!(got.contains("saved scans are not enabled"), "{got}");
    }

    #[test]
    fn an_export_name_cannot_break_out_of_its_header() {
        assert_eq!(header_filename("a\"b\r\nX: y.csv"), "a_b__X__y.csv");
        assert_eq!(header_filename("t1-Huntsman.csv"), "t1-Huntsman.csv");
        assert_eq!(header_filename(""), "export");
    }

    // --- The Settings page's provider keys ---

    const TEST_KEY: &str = "TEST_ONLY_SETTINGS_KEY_51c0";

    fn key_home(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("hse-serve-keys-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn key_routes(home: &Path) -> Routes {
        Routes {
            keys_home: Some(home.to_path_buf()),
            ..Routes::default()
        }
    }

    fn key_save(routes: &Routes, form: &str, extra: &str) -> String {
        scans_request(
            routes,
            None,
            &format!(
                "POST /api/settings/keys HTTP/1.1\r\n{HEADER}{extra}Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{form}",
                form.len()
            ),
        )
    }

    fn answer_json(answer: &str) -> serde_json::Value {
        let (_, body) = answer.split_once("\r\n\r\n").unwrap();
        serde_json::from_str(body).unwrap_or_else(|error| panic!("{error}: {body}"))
    }

    fn slot_state(answer: &serde_json::Value, slot: &str) -> (bool, bool) {
        let row = answer["slots"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["slot"] == slot)
            .unwrap_or_else(|| panic!("{slot} is not listed"));
        (
            row["set"].as_bool().unwrap(),
            row["saved"].as_bool().unwrap(),
        )
    }

    #[test]
    fn the_key_settings_list_every_catalogue_slot_and_a_save_reaches_the_keys_file_only() {
        let home = key_home("save");
        let routes = key_routes(&home);
        let file = home.join(keys::DEFAULT_KEYS_FILE);
        let listed = scans_request(
            &routes,
            None,
            &format!("GET /api/settings/keys HTTP/1.1\r\n{HEADER}\r\n"),
        );
        assert!(listed.starts_with("HTTP/1.1 200"), "{listed}");
        let listed = answer_json(&listed);
        let catalogue: usize = PROVIDERS.iter().map(|provider| provider.slots.len()).sum();
        assert_eq!(listed["slots"].as_array().unwrap().len(), catalogue);
        assert_eq!(listed["file"], file.display().to_string());
        assert!(
            listed["slots"]
                .as_array()
                .unwrap()
                .iter()
                .all(|row| row["saved"] == false)
        );

        let saved = key_save(
            &routes,
            &format!("slot=HUNTSMAN_SHODAN_KEY&value={TEST_KEY}"),
            "Sec-Fetch-Site: same-origin\r\n",
        );
        assert!(saved.starts_with("HTTP/1.1 200"), "{saved}");
        assert!(!saved.contains(TEST_KEY), "an answer never carries a key");
        assert_eq!(
            slot_state(&answer_json(&saved), "HUNTSMAN_SHODAN_KEY"),
            (true, true)
        );
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            format!("HUNTSMAN_SHODAN_KEY='{TEST_KEY}'\n")
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        // What a lookup reads is what was saved.
        let keys = Keys::for_lookup(Some(home.as_os_str())).keys;
        assert_eq!(keys.get("HUNTSMAN_SHODAN_KEY").unwrap().expose(), TEST_KEY);

        // An empty value removes the slot.
        let removed = key_save(&routes, "slot=HUNTSMAN_SHODAN_KEY&value=", "");
        assert!(removed.starts_with("HTTP/1.1 200"), "{removed}");
        assert!(!slot_state(&answer_json(&removed), "HUNTSMAN_SHODAN_KEY").1);
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "");
        let _ = std::fs::remove_dir_all(&home);
    }

    /// Spiderfoot's Settings → Import API Keys: a whole `SpiderFoot.cfg`, saved in one rewrite.
    #[test]
    fn a_spiderfoot_key_export_is_imported_into_the_keys_file_in_one_save() {
        let home = key_home("import");
        let routes = key_routes(&home);
        let file = home.join(keys::DEFAULT_KEYS_FILE);
        std::fs::write(&file, "# mine\nHUNTSMAN_SHODAN_KEY=old-key-1234\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let wigle = base64::standard(b"TEST_ONLY_WIGLE_AID:TEST_ONLY_WIGLE_TOKEN");
        let export = format!(
            "sfp_abstractapi:phonevalidation_api_key=\nsfp_fullhunt:api_key=TEST_ONLY_UNUSED\n\
             sfp_shodan:api_key={TEST_KEY}\nsfp_spider:maxpages=100\n\
             sfp_virustotal:api_key=TEST_ONLY_VT_KEY\nsfp_wigle:api_key_encoded={wigle}\n"
        );
        let form = format!("import={}", crate::http::percent_encode_component(&export));
        let imported = key_save(&routes, &form, "Sec-Fetch-Site: same-origin\r\n");
        assert!(imported.starts_with("HTTP/1.1 200"), "{imported}");
        for value in [
            TEST_KEY,
            "TEST_ONLY_VT_KEY",
            "TEST_ONLY_WIGLE_TOKEN",
            "TEST_ONLY_UNUSED",
        ] {
            assert!(!imported.contains(value), "an answer never carries a key");
        }
        let answer = answer_json(&imported);
        assert_eq!(
            answer["imported"],
            serde_json::json!({
                "slots": [
                    "HUNTSMAN_SHODAN_KEY",
                    "HUNTSMAN_VIRUSTOTAL_KEY",
                    "HUNTSMAN_WIGLE_USER",
                    "HUNTSMAN_WIGLE_TOKEN"
                ],
                "unused": ["sfp_fullhunt:api_key"],
                "settings": 1,
            })
        );
        assert_eq!(slot_state(&answer, "HUNTSMAN_VIRUSTOTAL_KEY"), (true, true));
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            format!(
                "# mine\nHUNTSMAN_SHODAN_KEY='{TEST_KEY}'\nHUNTSMAN_VIRUSTOTAL_KEY='TEST_ONLY_VT_KEY'\n\
                 HUNTSMAN_WIGLE_USER='TEST_ONLY_WIGLE_AID'\nHUNTSMAN_WIGLE_TOKEN='TEST_ONLY_WIGLE_TOKEN'\n"
            )
        );

        // One unreadable line saves nothing; nor does a file with no key a source takes.
        let before = std::fs::read_to_string(&file).unwrap();
        for (text, fragment) in [
            (
                "sfp_hunter:api_key=TEST_ONLY_NEW\nmy shodan key TEST_ONLY_PASTED\n",
                "nothing was imported: line 2",
            ),
            (
                "sfp_fullhunt:api_key=TEST_ONLY_UNUSED\n",
                "no Huntsman source takes sfp_fullhunt:api_key",
            ),
            ("sfp_shodan:api_key=\n", "sets no key"),
        ] {
            let form = format!("import={}", crate::http::percent_encode_component(text));
            let refused = key_save(&routes, &form, "");
            assert!(refused.starts_with("HTTP/1.1 422"), "{refused}");
            assert!(refused.contains(fragment), "{refused}");
            assert!(!refused.contains("TEST_ONLY_NEW") && !refused.contains("TEST_ONLY_PASTED"));
            assert_eq!(std::fs::read_to_string(&file).unwrap(), before);
        }
        let both = key_save(&routes, "import=x&slot=HUNTSMAN_SHODAN_KEY&value=y", "");
        assert!(both.starts_with("HTTP/1.1 400"), "{both}");
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn a_key_save_is_refused_off_the_page_in_the_url_or_for_a_slot_outside_the_catalogue() {
        let home = key_home("refused");
        let routes = key_routes(&home);
        let form = format!("slot=HUNTSMAN_SHODAN_KEY&value={TEST_KEY}");
        let status = |answer: &str| answer.split(' ').nth(1).unwrap_or_default().to_owned();
        for site in ["cross-site", "same-site"] {
            let answer = key_save(&routes, &form, &format!("Sec-Fetch-Site: {site}\r\n"));
            assert_eq!(status(&answer), "403", "{answer}");
        }
        let unheaded = scans_request(
            &routes,
            None,
            &format!(
                "POST /api/settings/keys HTTP/1.1\r\nContent-Length: {}\r\n\r\n{form}",
                form.len()
            ),
        );
        assert_eq!(status(&unheaded), "403", "{unheaded}");
        let in_the_url = scans_request(
            &routes,
            None,
            &format!("POST /api/settings/keys?{form} HTTP/1.1\r\n{HEADER}\r\n"),
        );
        assert_eq!(status(&in_the_url), "400", "{in_the_url}");
        let beside_a_form = scans_request(
            &routes,
            None,
            &format!(
                "POST /api/settings/keys?{form} HTTP/1.1\r\n{HEADER}Content-Length: {}\r\n\r\n{form}",
                form.len()
            ),
        );
        assert_eq!(status(&beside_a_form), "400", "{beside_a_form}");
        assert!(!beside_a_form.contains(TEST_KEY));
        for (form, want) in [
            (format!("slot=HOME&value={TEST_KEY}"), "400"),
            (format!("slot=HUNTSMAN_NOT_A_SLOT&value={TEST_KEY}"), "400"),
            ("slot=HUNTSMAN_SHODAN_KEY&value=changeme".to_owned(), "422"),
            ("slot=HUNTSMAN_SHODAN_KEY&value=%ZZ".to_owned(), "400"),
        ] {
            let answer = key_save(&routes, &form, "");
            assert_eq!(status(&answer), want, "{form}: {answer}");
            assert!(!answer.contains(TEST_KEY) && !answer.contains("changeme"));
        }
        let got_with_a_body = scans_request(
            &routes,
            None,
            &format!("GET /api/settings/keys HTTP/1.1\r\n{HEADER}Content-Length: 3\r\n\r\na=b"),
        );
        assert_eq!(status(&got_with_a_body), "400", "{got_with_a_body}");
        assert!(
            !home.join(keys::DEFAULT_KEYS_FILE).exists(),
            "nothing was saved"
        );

        // On a public bind the token is needed; without a home there is no keys file.
        let public = text(respond(
            &format!(
                "POST /api/settings/keys HTTP/1.1\r\n{HEADER}Content-Length: {}\r\n\r\n{form}",
                form.len()
            ),
            &test_config(public_bind(), Some("tok")),
            &routes,
        ));
        assert_eq!(status(&public), "401", "{public}");
        let homeless = key_save(&Routes::default(), &form, "");
        assert_eq!(status(&homeless), "404", "{homeless}");
        let _ = std::fs::remove_dir_all(&home);
    }

    /// A browser may send the form after its head, in a later packet; the server reads it whole.
    /// A body past the form bound is not read, and the save is refused at once.
    #[test]
    fn a_form_body_that_follows_its_head_is_read_whole_and_a_larger_one_is_refused_unread() {
        let home = key_home("socket");
        let server = Server::bind(ServeConfig::parse("127.0.0.1:0", None).unwrap())
            .unwrap()
            .with_keys_home(home.clone());
        let addr = server.local_addr().unwrap();
        let handle = thread::spawn(move || server.run_n(2).unwrap());
        let send = |head: String, body: &[u8]| {
            let mut client = TcpStream::connect(addr).unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            client.write_all(head.as_bytes()).unwrap();
            client.flush().unwrap();
            thread::sleep(Duration::from_millis(100));
            let _ = client.write_all(body);
            let mut answer = String::new();
            let _ = client.read_to_string(&mut answer);
            answer
        };
        let form = format!("slot=HUNTSMAN_SHODAN_KEY&value={TEST_KEY}");
        let saved = send(
            format!(
                "POST /api/settings/keys HTTP/1.1\r\nHost: localhost\r\n{HEADER}Content-Length: {}\r\n\r\n",
                form.len()
            ),
            form.as_bytes(),
        );
        assert!(saved.starts_with("HTTP/1.1 200"), "{saved}");
        let big = vec![b'a'; MAX_FORM_BYTES + 1];
        let started = Instant::now();
        let refused = send(
            format!(
                "POST /api/settings/keys HTTP/1.1\r\nHost: localhost\r\n{HEADER}Content-Length: {}\r\n\r\n",
                big.len()
            ),
            &big,
        );
        assert!(refused.starts_with("HTTP/1.1 400"), "{refused}");
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "answered without waiting"
        );
        handle.join().unwrap();
        let keys = Keys::for_lookup(Some(home.as_os_str())).keys;
        assert_eq!(keys.get("HUNTSMAN_SHODAN_KEY").unwrap().expose(), TEST_KEY);
        let _ = std::fs::remove_dir_all(&home);
    }

    /// Every keyed module the Settings page lists has a slot it can save, so no key field is shown
    /// that the server would refuse.
    #[test]
    fn every_keyed_module_on_the_settings_page_has_a_slot_it_can_save() {
        let (routes, _, dir) = scan_routes("keyslots");
        let settings = answer_json(&scans_request(
            &routes,
            None,
            &format!("GET /api/settings HTTP/1.1\r\n{HEADER}\r\n"),
        ));
        let saveable: BTreeSet<&str> = PROVIDERS
            .iter()
            .flat_map(|provider| provider.slots.iter().copied())
            .collect();
        let mut keyed = 0;
        for module in settings["modules"].as_array().unwrap() {
            let slots: Vec<&str> = module["key_env"]
                .as_array()
                .unwrap()
                .iter()
                .map(|slot| slot.as_str().unwrap())
                .collect();
            if slots.is_empty() {
                continue;
            }
            keyed += 1;
            assert!(
                slots.iter().any(|slot| saveable.contains(slot)),
                "{} lists {slots:?}, none of which the credential catalogue names",
                module["name"]
            );
        }
        assert!(keyed > 20, "the settings list its keyed modules: {keyed}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The page reads the key answer by these names, so a renamed field fails here rather than
    /// leaving the Settings page without its key fields.
    #[test]
    fn the_page_reads_the_key_answer_by_its_field_names() {
        let home = key_home("reads");
        let answer = answer_json(&scans_request(
            &key_routes(&home),
            None,
            &format!("GET /api/settings/keys HTTP/1.1\r\n{HEADER}\r\n"),
        ));
        for field in ["file", "warning", "slots"] {
            assert!(answer.get(field).is_some(), "the answer has no {field}");
        }
        for field in ["slot", "set", "saved", "provider"] {
            assert!(
                answer["slots"][0].get(field).is_some(),
                "a slot row has no {field}"
            );
        }
        for read in [
            "api('/api/settings/keys')",
            "keyslots.file",
            "keyslots.warning",
            "keyslots.slots.find(k=>k.slot===s)",
            "k.saved",
            "k.set",
            "method:'POST',body:new URLSearchParams({slot,value})",
            "method:'POST',body:new URLSearchParams({import:text})",
            "keyslots.imported",
            "i.slots",
            "i.unused",
            "i.settings",
        ] {
            assert!(INDEX_HTML.contains(read), "the page no longer reads {read}");
        }
        // An import answers with the same fields, and with what it imported.
        let imported = answer_json(&key_save(
            &key_routes(&home),
            &format!("import=sfp_shodan%3Aapi_key%3D{TEST_KEY}"),
            "",
        ));
        for field in ["slots", "unused", "settings"] {
            assert!(
                imported["imported"].get(field).is_some(),
                "an import's answer has no imported.{field}"
            );
        }
        let _ = std::fs::remove_dir_all(&home);
    }
}
