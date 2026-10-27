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
use crate::cell_radar::CellScan;
use crate::engineering_command;
use crate::entity::{Entity, EntityKind};
use crate::error::Error;
use crate::key_import;
use crate::keys::{self, Keys};
use crate::module::reachable_modules;
use crate::provider_credentials::PROVIDERS;
use crate::radar::TrackReport;
use crate::scan_api::ScanApi;
use crate::scan_route::{self, ScanKind};
use crate::scan_service::{INSPECT_KIND, LookupOutput, ScanRequest, ScanService, stamp_scan_id};
use crate::scan_store::{LogLevel, ScanStatus};
use crate::sha256::sha256;
use crate::source_outcome::SourceExecutionOutcome;
use crate::value_syntax::{form_decode, form_pairs};
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
const LOOKUP_STACK_BYTES: usize = crate::concurrent::JOB_STACK_BYTES;
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
/// A local file's raw bytes in, its EXIF and embedded document metadata out: the `exif` and
/// `docmeta` commands for a file picked in the browser.
const INSPECT_PATH: &str = "/api/inspect";
/// The radar track route: a `POST`, as each call appends a sweep to the track log.
const TRACK_PATH: &str = "/api/radar/track";
/// Free text in (an advert, a message thread, a page), the actionable entities in it out: the
/// `investigate` command for text pasted in the browser. The text is the body, read whole within
/// [`MAX_FORM_BYTES`]; a longer text is for `investigate --file` in Termux.
const OSINT_CASE_PATH: &str = "/api/osint/case";
const OSINT_RISK_PATH: &str = "/api/osint/area-risk";
const INVESTIGATE_PATH: &str = "/api/investigate";
/// The largest file `/api/inspect` reads: the bound the `exif` and `docmeta` commands read from
/// disk, so the page reads what the commands read (64 MiB).
const MAX_INSPECT_BYTES: usize = 64 * 1024 * 1024;
/// Inspections running at once. Each holds its whole file in memory, so a phone holds one; the
/// body is read only once its request has this place, so waiting uploads never pile up in memory.
const MAX_INSPECTIONS: usize = 1;
/// Time to receive one inspection upload: 64 MiB over a slow phone Wi-Fi link (about 1 MB/s).
const INSPECT_DEADLINE: Duration = Duration::from_secs(90);
/// The slowest a reader may take a response, past the time it is given to start. A reader that
/// takes a little at a time, each within [`IO_TIMEOUT`], would otherwise hold its connection, and
/// its place among [`MAX_CONNECTIONS`], for as long as it liked.
const MIN_WRITE_BYTES_PER_SEC: usize = 16 * 1024;
/// The file parsers build field tables and the report encodes them, so, like an analysis, an
/// inspection runs on its own thread with this stack.
const INSPECT_STACK_BYTES: usize = 4 * 1024 * 1024;
/// Longest file name `/api/inspect` keeps as the report's label.
const MAX_INSPECT_NAME_BYTES: usize = 255;
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

/// Inspects one uploaded file: its label (the browser's file name) and its bytes, answered as a
/// report like a lookup's. Installed by the binary, which owns the file parsers' composition.
pub type InspectHandler =
    Arc<dyn Fn(&str, &[u8]) -> Result<LookupReport, LookupError> + Send + Sync>;

/// Investigates one pasted text: the entities the classifier finds in it, answered as a report
/// like a lookup's, with no outcomes, as the command makes no request. Installed by the binary,
/// which owns the `investigate` command.
pub type InvestigateHandler = Arc<dyn Fn(&str) -> Result<LookupReport, LookupError> + Send + Sync>;

#[derive(Clone)]
struct Inspect {
    handler: InspectHandler,
    live: Arc<AtomicUsize>,
}

/// One `/api/inspect` body, read whole, and the inspection place it holds until it is answered.
struct Upload {
    body: Vec<u8>,
    place: Slot,
}

/// One bounded, no-root Android OS-cached Wi-Fi observation read.
/// Installed by the process boundary; the server library owns no sensor subprocess.
pub type RadarHandler = Arc<dyn Fn() -> Result<WifiScan, LookupError> + Send + Sync>;

/// One bounded, no-root read of the cells Android reports, as `radar cells` reads them.
pub type CellsHandler = Arc<dyn Fn() -> Result<CellScan, LookupError> + Send + Sync>;

/// One sweep of this device recorded into the track log `radar track` keeps, answered with the
/// log's report. Installed by the process boundary, which owns the sensors and the log's place.
pub type TrackHandler = Arc<dyn Fn() -> Result<TrackReport, LookupError> + Send + Sync>;

/// One sensor route: its handler and how many requests to it are running. Every sensor route
/// (`/api/radar/wifi`, `/api/radar/cells`, `/api/radar/track`) takes the same guarded path, so the
/// cells and the track log are read from the page under exactly the Wi-Fi radar's conditions.
struct Sensor<T> {
    handler: Arc<dyn Fn() -> Result<T, LookupError> + Send + Sync>,
    live: Arc<AtomicUsize>,
}

impl<T> Clone for Sensor<T> {
    fn clone(&self) -> Self {
        Self {
            handler: Arc::clone(&self.handler),
            live: Arc::clone(&self.live),
        }
    }
}

type Radar = Sensor<WifiScan>;

/// The routes a binary installs. A route whose handler is absent answers `404`.
#[derive(Clone, Default)]
struct Routes {
    lookups: Option<Lookups>,
    radar: Option<Radar>,
    cells: Option<Sensor<CellScan>>,
    track: Option<Sensor<TrackReport>>,
    analyze: Option<AnalyzeHandler>,
    inspect: Option<Inspect>,
    investigate: Option<InvestigateHandler>,
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

    /// Serve `GET /api/radar/cells` from the same Android telephony adapter as `radar cells`.
    /// Nothing is read before an explicitly requested API call.
    #[must_use]
    pub fn with_radar_cells(mut self, handler: CellsHandler) -> Self {
        self.routes.cells = Some(Sensor {
            handler,
            live: Arc::new(AtomicUsize::new(0)),
        });
        self
    }

    /// Serve `POST /api/radar/track` through `handler`, which records one sweep into the track
    /// log `radar track` keeps and answers its report. Without this the route answers `404`.
    #[must_use]
    pub fn with_radar_track(mut self, handler: TrackHandler) -> Self {
        self.routes.track = Some(Sensor {
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

    /// Serve `POST /api/inspect` through `handler`. Without this the route answers `404`.
    #[must_use]
    pub fn with_inspect(mut self, handler: InspectHandler) -> Self {
        self.routes.inspect = Some(Inspect {
            handler,
            live: Arc::new(AtomicUsize::new(0)),
        });
        self
    }

    /// Serve `POST /api/investigate` through `handler`. Without this the route answers `404`.
    #[must_use]
    pub fn with_investigate(mut self, handler: InvestigateHandler) -> Self {
        self.routes.investigate = Some(handler);
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
    let waiting = std::cell::Cell::new(waiting);
    let (request, upload, unread) = read_request_with(&mut stream, deadline, |head| {
        let admitted = inspect_admits(head, config, routes);
        if admitted.is_some() {
            // An admitted upload streams its body for up to INSPECT_DEADLINE: it is busy, and an
            // idle connection is what a full server closes to make room.
            drop(waiting.take());
        }
        admitted
    })?;
    // A whole request: the connection is busy now, not idle, and is no longer closed early.
    drop(waiting);
    let response = respond_with(&request, upload.as_ref(), config, routes);
    // The file is done with once the answer is built. The inspection place is held until the
    // answer is written, so one inspection's answer is in memory at a time, and a slow reader holds
    // it no longer than the deadline its upload had.
    let place = upload.map(|Upload { body, place }| {
        drop(body);
        place
    });
    let deadline = write_deadline(response.len(), place.is_some());
    write_within(&mut stream, &response, deadline)?;
    drop(place);
    stream
        .flush()
        .map_err(|error| Error::Store(format!("serve flush: {error}")))?;
    if unread > 0 {
        drain_unread(&mut stream, unread);
    }
    Ok(())
}

/// A refusal written while the client is still sending its body: a `503` for the inspection place
/// in use, a `413` for a file over the limit, a `408` for an upload that stalled, a `403` before
/// any body. Closing then, with unread bytes in the receive queue, makes the kernel answer the
/// client's next segment with RST instead of FIN, and a browser that meets the reset while
/// uploading (Firefox for Android, for one; Chrome re-reads the answer) shows a network error in
/// place of the status that explains the refusal. So the write side is shut, which sends the FIN
/// right after the answer, and the rest of the announced body is read and discarded: at most
/// [`MAX_INSPECT_BYTES`], so a lying length cannot hold the connection, within the
/// [`INSPECT_DEADLINE`] an admitted upload would have had, each read within [`IO_TIMEOUT`], so a
/// client that stops sending ends the drain at its first timed-out read. The inspection place, if
/// one was held, was given back before this.
fn drain_unread(stream: &mut TcpStream, unread: usize) {
    let _ = stream.shutdown(Shutdown::Write);
    let deadline = Instant::now() + INSPECT_DEADLINE;
    let mut left = unread.min(MAX_INSPECT_BYTES);
    let mut sink = vec![0_u8; 64 * 1024];
    while left > 0 {
        match read_step(stream, deadline, &mut sink) {
            Ok(Step::Read(read)) => left = left.saturating_sub(read),
            Ok(Step::Closed | Step::TimedOut) | Err(_) => break,
        }
    }
}

/// How much of an announced request (`announced` bytes, head and body) is still unread after
/// `read` bytes of it came in; nothing when no length was announced.
fn unread_after(announced: Option<usize>, read: usize) -> usize {
    announced.map_or(0, |announced| announced.saturating_sub(read))
}

/// When a response of `len` bytes must be written by: [`REQUEST_DEADLINE`] to start, or
/// [`INSPECT_DEADLINE`] for an inspection's answer, as long as its upload had, and a second for
/// every [`MIN_WRITE_BYTES_PER_SEC`] it holds.
fn write_deadline(len: usize, inspection: bool) -> Instant {
    let start = if inspection {
        INSPECT_DEADLINE
    } else {
        REQUEST_DEADLINE
    };
    let paced = u64::try_from(len / MIN_WRITE_BYTES_PER_SEC).unwrap_or(u64::MAX);
    Instant::now() + start + Duration::from_secs(paced)
}

/// Write all of `bytes`, each write within [`IO_TIMEOUT`] and all of them before `deadline`, so a
/// reader that takes a little at a time cannot hold the connection for ever.
fn write_within(stream: &mut TcpStream, mut bytes: &[u8], deadline: Instant) -> Result<(), Error> {
    while !bytes.is_empty() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(Error::Store(
                "serve write: the reader ran out of time".into(),
            ));
        }
        stream
            .set_write_timeout(Some(remaining.min(IO_TIMEOUT)))
            .map_err(|error| Error::Store(format!("serve write timeout: {error}")))?;
        match stream.write(bytes) {
            Ok(0) => return Err(Error::Store("serve write: the connection closed".into())),
            Ok(written) => bytes = &bytes[written..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(Error::Store(format!("serve write: {error}"))),
        }
    }
    Ok(())
}

#[cfg(test)]
fn read_request(stream: &mut TcpStream, deadline: Instant) -> Result<String, Error> {
    read_request_with(stream, deadline, |_| None).map(|(request, _, _)| request)
}

/// One read from `stream` within the time left before `deadline`.
enum Step {
    Read(usize),
    Closed,
    TimedOut,
}

fn read_step(stream: &mut TcpStream, deadline: Instant, buffer: &mut [u8]) -> Result<Step, Error> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Ok(Step::TimedOut);
    }
    // Bound each read by the time left in the whole-request budget (never longer than the
    // per-read timeout), so a client that dribbles bytes cannot hold the connection open
    // past the deadline.
    stream
        .set_read_timeout(Some(remaining.min(IO_TIMEOUT)))
        .map_err(|error| Error::Store(format!("serve read timeout: {error}")))?;
    match stream.read(buffer) {
        Ok(0) => Ok(Step::Closed),
        Ok(read) => Ok(Step::Read(read)),
        // A client that sends nothing, or stalls past its budget, has run out of time: it gets
        // the 408 that the timeout sentinel renders, not a dropped connection.
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) =>
        {
            Ok(Step::TimedOut)
        }
        Err(error) => Err(Error::Store(format!("serve read: {error}"))),
    }
}

/// Read one request. Its head and form body come back as text; when `admit` takes the head as an
/// inspection upload (its announced length and the place it holds), the body is read whole, as
/// raw bytes, within [`INSPECT_DEADLINE`], and the text is the head alone.
/// The count that comes back with them is how much of the body the head announced was left unread,
/// which the caller drains after answering, so a refusal reaches a client that is still sending.
fn read_request_with(
    stream: &mut TcpStream,
    mut deadline: Instant,
    admit: impl Fn(&str) -> Option<(usize, Slot)>,
) -> Result<(String, Option<Upload>, usize), Error> {
    let mut bytes = Vec::with_capacity(1024);
    let mut chunk = [0_u8; 1024];
    // Once the head is in: the whole request's length, the head and the form body it announces.
    let mut whole = None;
    // Once the head is in: the head and the whole body it announced, read or not.
    let mut announced = None;
    // Once an upload is admitted: where its body starts, and the place it holds.
    let mut upload: Option<(usize, Slot)> = None;

    // Until the head is in, it is read up to MAX_REQUEST_BYTES; then up to the end of the form
    // body it announces, which form_body_len bounds by MAX_FORM_BYTES however long the head was.
    while whole.map_or(bytes.len() < MAX_REQUEST_BYTES, |whole| bytes.len() < whole)
        || upload.is_some()
    {
        if let (Some((_, _)), Some(whole)) = (&upload, whole) {
            // An admitted upload is read straight into its buffer, as much as one read gives.
            let start = bytes.len();
            if start >= whole {
                break;
            }
            bytes.resize(whole.min(start + 64 * 1024), 0);
            let step = read_step(stream, deadline, &mut bytes[start..])?;
            match step {
                Step::Read(read) => bytes.truncate(start + read),
                Step::Closed => {
                    bytes.truncate(start);
                    break;
                }
                Step::TimedOut => {
                    return Ok((
                        "REQUEST_TIMEOUT".into(),
                        None,
                        unread_after(announced, bytes.len()),
                    ));
                }
            }
            continue;
        }
        let read = match read_step(stream, deadline, &mut chunk)? {
            Step::Read(read) => read,
            Step::Closed => break,
            Step::TimedOut => {
                return Ok((
                    "REQUEST_TIMEOUT".into(),
                    None,
                    unread_after(announced, bytes.len()),
                ));
            }
        };
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
                if let Some((length, place)) = admit(&String::from_utf8_lossy(&bytes[..head])) {
                    // The read that ended the head may hold bytes past the announced body.
                    bytes.truncate(head + length);
                    bytes.reserve_exact((head + length).saturating_sub(bytes.len()));
                    deadline = deadline.max(Instant::now() + INSPECT_DEADLINE);
                    upload = Some((head, place));
                    whole = Some(head + length);
                    announced = whole;
                    continue;
                }
                announced = Some(head + announced_body_len(&bytes[..head]));
                whole = Some(head + form_body_len(&bytes[..head]));
            }
        }
        if whole.is_some_and(|whole| bytes.len() >= whole) {
            break;
        }
    }

    if let Some((head, place)) = upload {
        // The head is moved out and the body kept in place, so the file is held once, not twice.
        let text = String::from_utf8_lossy(&bytes[..head]).into_owned();
        let unread = unread_after(announced, bytes.len());
        bytes.drain(..head);
        return Ok((text, Some(Upload { body: bytes, place }), unread));
    }

    if bytes.len() >= MAX_REQUEST_BYTES && !bytes.windows(4).any(|window| window == b"\r\n\r\n") {
        return Ok(("REQUEST_TOO_LARGE".into(), None, 0));
    }

    // Header values may carry bytes outside ASCII (RFC 9110 obs-text). Decoding them lossily keeps
    // such a request answerable instead of refusing it with no reply.
    Ok((
        String::from_utf8_lossy(&bytes).into_owned(),
        None,
        unread_after(announced, bytes.len()),
    ))
}

/// Whether a request head may upload a file to inspect: `POST /api/inspect` on a server that
/// serves it, passing every check its answer will make (the page's header, a same-site fetch, the
/// token, a loopback `Host`), announcing a body within [`MAX_INSPECT_BYTES`], with the one
/// inspection place free. Only then is its body read, so no other request makes the server hold a
/// file in memory. The announced length and the place come back.
fn inspect_admits(head: &str, config: &ServeConfig, routes: &Routes) -> Option<(usize, Slot)> {
    let inspect = routes.inspect.as_ref()?;
    let parsed = parse_request(head)?;
    let admitted = parsed.method == Method::Post
        && parsed.path == INSPECT_PATH
        && !parsed.transfer_encoding
        && page_refusal(&parsed, "inspection", true).is_none()
        && authorized(&parsed, config)
        && host_allowed(&parsed, config);
    if !admitted {
        return None;
    }
    let length = parsed
        .content_length
        .filter(|length| (1..=MAX_INSPECT_BYTES).contains(length))?;
    Some((length, Slot::take_of(&inspect.live, MAX_INSPECTIONS)?))
}

/// Only the scan API and the key save change state, so only they take POST, with the file
/// inspection, whose upload is too large for a query string.
fn takes_post(path: &str) -> bool {
    ScanApi::handles(path)
        || path == KEYS_PATH
        || path == INSPECT_PATH
        || path == TRACK_PATH
        || path == INVESTIGATE_PATH
        || path == OSINT_CASE_PATH
        || path == OSINT_RISK_PATH
}

/// `none` is a typed URL or bookmark; `same-origin` is this page. Anything else came from another
/// site.
fn same_site(sec_fetch_site: Option<&str>) -> bool {
    sec_fetch_site.is_none_or(|site| matches!(site, "same-origin" | "none"))
}

/// The `403` a browser-facing API route answers before anything else, naming the route as `noun`:
/// a fetch another site started, or, when the route `needs_header`, one without the page's
/// `X-Huntsman-Lookup: 1` header, which another origin cannot send without a CORS preflight this
/// server never approves. `None` when the request may go on. Every such route asks this one
/// function, so their guards cannot drift apart.
fn page_refusal(parsed: &ParsedRequest<'_>, noun: &str, needs_header: bool) -> Option<String> {
    if !same_site(parsed.sec_fetch_site) {
        return Some(json_error(403, &format!("cross-site {noun} refused")));
    }
    (needs_header && !parsed.lookup_header).then(|| {
        json_error(
            403,
            &format!("{noun} needs the X-Huntsman-Lookup: 1 header"),
        )
    })
}

/// Whether the request carries the bearer token this server needs, or the server needs none.
fn authorized(parsed: &ParsedRequest<'_>, config: &ServeConfig) -> bool {
    config
        .bearer_token
        .as_deref()
        .is_none_or(|expected| bearer_matches(parsed.authorization, expected))
}

/// The DNS-rebinding guard. A loopback server is reached from a page whose origin is a public name
/// rebound to a loopback address, so the browser sends that public name in `Host`: a loopback
/// server answers only loopback authorities (or an absent `Host`). A non-loopback bind is
/// intentionally public, gated by the bearer token, and its legitimate `Host` is not known here, so
/// the guard passes it.
fn host_allowed(parsed: &ParsedRequest<'_>, config: &ServeConfig) -> bool {
    !config.bind.ip().is_loopback() || host_is_allowed_for_loopback(parsed.host)
}

/// The body to read after a request's `head`: the `Content-Length` it announces, when that is at
/// most [`MAX_FORM_BYTES`]. A larger body is not read; the route answers without it.
fn form_body_len(head: &[u8]) -> usize {
    let announced = announced_body_len(head);
    if announced <= MAX_FORM_BYTES {
        announced
    } else {
        0
    }
}

/// The body a request's `head` announces, read or not: its `Content-Length`, or nothing.
fn announced_body_len(head: &[u8]) -> usize {
    parse_request(&String::from_utf8_lossy(head))
        .and_then(|parsed| parsed.content_length)
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
    /// A `Transfer-Encoding` was sent. It would override any `Content-Length` (RFC 9112 6.3), and
    /// this server reads no chunked body, so every route refuses it.
    transfer_encoding: bool,
    /// The `Content-Length`, when it is a number.
    content_length: Option<usize>,
    /// What followed the head, as far as it was read; `None` when the head never ended in its
    /// blank line, because the client stopped part way through it.
    body: Option<&'a str>,
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
    let mut transfer_encoding = false;
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
            transfer_encoding = true;
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
        transfer_encoding,
        content_length,
        body: request.split_once("\r\n\r\n").map(|(_, body)| body),
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
    /// Immutable Git revision embedded in the running server, or "unknown".
    build_sha: &'a str,
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

/// The bytes to write for one request that uploaded no file.
#[cfg(test)]
fn respond(request: &str, config: &ServeConfig, routes: &Routes) -> Vec<u8> {
    respond_with(request, None, config, routes)
}

/// The bytes to write for one request and the file it uploaded, if any: text for every answer but
/// a scan export that is a workbook. A `HEAD` answer is the `GET` answer's head alone, whichever
/// route built it.
fn respond_with(
    request: &str,
    upload: Option<&Upload>,
    config: &ServeConfig,
    routes: &Routes,
) -> Vec<u8> {
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
    let mut bytes = route(&parsed, upload, config, routes);
    if parsed.method == Method::Head {
        if let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            bytes.truncate(end + 4);
        }
    }
    bytes
}

/// Render the health contract without inflating the shared request router.
fn health_response(config: &ServeConfig, head: bool) -> String {
    let body = serde_json::to_string_pretty(&Health {
        status: "ok",
        name: "huntsman-recon",
        version: env!("CARGO_PKG_VERSION"),
        build_sha: crate::diagnostics::embedded_build_sha(),
        page: &PAGE_ID,
        auth: if config.bearer_token.is_some() {
            "token"
        } else {
            "none"
        },
    })
    .unwrap_or_else(|_| "{\"status\":\"error\"}".into());
    json_ok(&body, head)
}

/// The answer to a parsed request: the guards every route shares, then the route's own.
fn route(
    parsed: &ParsedRequest<'_>,
    upload: Option<&Upload>,
    config: &ServeConfig,
    routes: &Routes,
) -> Vec<u8> {
    if !host_allowed(parsed, config) {
        return response(
            403,
            "text/plain; charset=utf-8",
            "host not allowed\n",
            parsed.method == Method::Head,
        )
        .into_bytes();
    }

    if parsed.transfer_encoding {
        return response(
            400,
            "text/plain; charset=utf-8",
            "send a request body with a Content-Length, not a Transfer-Encoding\n",
            false,
        )
        .into_bytes();
    }

    if parsed.method == Method::Other || parsed.method == Method::Post && !takes_post(parsed.path) {
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
            | "/api/evidence"
            | "/evidence"
            | "/api/radar/wifi"
            | "/api/radar/cells"
            | TRACK_PATH
            | KEYS_PATH
            | INSPECT_PATH
            | OSINT_CASE_PATH
            | OSINT_RISK_PATH
            | INVESTIGATE_PATH
    ) || ScanApi::handles(parsed.path);
    if protected && !authorized(parsed, config) {
        return response(401, "application/json; charset=utf-8", UNAUTHORIZED, head).into_bytes();
    }

    if ScanApi::handles(parsed.path) {
        return scans_response(parsed, routes.scans.as_ref());
    }
    let text = match parsed.path {
        "/" | "/index.html" => response(200, "text/html; charset=utf-8", &PAGE, head),
        "/api/health" => health_response(config, head),
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
        "/api/lookup" => lookup_response(parsed, routes.lookups.as_ref(), routes.scans.as_ref()),
        "/api/radar/wifi" => {
            sensor_response(parsed, routes.radar.as_ref(), "Wi-Fi radar", Method::Get)
        }
        "/api/radar/cells" => {
            sensor_response(parsed, routes.cells.as_ref(), "cell radar", Method::Get)
        }
        TRACK_PATH => sensor_response(parsed, routes.track.as_ref(), "radar track", Method::Post),
        "/api/analyze" => analyze_response(parsed, routes.analyze.as_ref()),
        "/evidence" => dossier_page_response(parsed, config),
        "/api/evidence" => dossier_json_response(parsed, config),
        KEYS_PATH => keys_response(parsed, routes.keys_home.as_deref()),
        INSPECT_PATH => inspect_response(parsed, upload, routes),
        OSINT_CASE_PATH => osint_offline_response(parsed, false),
        OSINT_RISK_PATH => osint_offline_response(parsed, true),
        INVESTIGATE_PATH => investigate_response(parsed, routes.investigate.as_ref()),
        "/favicon.svg" => response(200, "image/svg+xml", FAVICON_SVG, head),
        "/favicon.ico" => response(204, "image/x-icon", "", head),
        _ => response(404, "text/plain; charset=utf-8", "not found\n", head),
    };
    text.into_bytes()
}

/** Render the complete case dossier on loopback only; never expose local case material on a public bind. */
fn dossier_page_response(parsed: &ParsedRequest<'_>, config: &ServeConfig) -> String {
    let head = parsed.method == Method::Head;
    if !config.bind.ip().is_loopback() {
        return json_error(403, "local evidence is available only on a loopback bind");
    }
    if !parsed.query.is_empty() {
        return json_error(400, "evidence page takes no query parameters");
    }
    match crate::dossier_view::load().and_then(|document| crate::dossier_view::render(&document)) {
        Ok(html) => response(200, "text/html; charset=utf-8; hse=dossier", &html, head),
        Err(message) => {
            let code = if message.contains("exceeds") {
                413
            } else if message.contains("cannot open") {
                404
            } else {
                422
            };
            response(
                code,
                "text/plain; charset=utf-8",
                &format!("{message}\n"),
                head,
            )
        }
    }
}

/// Return the complete source register, preserving all fields and records.
fn dossier_json_response(parsed: &ParsedRequest<'_>, config: &ServeConfig) -> String {
    if !config.bind.ip().is_loopback() {
        return json_error(403, "local evidence is available only on a loopback bind");
    }
    if !parsed.query.is_empty() {
        return json_error(400, "evidence API takes no query parameters");
    }
    match crate::dossier_view::load() {
        Ok(document) => match serde_json::to_string(&document) {
            Ok(json) => json_ok(&json, parsed.method == Method::Head),
            Err(_) => json_error(500, "dossier serialization failed"),
        },
        Err(message) => {
            let code = if message.contains("exceeds") {
                413
            } else if message.contains("cannot open") {
                404
            } else {
                422
            };
            json_error(code, &message)
        }
    }
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

/// Read a sensor (Android's OS-cached Wi-Fi scan, or the cells it reports) or record one track
/// sweep only after an explicitly initiated, same-origin, lookup-header-bearing request of the one
/// `method` it takes. A missing sensor is an error, never a fabricated empty scan. Each worker is
/// time- and concurrency-bounded, one request to a sensor at a time.
fn sensor_response<T: serde::Serialize + Send + 'static>(
    parsed: &ParsedRequest<'_>,
    sensor: Option<&Sensor<T>>,
    noun: &str,
    method: Method,
) -> String {
    let Some(sensor) = sensor else {
        return json_error(404, &format!("{noun} is not enabled on this server"));
    };
    if parsed.method != method {
        return json_error(405, &format!("{noun} needs {}", method.as_str()));
    }
    if let Some(refused) = page_refusal(parsed, &format!("{noun} request"), true) {
        return refused;
    }
    if !parsed.query.is_empty() {
        return json_error(400, &format!("{noun} takes no query parameters"));
    }
    if parsed.has_body {
        return json_error(400, &format!("{noun} takes no body"));
    }
    let Some(slot) = Slot::take_of(&sensor.live, MAX_RADAR_REQUESTS) else {
        return json_error(503, &format!("{noun} request already in progress"));
    };
    let handler = Arc::clone(&sensor.handler);
    let (sender, receiver) = sync_channel(1);
    let worker = thread::Builder::new()
        .name("serve-radar".into())
        .stack_size(LOOKUP_STACK_BYTES)
        .spawn(move || {
            let result = catch_unwind(AssertUnwindSafe(|| handler()));
            drop(slot);
            let _ = sender.send(result);
        });
    if worker.is_err() {
        return json_error(503, &format!("could not start a {noun} worker"));
    }
    match receiver.recv_timeout(RADAR_WAIT) {
        Ok(Ok(Ok(report))) => match serde_json::to_string(&report) {
            Ok(body) => json_ok(&body, false),
            Err(_) => json_error(500, &format!("{noun} observations could not be encoded")),
        },
        Ok(Ok(Err(error))) => json_error(error.status, &error.message),
        Ok(Err(_)) | Err(RecvTimeoutError::Disconnected) => {
            json_error(500, &format!("{noun} failed unexpectedly"))
        }
        Err(RecvTimeoutError::Timeout) => {
            json_error(504, &format!("{noun} did not answer in time"))
        }
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
    if let Some(refused) = page_refusal(parsed, "lookup", true) {
        return refused;
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
    if let Some(refused) = page_refusal(parsed, "scan request", true) {
        return refused.into_bytes();
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
        let value = form_decode(value).ok_or("query is not valid percent-encoded UTF-8")?;
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
    if let Some(refused) = page_refusal(parsed, "key request", true) {
        return refused;
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
    let Some(body) = parsed.body else {
        return Err(json_error(400, "the request ended before its head did"));
    };
    if parsed.content_length != Some(body.len()) {
        return Err(json_error(
            400,
            &format!("send the form as a body of at most {MAX_FORM_BYTES} bytes"),
        ));
    }
    let Some(form) = form_pairs(body) else {
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
/// Reuse Huntsman's existing authorization and same-site gates for both
/// bounded, offline JSON OSINT methods. No remote provider request is made.
fn osint_offline_response(parsed: &ParsedRequest<'_>, risk: bool) -> String {
    if parsed.method != Method::Post {
        return json_error(405, "OSINT source analysis requires POST");
    }
    if let Some(refusal) = page_refusal(parsed, "OSINT source analysis", true) {
        return refusal;
    }
    if !parsed.query.is_empty() {
        return json_error(
            400,
            "OSINT analysis accepts JSON body, not query parameters",
        );
    }
    let Some(length) = parsed.content_length else {
        return json_error(400, "OSINT analysis needs content length");
    };
    if length == 0 || length > MAX_FORM_BYTES {
        return json_error(
            413,
            "OSINT body size exceeded; use the CLI for larger datasets",
        );
    }
    let Some(body) = parsed.body else {
        return json_error(400, "OSINT analysis body missing");
    };
    if body.len() != length {
        return json_error(400, "OSINT analysis body incomplete or invalid UTF-8");
    }
    if risk {
        match crate::osint_area_risk::estimate_json(body.as_bytes()) {
            Ok(report) => serde_json::to_string(&report).map_or_else(
                |_| json_error(500, "OSINT area result serialization failed"),
                |json| json_ok(&json, false),
            ),
            Err(_) => json_error(400, "OSINT area input invalid"),
        }
    } else {
        match crate::osint_casework::review_json(body.as_bytes()) {
            Ok(report) => serde_json::to_string(&report).map_or_else(
                |_| json_error(500, "OSINT case result serialization failed"),
                |json| json_ok(&json, false),
            ),
            Err(_) => json_error(400, "OSINT case input invalid"),
        }
    }
}

fn analyze_response(parsed: &ParsedRequest<'_>, analyze: Option<&AnalyzeHandler>) -> String {
    let Some(analyze) = analyze else {
        return json_error(404, "analysis is not enabled on this server");
    };
    if parsed.method != Method::Get {
        return json_error(405, "analysis needs GET");
    }
    if let Some(refused) = page_refusal(parsed, "analysis", false) {
        return refused;
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

/// `POST /api/investigate`: the actionable entities in the text sent as the body, as a report like
/// a lookup's. The text travels in the body, never the URL, which is kept in history and logs;
/// it is read whole within [`MAX_FORM_BYTES`], as a key save is, so a longer text is refused with
/// the command that reads one from a file in Termux.
fn investigate_response(
    parsed: &ParsedRequest<'_>,
    handler: Option<&InvestigateHandler>,
) -> String {
    let Some(handler) = handler else {
        return json_error(404, "text investigation is not enabled on this server");
    };
    if parsed.method != Method::Post {
        return json_error(405, "investigation needs POST with the text as the body");
    }
    if let Some(refused) = page_refusal(parsed, "investigation", true) {
        return refused;
    }
    if !parsed.query.is_empty() {
        return json_error(
            400,
            "investigation takes no query string: send the text as the body",
        );
    }
    let length = match parsed.content_length {
        None | Some(0) => return json_error(400, "investigation needs the text as the body"),
        Some(length) if length > MAX_FORM_BYTES => {
            return json_error(
                413,
                &format!(
                    "the text is longer than {MAX_FORM_BYTES} bytes; in Termux, investigate --file FILE reads a longer one"
                ),
            );
        }
        Some(length) => length,
    };
    let Some(body) = parsed.body else {
        return json_error(400, "the request ended before its head did");
    };
    // The request was decoded lossily, so a byte that was not UTF-8 is U+FFFD by now and never
    // fewer bytes than it was: a body shorter than it announced was cut.
    if body.len() < length {
        return json_error(400, "the text ended before the length it announced");
    }
    let text = body.to_owned();
    let handler = Arc::clone(handler);
    let worker = thread::Builder::new()
        .name("serve-investigate".into())
        .stack_size(ANALYZE_STACK_BYTES)
        .spawn(move || handler(&text));
    let outcome = match worker {
        Ok(worker) => worker.join(),
        Err(_) => return json_error(503, "could not start an investigation worker"),
    };
    match outcome {
        Ok(Ok(report)) => match serde_json::to_string(&report) {
            Ok(body) => json_ok(&body, false),
            Err(_) => json_error(500, "the investigation could not be encoded"),
        },
        Ok(Err(error)) => json_error(error.status, &error.message),
        Err(_) => json_error(500, "investigation failed unexpectedly"),
    }
}

/// `POST /api/inspect?name=FILE`: the uploaded file's EXIF and embedded document metadata, as a
/// report. The body is the file's raw bytes (`fetch` with a `File` as its body), read only once
/// [`inspect_admits`] took the request; a request it did not take is answered why here.
fn inspect_response(
    parsed: &ParsedRequest<'_>,
    upload: Option<&Upload>,
    routes: &Routes,
) -> String {
    let Some(inspect) = routes.inspect.as_ref() else {
        return json_error(404, "file inspection is not enabled on this server");
    };
    if parsed.method != Method::Post {
        return json_error(405, "inspection needs POST with the file as the body");
    }
    if let Some(refused) = page_refusal(parsed, "inspection", true) {
        return refused;
    }
    let length = match parsed.content_length {
        None | Some(0) => return json_error(400, "inspection needs the file as the body"),
        Some(length) if length > MAX_INSPECT_BYTES => {
            return json_error(413, "the file is larger than 64 MiB");
        }
        Some(length) => length,
    };
    let Some(upload) = upload else {
        // The upload gate only sees a head that ended in its blank line, so one that never did was
        // cut short. Otherwise every other check passed, and the one place was taken.
        if parsed.body.is_none() {
            return json_error(400, "the request ended before its head did");
        }
        return json_error(503, "an inspection is already running; retry shortly");
    };
    if upload.body.len() != length {
        return json_error(400, "the upload ended before the length it announced");
    }
    let label = match inspect_label(parsed.query) {
        Ok(label) => label,
        Err(message) => return json_error(400, message),
    };
    let handler = &inspect.handler;
    let body = upload.body.as_slice();
    let service = routes.scans.as_deref().map(ScanApi::service);
    let outcome = thread::scope(|scope| {
        thread::Builder::new()
            .name("serve-inspect".into())
            .stack_size(INSPECT_STACK_BYTES)
            .spawn_scoped(scope, || {
                catch_unwind(AssertUnwindSafe(|| {
                    handler(&label, body).map(|report| match service {
                        Some(service) => keep_inspection(service, &label, report),
                        None => report,
                    })
                }))
            })
            .map(thread::ScopedJoinHandle::join)
    });
    match outcome {
        Ok(Ok(Ok(Ok(report)))) => match serde_json::to_string(&report) {
            Ok(body) => json_ok(&body, false),
            Err(_) => json_error(500, "the inspection could not be encoded"),
        },
        Ok(Ok(Ok(Err(error)))) => json_error(error.status, &error.message),
        Ok(Ok(Err(_)) | Err(_)) => json_error(500, "inspection failed unexpectedly"),
        Err(_) => json_error(503, "could not start an inspection worker"),
    }
}

/// The inspection kept as a `FINISHED` scan of the file, named in the report's `scan` and
/// `status`, with every entity stamped with that scan's id so its provenance names a scan
/// `/api/scans/ID` reads again. When the store refuses, the report is answered whole all the same,
/// with a `scans` outcome saying why it was not kept: a full store never costs the file's findings.
fn keep_inspection(service: &ScanService, label: &str, mut report: LookupReport) -> LookupReport {
    let found = LookupOutput {
        text: report.text.clone(),
        entities: report.entities.clone(),
        outcomes: report.outcomes.clone(),
    };
    match service.keep(
        label,
        crate::sf_types::base_type(&EntityKind::Document),
        INSPECT_KIND,
        found,
    ) {
        Ok(record) => {
            stamp_scan_id(&mut report.entities, &record.id);
            report.scan = Some(record.id);
            report.status = Some(record.status.as_str());
        }
        Err(error) => report.outcomes.push(SourceExecutionOutcome::inconclusive(
            "scans",
            crate::clock::unix_now(),
            format!("not kept as a saved scan: {error}"),
        )),
    }
    report
}

/// The report label for an upload: the `name` query value, reduced to a file name (no directory),
/// with control characters dropped, within [`MAX_INSPECT_NAME_BYTES`]; `upload` when it is absent
/// or empty. Unknown keys are ignored.
fn inspect_label(raw: &str) -> Result<String, &'static str> {
    let mut name = String::new();
    for pair in raw.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if key == "name" {
            name = form_decode(value).ok_or("name is not valid percent-encoded UTF-8")?;
        }
    }
    let base = name.rsplit(['/', '\\']).next().unwrap_or("");
    let mut label = String::new();
    for c in base.chars().filter(|c| !c.is_control()) {
        if label.len() + c.len_utf8() > MAX_INSPECT_NAME_BYTES {
            break;
        }
        label.push(c);
    }
    let label = label.trim();
    Ok(if label.is_empty() {
        "upload".to_owned()
    } else {
        label.to_owned()
    })
}

/// The seeds in a query's `seeds` value, one per line: each is trimmed and blank lines are
/// dropped. Unknown keys are ignored.
fn parse_analyze_seeds(raw: &str) -> Result<Vec<String>, String> {
    let mut text = String::new();
    for pair in raw.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if key == "seeds" {
            text = form_decode(value)
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

/// Dedicated, script-free CSP for locally rendered dossier pages.
static DOSSIER_POLICY: LazyLock<String> = LazyLock::new(|| {
    format!(
        "default-src 'none'; script-src 'none'; style-src '{}'; img-src 'none'; connect-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        hash_source(crate::dossier_view::STYLE)
    )
});

/// Every other response loads nothing and may not be framed.
const OTHER_POLICY: &str = "default-src 'none'; frame-ancestors 'none'";

/// The text between `<tag>` and `</tag>`, the part a browser hashes for a CSP hash source.
pub(crate) fn inline_block<'a>(page: &'a str, tag: &str) -> &'a str {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    match (page.find(&open), page.find(&close)) {
        (Some(start), Some(end)) if start + open.len() <= end => &page[start + open.len()..end],
        _ => "",
    }
}

pub(crate) fn hash_source(content: &str) -> String {
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
        504 => "Gateway Timeout",
        _ => "Error",
    };
    let status_header = match status {
        503 => "Retry-After: 1\r\n",
        401 => "WWW-Authenticate: Bearer realm=\"huntsman-recon\"\r\n",
        _ => "",
    };
    let policy = if content_type.ends_with("; hse=dossier") {
        DOSSIER_POLICY.as_str()
    } else if content_type.starts_with("text/html") {
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
mod tests;
