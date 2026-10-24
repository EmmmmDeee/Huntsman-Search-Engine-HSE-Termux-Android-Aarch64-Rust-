//! HTTP boundary: plain request/response structs, a `Transport` trait, and one
//! real transport. Everything above this layer (fetch, providers) is tested with a
//! fake `Transport`; only this file touches sockets.
//!
//! Hygiene that applies to every request: credentials never appear in `Debug`
//! output, redirects are not followed here (the fetch layer follows them and strips
//! credentials when the origin changes), bodies are read under a hard byte cap, and
//! the resolver only returns addresses the egress policy permits, so a hostname
//! cannot be rebound onto the operator's own network.

use std::fmt;
use std::io::{self, Read};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::de::DeserializeOwned;
use ureq::http::{self, Uri};
use ureq::tls::{Certificate, PemItem, RootCerts, TlsConfig};
use ureq::unversioned::resolver::{DefaultResolver, ResolvedSocketAddrs, Resolver};
use ureq::unversioned::transport::{DefaultConnector, NextTimeout};

use crate::egress::EgressPolicy;
use crate::error::Error;
use crate::redact::REDACTED;
use crate::source_outcome::SourceOutcomeKind;

pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(20);
pub const DEFAULT_MAX_BODY: usize = 4 * 1024 * 1024;
pub const DEFAULT_USER_AGENT: &str = concat!("huntsman-recon/", env!("CARGO_PKG_VERSION"));
const BLOCKED_PREFIX: &str = "egress-policy:";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Head,
    Post,
}

impl Method {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Post => "POST",
        }
    }
}

/// Header names whose values must never be printed or logged.
#[must_use]
pub fn is_sensitive_header(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    matches!(
        n.as_str(),
        "authorization" | "proxy-authorization" | "cookie" | "set-cookie"
    ) || ["key", "token", "secret", "password", "auth"]
        .iter()
        .any(|needle| n.contains(needle))
}

#[derive(Clone, PartialEq, Eq)]
pub struct Request {
    pub method: Method,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// Cap for this request, end to end. `None` uses the transport's timeout; a
    /// value only ever lowers it. Set from a [`crate::deadline::Deadline`] so one
    /// lookup's requests share a single budget. Kept across redirects the fetch
    /// layer follows.
    pub timeout: Option<Duration>,
}

impl Request {
    #[must_use]
    pub fn get(url: impl Into<String>) -> Self {
        Self {
            method: Method::Get,
            url: url.into(),
            headers: Vec::new(),
            body: Vec::new(),
            timeout: None,
        }
    }

    #[must_use]
    pub fn post(url: impl Into<String>, body: Vec<u8>) -> Self {
        Self {
            method: Method::Post,
            body,
            ..Self::get(url)
        }
    }

    #[must_use]
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Cap this request at `timeout` (never above the transport's own timeout).
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Case-insensitive header lookup.
    #[must_use]
    pub fn header_value(&self, name: &str) -> Option<&str> {
        find_header(&self.headers, name)
    }
}

impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let headers: Vec<(&str, &str)> = self
            .headers
            .iter()
            .map(|(k, v)| {
                (
                    k.as_str(),
                    if is_sensitive_header(k) {
                        REDACTED
                    } else {
                        v.as_str()
                    },
                )
            })
            .collect();
        f.debug_struct("Request")
            .field("method", &self.method)
            .field("url", &redact_url(&self.url))
            .field("headers", &headers)
            .field("body_len", &self.body.len())
            .field("timeout", &self.timeout)
            .finish()
    }
}

/// Response headers have lowercase names. `truncated` is set when the body hit the
/// byte cap, in which case an empty parse is not evidence of absence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub truncated: bool,
}

impl Response {
    #[must_use]
    pub fn header_value(&self, name: &str) -> Option<&str> {
        find_header(&self.headers, name)
    }

    /// The body as text, borrowed when it is valid UTF-8 (the common case) and copied with
    /// replacement characters only when it is not. A classifier that reads the body once
    /// takes this; [`Self::text`] copies.
    #[must_use]
    pub fn text_view(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.body)
    }

    #[must_use]
    pub fn text(&self) -> String {
        self.text_view().into_owned()
    }
}

fn find_header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Append one URL-encoded query parameter to `url`'s query, before any fragment: a parameter
/// after the `#` would never be sent.
#[must_use]
pub fn append_query_param(url: &str, name: &str, value: &str) -> String {
    let (base, fragment) = url
        .split_once('#')
        .map_or((url, None), |(base, fragment)| (base, Some(fragment)));
    let separator = if base.contains('?') { '&' } else { '?' };
    let mut out = format!(
        "{base}{separator}{name}={}",
        percent_encode_component(value)
    );
    if let Some(fragment) = fragment {
        out.push('#');
        out.push_str(fragment);
    }
    out
}

/// One query component, form-encoded: unreserved bytes are kept, a space is `+`, and every other
/// byte is `%XX`.
#[must_use]
pub fn percent_encode_component(raw: &str) -> String {
    let mut out = String::new();
    for byte in raw.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(char::from(byte));
            }
            b' ' => out.push('+'),
            _ => {
                out.push('%');
                out.push(hex_upper_digit(byte >> 4));
                out.push(hex_upper_digit(byte & 0x0f));
            }
        }
    }
    out
}

/// One path segment or query value, RFC 3986 encoded: unreserved bytes are kept, and every other
/// byte, a space included, is `%XX`.
#[must_use]
pub fn percent_encode_unreserved(raw: &str) -> String {
    let mut out = String::new();
    for byte in raw.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push(hex_upper_digit(byte >> 4));
            out.push(hex_upper_digit(byte & 0x0f));
        }
    }
    out
}

pub(crate) fn hex_upper_digit(value: u8) -> char {
    match value {
        0..=9 => char::from(b'0' + value),
        10..=15 => char::from(b'A' + (value - 10)),
        _ => unreachable!("hex nibble"),
    }
}

pub(crate) fn parse_json_body<T: DeserializeOwned>(response: &Response) -> serde_json::Result<T> {
    serde_json::from_slice(&response.body)
}

/// A request that never produced an HTTP response. `kind` is the causal outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportFailure {
    pub kind: SourceOutcomeKind,
    pub detail: String,
    /// The egress policy refused the destination; nothing was sent.
    pub blocked: bool,
}

pub trait Transport {
    /// # Errors
    /// `TransportFailure` when no HTTP response was obtained.
    fn send(&self, request: &Request) -> Result<Response, TransportFailure>;

    /// The addresses `name` resolves to through the system resolver, as a DNS blocklist is asked:
    /// on a phone that is the network's own resolver, which lists such as Spamhaus answer and
    /// public `DoH` resolvers are refused by. A name that does not exist resolves to no address.
    /// A transport without a resolver fails every name.
    ///
    /// # Errors
    /// `TransportFailure` when the resolver gave no answer.
    fn resolve(&self, name: &str) -> Result<Vec<IpAddr>, TransportFailure> {
        Err(TransportFailure {
            kind: SourceOutcomeKind::DnsFailure,
            detail: format!("no system resolver to ask for {name}"),
            blocked: false,
        })
    }

    /// Send one DNS message to `server` over UDP and return the datagram it sends back, as a
    /// resolver that offers no DNS-over-HTTPS is asked. A transport without UDP fails every
    /// exchange.
    ///
    /// # Errors
    /// `TransportFailure` when nothing came back within [`UDP_TIMEOUT`], or the egress policy
    /// refuses `server` (then nothing was sent).
    fn exchange_udp(
        &self,
        server: SocketAddr,
        _message: &[u8],
    ) -> Result<Vec<u8>, TransportFailure> {
        Err(TransportFailure {
            kind: SourceOutcomeKind::ConnectFailure,
            detail: format!("no UDP to ask {server}"),
            blocked: false,
        })
    }

    /// Whether the lookup this transport serves asks `module`, by its Huntsman name: every leg
    /// asks before it sends, and one that may not sends nothing and leaves no outcome. Only
    /// [`crate::module_selection::Selected`] runs fewer than every module; a transport that wraps
    /// another passes the question on.
    fn runs_module(&self, _module: &str) -> bool {
        true
    }

    /// This transport as one several threads may share, when it is one. A lookup with several
    /// independent sources to ask asks them all at once through it, and one after another
    /// through a transport that cannot be shared; the answers fold the same either way.
    fn shared(&self) -> Option<&(dyn Transport + Sync)> {
        None
    }
}

/// The longest one UDP exchange waits for its answer.
pub const UDP_TIMEOUT: Duration = Duration::from_secs(4);

/// Send `message` to `server` from a fresh socket connected to it, so only `server`'s datagrams
/// are read, and wait at most `timeout` for one.
fn udp_exchange(
    server: SocketAddr,
    message: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, TransportFailure> {
    let failure = |error: &io::Error| TransportFailure {
        kind: if matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        ) {
            SourceOutcomeKind::TtfbTimeout
        } else {
            SourceOutcomeKind::ConnectFailure
        },
        detail: format!("{server}: {error}"),
        blocked: false,
    };
    let local: SocketAddr = if server.is_ipv4() {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let socket = std::net::UdpSocket::bind(local).map_err(|e| failure(&e))?;
    socket.connect(server).map_err(|e| failure(&e))?;
    socket
        .set_read_timeout(Some(timeout))
        .map_err(|e| failure(&e))?;
    socket.send(message).map_err(|e| failure(&e))?;
    let mut buffer = vec![0_u8; 65_535];
    let length = socket.recv(&mut buffer).map_err(|e| failure(&e))?;
    buffer.truncate(length);
    Ok(buffer)
}

/// The longest one system-resolver question may take: a blocklist that does not answer is
/// reported as such instead of holding up the lookup.
pub const RESOLVE_TIMEOUT: Duration = Duration::from_secs(8);

/// Maximum live native resolver calls, including calls whose waiting client timed out.
/// Native getaddrinfo cannot be cancelled; capacity is returned only when its worker exits.
const MAX_SYSTEM_RESOLVERS: usize = 8;
static LIVE_SYSTEM_RESOLVERS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

struct ResolverWorkerSlot(&'static std::sync::atomic::AtomicUsize);

impl Drop for ResolverWorkerSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

fn reserve_resolver_worker(
    active: &'static std::sync::atomic::AtomicUsize,
    capacity: usize,
) -> Option<ResolverWorkerSlot> {
    use std::sync::atomic::Ordering;
    let mut count = active.load(Ordering::Acquire);
    loop {
        if count >= capacity {
            return None;
        }
        match active.compare_exchange_weak(
            count,
            count + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return Some(ResolverWorkerSlot(active)),
            Err(observed) => count = observed,
        }
    }
}

/// Ask the native resolver on a bounded worker thread. Timed-out workers continue to
/// occupy capacity until they exit, preventing unbounded native-thread accumulation.
fn system_resolve(name: &str, timeout: Duration) -> Result<Vec<IpAddr>, TransportFailure> {
    use std::net::ToSocketAddrs as _;
    let asked = name.to_owned();
    system_resolve_with(
        name,
        timeout,
        &LIVE_SYSTEM_RESOLVERS,
        MAX_SYSTEM_RESOLVERS,
        move || {
            (asked.as_str(), 0).to_socket_addrs().map(|addresses| {
                let mut ips: Vec<IpAddr> = addresses.map(|address| address.ip()).collect();
                ips.sort_unstable();
                ips.dedup();
                ips
            })
        },
    )
}

/// Resolver injection keeps saturation and worker-lifetime tests offline and deterministic.
fn system_resolve_with<F>(
    name: &str,
    timeout: Duration,
    active: &'static std::sync::atomic::AtomicUsize,
    capacity: usize,
    resolve: F,
) -> Result<Vec<IpAddr>, TransportFailure>
where
    F: FnOnce() -> io::Result<Vec<IpAddr>> + Send + 'static,
{
    let failure = |detail: String| TransportFailure {
        kind: SourceOutcomeKind::DnsFailure,
        detail,
        blocked: false,
    };
    let permit = reserve_resolver_worker(active, capacity).ok_or_else(|| {
        failure(format!(
            "{name}: native resolver capacity exhausted ({capacity} workers in flight)"
        ))
    })?;
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("resolve".into())
        .spawn(move || {
            // Owned by the worker, not the timed-out caller. Also released on panic.
            let _permit = permit;
            let _ = sender.send(resolve());
        })
        .map_err(|e| failure(format!("resolver thread: {e}")))?;
    match receiver.recv_timeout(timeout) {
        Ok(Ok(addresses)) => Ok(addresses),
        Ok(Err(error)) if names_no_address(&error.to_string()) => Ok(Vec::new()),
        Ok(Err(error)) => Err(failure(format!("{name}: {error}"))),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(failure(format!(
            "{name}: no answer within {}s",
            timeout.as_secs()
        ))),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Err(failure(format!(
            "{name}: native resolver worker stopped without an answer"
        ))),
    }
}

/// Whether a resolver error says the name has no address, in the words glibc, musl, bionic and
/// the BSDs use, rather than that no server answered. **Pure.**
pub(crate) fn names_no_address(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    !message.contains("temporary")
        && [
            "not known",
            "no address associated",
            "does not resolve",
            "nodename nor servname",
            "no such host",
            "non-recoverable failure in name resolution",
        ]
        .iter()
        .any(|phrase| message.contains(phrase))
}

/// Strip userinfo and query string: both routinely carry secrets (`user:pass@`,
/// `?api_key=`), and neither is needed to identify a source in a log.
#[must_use]
pub fn redact_url(url: &str) -> String {
    let (no_frag, _) = url.split_once('#').unwrap_or((url, ""));
    let (base, query) = match no_frag.split_once('?') {
        Some((b, _)) => (b, true),
        None => (no_frag, false),
    };
    let base = match base.split_once("://") {
        Some((scheme, rest)) => {
            let (authority, path) = rest
                .split_once('/')
                .map_or((rest, None), |(a, p)| (a, Some(p)));
            let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
            match path {
                Some(p) => format!("{scheme}://{host}/{p}"),
                None => format!("{scheme}://{host}"),
            }
        }
        // `scheme:user:pass@host/...` without the slashes: the userinfo is still dropped.
        None => match base.split_once(':') {
            Some((scheme, rest)) => {
                let (authority, path) = rest
                    .split_once('/')
                    .map_or((rest, None), |(a, p)| (a, Some(p)));
                match (authority.rsplit_once('@'), path) {
                    (Some((_, host)), Some(p)) => format!("{scheme}:{host}/{p}"),
                    (Some((_, host)), None) => format!("{scheme}:{host}"),
                    (None, _) => base.to_owned(),
                }
            }
            None => base.to_owned(),
        },
    };
    if query {
        format!("{base}?{REDACTED}")
    } else {
        base
    }
}

/// Resolve a `Location` header against the URL that produced it.
///
/// # Errors
/// `Error::Network` when either URL is not a valid http(s) URL.
pub fn resolve_location(base: &str, location: &str) -> Result<String, Error> {
    let base = base.split_once('#').map_or(base, |(url, _)| url);
    let location = location.trim();
    let location = location.split_once('#').map_or(location, |(l, _)| l);
    let base_uri = parse_http_uri(base)?;
    let scheme = base_uri.scheme_str().unwrap_or("http");
    let authority = base_uri
        .authority()
        .ok_or_else(|| Error::Network(format!("no host in {}", redact_url(base))))?;
    let joined = if has_scheme(location) {
        location.to_owned()
    } else if let Some(rest) = location.strip_prefix("//") {
        format!("{scheme}://{rest}")
    } else if location.starts_with('/') {
        format!("{scheme}://{authority}{location}")
    } else if location.is_empty() {
        base.to_owned()
    } else if location.starts_with('?') {
        format!("{scheme}://{authority}{}{location}", base_uri.path())
    } else {
        let path = base_uri.path();
        let dir = path.rfind('/').map_or("/", |i| &path[..=i]);
        format!("{scheme}://{authority}{dir}{location}")
    };
    let target = parse_http_uri(&joined)?;
    let path = remove_dot_segments(target.path());
    if path == target.path() {
        return Ok(joined);
    }
    let authority = target
        .authority()
        .ok_or_else(|| Error::Network("redirect has no authority".into()))?;
    let query = target.query().map_or_else(String::new, |q| format!("?{q}"));
    Ok(format!(
        "{}://{authority}{path}{query}",
        target.scheme_str().unwrap_or(scheme)
    ))
}

/// RFC 3986 section 5.2.4. Operate on raw path bytes, preserving empty
/// segments and encoded octets; queries never pass through this function.
fn remove_dot_segments(mut input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    while !input.is_empty() {
        if let Some(rest) = input
            .strip_prefix("../")
            .or_else(|| input.strip_prefix("./"))
        {
            input = rest;
        } else if input.starts_with("/./") {
            input = &input[2..];
        } else if input == "/." {
            input = "/";
        } else if input.starts_with("/../") || input == "/.." {
            input = if input == "/.." { "/" } else { &input[3..] };
            output.truncate(output.rfind('/').unwrap_or(0));
        } else if matches!(input, "." | "..") {
            input = "";
        } else {
            let start = usize::from(input.starts_with('/'));
            let end = input[start..].find('/').map_or(input.len(), |i| start + i);
            output.push_str(&input[..end]);
            input = &input[end..];
        }
    }
    output
}

/// RFC 3986 scheme prefix (`javascript:`, `mailto:`, `https:`), with or without `//`.
fn has_scheme(s: &str) -> bool {
    let Some((head, _)) = s.split_once(':') else {
        return false;
    };
    let mut chars = head.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

/// # Errors
/// `Error::Network` unless `url` is an absolute http(s) URL with a host.
pub fn parse_http_uri(url: &str) -> Result<Uri, Error> {
    let uri: Uri = url
        .parse()
        .map_err(|_| Error::Network(format!("invalid url: {}", redact_url(url))))?;
    match uri.scheme_str() {
        Some("http" | "https") if uri.host().is_some_and(|h| !h.is_empty()) => Ok(uri),
        _ => Err(Error::Network(format!(
            "only absolute http(s) urls are fetched: {}",
            redact_url(url)
        ))),
    }
}

/// `scheme://host:port` identity of a URL, used to decide whether credentials may
/// follow a redirect.
#[must_use]
pub fn origin_of(url: &str) -> Option<String> {
    let uri = parse_http_uri(url).ok()?;
    let scheme = uri.scheme_str()?;
    let port = uri
        .port_u16()
        .unwrap_or(if scheme == "https" { 443 } else { 80 });
    Some(format!(
        "{scheme}://{}:{port}",
        uri.host()?.to_ascii_lowercase()
    ))
}

/// The root certificates TLS connections are verified against.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum TrustRoots {
    /// Mozilla's roots compiled into the binary.
    #[default]
    Bundled,
    /// Every certificate in this PEM file, instead of the bundled roots.
    Bundle(PathBuf),
}

impl TrustRoots {
    /// `Bundle` when `HUNTSMAN_CA_BUNDLE` names a file, otherwise `Bundled`.
    #[must_use]
    pub fn from_environment() -> Self {
        crate::environment::ca_bundle().map_or(Self::Bundled, |path| Self::Bundle(path.into()))
    }
}

/// Largest CA bundle read; system bundles are a few hundred KiB.
const MAX_CA_BUNDLE: u64 = 4 * 1024 * 1024;

/// Every certificate in the PEM file at `path`. An unreadable, oversized or certificate-free
/// file is an error, never an empty trust store.
pub fn load_ca_bundle(path: &Path) -> Result<Vec<Certificate<'static>>, String> {
    let shown = path.display();
    let file = std::fs::File::open(path)
        .map_err(|e| format!("{}={shown}: {e}", crate::environment::CA_BUNDLE_ENV))?;
    let mut pem = Vec::new();
    file.take(MAX_CA_BUNDLE + 1)
        .read_to_end(&mut pem)
        .map_err(|e| format!("{}={shown}: {e}", crate::environment::CA_BUNDLE_ENV))?;
    if pem.len() as u64 > MAX_CA_BUNDLE {
        return Err(format!(
            "{}={shown}: larger than {MAX_CA_BUNDLE} bytes",
            crate::environment::CA_BUNDLE_ENV
        ));
    }
    let mut certificates = Vec::new();
    for item in ureq::tls::parse_pem(&pem) {
        match item {
            Ok(PemItem::Certificate(certificate)) => certificates.push(certificate),
            Ok(_) => {}
            Err(e) => {
                return Err(format!(
                    "{}={shown}: unreadable PEM: {e}",
                    crate::environment::CA_BUNDLE_ENV
                ));
            }
        }
    }
    if certificates.is_empty() {
        return Err(format!(
            "{}={shown}: no certificates",
            crate::environment::CA_BUNDLE_ENV
        ));
    }
    Ok(certificates)
}

#[derive(Debug, Clone)]
pub struct TransportConfig {
    pub timeout: Duration,
    pub max_body: usize,
    pub user_agent: String,
    pub egress: EgressPolicy,
    pub trust: TrustRoots,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_TIMEOUT,
            max_body: DEFAULT_MAX_BODY,
            user_agent: DEFAULT_USER_AGENT.to_owned(),
            egress: EgressPolicy::default(),
            trust: TrustRoots::from_environment(),
        }
    }
}

/// Resolver that drops every address the egress policy refuses. Connecting uses the
/// returned addresses, so the check cannot be bypassed by a second lookup.
#[derive(Debug)]
struct GuardedResolver {
    policy: EgressPolicy,
}

impl Resolver for GuardedResolver {
    fn resolve(
        &self,
        uri: &Uri,
        config: &ureq::config::Config,
        timeout: NextTimeout,
    ) -> Result<ResolvedSocketAddrs, ureq::Error> {
        let all = DefaultResolver::default().resolve(uri, config, timeout)?;
        let mut kept = self.empty();
        let mut refused: Option<SocketAddr> = None;
        for addr in all.iter().copied() {
            if self.policy.permits(addr.ip()) {
                kept.push(addr);
            } else {
                refused = Some(addr);
            }
        }
        if kept.is_empty() {
            let why = refused.map_or_else(String::new, |a| format!(" ({})", a.ip()));
            return Err(ureq::Error::Io(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{BLOCKED_PREFIX} destination{why} is not publicly routable"),
            )));
        }
        Ok(kept)
    }
}

/// The real transport: blocking, rustls, bounded, no redirects, egress-guarded.
pub struct UreqTransport {
    agent: ureq::Agent,
    max_body: usize,
    timeout: Duration,
    egress: EgressPolicy,
    /// Why the configured trust roots could not be loaded. Every request fails with it,
    /// so a broken bundle never falls back to other roots.
    trust_failure: Option<String>,
}

impl UreqTransport {
    #[must_use]
    pub fn new(config: &TransportConfig) -> Self {
        let mut agent_config = ureq::Agent::config_builder()
            .timeout_global(Some(config.timeout))
            .http_status_as_error(false)
            .max_redirects(0)
            .user_agent(config.user_agent.clone());
        // PublicOnly depends on GuardedResolver controlling destination
        // resolution. Environment proxies may resolve the destination
        // themselves, so direct transport is required in this mode.
        if config.egress == EgressPolicy::PublicOnly {
            agent_config = agent_config.proxy(None);
        }
        let mut trust_failure = None;
        if let TrustRoots::Bundle(path) = &config.trust {
            match load_ca_bundle(path) {
                Ok(certificates) => {
                    agent_config = agent_config.tls_config(
                        TlsConfig::builder()
                            .root_certs(RootCerts::Specific(Arc::new(certificates)))
                            .build(),
                    );
                }
                Err(reason) => trust_failure = Some(reason),
            }
        }
        let agent_config = agent_config.build();
        let agent = ureq::Agent::with_parts(
            agent_config,
            DefaultConnector::default(),
            GuardedResolver {
                policy: config.egress,
            },
        );
        Self {
            agent,
            max_body: config.max_body,
            timeout: config.timeout,
            egress: config.egress,
            trust_failure,
        }
    }
}

impl UreqTransport {
    /// Why every question fails, when the configured trust roots could not be loaded: a
    /// misconfigured transport asks nothing, over HTTPS or otherwise, so the operator sees one
    /// failure instead of a lookup that half works.
    fn misconfigured(&self) -> Option<TransportFailure> {
        self.trust_failure.as_ref().map(|reason| TransportFailure {
            kind: SourceOutcomeKind::TlsFailure,
            detail: reason.clone(),
            blocked: false,
        })
    }
}

impl Default for UreqTransport {
    fn default() -> Self {
        Self::new(&TransportConfig::default())
    }
}

impl Transport for UreqTransport {
    fn shared(&self) -> Option<&(dyn Transport + Sync)> {
        Some(self)
    }

    fn resolve(&self, name: &str) -> Result<Vec<IpAddr>, TransportFailure> {
        if let Some(failure) = self.misconfigured() {
            return Err(failure);
        }
        system_resolve(name, RESOLVE_TIMEOUT.min(self.timeout))
    }

    fn exchange_udp(
        &self,
        server: SocketAddr,
        message: &[u8],
    ) -> Result<Vec<u8>, TransportFailure> {
        if let Some(failure) = self.misconfigured() {
            return Err(failure);
        }
        if !self.egress.permits(server.ip()) {
            return Err(TransportFailure {
                kind: SourceOutcomeKind::ConnectFailure,
                detail: format!(
                    "{BLOCKED_PREFIX} destination ({}) is not publicly routable",
                    server.ip()
                ),
                blocked: true,
            });
        }
        udp_exchange(server, message, UDP_TIMEOUT.min(self.timeout))
    }

    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        if let Some(failure) = self.misconfigured() {
            return Err(failure);
        }
        let invalid = |detail: String| TransportFailure {
            kind: SourceOutcomeKind::ProtocolDrift,
            detail,
            blocked: false,
        };
        parse_http_uri(&request.url).map_err(|e| invalid(e.to_string()))?;
        let mut builder = http::Request::builder()
            .method(request.method.as_str())
            .uri(request.url.as_str());
        for (name, value) in &request.headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        let mut built = builder
            .body(request.body.as_slice())
            .map_err(|e| invalid(format!("request: {e}")))?;
        if let Some(cap) = request.timeout {
            // End to end (DNS through the last body byte), like the agent's own
            // timeout, and never above it.
            built = self
                .agent
                .configure_request(built)
                .timeout_global(Some(cap.min(self.timeout)))
                .build();
        }
        let response = self.agent.run(built).map_err(|e| map_ureq_error(&e))?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .filter_map(|(k, v)| {
                v.to_str()
                    .ok()
                    .map(|v| (k.as_str().to_ascii_lowercase(), v.to_owned()))
            })
            .collect();
        let (body, truncated) = read_capped(response.into_body().into_reader(), self.max_body)
            .map_err(|e| TransportFailure {
                kind: body_read_failure_kind(&e),
                detail: format!("body read: {e}"),
                blocked: false,
            })?;
        Ok(Response {
            status,
            headers,
            body,
            truncated,
        })
    }
}

/// Classify a failed body read. `ureq` 3's body reader reports its own errors,
/// including the request's timeout firing mid-body, as an `io::Error` of kind
/// `Other` wrapping the `ureq::Error` (`ureq::Error::into_io`), so the kind alone
/// would file a timeout as a connection failure. **Pure.**
fn body_read_failure_kind(e: &io::Error) -> SourceOutcomeKind {
    let timed_out = e.kind() == io::ErrorKind::TimedOut
        || e.get_ref()
            .and_then(|inner| inner.downcast_ref::<ureq::Error>())
            .is_some_and(|inner| match inner {
                ureq::Error::Timeout(_) => true,
                ureq::Error::Io(io) => io.kind() == io::ErrorKind::TimedOut,
                _ => false,
            });
    if timed_out {
        SourceOutcomeKind::BodyTimeout
    } else {
        SourceOutcomeKind::ConnectFailure
    }
}

/// Read at most `max` bytes; report whether more was available.
fn read_capped(reader: impl Read, max: usize) -> io::Result<(Vec<u8>, bool)> {
    let mut body = Vec::new();
    let limit = u64::try_from(max).unwrap_or(u64::MAX).saturating_add(1);
    reader.take(limit).read_to_end(&mut body)?;
    let truncated = body.len() > max;
    body.truncate(max);
    Ok((body, truncated))
}

fn map_ureq_error(err: &ureq::Error) -> TransportFailure {
    use ureq::Error as E;
    let detail = err.to_string();
    let (kind, blocked) = match err {
        E::HostNotFound => (SourceOutcomeKind::DnsFailure, false),
        E::Timeout(_) => (SourceOutcomeKind::TtfbTimeout, false),
        E::Io(e)
            if e.kind() == io::ErrorKind::PermissionDenied && detail.contains(BLOCKED_PREFIX) =>
        {
            (SourceOutcomeKind::ConnectFailure, true)
        }
        E::Io(e) if e.kind() == io::ErrorKind::TimedOut => (SourceOutcomeKind::TtfbTimeout, false),
        E::Io(_) | E::ConnectionFailed => (SourceOutcomeKind::ConnectFailure, false),
        E::Tls(_) | E::Rustls(_) | E::Pem(_) => (SourceOutcomeKind::TlsFailure, false),
        _ => (SourceOutcomeKind::ProtocolDrift, false),
    };
    TransportFailure {
        kind,
        detail,
        blocked,
    }
}

/// The seconds to wait that a `Retry-After` value asks for (RFC 9110 §10.2.3): delta-seconds, or an
/// HTTP-date counted from `now_unix`, a date already past being `0`. `None` when it is neither.
/// The one reader of the header; each caller applies its own cap.
#[must_use]
pub fn retry_after_secs(value: &str, now_unix: u64) -> Option<u64> {
    let value = value.trim();
    if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) {
        // All digits but past u64 is a very long wait, which each caller caps, not no wait.
        return Some(value.parse().unwrap_or(u64::MAX));
    }
    let at = crate::timefmt::parse_http_date(value, now_unix)?;
    let now = i64::try_from(now_unix).unwrap_or(i64::MAX);
    Some(u64::try_from(at.saturating_sub(now)).unwrap_or(0))
}

#[cfg(test)]
mod tests {
    #[test]
    fn native_resolver_workers_stay_bounded_after_caller_timeouts() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static ACTIVE: AtomicUsize = AtomicUsize::new(0);
        const CAP: usize = 2;
        let mut release = Vec::new();
        for _ in 0..CAP {
            let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
            let (started_tx, started_rx) = std::sync::mpsc::channel::<()>();
            let err = super::system_resolve_with(
                "stalled.invalid",
                std::time::Duration::from_millis(30),
                &ACTIVE,
                CAP,
                move || {
                    started_tx.send(()).expect("signal worker start");
                    release_rx.recv().expect("release worker");
                    Ok(Vec::new())
                },
            )
            .expect_err("blocked worker must time out");
            started_rx
                .recv_timeout(std::time::Duration::from_secs(2))
                .expect("worker started");
            assert!(err.detail.contains("no answer within"), "{}", err.detail);
            release.push(release_tx);
        }
        assert_eq!(ACTIVE.load(Ordering::Acquire), CAP);
        for _ in 0..(CAP * 3) {
            let err = super::system_resolve_with(
                "stalled.invalid",
                std::time::Duration::from_secs(1),
                &ACTIVE,
                CAP,
                || panic!("saturated resolver must not spawn"),
            )
            .expect_err("capacity must refuse new work");
            assert!(err.detail.contains("capacity exhausted"), "{}", err.detail);
            assert_eq!(err.kind, super::SourceOutcomeKind::DnsFailure);
            assert_eq!(ACTIVE.load(Ordering::Acquire), CAP);
        }
        for sender in release {
            sender.send(()).expect("release blocked worker");
        }
        let until = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while ACTIVE.load(Ordering::Acquire) != 0 && std::time::Instant::now() < until {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert_eq!(ACTIVE.load(Ordering::Acquire), 0);
        let address = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let result = super::system_resolve_with(
            "recovered.invalid",
            std::time::Duration::from_secs(1),
            &ACTIVE,
            CAP,
            move || Ok(vec![address]),
        )
        .expect("capacity recovered");
        assert_eq!(result, vec![address]);
    }

    #[test]
    fn native_resolver_worker_panic_releases_capacity() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static ACTIVE: AtomicUsize = AtomicUsize::new(0);
        let err = super::system_resolve_with(
            "panic.invalid",
            std::time::Duration::from_secs(1),
            &ACTIVE,
            1,
            || -> std::io::Result<Vec<std::net::IpAddr>> {
                panic!("injected resolver panic");
            },
        )
        .expect_err("worker panic is not a negative DNS answer");
        assert!(err.detail.contains("worker stopped"), "{}", err.detail);
        assert_eq!(ACTIVE.load(Ordering::Acquire), 0);
    }

    fn bundle_transport(path: &Path) -> UreqTransport {
        UreqTransport::new(&TransportConfig {
            trust: TrustRoots::Bundle(path.to_path_buf()),
            ..TransportConfig::default()
        })
    }

    fn scratch(name: &str, contents: &[u8]) -> PathBuf {
        let path = std::env::temp_dir().join(format!("huntsman-ca-{}-{name}", std::process::id()));
        std::fs::write(&path, contents).unwrap();
        path
    }

    const TEST_ROOT_PEM: &[u8] = include_bytes!("../tests/fixtures/tls/isrg_root_x1.pem");

    #[test]
    fn a_ca_bundle_replaces_the_bundled_roots() {
        let path = scratch("valid.pem", TEST_ROOT_PEM);
        let transport = bundle_transport(&path);
        assert!(transport.trust_failure.is_none());
        match transport.agent.config().tls_config().root_certs() {
            RootCerts::Specific(certificates) => assert_eq!(certificates.len(), 1),
            other => panic!("expected the bundle's roots, got {other:?}"),
        }
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn without_a_bundle_the_bundled_roots_are_used() {
        let transport = UreqTransport::new(&TransportConfig {
            trust: TrustRoots::Bundled,
            ..TransportConfig::default()
        });
        assert!(matches!(
            transport.agent.config().tls_config().root_certs(),
            RootCerts::WebPki
        ));
    }

    #[test]
    fn an_unusable_bundle_fails_every_request_closed_without_sending() {
        let empty = scratch("empty.pem", b"not a certificate\n");
        let missing = std::env::temp_dir().join("huntsman-ca-definitely-missing.pem");
        for (path, expected) in [
            (&empty, "no certificates"),
            (&missing, "HUNTSMAN_CA_BUNDLE="),
        ] {
            let transport = bundle_transport(path);
            let failure = transport
                .send(&Request::get("https://198.51.100.1/"))
                .unwrap_err();
            assert_eq!(failure.kind, SourceOutcomeKind::TlsFailure);
            assert!(!failure.blocked);
            assert!(failure.detail.contains(expected), "{}", failure.detail);
            assert!(failure.detail.contains(crate::environment::CA_BUNDLE_ENV));
            // Nor does it ask the system resolver: the whole transport is closed.
            let refused = transport.resolve("2.0.0.127.zen.spamhaus.org").unwrap_err();
            assert_eq!(refused, failure);
            let query = crate::dns_wire::query(0, "example.com", crate::dns_wire::A).unwrap();
            let unsent = transport
                .exchange_udp(SocketAddr::from(([9, 9, 9, 9], 53)), &query)
                .unwrap_err();
            assert_eq!(unsent, failure);
        }
        std::fs::remove_file(empty).unwrap();
    }

    use super::*;

    #[test]
    fn the_two_encoders_differ_only_in_how_a_space_is_written() {
        let raw = "a b+c~/é-_.";
        assert_eq!(percent_encode_component(raw), "a+b%2Bc~%2F%C3%A9-_.");
        assert_eq!(percent_encode_unreserved(raw), "a%20b%2Bc~%2F%C3%A9-_.");
    }

    #[test]
    fn public_only_ignores_environment_proxy() {
        const CHILD: &str = "HSE_PROXY_CONFIG_TEST_CHILD";
        if std::env::var_os(CHILD).is_some() {
            assert!(UreqTransport::default().agent.config().proxy().is_none());
            let unrestricted = UreqTransport::new(&TransportConfig {
                egress: EgressPolicy::Unrestricted,
                ..TransportConfig::default()
            });
            assert!(unrestricted.agent.config().proxy().is_some());
            return;
        }

        let mut child = std::process::Command::new(std::env::current_exe().unwrap());
        child
            .args([
                "--exact",
                "http::tests::public_only_ignores_environment_proxy",
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
            child.env(key, "http://proxy.example:8080");
        }
        let result = child.output().unwrap();
        assert!(
            result.status.success(),
            "{}{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
    }

    #[test]
    fn debug_output_never_contains_credentials() {
        let r = Request::get("https://user:pw@example.com/p?api_key=SECRETVALUE#frag")
            .header("Authorization", "Bearer TOKENVALUE")
            .header("X-Api-Key", "SECRETVALUE")
            .header("Accept", "text/html");
        let shown = format!("{r:?}");
        assert!(!shown.contains("SECRETVALUE"));
        assert!(!shown.contains("pw@"));
        assert!(shown.contains("text/html"));
        assert!(shown.contains("example.com/p"));
    }

    #[test]
    fn a_timeout_inside_a_body_read_is_a_body_timeout() {
        let wrapped = ureq::Error::Timeout(ureq::Timeout::Global).into_io();
        assert_eq!(wrapped.kind(), io::ErrorKind::Other);
        assert_eq!(
            body_read_failure_kind(&wrapped),
            SourceOutcomeKind::BodyTimeout
        );
        let io_timeout = ureq::Error::Io(io::Error::from(io::ErrorKind::TimedOut)).into_io();
        assert_eq!(
            body_read_failure_kind(&io_timeout),
            SourceOutcomeKind::BodyTimeout
        );
        assert_eq!(
            body_read_failure_kind(&io::Error::from(io::ErrorKind::TimedOut)),
            SourceOutcomeKind::BodyTimeout
        );
        let reset = io::Error::from(io::ErrorKind::ConnectionReset);
        assert_eq!(
            body_read_failure_kind(&reset),
            SourceOutcomeKind::ConnectFailure
        );
        let eof = ureq::Error::Io(io::Error::from(io::ErrorKind::UnexpectedEof)).into_io();
        assert_eq!(
            body_read_failure_kind(&eof),
            SourceOutcomeKind::ConnectFailure
        );
    }

    #[test]
    fn sensitive_header_names() {
        for h in [
            "Authorization",
            "cookie",
            "X-API-KEY",
            "x-auth-token",
            "Set-Cookie",
        ] {
            assert!(is_sensitive_header(h), "{h}");
        }
        for h in ["accept", "user-agent", "content-type", "location"] {
            assert!(!is_sensitive_header(h), "{h}");
        }
    }

    #[test]
    fn redact_url_drops_userinfo_query_and_fragment() {
        assert_eq!(
            redact_url("https://user:pw@host.example:8443/a/b?k=v#f"),
            "https://host.example:8443/a/b?[redacted]"
        );
        assert_eq!(redact_url("https://host.example"), "https://host.example");
        assert_eq!(redact_url("not a url"), "not a url");
        assert_eq!(
            redact_url("http:user:secret@host.example/a?k=v"),
            "http:host.example/a?[redacted]"
        );
        assert_eq!(redact_url("http:user:secret@host"), "http:host");
        assert_eq!(redact_url("host.example:8080/a"), "host.example:8080/a");
    }

    #[test]
    fn an_overlong_retry_after_is_a_long_wait_not_none() {
        assert_eq!(retry_after_secs("7200", 0), Some(7200));
        assert_eq!(retry_after_secs("18446744073709551616", 0), Some(u64::MAX));
        assert_eq!(retry_after_secs("-1", 0), None);
    }

    #[test]
    fn locations_resolve_like_a_browser() {
        let base = "https://a.example/dir/page?x=1";
        for (loc, want) in [
            ("https://b.example/z", "https://b.example/z"),
            ("//b.example/z", "https://b.example/z"),
            ("/root", "https://a.example/root"),
            ("sibling", "https://a.example/dir/sibling"),
            ("/root#frag", "https://a.example/root"),
        ] {
            assert_eq!(resolve_location(base, loc).as_deref(), Ok(want), "{loc}");
        }
        assert!(resolve_location(base, "javascript:alert(1)").is_err());
        assert!(resolve_location(base, "ftp://a.example/x").is_err());
        assert!(resolve_location("not a url", "/x").is_err());
    }

    #[test]
    fn redirect_reference_rfc_path_and_query_cases() {
        let base = "http://a.example/b/c/d;p?q";
        for (reference, expected) in [
            ("", "/b/c/d;p?q"),
            ("#fragment", "/b/c/d;p?q"),
            ("?y", "/b/c/d;p?y"),
            ("?", "/b/c/d;p?"),
            ("g?y", "/b/c/g?y"),
            ("./g", "/b/c/g"),
            (".", "/b/c/"),
            ("./", "/b/c/"),
            ("..", "/b/"),
            ("../", "/b/"),
            ("../g", "/b/g"),
            ("../..", "/"),
            ("../../", "/"),
            ("../../g", "/g"),
            ("../../../g", "/g"),
            ("../../../../g", "/g"),
            ("/./g", "/g"),
            ("/../g", "/g"),
            ("./../g", "/b/g"),
            ("./g/.", "/b/c/g/"),
            ("g/./h", "/b/c/g/h"),
            ("g/../h", "/b/c/h"),
            ("g;x=1/../y", "/b/c/y"),
            ("g?y/./x", "/b/c/g?y/./x"),
            ("g?y/../x", "/b/c/g?y/../x"),
            ("g//h", "/b/c/g//h"),
            ("%2e/%2F", "/b/c/%2e/%2F"),
            (".g/g./g../..g", "/b/c/.g/g./g../..g"),
            (
                "https://a.example/x/../z?q/../x",
                "https://a.example/z?q/../x",
            ),
        ] {
            let expected = if expected.starts_with("https:") {
                expected.to_owned()
            } else {
                format!("http://a.example{expected}")
            };
            assert_eq!(
                resolve_location(base, reference).expect("valid reference"),
                expected,
                "{reference:?}"
            );
        }
        assert_eq!(
            resolve_location("http://a.example/path?q#old", "#new").expect("base fragment"),
            "http://a.example/path?q"
        );
    }

    #[test]
    fn path_normalization_is_idempotent_and_never_normalizes_query_data() {
        for first in ["a", ".", "..", "", "%2e", "é"] {
            for second in ["b", ".", "..", "", "%2F", "中"] {
                for third in ["c", ".", "..", "", "%2e%2e", "x;y=1"] {
                    let path = format!("/{first}/{second}/{third}");
                    let normalized = remove_dot_segments(&path);
                    assert_eq!(remove_dot_segments(&normalized), normalized);
                    let resolved = resolve_location(
                        "https://a.example/base",
                        &format!("https://a.example{path}?x=/.././%2e"),
                    )
                    .expect("reference");
                    let uri = parse_http_uri(&resolved).expect("valid target");
                    assert_eq!(uri.path(), normalized);
                    assert_eq!(uri.query(), Some("x=/.././%2e"));
                    assert_eq!(origin_of(&resolved), Some("https://a.example:443".into()));
                }
            }
        }
    }

    #[test]
    fn origins_distinguish_scheme_host_and_port() {
        let a = origin_of("https://Example.com/x").expect("origin");
        assert_eq!(a, "https://example.com:443");
        assert_eq!(origin_of("https://example.com:443/y"), Some(a.clone()));
        assert_ne!(
            origin_of("http://example.com/x").as_deref(),
            Some(a.as_str())
        );
        assert_ne!(
            origin_of("https://example.com:8443/x").as_deref(),
            Some(a.as_str())
        );
        assert_eq!(origin_of("file:///etc/passwd"), None);
    }

    #[test]
    fn query_params_append_and_encode() {
        assert_eq!(
            append_query_param("https://example.com", "q", "a b"),
            "https://example.com?q=a+b"
        );
        assert_eq!(
            append_query_param("https://example.com?x=1", "q", "a&b"),
            "https://example.com?x=1&q=a%26b"
        );
        assert_eq!(
            append_query_param("https://example.com/x#frag", "key", "s"),
            "https://example.com/x?key=s#frag"
        );
        assert_eq!(
            append_query_param("https://example.com/x?a=1#f?g", "key", "s"),
            "https://example.com/x?a=1&key=s#f?g"
        );
    }

    #[test]
    fn non_http_schemes_are_refused() {
        for u in [
            "file:///etc/passwd",
            "gopher://x/",
            "ftp://x/",
            "//x/y",
            "/x",
            "",
            "http://",
        ] {
            assert!(parse_http_uri(u).is_err(), "{u}");
        }
    }

    #[test]
    fn body_cap_is_exact_and_reports_truncation() {
        let data = vec![7u8; 10];
        assert_eq!(
            read_capped(&data[..], 10).expect("read"),
            (data.clone(), false)
        );
        let (b, t) = read_capped(&data[..], 9).expect("read");
        assert_eq!((b.len(), t), (9, true));
        let (b, t) = read_capped(&data[..], 0).expect("read");
        assert_eq!((b.len(), t), (0, true));
        assert_eq!(read_capped(&[][..], 0).expect("read"), (Vec::new(), false));
    }
    #[test]
    fn text_view_borrows_a_utf8_body_and_copies_only_an_invalid_one() {
        let valid = Response {
            status: 200,
            headers: Vec::new(),
            body: b"{\"ok\":true}".to_vec(),
            truncated: false,
        };
        assert!(matches!(
            valid.text_view(),
            std::borrow::Cow::Borrowed("{\"ok\":true}")
        ));
        assert_eq!(valid.text(), "{\"ok\":true}");
        let invalid = Response {
            status: 200,
            headers: Vec::new(),
            body: vec![b'a', 0xff, b'b'],
            truncated: false,
        };
        assert!(matches!(invalid.text_view(), std::borrow::Cow::Owned(_)));
        assert_eq!(invalid.text(), "a\u{fffd}b");
    }
}
