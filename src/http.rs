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
use std::net::SocketAddr;
use std::time::Duration;

use serde::de::DeserializeOwned;
use ureq::http::{self, Uri};
use ureq::unversioned::resolver::{DefaultResolver, ResolvedSocketAddrs, Resolver};
use ureq::unversioned::transport::{DefaultConnector, NextTimeout};

use crate::egress::EgressPolicy;
use crate::error::Error;
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
}

impl Request {
    #[must_use]
    pub fn get(url: impl Into<String>) -> Self {
        Self {
            method: Method::Get,
            url: url.into(),
            headers: Vec::new(),
            body: Vec::new(),
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
                        "[redacted]"
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

    #[must_use]
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

fn find_header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Append one URL-encoded query parameter to `url`.
#[must_use]
pub fn append_query_param(url: &str, name: &str, value: &str) -> String {
    let separator = if url.contains('?') { '&' } else { '?' };
    format!("{url}{separator}{name}={}", percent_encode_component(value))
}

fn percent_encode_component(raw: &str) -> String {
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
        None => base.to_owned(),
    };
    if query {
        format!("{base}?[redacted]")
    } else {
        base
    }
}

/// Resolve a `Location` header against the URL that produced it.
///
/// # Errors
/// `Error::Network` when either URL is not a valid http(s) URL.
pub fn resolve_location(base: &str, location: &str) -> Result<String, Error> {
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
    } else {
        let path = base_uri.path();
        let dir = path.rfind('/').map_or("/", |i| &path[..=i]);
        format!("{scheme}://{authority}{dir}{location}")
    };
    parse_http_uri(&joined)?;
    Ok(joined)
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

#[derive(Debug, Clone)]
pub struct TransportConfig {
    pub timeout: Duration,
    pub max_body: usize,
    pub user_agent: String,
    pub egress: EgressPolicy,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_TIMEOUT,
            max_body: DEFAULT_MAX_BODY,
            user_agent: DEFAULT_USER_AGENT.to_owned(),
            egress: EgressPolicy::default(),
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
}

impl UreqTransport {
    #[must_use]
    pub fn new(config: &TransportConfig) -> Self {
        let agent_config = ureq::Agent::config_builder()
            .timeout_global(Some(config.timeout))
            .http_status_as_error(false)
            .max_redirects(0)
            .user_agent(config.user_agent.clone())
            .build();
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
        }
    }
}

impl Default for UreqTransport {
    fn default() -> Self {
        Self::new(&TransportConfig::default())
    }
}

impl Transport for UreqTransport {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
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
        let built = builder
            .body(request.body.as_slice())
            .map_err(|e| invalid(format!("request: {e}")))?;
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
                kind: if e.kind() == io::ErrorKind::TimedOut {
                    SourceOutcomeKind::BodyTimeout
                } else {
                    SourceOutcomeKind::ConnectFailure
                },
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
