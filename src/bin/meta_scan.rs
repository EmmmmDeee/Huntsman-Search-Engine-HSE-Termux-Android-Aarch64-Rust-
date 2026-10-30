//! Native MetaScan-compatible Facebook page intelligence for unrooted Android/Termux.
//! Reuses Huntsman's egress guard, TLS, redaction and credential provenance.
//! Only the four original `RapidAPI` collection endpoints are claimed as implemented.
//! External provider results are unverified observations, not identity assertions.

use std::collections::BTreeSet;
use std::env;
use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use huntsman_recon::credential_origin::AuthenticationAuthority;
use huntsman_recon::fetch::{AuthStyle, Credential, FetchOptions, fetch};
use huntsman_recon::http::{
    Request, Transport, TransportConfig, UreqTransport, append_query_param, parse_http_uri,
};
use huntsman_recon::keys::{Keys, Secret};
use huntsman_recon::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};
use huntsman_recon::web_query::{self, SearchHit};
use serde::Serialize;
use serde_json::{Value, json};

const API_HOST: &str = "facebook-pages-scraper3.p.rapidapi.com";
const API_ORIGIN: &str = "https://facebook-pages-scraper3.p.rapidapi.com:443";
const KEY_SLOT: &str = "RAPIDAPI_KEY";
const DEFAULT_BIND: &str = "127.0.0.1:8787";
const HTTP_MAX_HEAD: usize = 8192;
const HTTP_MAX_BODY: usize = 4096;
const WEB_MAX_CLIENTS: usize = 8;
const MAX_PROVIDER_BODY: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Endpoint {
    Profile,
    BusinessHome,
    BusinessAbout,
    Transparency,
}

impl Endpoint {
    const fn path(self) -> &'static str {
        match self {
            Self::Profile => "/get-profile-home-page-details",
            Self::BusinessHome => "/get-business-home-page-details",
            Self::BusinessAbout => "/get-business-about-details-page",
            Self::Transparency => "/get-business-about-profile-transparency-page-details",
        }
    }

    const fn id(self) -> &'static str {
        match self {
            Self::Profile => "profile",
            Self::BusinessHome => "business_home",
            Self::BusinessAbout => "business_about",
            Self::Transparency => "business_transparency",
        }
    }

    fn url(self, username: &str) -> String {
        let page = format!("https://www.facebook.com/{username}");
        let url = format!("https://{API_HOST}{}", self.path());
        let url = append_query_param(&url, "urlSupplier", &page);
        if self == Self::Profile {
            append_query_param(&url, "url", &page)
        } else {
            url
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct EndpointResult {
    source: &'static str,
    state: &'static str,
    http_status: Option<u16>,
    data: Option<Value>,
    message: Option<String>,
}

impl EndpointResult {
    fn new(
        source: &'static str,
        state: &'static str,
        status: Option<u16>,
        data: Option<Value>,
        message: Option<&str>,
    ) -> Self {
        Self {
            source,
            state,
            http_status: status,
            data,
            message: message.map(str::to_owned),
        }
    }
    fn missing(source: &'static str) -> Self {
        Self::new(
            source,
            "not_configured",
            None,
            None,
            Some(
                "Set RAPIDAPI_KEY in the environment or ~/.huntsman.env; no provider request was made",
            ),
        )
    }
    fn successful(&self) -> bool {
        self.state == "observed"
    }
}

#[derive(Debug, Clone, Serialize)]
struct IndexedDiscovery {
    state: &'static str,
    evidence_role: &'static str,
    hits: Vec<SearchHit>,
    outcomes: Vec<SourceExecutionOutcome>,
}

#[derive(Debug, Clone, Serialize)]
struct Report {
    username: String,
    page_url: String,
    observed_at_unix: u64,
    provider: &'static str,
    verification: &'static str,
    discovery: Option<IndexedDiscovery>,
    profile: EndpointResult,
    business_home: Option<EndpointResult>,
    business_about: Option<EndpointResult>,
    business_transparency: Option<EndpointResult>,
}

impl Report {
    fn has_observation(&self) -> bool {
        self.discovery.as_ref().is_some_and(|d| !d.hits.is_empty())
            || self.profile.successful()
            || self
                .business_home
                .as_ref()
                .is_some_and(EndpointResult::successful)
            || self
                .business_about
                .as_ref()
                .is_some_and(EndpointResult::successful)
            || self
                .business_transparency
                .as_ref()
                .is_some_and(EndpointResult::successful)
    }

    fn as_text(&self) -> String {
        let mut out = format!(
            "MetaScan (Huntsman Rust)\nUsername: {}\nPage: {}\nObserved at (Unix): {}\nVerification: {}\n\n",
            self.username, self.page_url, self.observed_at_unix, self.verification
        );
        if let Some(discovery) = &self.discovery {
            let _ = writeln!(
                out,
                "[PUBLIC INDEX DISCOVERY]\nState: {}\nEvidence: {}\nDirect page leads: {}",
                discovery.state,
                discovery.evidence_role,
                discovery.hits.len()
            );
            for hit in &discovery.hits {
                let _ = writeln!(out, "engine={} url={}", hit.engine, hit.url);
            }
            for outcome in &discovery.outcomes {
                let _ = writeln!(
                    out,
                    "engine={} outcome={}",
                    outcome.module,
                    outcome.kind.as_str()
                );
            }
            out.push('\n');
        }
        for (label, item) in [
            ("PROFILE", Some(&self.profile)),
            ("BUSINESS HOME", self.business_home.as_ref()),
            ("BUSINESS ABOUT", self.business_about.as_ref()),
            ("TRANSPARENCY", self.business_transparency.as_ref()),
        ] {
            if let Some(item) = item {
                let _ = writeln!(
                    out,
                    "[{label}]\nStatus: {}\nHTTP: {}",
                    item.state,
                    item.http_status
                        .map_or_else(|| "n/a".to_owned(), |n| n.to_string())
                );
                if let Some(message) = &item.message {
                    let _ = writeln!(out, "Note: {message}");
                }
                if let Some(data) = &item.data {
                    out.push_str(&serde_json::to_string_pretty(data).unwrap_or_default());
                    out.push('\n');
                }
                out.push('\n');
            }
        }
        out
    }
}

fn checked_username(raw: &str) -> Result<String, &'static str> {
    let username = raw.trim().trim_start_matches('@');
    if username.is_empty()
        || username.len() > 100
        || !username
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        || username == "."
        || username == ".."
    {
        return Err(
            "Facebook handle must be 1..100 ASCII letters, digits, periods, dashes or underscores",
        );
    }
    Ok(username.to_owned())
}

// Status is a provider outcome, never evidence that a Facebook account does not exist.
fn status_failure(source: &'static str, status: u16) -> Option<EndpointResult> {
    let (state, message) = match status {
        200..=299 => return None,
        401 => (
            "authentication_rejected",
            "RapidAPI rejected the configured key",
        ),
        402 | 403 => (
            "entitlement_denied",
            "Subscription or endpoint access is unavailable",
        ),
        404 => (
            "not_found",
            "Provider returned 404; this is not proof the Facebook page is absent",
        ),
        429 => (
            "rate_limited",
            "Provider rate limit reached; retry after the provider allows it",
        ),
        500..=599 => ("upstream_error", "RapidAPI upstream service error"),
        _ => ("http_error", "RapidAPI returned an unexpected HTTP status"),
    };
    Some(EndpointResult::new(
        source,
        state,
        Some(status),
        None,
        Some(message),
    ))
}

fn classify_provider_reply(
    source: &'static str,
    response: &huntsman_recon::http::Response,
    outcome: SourceOutcomeKind,
) -> EndpointResult {
    let status = Some(response.status);
    if let Some(failure) = status_failure(source, response.status) {
        return failure;
    }
    if response.truncated {
        return EndpointResult::new(
            source,
            "truncated",
            status,
            None,
            Some("Response exceeded 1 MiB limit"),
        );
    }
    if outcome != SourceOutcomeKind::Inconclusive {
        return EndpointResult::new(
            source,
            "unusable_response",
            status,
            None,
            Some("Response failed Huntsman content validation"),
        );
    }
    let Ok(data) = serde_json::from_slice::<Value>(&response.body) else {
        return EndpointResult::new(
            source,
            "invalid_json",
            status,
            None,
            Some("Response was not valid JSON"),
        );
    };
    if data.is_null()
        || data.as_object().is_some_and(serde_json::Map::is_empty)
        || data.as_array().is_some_and(Vec::is_empty)
    {
        return EndpointResult::new(
            source,
            "empty",
            status,
            None,
            Some("Provider returned no records"),
        );
    }
    if data
        .get("error")
        .is_some_and(|e| !e.is_null() && e != &Value::Bool(false))
        || data.get("success") == Some(&Value::Bool(false))
    {
        return EndpointResult::new(
            source,
            "provider_error",
            status,
            None,
            Some("Provider reported an error in its JSON response"),
        );
    }
    EndpointResult::new(
        source,
        "observed",
        status,
        Some(data),
        Some("Unverified third-party response; corroborate before attribution"),
    )
}

fn provider_result<T: Transport + ?Sized>(
    transport: &T,
    secret: Option<&Secret>,
    endpoint: Endpoint,
    username: &str,
    now: u64,
    timeout: Duration,
) -> EndpointResult {
    let source = endpoint.id();
    let Some(secret) = secret else {
        return EndpointResult::missing(source);
    };
    let Ok(authority) =
        AuthenticationAuthority::configured_slot("rapidapi-facebook-pages-scraper3", KEY_SLOT, now)
    else {
        return EndpointResult::new(
            source,
            "refused",
            None,
            None,
            Some("Credential authority was refused"),
        );
    };
    let Ok(credential) = Credential::new(
        authority,
        secret.clone(),
        AuthStyle::Header("x-rapidapi-key".into()),
    ) else {
        return EndpointResult::new(
            source,
            "refused",
            None,
            None,
            Some("Credential was refused"),
        );
    };
    let credential = credential.only_for_origin(API_ORIGIN);
    // The key is never placed in the URL, recorded in the result, or sent on redirects.
    let request = Request::get(endpoint.url(username))
        .header("Accept", "application/json")
        .header("x-rapidapi-host", API_HOST)
        .with_timeout(timeout);
    // At most three attempts. Do not automatically retry a 429: it may incur paid quota.
    for attempt in 0..3 {
        let Ok(fetched) = fetch(
            transport,
            request.clone(),
            Some(&credential),
            &FetchOptions::no_redirects(),
            source,
            now,
        ) else {
            return EndpointResult::new(
                source,
                "refused",
                None,
                None,
                Some("Request refused by outbound policy"),
            );
        };
        let Some(response) = fetched.response else {
            return EndpointResult::new(
                source,
                "network_error",
                None,
                None,
                Some("No usable HTTP response"),
            );
        };
        if matches!(response.status, 500 | 502 | 503 | 504) && attempt < 2 {
            thread::sleep(Duration::from_millis(600 * (1_u64 << attempt)));
            continue;
        }
        return classify_provider_reply(source, &response, fetched.outcome.kind);
    }
    EndpointResult::new(
        source,
        "upstream_error",
        None,
        None,
        Some("Retries exhausted"),
    )
}

fn scan<T: Transport + ?Sized>(
    transport: &T,
    secret: Option<&Secret>,
    username: &str,
    business: bool,
    now: u64,
    timeout: Duration,
) -> Result<Report, &'static str> {
    let username = checked_username(username)?;
    let get = |ep| provider_result(transport, secret, ep, &username, now, timeout);
    Ok(Report {
        page_url: format!("https://www.facebook.com/{username}"),
        profile: get(Endpoint::Profile),
        business_home: business.then(|| get(Endpoint::BusinessHome)),
        business_about: business.then(|| get(Endpoint::BusinessAbout)),
        business_transparency: business.then(|| get(Endpoint::Transparency)),
        username,
        observed_at_unix: now,
        provider: "facebook-pages-scraper3.p.rapidapi.com",
        verification: "unverified_provider_observation",
        discovery: None,
    })
}

/// Exact direct page URL candidates from public indexes: never identity verification.
fn is_direct_facebook_page(url: &str, username: &str) -> bool {
    let Ok(uri) = parse_http_uri(url) else {
        return false;
    };
    let known_host = matches!(
        uri.host().map(str::to_ascii_lowercase).as_deref(),
        Some("facebook.com" | "www.facebook.com" | "m.facebook.com")
    );
    uri.scheme_str() == Some("https")
        && known_host
        && uri.port_u16().is_none_or(|port| port == 443)
        && uri
            .path()
            .trim_end_matches('/')
            .strip_prefix('/')
            .is_some_and(|name| name.eq_ignore_ascii_case(username))
}

/// Keyless search is a bounded discovery of indexed URLs, not Facebook profile scraping.
/// A zero-hit result never means that the requested account does not exist.
fn scan_indexed<T: Transport + ?Sized>(
    transport: &T,
    raw: &str,
    now: u64,
) -> Result<Report, &'static str> {
    let username = checked_username(raw)?;
    let query = format!("site:facebook.com \"{username}\"");
    let (hits, outcomes, state) = match web_query::search(transport, &query, now) {
        Ok(report) => {
            let mut seen = BTreeSet::new();
            let mut hits = Vec::new();
            for hit in report.hits {
                if is_direct_facebook_page(&hit.url, &username) && seen.insert(hit.url.clone()) {
                    hits.push(hit);
                }
                if hits.len() >= 20 {
                    break;
                }
            }
            let state = if hits.is_empty() {
                "no_indexed_leads"
            } else {
                "indexed_leads"
            };
            (hits, report.outcomes, state)
        }
        Err(_) => (Vec::new(), Vec::new(), "search_unavailable"),
    };
    Ok(Report {
        page_url: format!("https://www.facebook.com/{username}"),
        profile: EndpointResult::new(
            "profile",
            "not_requested",
            None,
            None,
            Some("Indexed discovery does not extract or verify Facebook profile attributes"),
        ),
        business_home: None,
        business_about: None,
        business_transparency: None,
        username,
        observed_at_unix: now,
        provider: "public_search_indexes",
        verification: "unverified_indexed_url_lead",
        discovery: Some(IndexedDiscovery {
            state,
            evidence_role: "url_discovery_only_no_identity_verification",
            hits,
            outcomes,
        }),
    })
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |x| x.as_secs())
}

fn configured_secret() -> Option<Secret> {
    let resolved = Keys::for_lookup(env::var_os("HOME").as_deref());
    if let Some(warning) = resolved.warning {
        eprintln!("{warning}");
    }
    resolved.keys.get(KEY_SLOT)
}

fn transport(timeout: Duration) -> UreqTransport {
    UreqTransport::new(&TransportConfig {
        timeout,
        max_body: MAX_PROVIDER_BODY,
        user_agent: concat!("huntsman-meta-scan/", env!("CARGO_PKG_VERSION")).to_owned(),
        ..TransportConfig::default()
    })
}

fn json_reply(stream: &mut TcpStream, status: &str, value: &Value) -> std::io::Result<()> {
    http_reply(
        stream,
        status,
        "application/json; charset=utf-8",
        value.to_string().as_bytes(),
    )
}

fn http_reply(
    stream: &mut TcpStream,
    status: &str,
    mime: &str,
    bytes: &[u8],
) -> std::io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: {mime}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nContent-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'\r\nConnection: close\r\n\r\n",
        bytes.len()
    )?;
    stream.write_all(bytes)
}

#[derive(Debug)]
struct HttpRequest {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl HttpRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

fn read_request(stream: &mut TcpStream) -> Result<HttpRequest, &'static str> {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| "read timeout setup failed")?;
    let mut bytes = Vec::with_capacity(2048);
    let mut chunk = [0_u8; 1024];
    let header_end = loop {
        let n = stream.read(&mut chunk).map_err(|_| "request read failed")?;
        if n == 0 {
            return Err("connection closed while reading headers");
        }
        bytes.extend_from_slice(&chunk[..n]);
        if let Some(i) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            if i + 4 > HTTP_MAX_HEAD {
                return Err("headers too large");
            }
            break i + 4;
        }
        if bytes.len() > HTTP_MAX_HEAD {
            return Err("headers too large");
        }
    };
    let text = std::str::from_utf8(&bytes[..header_end]).map_err(|_| "invalid request headers")?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next().ok_or("missing request line")?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or("missing method")?.to_owned();
    let path = parts.next().ok_or("missing path")?.to_owned();
    if parts.next() != Some("HTTP/1.1") || parts.next().is_some() {
        return Err("HTTP/1.1 required");
    }
    if path.len() > 256 || !path.starts_with('/') {
        return Err("invalid path");
    }
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':').ok_or("invalid header")?;
        if name.trim().is_empty() {
            return Err("invalid header");
        }
        headers.push((name.trim().to_owned(), value.trim().to_owned()));
    }
    let lengths: Vec<_> = headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case("content-length"))
        .map(|(_, v)| v.as_str())
        .collect();
    if lengths.len() > 1 {
        return Err("duplicate content length");
    }
    if headers
        .iter()
        .any(|(n, _)| n.eq_ignore_ascii_case("transfer-encoding"))
    {
        return Err("transfer encoding not supported");
    }
    let length = match lengths.first() {
        Some(s) => s.parse::<usize>().map_err(|_| "invalid content length")?,
        None => 0,
    };
    if length > HTTP_MAX_BODY {
        return Err("body exceeds limit");
    }
    let mut body = bytes[header_end..].to_vec();
    if body.len() > length {
        return Err("unexpected request body");
    }
    while body.len() < length {
        let remain = length - body.len();
        let take = remain.min(chunk.len());
        let n = stream
            .read(&mut chunk[..take])
            .map_err(|_| "body read failed")?;
        if n == 0 {
            return Err("incomplete request body");
        }
        body.extend_from_slice(&chunk[..n]);
    }
    Ok(HttpRequest {
        method,
        path,
        headers,
        body,
    })
}

fn allowed_host(host: Option<&str>, port: u16) -> bool {
    let allowed = [
        format!("127.0.0.1:{port}"),
        format!("localhost:{port}"),
        format!("[::1]:{port}"),
    ];
    host.is_some_and(|h| allowed.iter().any(|v| h.eq_ignore_ascii_case(v)))
}

fn serve_scan_request(stream: &mut TcpStream, request: &HttpRequest, port: u16, timeout: Duration) {
    if request.header("X-Meta-Scan") != Some("1")
        || request
            .header("Content-Type")
            .is_none_or(|v| !v.to_ascii_lowercase().starts_with("application/json"))
        || request.header("Origin").is_some_and(|v| {
            v != format!("http://127.0.0.1:{port}") && v != format!("http://localhost:{port}")
        })
    {
        let _ = json_reply(
            stream,
            "403 Forbidden",
            &json!({"error":"same-origin JSON request and X-Meta-Scan header required"}),
        );
        return;
    }
    let Ok(input) = serde_json::from_slice::<Value>(&request.body) else {
        let _ = json_reply(
            stream,
            "400 Bad Request",
            &json!({"error":"invalid JSON body"}),
        );
        return;
    };
    let Some(username) = input.get("username").and_then(Value::as_str) else {
        let _ = json_reply(
            stream,
            "400 Bad Request",
            &json!({"error":"username required"}),
        );
        return;
    };
    let business = input
        .get("include_business")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let mode = input
        .get("mode")
        .and_then(Value::as_str)
        .unwrap_or("indexed");
    if !matches!(mode, "indexed" | "provider") {
        let _ = json_reply(
            stream,
            "400 Bad Request",
            &json!({"error":"unknown collection mode"}),
        );
        return;
    }
    let key = (mode == "provider").then(configured_secret).flatten();
    let transport = transport(timeout);
    let result = if mode == "provider" {
        scan(
            &transport,
            key.as_ref(),
            username,
            business,
            unix_now(),
            timeout,
        )
    } else {
        scan_indexed(&transport, username, unix_now())
    };
    match result {
        Ok(report) => {
            let _ = json_reply(
                stream,
                "200 OK",
                &serde_json::to_value(report)
                    .unwrap_or_else(|_| json!({"error":"serialisation failed"})),
            );
        }
        Err(reason) => {
            let _ = json_reply(stream, "400 Bad Request", &json!({"error":reason}));
        }
    }
}

fn serve_client(mut stream: TcpStream, port: u16, timeout: Duration) {
    let request = match read_request(&mut stream) {
        Ok(req) => req,
        Err(msg) => {
            let _ = json_reply(&mut stream, "400 Bad Request", &json!({"error":msg}));
            return;
        }
    };
    if !allowed_host(request.header("Host"), port) {
        let _ = json_reply(
            &mut stream,
            "403 Forbidden",
            &json!({"error":"loopback Host header required"}),
        );
        return;
    }
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/") => {
            let _ = http_reply(
                &mut stream,
                "200 OK",
                "text/html; charset=utf-8",
                include_str!("meta_scan.html").as_bytes(),
            );
        }
        ("GET", "/api/status") => {
            let _ = json_reply(
                &mut stream,
                "200 OK",
                &json!({
                    "name": "Huntsman MetaScan", "provider": API_HOST,
                    "api_key_configured": configured_secret().is_some(),
                    "binding": "loopback", "platform": "Termux-compatible, no root"
                }),
            );
        }
        ("POST", "/api/scan") => serve_scan_request(&mut stream, &request, port, timeout),
        _ => {
            let _ = json_reply(
                &mut stream,
                "404 Not Found",
                &json!({"error":"route not found"}),
            );
        }
    }
}

fn serve(bind: &str, timeout: Duration) -> Result<(), String> {
    let addr: SocketAddr = bind
        .parse()
        .map_err(|_| "bind must be a numeric loopback address:port".to_owned())?;
    if !addr.ip().is_loopback() || addr.port() < 1024 {
        return Err("Web UI must bind to loopback and an unprivileged port (>=1024)".to_owned());
    }
    let listener = TcpListener::bind(addr).map_err(|e| format!("cannot listen on {bind}: {e}"))?;
    println!("MetaScan Web UI: http://{bind}/");
    let active = Arc::new(AtomicUsize::new(0));
    for connection in listener.incoming() {
        let Ok(mut client) = connection else {
            continue;
        };
        let old = active.fetch_add(1, Ordering::AcqRel);
        if old >= WEB_MAX_CLIENTS {
            active.fetch_sub(1, Ordering::AcqRel);
            let _ = json_reply(
                &mut client,
                "503 Service Unavailable",
                &json!({"error":"connection capacity reached"}),
            );
            continue;
        }
        let counter = Arc::clone(&active);
        let launched = thread::Builder::new()
            .name("meta-scan-http".into())
            .stack_size(2 * 1024 * 1024)
            .spawn(move || {
                struct Release(Arc<AtomicUsize>);
                impl Drop for Release {
                    fn drop(&mut self) {
                        self.0.fetch_sub(1, Ordering::AcqRel);
                    }
                }
                let _release = Release(counter);
                serve_client(client, addr.port(), timeout);
            });
        if launched.is_err() {
            active.fetch_sub(1, Ordering::AcqRel);
        }
    }
    Ok(())
}

#[derive(Default)]
struct Options {
    username: Option<String>,
    batch: Option<PathBuf>,
    out_json: Option<PathBuf>,
    out_txt: Option<PathBuf>,
    serve: bool,
    bind: String,
    business: bool,
    show_raw: bool,
    provider: bool,
    connect_timeout: u64,
    read_timeout: u64,
}

fn usage() -> &'static str {
    "Usage:\n  meta_scan -u HANDLE [--provider] [--no-business] [--show-raw] [--out-json DIR] [--out-txt DIR]\n  meta_scan --batch FILE [--provider] [--out-json DIR] [--out-txt DIR]\n  meta_scan --serve [--bind 127.0.0.1:8787]\nOptions: --connect-timeout SECONDS --read-timeout SECONDS\nDefault: keyless public indexed URL discovery, not profile scraping.\n--provider: opt into RapidAPI profile/business requests (may consume billable quota).\nAPI key: RAPIDAPI_KEY environment variable or mode-0600 ~/.huntsman.env\n"
}

fn parse_args(args: impl IntoIterator<Item = String>) -> Result<Options, String> {
    let mut out = Options {
        bind: DEFAULT_BIND.to_owned(),
        business: true,
        connect_timeout: 15,
        read_timeout: 45,
        ..Options::default()
    };
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-u" | "--username" => out.username = Some(iter.next().ok_or("missing username")?),
            "--batch" => out.batch = Some(iter.next().ok_or("missing batch path")?.into()),
            "--out-json" => {
                out.out_json = Some(iter.next().ok_or("missing JSON directory")?.into());
            }
            "--out-txt" => out.out_txt = Some(iter.next().ok_or("missing TXT directory")?.into()),
            "--bind" => out.bind = iter.next().ok_or("missing bind")?,
            "--no-business" => out.business = false,
            "--show-raw" => out.show_raw = true,
            "--provider" => out.provider = true,
            "--serve" => out.serve = true,
            "--connect-timeout" => {
                out.connect_timeout = iter
                    .next()
                    .ok_or("missing timeout")?
                    .parse()
                    .map_err(|_| "invalid timeout")?;
            }
            "--read-timeout" => {
                out.read_timeout = iter
                    .next()
                    .ok_or("missing timeout")?
                    .parse()
                    .map_err(|_| "invalid timeout")?;
            }
            "-h" | "--help" => return Err(usage().to_owned()),
            _ => return Err(format!("unknown option: {arg}\n{}", usage())),
        }
    }
    if !(1..=120).contains(&out.connect_timeout) || !(1..=120).contains(&out.read_timeout) {
        return Err("timeouts must be 1..120 seconds".to_owned());
    }
    let choices = usize::from(out.serve)
        + usize::from(out.batch.is_some())
        + usize::from(out.username.is_some());
    if choices != 1 {
        return Err(format!(
            "select exactly one of --serve, --batch, or -u\n{}",
            usage()
        ));
    }
    Ok(out)
}

fn save_report(dir: &Path, report: &Report, ext: &str, contents: &[u8]) -> Result<PathBuf, String> {
    fs::create_dir_all(dir).map_err(|e| format!("cannot create report directory: {e}"))?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    for suffix in 0..10 {
        let path = dir.join(format!("{}_{}_{}.{}", report.username, stamp, suffix, ext));
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        match opts.open(&path) {
            Ok(mut file) => {
                file.write_all(contents)
                    .map_err(|e| format!("cannot write report: {e}"))?;
                return Ok(path);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(format!("cannot create report: {e}")),
        }
    }
    Err("could not allocate a unique report filename".to_owned())
}

fn run() -> Result<(), String> {
    let opts = parse_args(env::args().skip(1))?;
    let timeout = Duration::from_secs((opts.connect_timeout + opts.read_timeout).min(120));
    if opts.serve {
        return serve(&opts.bind, timeout);
    }
    let names = if let Some(file) = opts.batch {
        let meta =
            fs::metadata(&file).map_err(|e| format!("cannot read batch file metadata: {e}"))?;
        if meta.len() > 64 * 1024 {
            return Err("batch file exceeds 64 KiB".into());
        }
        let raw = fs::read_to_string(&file).map_err(|e| format!("cannot read batch file: {e}"))?;
        let names: Vec<String> = raw
            .lines()
            .map(str::trim)
            .filter(|v| !v.is_empty() && !v.starts_with('#'))
            .map(str::to_owned)
            .collect();
        if names.is_empty() || names.len() > 200 {
            return Err("batch requires 1..200 usernames".into());
        }
        names
    } else {
        vec![opts.username.ok_or("username missing")?]
    };
    let names: Vec<String> = names
        .into_iter()
        .map(|x| checked_username(&x).map_err(str::to_owned))
        .collect::<Result<_, _>>()?;
    let secret = opts.provider.then(configured_secret).flatten();
    if opts.provider && secret.is_none() {
        return Err("RAPIDAPI_KEY is not configured; set it in ~/.huntsman.env (chmod 600) or the environment".into());
    }
    let transport = transport(timeout);
    let mut successful = 0;
    for name in names {
        let report = if opts.provider {
            scan(
                &transport,
                secret.as_ref(),
                &name,
                opts.business,
                unix_now(),
                timeout,
            )
        } else {
            scan_indexed(&transport, &name, unix_now())
        }
        .map_err(str::to_owned)?;
        if report.has_observation() {
            successful += 1;
        }
        if opts.show_raw {
            println!(
                "{}",
                serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
            );
        } else {
            println!("{}", report.as_text());
        }
        if let Some(dir) = &opts.out_json {
            let payload = serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?;
            println!(
                "Saved: {}",
                save_report(dir, &report, "json", &payload)?.display()
            );
        }
        if let Some(dir) = &opts.out_txt {
            println!(
                "Saved: {}",
                save_report(dir, &report, "txt", report.as_text().as_bytes())?.display()
            );
        }
    }
    if successful == 0 {
        return Err(
            "No direct indexed URL leads or provider observations; this is not proof the page is absent".into(),
        );
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use huntsman_recon::http::{Response, TransportFailure};
    use std::sync::Mutex;

    struct Fake {
        status: u16,
        body: &'static str,
        truncated: bool,
        sent: Mutex<Vec<Request>>,
    }
    impl Fake {
        fn new(status: u16, body: &'static str) -> Self {
            Self {
                status,
                body,
                truncated: false,
                sent: Mutex::new(Vec::new()),
            }
        }
    }
    impl Transport for Fake {
        fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
            self.sent.lock().unwrap().push(request.clone());
            Ok(Response {
                status: self.status,
                headers: vec![("content-type".into(), "application/json".into())],
                body: self.body.as_bytes().to_vec(),
                truncated: self.truncated,
            })
        }
    }

    #[test]
    fn usernames_cannot_smuggle_paths_or_queries() {
        for bad in [
            "",
            "/",
            "abc/def",
            "x?key=1",
            "https://facebook.com/example",
            "a\nb",
            "..",
            "a b",
            "a#b",
        ] {
            assert!(checked_username(bad).is_err(), "{bad}");
        }
        assert_eq!(checked_username("@nasa").unwrap(), "nasa");
        assert_eq!(checked_username(" Page.Name ").unwrap(), "Page.Name");
    }

    #[test]
    fn the_four_original_endpoints_are_called_without_leaking_key_into_urls() {
        let fake = Fake::new(200, r#"{"name":"Example","followers":42}"#);
        let key = Secret::new("test-provider-key").unwrap();
        let report = scan(
            &fake,
            Some(&key),
            "nasa",
            true,
            1234,
            Duration::from_secs(10),
        )
        .unwrap();
        assert!(report.has_observation());
        assert_eq!(report.profile.state, "observed");
        let requests = fake.sent.lock().unwrap();
        assert_eq!(requests.len(), 4);
        for (request, path) in requests.iter().zip([
            "/get-profile-home-page-details",
            "/get-business-home-page-details",
            "/get-business-about-details-page",
            "/get-business-about-profile-transparency-page-details",
        ]) {
            assert!(request.url.contains(path));
            assert!(
                request
                    .url
                    .contains("urlSupplier=https%3A%2F%2Fwww.facebook.com%2Fnasa")
            );
            assert!(!request.url.contains("test-provider-key"));
            assert_eq!(request.header_value("x-rapidapi-host"), Some(API_HOST));
        }
        assert!(
            requests[0]
                .url
                .contains("&url=https%3A%2F%2Fwww.facebook.com%2Fnasa")
        );
        assert!(!requests[1].url.contains("&url="));
    }

    #[test]
    fn no_key_does_not_contact_provider() {
        let fake = Fake::new(200, r#"{"name":"Example"}"#);
        let report = scan(&fake, None, "nasa", true, 1234, Duration::from_secs(10)).unwrap();
        assert!(!report.has_observation());
        assert_eq!(report.profile.state, "not_configured");
        assert!(fake.sent.lock().unwrap().is_empty());
    }

    #[test]
    fn provider_errors_do_not_become_false_findings() {
        for (code, body, state) in [
            (401, "{}", "authentication_rejected"),
            (403, "{}", "entitlement_denied"),
            (404, "{}", "not_found"),
            (429, "{}", "rate_limited"),
            (200, "not json", "invalid_json"),
            (200, "{}", "empty"),
            (200, r#"{"error":"invalid token"}"#, "provider_error"),
        ] {
            let fake = Fake::new(code, body);
            let key = Secret::new("test-provider-key").unwrap();
            let report = scan(&fake, Some(&key), "nasa", false, 1, Duration::from_secs(3)).unwrap();
            assert_eq!(report.profile.state, state, "{code} {body}");
            assert!(!report.has_observation());
        }
    }

    #[test]
    fn web_server_rejects_external_binds_and_unauthorised_hosts() {
        assert!(!allowed_host(Some("evil.example"), 8787));
        assert!(!allowed_host(Some("127.0.0.1:9000"), 8787));
        assert!(allowed_host(Some("127.0.0.1:8787"), 8787));
        assert!(allowed_host(Some("localhost:8787"), 8787));
        assert!(
            parse_args([
                "--serve".to_owned(),
                "--bind".to_owned(),
                "0.0.0.0:8787".to_owned()
            ])
            .is_ok()
        );
    }

    #[test]
    fn keyless_discovery_rejects_nonfacebook_hosts_and_nondirect_paths() {
        assert!(is_direct_facebook_page(
            "https://www.facebook.com/nasa",
            "nasa"
        ));
        assert!(is_direct_facebook_page(
            "https://m.facebook.com/NASA/",
            "nasa"
        ));
        for bad in [
            "http://facebook.com/nasa",
            "https://facebook.com.evil.test/nasa",
            "https://www.facebook.com/nasa/posts",
            "https://www.facebook.com/nasa2",
            "https://www.facebook.com/nasa%2Fposts",
            "https://www.facebook.com:8443/nasa",
        ] {
            assert!(!is_direct_facebook_page(bad, "nasa"), "{bad}");
        }
    }

    #[test]
    fn indexed_scan_does_not_use_rapidapi_or_credentials() {
        let fake = Fake::new(200, "<html><body>No indexed results</body></html>");
        let report = scan_indexed(&fake, "nasa", 1234).unwrap();
        assert_eq!(report.provider, "public_search_indexes");
        assert_eq!(report.profile.state, "not_requested");
        assert!(report.discovery.is_some());
        assert!(!report.has_observation());
        let requests = fake.sent.lock().unwrap();
        assert_eq!(requests.len(), 3);
        for req in requests.iter() {
            assert!(!req.url.contains("rapidapi"));
            assert!(req.header_value("x-rapidapi-key").is_none());
        }
    }

    #[test]
    fn indexed_scan_keeps_only_matching_direct_page_urls_as_leads() {
        let fake = Fake::new(
            200,
            r#"<html><a href="https://www.facebook.com/examplelegit">Page</a>
            <a href="https://www.facebook.com/examplelegit/posts">Post</a>
            <a href="https://facebook.com.evil.example/examplelegit">Lookalike</a></html>"#,
        );
        let report = scan_indexed(&fake, "examplelegit", 1235).unwrap();
        let discovery = report.discovery.unwrap();
        assert_eq!(discovery.state, "indexed_leads");
        assert_eq!(discovery.evidence_role, "url_discovery_only_no_identity_verification");
        assert_eq!(discovery.hits.len(), 1);
        assert_eq!(discovery.hits[0].url, "https://www.facebook.com/examplelegit");
    }

    #[test]
    fn collection_defaults_to_keyless_mode_without_provider_opt_in() {
        assert!(!parse_args(["-u".into(), "nasa".into()]).unwrap().provider);
        assert!(
            parse_args(["-u".into(), "nasa".into(), "--provider".into()])
                .unwrap()
                .provider
        );
    }

    #[test]
    fn batch_and_single_modes_are_exclusive() {
        assert!(
            parse_args([
                "-u".into(),
                "a".into(),
                "--batch".into(),
                "users.txt".into()
            ])
            .is_err()
        );
        assert!(parse_args(["--connect-timeout".into(), "0".into(), "--serve".into()]).is_err());
        assert!(parse_args(["--serve".into()]).is_ok());
    }
}
