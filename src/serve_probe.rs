//! The client half of `serve`: does a running server answer, is it Huntsman, and does its page
//! and offline analysis work? `doctor` and `doctor serve` report this probe, so the phone checks
//! the web UI in one place.
//!
//! Three requests, each over its own loopback connection with a deadline:
//! 1. `GET /api/health` names `huntsman-recon`. A refused connection means nothing listens; any
//!    other answer means another program holds the port.
//! 2. `GET /` returns the page. Its `Content-Security-Policy` lists the SHA-256 of the page's one
//!    inline script, so a browser runs it, and the page calls `/api/lookup`, `/api/analyze` and
//!    `/api/health`.
//! 3. `GET /api/analyze` on two fixture seeds returns `entities`, `relations` and `termination`.
//!    It is offline on the server, so the probe spends no quota.

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::base64;
use crate::sha256::sha256;

/// The analysis the probe asks for: two fixture seeds, percent-encoded, one per line.
pub const ANALYZE_PROBE_PATH: &str = "/api/analyze?seeds=alice%40example.com%0Aexample.com";
/// The API routes the page must call.
pub const PAGE_ROUTES: [&str; 3] = ["/api/lookup", "/api/analyze", "/api/health"];
/// The most of one response the probe reads. The page is about 25 KiB.
const MAX_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;

/// What the probe found at the address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServeState {
    /// Health, page and analysis all answered as they should.
    Healthy,
    /// Nothing accepted a connection.
    NotRunning,
    /// Something answered, but not as `huntsman-recon`: another program holds the port.
    Foreign,
    /// Huntsman answered, and its API wants a token this probe did not send or that it refused.
    Unauthorized,
    /// Huntsman answered, but its page or analysis is broken.
    Degraded,
}

impl ServeState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::NotRunning => "not_running",
            Self::Foreign => "foreign",
            Self::Unauthorized => "unauthorized",
            Self::Degraded => "degraded",
        }
    }
}

/// The probe's verdict. `problems` says what failed, in words with no response content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServeProbe {
    pub addr: String,
    pub state: ServeState,
    /// The version `/api/health` reported, when Huntsman answered.
    pub version: Option<String>,
    pub problems: Vec<String>,
    pub elapsed_ms: u64,
}

/// One HTTP response, as much of it as the probe needs.
struct Response {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl Response {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// Probe the server at `addr`. `token` is sent as a bearer token to the protected route.
#[must_use]
pub fn probe(addr: SocketAddr, token: Option<&str>, timeout: Duration) -> ServeProbe {
    let started = Instant::now();
    let (state, version, problems) = run(addr, token, timeout);
    ServeProbe {
        addr: addr.to_string(),
        state,
        version,
        problems,
        elapsed_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
    }
}

fn run(
    addr: SocketAddr,
    token: Option<&str>,
    timeout: Duration,
) -> (ServeState, Option<String>, Vec<String>) {
    let health = match get(addr, "/api/health", None, timeout) {
        Ok(response) => response,
        Err(error) if is_refused(&error) => {
            return (ServeState::NotRunning, None, Vec::new());
        }
        Err(error) => {
            return (
                ServeState::Foreign,
                None,
                vec![format!("/api/health: {}", error.kind())],
            );
        }
    };
    let Some(version) = huntsman_version(&health) else {
        return (
            ServeState::Foreign,
            None,
            vec![format!(
                "/api/health answered {} and did not name huntsman-recon",
                health.status
            )],
        );
    };

    let mut problems = Vec::new();
    match get(addr, "/", None, timeout) {
        Ok(page) => problems.extend(page_problems(&page)),
        Err(error) => problems.push(format!("/: {}", error.kind())),
    }
    let mut unauthorized = false;
    match get(addr, ANALYZE_PROBE_PATH, token, timeout) {
        Ok(response) if response.status == 401 => unauthorized = true,
        Ok(response) => problems.extend(analysis_problems(&response)),
        Err(error) => problems.push(format!("/api/analyze: {}", error.kind())),
    }
    let state = if !problems.is_empty() {
        ServeState::Degraded
    } else if unauthorized {
        ServeState::Unauthorized
    } else {
        ServeState::Healthy
    };
    (state, Some(version), problems)
}

fn is_refused(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::ConnectionRefused | ErrorKind::AddrNotAvailable
    )
}

/// The version `/api/health` reports, when the answer is Huntsman's.
fn huntsman_version(response: &Response) -> Option<String> {
    if response.status != 200 {
        return None;
    }
    let value: serde_json::Value = serde_json::from_str(&response.body).ok()?;
    if value.get("name")?.as_str()? != "huntsman-recon" {
        return None;
    }
    Some(value.get("version")?.as_str()?.to_owned())
}

/// Why the page would not work in a browser, or nothing when it would.
fn page_problems(page: &Response) -> Vec<String> {
    let mut problems = Vec::new();
    if page.status != 200 {
        problems.push(format!("/ answered {}", page.status));
        return problems;
    }
    if !page
        .header("content-type")
        .is_some_and(|value| value.starts_with("text/html"))
    {
        problems.push("/ is not text/html".to_owned());
    }
    let script = inline_block(&page.body, "script");
    if script.is_empty() {
        problems.push("/ has no inline script".to_owned());
    } else {
        let hash = format!("'sha256-{}'", base64::standard(&sha256(script.as_bytes())));
        let listed = page
            .header("content-security-policy")
            .and_then(|policy| directive(policy, "script-src"))
            .is_some_and(|sources| sources.split_whitespace().any(|source| source == hash));
        if !listed {
            problems.push(
                "/ policy does not list its script's hash, so a browser would block the page"
                    .to_owned(),
            );
        }
    }
    for route in PAGE_ROUTES {
        if !page.body.contains(route) {
            problems.push(format!("/ does not call {route}"));
        }
    }
    problems
}

/// Why the analysis answer is wrong, or nothing when it is right.
fn analysis_problems(response: &Response) -> Vec<String> {
    if response.status != 200 {
        return vec![format!("/api/analyze answered {}", response.status)];
    }
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&response.body) else {
        return vec!["/api/analyze did not answer JSON".to_owned()];
    };
    ["entities", "relations", "termination"]
        .into_iter()
        .filter(|field| value.get(field).is_none())
        .map(|field| format!("/api/analyze has no {field}"))
        .collect()
}

/// The sources of one directive of a `Content-Security-Policy` value.
fn directive<'a>(policy: &'a str, name: &str) -> Option<&'a str> {
    policy.split(';').find_map(|part| {
        let part = part.trim();
        let (directive, sources) = part.split_once(char::is_whitespace).unwrap_or((part, ""));
        directive.eq_ignore_ascii_case(name).then_some(sources)
    })
}

/// The text between `<tag>` and `</tag>`: what a browser hashes for a CSP hash source.
fn inline_block<'a>(page: &'a str, tag: &str) -> &'a str {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    match (page.find(&open), page.find(&close)) {
        (Some(start), Some(end)) if start + open.len() <= end => &page[start + open.len()..end],
        _ => "",
    }
}

fn get(
    addr: SocketAddr,
    path: &str,
    token: Option<&str>,
    timeout: Duration,
) -> std::io::Result<Response> {
    let mut stream = TcpStream::connect_timeout(&addr, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let authorization = token.map_or_else(String::new, |token| {
        format!("Authorization: Bearer {token}\r\n")
    });
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: {addr}\r\nUser-Agent: huntsman-recon-doctor\r\n{authorization}Connection: close\r\n\r\n"
    )?;
    let mut raw = Vec::new();
    stream.take(MAX_RESPONSE_BYTES).read_to_end(&mut raw)?;
    parse_response(&raw)
        .ok_or_else(|| std::io::Error::new(ErrorKind::InvalidData, "not an HTTP/1.1 response"))
}

fn parse_response(raw: &[u8]) -> Option<Response> {
    let text = String::from_utf8_lossy(raw);
    let (head, body) = text.split_once("\r\n\r\n")?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next()?;
    let mut parts = status_line.split_whitespace();
    if !parts.next()?.starts_with("HTTP/1.") {
        return None;
    }
    let status = parts.next()?.parse().ok()?;
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_owned(), value.trim().to_owned()))
        .collect();
    Some(Response {
        status,
        headers,
        body: body.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(status: u16, headers: &[(&str, &str)], body: &str) -> Response {
        Response {
            status,
            headers: headers
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                .collect(),
            body: body.to_owned(),
        }
    }

    fn page(script: &str, policy_script: &str) -> Response {
        let hash = base64::standard(&sha256(policy_script.as_bytes()));
        response(
            200,
            &[
                ("Content-Type", "text/html; charset=utf-8"),
                (
                    "Content-Security-Policy",
                    &format!("default-src 'none'; script-src 'sha256-{hash}'; style-src 'self'"),
                ),
            ],
            &format!(
                "<html><script>{script}</script><a>/api/lookup /api/analyze /api/health</a></html>"
            ),
        )
    }

    #[test]
    fn a_page_whose_policy_lists_its_script_hash_passes() {
        assert_eq!(page_problems(&page("go()", "go()")), Vec::<String>::new());
    }

    #[test]
    fn a_page_whose_script_changed_without_its_hash_is_reported() {
        let problems = page_problems(&page("go(1)", "go()"));
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("hash"), "{problems:?}");
    }

    #[test]
    fn a_page_missing_a_route_names_the_route() {
        let mut broken = page("go()", "go()");
        broken.body = broken.body.replace("/api/analyze", "");
        assert_eq!(page_problems(&broken), ["/ does not call /api/analyze"]);
    }

    #[test]
    fn only_a_health_answer_naming_huntsman_is_huntsman() {
        let ours = response(
            200,
            &[],
            r#"{"status":"ok","name":"huntsman-recon","version":"1.2.3"}"#,
        );
        assert_eq!(huntsman_version(&ours).as_deref(), Some("1.2.3"));
        for other in [
            response(200, &[], r#"{"name":"jupyter"}"#),
            response(200, &[], "<html>"),
            response(404, &[], r#"{"name":"huntsman-recon","version":"1"}"#),
        ] {
            assert_eq!(huntsman_version(&other), None);
        }
    }

    #[test]
    fn an_analysis_missing_a_field_names_it() {
        let ok = response(
            200,
            &[],
            r#"{"entities":[],"relations":[],"termination":{}}"#,
        );
        assert!(analysis_problems(&ok).is_empty());
        let partial = response(200, &[], r#"{"entities":[]}"#);
        assert_eq!(
            analysis_problems(&partial),
            [
                "/api/analyze has no relations",
                "/api/analyze has no termination"
            ]
        );
        assert_eq!(
            analysis_problems(&response(500, &[], "")),
            ["/api/analyze answered 500"]
        );
    }

    #[test]
    fn responses_parse_with_any_header_case() {
        let parsed =
            parse_response(b"HTTP/1.1 204 No Content\r\ncontent-type: x\r\n\r\n").expect("parses");
        assert_eq!(parsed.status, 204);
        assert_eq!(parsed.header("Content-Type"), Some("x"));
        assert!(parse_response(b"SSH-2.0-OpenSSH\r\n\r\n").is_none());
        assert!(parse_response(b"HTTP/1.1 200 OK").is_none());
    }

    #[test]
    fn a_closed_port_is_not_running() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        drop(listener);
        let found = probe(addr, None, Duration::from_secs(2));
        assert_eq!(found.state, ServeState::NotRunning);
    }

    #[test]
    fn another_program_on_the_port_is_foreign() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut buf = [0_u8; 1024];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi");
        });
        let found = probe(addr, None, Duration::from_secs(2));
        server.join().expect("server");
        assert_eq!(found.state, ServeState::Foreign);
        assert_eq!(found.version, None);
    }
}
