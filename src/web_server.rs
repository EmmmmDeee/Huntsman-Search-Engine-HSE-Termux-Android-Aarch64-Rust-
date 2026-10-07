//! Minimal embedded Web UI and HTTP API for Huntsman Recon.
//!
//! The default bind is loopback-only. Explicit non-loopback binds require a
//! non-empty bearer token supplied by the caller. The server is dependency-free,
//! blocking, bounded per request, and exposes only read-only metadata endpoints.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use serde::Serialize;

use crate::engineering_command;
use crate::error::Error;
use crate::module::reachable_modules;

pub const DEFAULT_BIND: &str = "127.0.0.1:8080";

/// Resolve the implicit server bind without weakening the explicit bind contract.
///
/// Local/Termux runs stay loopback-only. Railway runs use the platform-provided
/// PORT on all interfaces so Railway routing and health checks reach the server.
/// HSE_BIND always wins and an explicit CLI --bind still wins later.
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
                    return Err(Error::Invalid("HSE_AUTH_TOKEN must not be empty".into()));
                }
                Some(token)
            }
            None => None,
        };

        if !bind.ip().is_loopback() && bearer_token.is_none() {
            return Err(Error::Invalid(
                "non-loopback serve bind requires HSE_AUTH_TOKEN".into(),
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

    /// Run until the listener returns an unrecoverable error.
    ///
    /// # Errors
    /// Returns the listener error that stops the loop.
    pub fn run(&self) -> Result<(), Error> {
        loop {
            let (stream, _) = self
                .listener
                .accept()
                .map_err(|error| Error::Store(format!("serve accept: {error}")))?;
            let _handled = self.handle_stream(stream);
        }
    }

    #[cfg(test)]
    fn run_n(&self, count: usize) -> Result<(), Error> {
        for _ in 0..count {
            let (stream, _) = self
                .listener
                .accept()
                .map_err(|error| Error::Store(format!("serve accept: {error}")))?;
            self.handle_stream(stream)?;
        }
        Ok(())
    }

    fn handle_stream(&self, mut stream: TcpStream) -> Result<(), Error> {
        stream
            .set_read_timeout(Some(IO_TIMEOUT))
            .map_err(|error| Error::Store(format!("serve read timeout: {error}")))?;
        stream
            .set_write_timeout(Some(IO_TIMEOUT))
            .map_err(|error| Error::Store(format!("serve write timeout: {error}")))?;

        let request = read_request(&mut stream)?;
        let response = response_for_request(&request, self.config.bearer_token.as_deref());
        stream
            .write_all(response.as_bytes())
            .map_err(|error| Error::Store(format!("serve write: {error}")))?;
        stream
            .flush()
            .map_err(|error| Error::Store(format!("serve flush: {error}")))
    }
}

fn read_request(stream: &mut TcpStream) -> Result<String, Error> {
    let mut bytes = Vec::with_capacity(1024);
    let mut chunk = [0_u8; 1024];

    while bytes.len() < MAX_REQUEST_BYTES {
        let read = stream
            .read(&mut chunk)
            .map_err(|error| Error::Store(format!("serve read: {error}")))?;
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

    String::from_utf8(bytes).map_err(|_| Error::Invalid("serve request is not UTF-8".into()))
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
        413 => "Payload Too Large",
        500 => "Internal Server Error",
        _ => "Error",
    };
    let content_length = body.len();
    let rendered_body = if head { "" } else { body };
    format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {content_length}\r\nCache-Control: no-store\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\n\r\n{rendered_body}"
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
        assert_eq!(
            resolve_serve_bind(None, None, false).unwrap(),
            DEFAULT_BIND
        );
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
}
