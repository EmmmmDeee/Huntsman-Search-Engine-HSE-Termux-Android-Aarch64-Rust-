//! Small, loopback-only browser interface for local search.
//!
//! The server uses only the standard library so it remains suitable for the
//! Android/Termux target. It intentionally has no remote bind option.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use serde_json::{Value, json};

use crate::search::{Document, search, tokenize};

const MAX_REQUEST_BYTES: usize = 8 * 1024;
const MAX_QUERY_BYTES: usize = 512;
const READ_TIMEOUT: Duration = Duration::from_secs(2);

const UI: &str = r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark light">
<title>Huntsman Recon · Local Console</title>
<style>
:root{font:16px/1.5 system-ui,sans-serif;color:#e9eff5;background:#101820;--muted:#9aabb9;--line:#334451;--accent:#83d3bd}
*{box-sizing:border-box}body{margin:0}.shell{max-width:940px;margin:auto;padding:28px 20px}
header{display:flex;justify-content:space-between;gap:16px;align-items:center;border-bottom:1px solid var(--line);padding-bottom:18px}
h1{font-size:1.35rem;margin:0}h2{font-size:1.05rem;margin:0 0 12px}p{color:var(--muted)}
.badge{border:1px solid var(--accent);border-radius:999px;padding:3px 10px;color:var(--accent);font-size:.82rem}
main{display:grid;gap:18px;margin-top:22px}.panel{border:1px solid var(--line);border-radius:12px;padding:20px;background:#17232d}
form{display:flex;gap:10px}input,button{font:inherit;border-radius:7px;padding:10px 12px}
input{flex:1;min-width:0;background:#0e171e;color:inherit;border:1px solid var(--line)}
button{border:0;background:var(--accent);color:#102019;font-weight:700;cursor:pointer}
button:focus-visible,input:focus-visible{outline:3px solid #e4c36b;outline-offset:2px}
.hint,.meta{font-size:.9rem;color:var(--muted)}.status{display:flex;gap:10px;align-items:center}
.dot{width:9px;height:9px;border-radius:50%;background:var(--accent)}.error{color:#ffb2a8}
table{width:100%;border-collapse:collapse;margin-top:12px}th,td{text-align:left;padding:9px;border-bottom:1px solid var(--line);overflow-wrap:anywhere}
th{color:var(--muted);font-weight:600}.empty{color:var(--muted);padding:14px 0}
@media(max-width:600px){.shell{padding:18px 12px}form{flex-direction:column}header{align-items:flex-start;flex-direction:column}.panel{padding:15px}}
</style>
</head>
<body><div class="shell">
<header><h1>Huntsman Recon <span class="meta">· Local Console</span></h1><span class="badge">loopback only</span></header>
<main>
<section class="panel" aria-labelledby="health-title"><h2 id="health-title">Service status</h2><div id="status" class="status" role="status">Connecting…</div><p id="config" class="hint">Loading configuration…</p></section>
<section class="panel" aria-labelledby="search-title"><h2 id="search-title">Search local sample records</h2>
<form id="search-form"><label class="meta" for="query">All search terms must match</label><input id="query" name="q" type="search" minlength="2" maxlength="512" required autocomplete="off" placeholder="e.g. brisbane port"><button type="submit">Search</button></form>
<p class="hint">This first web release searches bundled demonstration records only. It does not run SpiderFoot scans or contact search providers.</p>
<div id="results" aria-live="polite" class="empty">Enter two or more searchable characters to begin.</div>
</section>
<section class="panel"><h2>Compatibility status</h2><p class="hint">Termux Android arm64 is cross-built in CI. A successful cross-build does not prove installation or runtime behavior on a handset. SpiderFoot 4.0 feature parity is not claimed.</p></section>
</main></div>
<script>
const statusNode=document.querySelector("#status"),configNode=document.querySelector("#config"),resultsNode=document.querySelector("#results");
async function loadStatus(){try{const r=await fetch("/api/status");if(!r.ok)throw new Error("HTTP "+r.status);const s=await r.json();const dot=document.createElement("span");dot.className="dot";statusNode.replaceChildren(dot,document.createTextNode("Ready · "+s.product_version));configNode.textContent="Bind: "+s.bind+" · Data: "+s.data_mode+" · Network collection: disabled";}catch(e){statusNode.textContent="Status unavailable";statusNode.classList.add("error");configNode.textContent=String(e)}}
document.querySelector("#search-form").addEventListener("submit",async e=>{e.preventDefault();const q=document.querySelector("#query").value;resultsNode.textContent="Searching…";resultsNode.className="empty";try{const r=await fetch("/api/search?q="+encodeURIComponent(q));const data=await r.json();if(!r.ok)throw new Error(data.error||"Request failed");if(!data.results.length){resultsNode.textContent="No matching records.";return}const table=document.createElement("table"),head=table.createTHead().insertRow();for(const label of ["Score","Record","Source"]){const th=document.createElement("th");th.textContent=label;head.append(th)}const body=table.createTBody();for(const hit of data.results){const row=body.insertRow();for(const value of [hit.score,hit.id,hit.source]){const cell=row.insertCell();cell.textContent=String(value)}}resultsNode.replaceChildren(table)}catch(err){resultsNode.textContent=String(err);resultsNode.className="empty error"}});
loadStatus();
</script></body></html>"##;

#[derive(Debug, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
}

impl HttpResponse {
    fn new(status: u16, content_type: &'static str, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            content_type,
            body: body.into(),
        }
    }

    fn json(status: u16, value: Value) -> Self {
        Self::new(
            status,
            "application/json; charset=utf-8",
            serde_json::to_vec(&value).unwrap_or_else(|_| b"{\"error\":\"serialization failed\"}".to_vec()),
        )
    }
}

/// Bind the web interface to IPv4 loopback only.
///
/// # Errors
/// Returns the operating-system error if the requested port cannot be bound.
pub fn bind_loopback(port: u16) -> io::Result<TcpListener> {
    TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port))
}

/// Serve the local browser interface on `127.0.0.1:port` until the process exits.
///
/// # Errors
/// Returns an I/O error if binding or accepting connections fails.
pub fn run(port: u16) -> io::Result<()> {
    let listener = bind_loopback(port)?;
    let address = listener.local_addr()?;
    eprintln!("Huntsman Recon web UI: http://{address}/ (loopback only; Ctrl-C to stop)");
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let _ = serve_connection(stream);
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn serve_connection(mut stream: TcpStream) -> io::Result<()> {
    stream.set_read_timeout(Some(READ_TIMEOUT))?;
    let request = read_request(&mut stream)?;
    let response = handle_request(&request);
    write_response(&mut stream, response)
}

fn read_request(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut request = Vec::with_capacity(1024);
    let mut byte = [0u8; 1];
    while request.len() < MAX_REQUEST_BYTES {
        match stream.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => {
                request.push(byte[0]);
                if request.ends_with(b"\r\n\r\n") {
                    return Ok(request);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(request)
}

fn write_response(stream: &mut TcpStream, response: HttpResponse) -> io::Result<()> {
    let reason = match response.status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        431 => "Request Header Fields Too Large",
        _ => "Internal Server Error",
    };
    write!(
        stream,
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'\r\n\r\n",
        response.status,
        reason,
        response.content_type,
        response.body.len()
    )?;
    stream.write_all(&response.body)
}

/// Route one bounded HTTP/1.x request. Exposed so API behavior is testable offline.
#[must_use]
pub fn handle_request(request: &[u8]) -> HttpResponse {
    if request.len() >= MAX_REQUEST_BYTES && !request.ends_with(b"\r\n\r\n") {
        return error(431, "request headers too large");
    }
    let Ok(request) = std::str::from_utf8(request) else {
        return error(400, "request must be UTF-8");
    };
    let Some(request_line) = request.split("\r\n").next() else {
        return error(400, "missing request line");
    };
    let mut parts = request_line.split_ascii_whitespace();
    let (Some(method), Some(target), Some(version)) = (parts.next(), parts.next(), parts.next())
    else {
        return error(400, "malformed request line");
    };
    if parts.next().is_some() || !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        return error(400, "malformed request line");
    }
    if !request.ends_with("\r\n\r\n") {
        return error(400, "incomplete request headers");
    }
    let hosts: Vec<&str> = request
        .split("\r\n")
        .skip(1)
        .take_while(|line| !line.is_empty())
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("host").then_some(value.trim())
        })
        .collect();
    if hosts.len() != 1 || !is_loopback_host(hosts[0]) {
        return error(403, "Host must be localhost or 127.0.0.1");
    }
    if method != "GET" {
        return error(405, "only GET is supported");
    }
    if !target.starts_with('/') || target.starts_with("//") {
        return error(400, "origin-form request target required");
    }

    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    match path {
        "/" => HttpResponse::new(200, "text/html; charset=utf-8", UI),
        "/api/status" => HttpResponse::json(
            200,
            json!({
                "product": "huntsman-recon",
                "product_version": env!("CARGO_PKG_VERSION"),
                "bind": "127.0.0.1",
                "data_mode": "bundled sample records",
                "network_collection": false,
                "spiderfoot_compatibility": "not claimed"
            }),
        ),
        "/api/config" => HttpResponse::json(
            200,
            json!({
                "bind": "127.0.0.1",
                "port": "configured at launch",
                "data_mode": "bundled sample records",
                "network_collection": false,
                "writable_settings": false
            }),
        ),
        "/api/search" => search_response(query),
        _ => error(404, "not found"),
    }
}

fn search_response(query: &str) -> HttpResponse {
    let mut query_value = None;
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let Ok(key) = decode_component(key) else {
            return error(400, "invalid query encoding");
        };
        if key == "q" {
            if query_value.is_some() {
                return error(400, "provide one q parameter");
            }
            let Ok(value) = decode_component(value) else {
                return error(400, "invalid query encoding");
            };
            query_value = Some(value);
        }
    }
    let Some(query) = query_value else {
        return error(400, "missing q parameter");
    };
    if query.len() > MAX_QUERY_BYTES {
        return error(400, "query exceeds 512 bytes");
    }
    if tokenize(&query).is_empty() {
        return error(400, "query needs a searchable term of at least two characters");
    }
    let docs = [
        Document {
            id: "brisbane".into(),
            body: "Brisbane port radar sighting".into(),
            source: "bundled sample".into(),
        },
        Document {
            id: "sydney".into(),
            body: "Sydney harbour note".into(),
            source: "bundled sample".into(),
        },
    ];
    let results: Vec<Value> = search(&docs, &query)
        .into_iter()
        .map(|hit| {
            json!({
                "id": hit.id,
                "score": hit.score,
                "source": hit.source
            })
        })
        .collect();
    HttpResponse::json(200, json!({ "query": query, "results": results }))
}

fn decode_component(value: &str) -> Result<String, ()> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                let high = hex_value(bytes[index + 1]).ok_or(())?;
                let low = hex_value(bytes[index + 2]).ok_or(())?;
                decoded.push((high << 4) | low);
                index += 3;
            }
            b'%' => return Err(()),
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(decoded).map_err(|_| ())
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn is_loopback_host(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    let (hostname, port) = host
        .split_once(':')
        .map_or((host.as_str(), None), |(name, port)| (name, Some(port)));
    matches!(hostname, "localhost" | "127.0.0.1")
        && port.is_none_or(|port| port.parse::<u16>().is_ok())
}

fn error(status: u16, message: &str) -> HttpResponse {
    HttpResponse::json(status, json!({ "error": message }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(target: &str) -> Vec<u8> {
        format!("GET {target} HTTP/1.1\r\nHost: localhost\r\n\r\n").into_bytes()
    }

    fn json_body(response: &HttpResponse) -> Value {
        serde_json::from_slice(&response.body).expect("JSON response")
    }

    #[test]
    fn rejects_dns_rebinding_hosts_and_duplicate_host_headers() {
        let rebinding = b"GET /api/status HTTP/1.1\r\nHost: attacker.example\r\n\r\n";
        assert_eq!(handle_request(rebinding).status, 403);
        let duplicate = b"GET /api/status HTTP/1.1\r\nHost: localhost\r\nHost: 127.0.0.1\r\n\r\n";
        assert_eq!(handle_request(duplicate).status, 403);
        assert_eq!(
            handle_request(b"GET /api/status HTTP/1.1\r\nHost: localhost.evil\r\n\r\n").status,
            403
        );
        assert_eq!(
            handle_request(b"GET /api/status HTTP/1.1\r\nHost: 127.0.0.1:8787\r\n\r\n").status,
            200
        );
    }

    #[test]
    fn serves_an_http_exchange_over_a_loopback_socket() {
        use std::net::TcpStream;
        use std::thread;

        let listener = bind_loopback(0).expect("bind");
        let address = listener.local_addr().expect("address");
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            serve_connection(stream).expect("serve request");
        });
        let mut client = TcpStream::connect(address).expect("connect");
        client
            .write_all(b"GET /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            .expect("write request");
        let mut response = Vec::new();
        client.read_to_end(&mut response).expect("read response");
        server.join().expect("server thread");
        let response = String::from_utf8(response).expect("HTTP response");
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
        assert!(response.contains("X-Content-Type-Options: nosniff"), "{response}");
        assert!(response.contains("\"bind\":\"127.0.0.1\""), "{response}");
    }

    #[test]
    fn listener_is_bound_to_loopback_even_when_ephemeral_port_is_used() {
        let listener = bind_loopback(0).expect("bind loopback");
        let address = listener.local_addr().expect("local address");
        assert!(address.ip().is_loopback(), "{address}");
    }

    #[test]
    fn serves_ui_status_and_read_only_configuration() {
        let ui = handle_request(&request("/"));
        assert_eq!(ui.status, 200);
        assert_eq!(ui.content_type, "text/html; charset=utf-8");
        let html = String::from_utf8(ui.body).expect("HTML");
        assert!(html.contains("Search local sample records"));
        assert!(html.contains("/api/search"));
        assert!(html.contains("SpiderFoot 4.0 feature parity is not claimed"));

        let status = handle_request(&request("/api/status"));
        assert_eq!(status.status, 200);
        assert_eq!(json_body(&status)["bind"], "127.0.0.1");
        assert_eq!(json_body(&status)["network_collection"], false);

        let config = handle_request(&request("/api/config"));
        assert_eq!(json_body(&config)["writable_settings"], false);
    }

    #[test]
    fn local_search_returns_ranked_json_and_encodes_untrusted_values() {
        let response = handle_request(&request("/api/search?q=brisbane+port"));
        assert_eq!(response.status, 200);
        assert_eq!(json_body(&response)["results"][0]["id"], "brisbane");

        let response = handle_request(&request("/api/search?q=%3Cscript%3E"));
        assert_eq!(response.status, 200);
        assert_eq!(json_body(&response)["query"], "<script>");
        assert!(UI.contains("cell.textContent=String(value)"));
        assert!(!UI.contains("innerHTML"));
    }

    #[test]
    fn malformed_and_oversized_queries_fail_closed() {
        for target in [
            "/api/search",
            "/api/search?q=%GG",
            "/api/search?q=a",
            "/api/search?q=port&q=brisbane",
        ] {
            assert_eq!(handle_request(&request(target)).status, 400, "{target}");
        }
        let large = format!("/api/search?q={}", "a".repeat(MAX_QUERY_BYTES + 1));
        assert_eq!(handle_request(&request(&large)).status, 400);
        assert_eq!(
            handle_request(b"POST /api/search?q=port HTTP/1.1\r\n\r\n").status,
            405
        );
        assert_eq!(handle_request(&request("/unknown")).status, 404);
        assert_eq!(handle_request(b"GET / HTTP/1.1\r\n").status, 400);
    }

    #[test]
    fn query_decoder_rejects_invalid_utf8_and_decodes_unicode() {
        assert_eq!(decode_component("brisbane+port").as_deref(), Ok("brisbane port"));
        assert_eq!(decode_component("%C3%A9").as_deref(), Ok("é"));
        assert!(decode_component("%FF").is_err());
        assert!(decode_component("%1").is_err());
    }
}
