//! Native Rust server-rendered interface for `MetaScan`.
//!
//! No JavaScript, WASM, Python, Node, template engine, CDN, or frontend build.
//! Native HTML forms make all collection, filtering, state and exports Rust-owned.

use super::{
    API_HOST, CollectionMode, HttpRequest, Report, WEB_MAX_CLIENTS, allowed_host, checked_username,
    configured_secret, http_reply, json_reply, read_request, scan_mode, transport, unix_now,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs::File;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::Duration;

const MAX_HANDLES: usize = 20;
const MAX_REPORT_JSON_BYTES: usize = 8 * 1024 * 1024;
const MAX_PREVIEW_CHARS: usize = 12_000;

#[derive(Default)]
struct Saved {
    reports: Vec<Report>,
    handles: String,
    mode: CollectionMode,
    business: bool,
}

struct WebState {
    csrf: String,
    saved: Mutex<Saved>,
}

fn secret_token() -> std::io::Result<String> {
    let mut entropy = [0_u8; 16];
    File::open("/dev/urandom")?.read_exact(&mut entropy)?;
    let mut token = String::with_capacity(32);
    for byte in entropy {
        let _ = write!(token, "{byte:02x}");
    }
    Ok(token)
}

fn hex_digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn decode_form_component(input: &str) -> Result<String, &'static str> {
    let raw = input.as_bytes();
    let mut output = Vec::with_capacity(raw.len());
    let mut index = 0;
    while index < raw.len() {
        match raw[index] {
            b'+' => output.push(b' '),
            b'%' => {
                if index + 2 >= raw.len() {
                    return Err("malformed form percent encoding");
                }
                let high = hex_digit(raw[index + 1]).ok_or("invalid form hex escape")?;
                let low = hex_digit(raw[index + 2]).ok_or("invalid form hex escape")?;
                output.push(high * 16 + low);
                index += 2;
            }
            byte => output.push(byte),
        }
        index += 1;
    }
    String::from_utf8(output).map_err(|_| "form requires UTF-8")
}

fn decode_form(body: &[u8]) -> Result<BTreeMap<String, String>, &'static str> {
    let text = std::str::from_utf8(body).map_err(|_| "form requires UTF-8")?;
    let mut form = BTreeMap::new();
    for (index, item) in text.split('&').enumerate() {
        if index >= 16 {
            return Err("too many form fields");
        }
        let (key, value) = item.split_once('=').ok_or("invalid form field")?;
        let name = decode_form_component(key)?;
        if name.len() > 32 || form.contains_key(&name) {
            return Err("invalid or duplicate form field");
        }
        form.insert(name, decode_form_component(value)?);
    }
    Ok(form)
}

fn checked_form(
    request: &HttpRequest,
    state: &WebState,
    port: u16,
) -> Result<BTreeMap<String, String>, &'static str> {
    if !request
        .header("Content-Type")
        .is_some_and(|type_| type_.eq_ignore_ascii_case("application/x-www-form-urlencoded"))
    {
        return Err("a native URL-encoded HTML form is required");
    }
    if let Some(origin) = request.header("Origin") {
        let valid = origin == format!("http://127.0.0.1:{port}")
            || origin == format!("http://localhost:{port}")
            || origin == format!("http://[::1]:{port}");
        if !valid {
            return Err("cross-origin form submission is refused");
        }
    }
    let form = decode_form(&request.body)?;
    if form.get("csrf").map(String::as_str) != Some(state.csrf.as_str()) {
        return Err("invalid or missing form session token");
    }
    Ok(form)
}

fn checked_handles(raw: &str) -> Result<Vec<String>, &'static str> {
    let mut seen = BTreeSet::new();
    let mut handles = Vec::new();
    for handle in raw.lines().map(str::trim).filter(|part| !part.is_empty()) {
        let normalized = checked_username(handle)?;
        if seen.insert(normalized.to_ascii_lowercase()) {
            handles.push(normalized);
        }
        if handles.len() > MAX_HANDLES {
            return Err("Web UI accepts up to 20 unique handles per scan");
        }
    }
    if handles.is_empty() {
        return Err("enter at least one Facebook page handle");
    }
    Ok(handles)
}

fn html_escape(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    for character in input.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&#39;"),
            _ => output.push(character),
        }
    }
    output
}

fn preview_json(value: &serde_json::Value) -> String {
    let raw = serde_json::to_string_pretty(value).unwrap_or_default();
    let mut shown = String::new();
    for ch in raw.chars().take(MAX_PREVIEW_CHARS) {
        shown.push(ch);
    }
    if raw.chars().count() > MAX_PREVIEW_CHARS {
        shown.push_str("\n[Preview truncated: full response remains in JSON export]");
    }
    html_escape(&shown)
}

fn render_endpoint(out: &mut String, label: &str, result: &super::EndpointResult) {
    let _ = write!(
        out,
        "<section class=\"endpoint\"><div class=\"endpoint-head\"><strong>{}</strong><span class=\"badge\">{}</span></div>",
        html_escape(label),
        html_escape(result.state)
    );
    if let Some(status) = result.http_status {
        let _ = write!(out, "<p class=\"small\">HTTP {status}</p>");
    }
    if let Some(message) = &result.message {
        let _ = write!(out, "<p>{}</p>", html_escape(message));
    }
    if let Some(data) = &result.data {
        let _ = write!(
            out,
            "<details><summary>Provider response (unverified)</summary><pre>{}</pre></details>",
            preview_json(data)
        );
    }
    out.push_str("</section>");
}

fn render_report(out: &mut String, report: &Report) {
    let _ = write!(
        out,
        "<article class=\"report\"><h3>@{}</h3><p class=\"small\">{} · {}</p>",
        html_escape(&report.username),
        html_escape(report.provider),
        html_escape(report.verification)
    );
    if let Some(discovery) = &report.discovery {
        let _ = write!(
            out,
            "<h4>Public indexed URL leads · {}</h4><p class=\"small\">{} · {} candidate(s). Index links are not profile or identity verification.</p>",
            html_escape(discovery.state),
            html_escape(discovery.evidence_role),
            discovery.hits.len()
        );
        for hit in &discovery.hits {
            let link = html_escape(&hit.url);
            let _ = write!(
                out,
                "<p class=\"hit\">{} · <a target=\"_blank\" rel=\"noopener noreferrer\" href=\"{}\">{}</a></p>",
                html_escape(&hit.engine),
                link,
                link
            );
        }
        out.push_str("<details><summary>Search source outcomes</summary>");
        for outcome in &discovery.outcomes {
            let _ = write!(
                out,
                "<p>{}: {}</p>",
                html_escape(&outcome.module),
                html_escape(outcome.kind.as_str())
            );
        }
        out.push_str("</details>");
    }
    render_endpoint(out, "Profile", &report.profile);
    for (label, result) in [
        ("Business homepage", report.business_home.as_ref()),
        ("Business About", report.business_about.as_ref()),
        ("Page transparency", report.business_transparency.as_ref()),
    ] {
        if let Some(item) = result {
            render_endpoint(out, label, item);
        }
    }
    out.push_str("</article>");
}

const STYLE: &str = r"
:root{color-scheme:dark;font-family:system-ui,-apple-system,Roboto,sans-serif;background:#0c1422;color:#e8edf8}
*{box-sizing:border-box}body{margin:0;line-height:1.5}
main{max-width:900px;margin:auto;padding:clamp(16px,4vw,32px)}
header{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;align-items:center;margin-bottom:18px}
h1{font-size:clamp(27px,6vw,38px);margin:0}h2{font-size:20px;margin:0 0 12px}h3{margin:0 0 10px}
p{color:#c0cde0;margin:8px 0}.small{font-size:13px;color:#b3c5dc}
.card{border:1px solid #344861;border-radius:17px;background:#111e31;padding:clamp(15px,3vw,24px);margin:0 0 20px}
label{display:block;margin:12px 0 7px;font-weight:600}
textarea,select{display:block;width:100%;background:#091525;border:1px solid #637b9c;color:#fff;border-radius:10px;padding:12px;font:15px/1.6 system-ui}
textarea{min-height:120px;font-family:ui-monospace,monospace;resize:vertical}
input[type=checkbox]{accent-color:#46a4ff;width:19px;height:19px;vertical-align:middle}
button{appearance:none;background:#156ac2;border:1px solid #4e9ce3;color:white;padding:11px 16px;border-radius:11px;font:600 14px system-ui;cursor:pointer}
button:focus-visible,textarea:focus-visible,select:focus-visible{outline:3px solid #99d2ff}
button:disabled{opacity:.5}a{color:#9fd5ff;overflow-wrap:anywhere}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin:12px 0}
.notice{border-left:3px solid #e9af56;background:#352c225c;border-radius:4px;padding:9px 12px}
.status{font-size:13px;background:#1a354f;border:1px solid #4a7294;border-radius:25px;padding:6px 11px}
.report{border:1px solid #45617c;border-radius:12px;margin:16px 0;padding:15px}
.endpoint{border:1px solid #334c68;border-radius:9px;margin:12px 0;padding:10px}
.endpoint-head{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap}
.badge{border-radius:20px;padding:3px 10px;background:#28425f;font-size:12px}
pre{white-space:pre-wrap;overflow-wrap:anywhere;max-height:320px;overflow:auto;background:#081322;padding:12px;border-radius:6px;font-size:12px}
summary{cursor:pointer;color:#9fd5ff;font-weight:600}.hit{overflow-wrap:anywhere}
footer{font-size:12px;color:#9eafc5;padding:8px 0}
";

fn render_page(state: &WebState, message: Option<&str>) -> String {
    let saved = state.saved.lock().unwrap_or_else(PoisonError::into_inner);
    let mut out = String::with_capacity(16 * 1024);
    out.push_str("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">");
    out.push_str("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1,viewport-fit=cover\">");
    out.push_str("<meta name=\"theme-color\" content=\"#101a2b\">");
    out.push_str("<title>Huntsman MetaScan · Native Rust</title><style>");
    out.push_str(STYLE);
    out.push_str("</style></head><body><main><header><div><p class=\"small\">Huntsman · Rust · Android aarch64</p>");
    out.push_str("<h1>MetaScan</h1><p>Facebook intelligence and indexed discovery</p></div>");
    let configured = if configured_secret().is_some() {
        "Provider key configured"
    } else {
        "Keyless mode available"
    };
    let _ = write!(out, "<span class=\"status\">{configured}</span></header>");
    out.push_str("<section class=\"card\"><h2>New collection</h2>");
    out.push_str("<p>Public index discovery is free and the default. Provider enrichment must be explicitly selected and may use billable quota.</p>");
    out.push_str("<form action=\"/scan\" method=\"post\" accept-charset=\"UTF-8\">");
    let _ = write!(
        out,
        "<input type=\"hidden\" name=\"csrf\" value=\"{}\">",
        html_escape(&state.csrf)
    );
    out.push_str("<label for=\"handles\">Facebook page handles (one per line, up to 20)</label>");
    let _ = write!(
        out,
        "<textarea id=\"handles\" name=\"handles\" maxlength=\"3000\" required spellcheck=\"false\" placeholder=\"nasa&#10;HackUnderway\">{}</textarea>",
        html_escape(&saved.handles)
    );
    out.push_str("<label for=\"mode\">Collection mode</label><select name=\"mode\" id=\"mode\">");
    for (mode, label) in [
        ("indexed", "Keyless public URL discovery (no API charges)"),
        (
            "provider",
            "RapidAPI profile and business enrichment (may be paid)",
        ),
        (
            "combined",
            "Both: keyless indexed discovery and paid provider enrichment",
        ),
    ] {
        let selected = if CollectionMode::from_name(mode) == Some(saved.mode) {
            " selected"
        } else {
            ""
        };
        let _ = write!(
            out,
            "<option value=\"{mode}\"{selected}>{}</option>",
            html_escape(label)
        );
    }
    out.push_str("</select><label><input type=\"checkbox\" name=\"business\" value=\"yes\"");
    if saved.business {
        out.push_str(" checked");
    }
    out.push_str("> Include provider business/About/transparency endpoints</label>");
    out.push_str("<div class=\"row\"><button type=\"submit\">Run collection</button></div></form>");
    out.push_str("<p class=\"notice\">Discovery links are unverified leads, not account or identity claims. No API request is charged unless you explicitly select provider enrichment. No JavaScript, WASM, telemetry, CDN or browser credential storage.</p>");
    if let Some(message) = message {
        let _ = write!(
            out,
            "<p role=\"status\" class=\"notice\">{}</p>",
            html_escape(message)
        );
    }
    out.push_str("</section><section class=\"card\"><h2>Results</h2>");
    if saved.reports.is_empty() {
        out.push_str("<p>No report loaded. Run collection above.</p>");
    } else {
        let _ = write!(
            out,
            "<p class=\"small\">{} report(s) kept locally in process memory.</p>",
            saved.reports.len()
        );
        out.push_str("<form method=\"post\" action=\"/export\" class=\"row\">");
        let _ = write!(
            out,
            "<input type=\"hidden\" name=\"csrf\" value=\"{}\">",
            html_escape(&state.csrf)
        );
        out.push_str("<button name=\"format\" value=\"json\" type=\"submit\">Export JSON</button>");
        out.push_str(
            "<button name=\"format\" value=\"txt\" type=\"submit\">Export TXT</button></form>",
        );
        for report in &saved.reports {
            render_report(&mut out, report);
        }
    }
    out.push_str("</section><footer>Rendered, validated and exported entirely by Rust. Loopback-only, no root, no runtime LLM. HackUnderway MetaScan attribution (MIT).</footer>");
    out.push_str("</main></body></html>");
    out
}

fn html_response(stream: &mut TcpStream, status: &str, page: &str) {
    let _ = http_reply(stream, status, "text/html; charset=utf-8", page.as_bytes());
}

fn handle_form_scan(
    stream: &mut TcpStream,
    state: &WebState,
    req: &HttpRequest,
    port: u16,
    timeout: Duration,
) {
    let form = match checked_form(req, state, port) {
        Ok(form) => form,
        Err(reason) => {
            html_response(stream, "403 Forbidden", &render_page(state, Some(reason)));
            return;
        }
    };
    let mode = form.get("mode").map_or("indexed", String::as_str);
    let Some(mode) = CollectionMode::from_name(mode) else {
        html_response(
            stream,
            "400 Bad Request",
            &render_page(state, Some("Unknown scan mode")),
        );
        return;
    };
    let raw = form.get("handles").map_or("", String::as_str);
    let handles = match checked_handles(raw) {
        Ok(handles) => handles,
        Err(reason) => {
            html_response(stream, "400 Bad Request", &render_page(state, Some(reason)));
            return;
        }
    };
    let business = form.get("business").is_some_and(|v| v == "yes");
    let key = mode.requires_key().then(configured_secret).flatten();
    if mode.requires_key() && key.is_none() {
        html_response(
            stream,
            "400 Bad Request",
            &render_page(
                state,
                Some("RapidAPI provider key not configured; select free indexed discovery instead"),
            ),
        );
        return;
    }
    let transport = transport(timeout);
    let mut reports = Vec::with_capacity(handles.len());
    let mut bytes = 0;
    let mut limit_reached = false;
    for handle in handles {
        let result = scan_mode(
            &transport,
            key.as_ref(),
            &handle,
            mode,
            business,
            unix_now(),
            timeout,
        );
        if let Ok(report) = result {
            let size = serde_json::to_vec(&report).map_or(MAX_REPORT_JSON_BYTES + 1, |v| v.len());
            if bytes + size > MAX_REPORT_JSON_BYTES {
                limit_reached = true;
                break;
            }
            bytes += size;
            reports.push(report);
        }
    }
    let count = reports.len();
    let mut saved = state.saved.lock().unwrap_or_else(PoisonError::into_inner);
    saved.reports = reports;
    raw.clone_into(&mut saved.handles);
    saved.mode = mode;
    saved.business = business;
    drop(saved);
    let message = if limit_reached {
        format!("{count} report(s) stored; stopped at the 8 MiB in-memory cap")
    } else {
        format!("{count} report(s) collected; each source status is shown below")
    };
    html_response(stream, "200 OK", &render_page(state, Some(&message)));
}

fn download_reply(stream: &mut TcpStream, kind: &str, bytes: &[u8]) -> std::io::Result<()> {
    let (mime, extension) = if kind == "json" {
        ("application/json; charset=utf-8", "json")
    } else {
        ("text/plain; charset=utf-8", "txt")
    };
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: {mime}\r\nContent-Disposition: attachment; filename=\"huntsman_meta_scan.{extension}\"\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n",
        bytes.len()
    )?;
    stream.write_all(bytes)
}

fn handle_export(stream: &mut TcpStream, state: &WebState, req: &HttpRequest, port: u16) {
    let form = match checked_form(req, state, port) {
        Ok(form) => form,
        Err(reason) => {
            html_response(stream, "403 Forbidden", &render_page(state, Some(reason)));
            return;
        }
    };
    let kind = form.get("format").map_or("", String::as_str);
    if !matches!(kind, "json" | "txt") {
        html_response(
            stream,
            "400 Bad Request",
            &render_page(state, Some("Export format must be JSON or TXT")),
        );
        return;
    }
    let saved = state.saved.lock().unwrap_or_else(PoisonError::into_inner);
    if saved.reports.is_empty() {
        drop(saved);
        html_response(
            stream,
            "400 Bad Request",
            &render_page(state, Some("No report to export")),
        );
        return;
    }
    let payload = if kind == "json" {
        serde_json::to_vec_pretty(&saved.reports).unwrap_or_default()
    } else {
        saved
            .reports
            .iter()
            .map(Report::as_text)
            .collect::<Vec<_>>()
            .join("\n---\n")
            .into_bytes()
    };
    drop(saved);
    let _ = download_reply(stream, kind, &payload);
}

fn handle_compat_json(stream: &mut TcpStream, req: &HttpRequest, port: u16, timeout: Duration) {
    if req.header("X-Meta-Scan") != Some("1")
        || req
            .header("Content-Type")
            .is_none_or(|value| !value.to_ascii_lowercase().starts_with("application/json"))
        || req.header("Origin").is_some_and(|origin| {
            origin != format!("http://127.0.0.1:{port}")
                && origin != format!("http://localhost:{port}")
        })
    {
        let _ = json_reply(
            stream,
            "403 Forbidden",
            &serde_json::json!({"error":"same-origin JSON request and X-Meta-Scan header required"}),
        );
        return;
    }
    let Ok(body) = serde_json::from_slice::<serde_json::Value>(&req.body) else {
        let _ = json_reply(
            stream,
            "400 Bad Request",
            &serde_json::json!({"error":"invalid JSON body"}),
        );
        return;
    };
    let Some(username) = body.get("username").and_then(serde_json::Value::as_str) else {
        let _ = json_reply(
            stream,
            "400 Bad Request",
            &serde_json::json!({"error":"username required"}),
        );
        return;
    };
    let mode = body
        .get("mode")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("indexed");
    let Some(mode) = CollectionMode::from_name(mode) else {
        let _ = json_reply(
            stream,
            "400 Bad Request",
            &serde_json::json!({"error":"unknown collection mode"}),
        );
        return;
    };
    let business = body
        .get("include_business")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(true);
    let key = mode.requires_key().then(configured_secret).flatten();
    let transport = transport(timeout);
    let result = scan_mode(
        &transport,
        key.as_ref(),
        username,
        mode,
        business,
        unix_now(),
        timeout,
    );
    match result {
        Ok(report) => {
            let _ = json_reply(
                stream,
                "200 OK",
                &serde_json::to_value(report).unwrap_or_default(),
            );
        }
        Err(error) => {
            let _ = json_reply(
                stream,
                "400 Bad Request",
                &serde_json::json!({"error":error}),
            );
        }
    }
}

fn serve_client(mut stream: TcpStream, state: &WebState, port: u16, timeout: Duration) {
    let req = match read_request(&mut stream) {
        Ok(req) => req,
        Err(error) => {
            let _ = json_reply(
                &mut stream,
                "400 Bad Request",
                &serde_json::json!({"error":error}),
            );
            return;
        }
    };
    if !allowed_host(req.header("Host"), port) {
        let _ = json_reply(
            &mut stream,
            "403 Forbidden",
            &serde_json::json!({"error":"loopback Host header required"}),
        );
        return;
    }
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/") => html_response(&mut stream, "200 OK", &render_page(state, None)),
        ("GET", "/api/status") => {
            let _ = json_reply(
                &mut stream,
                "200 OK",
                &serde_json::json!({
                    "name":"Huntsman MetaScan", "provider":API_HOST,
                    "api_key_configured":configured_secret().is_some(), "binding":"loopback",
                    "interface":"native_rust_server_rendered_no_javascript"
                }),
            );
        }
        ("POST", "/scan") => handle_form_scan(&mut stream, state, &req, port, timeout),
        ("POST", "/export") => handle_export(&mut stream, state, &req, port),
        ("POST", "/api/scan") => handle_compat_json(&mut stream, &req, port, timeout),
        _ => {
            let _ = json_reply(
                &mut stream,
                "404 Not Found",
                &serde_json::json!({"error":"route not found"}),
            );
        }
    }
}

pub(super) fn serve(bind: &str, timeout: Duration) -> Result<(), String> {
    let address: SocketAddr = bind
        .parse()
        .map_err(|_| "bind must be a numeric loopback address:port".to_owned())?;
    if !address.ip().is_loopback() || address.port() < 1024 {
        return Err("Web UI must bind to loopback and an unprivileged port (>=1024)".to_owned());
    }
    let listener =
        TcpListener::bind(address).map_err(|err| format!("cannot listen on {bind}: {err}"))?;
    let csrf = secret_token()
        .map_err(|_| "cannot load OS randomness for local form session".to_owned())?;
    let state = Arc::new(WebState {
        csrf,
        saved: Mutex::new(Saved {
            business: true,
            ..Saved::default()
        }),
    });
    println!("MetaScan pure Rust Web UI: http://{bind}/");
    let active = Arc::new(AtomicUsize::new(0));
    for connection in listener.incoming() {
        let Ok(mut client) = connection else { continue };
        let previous = active.fetch_add(1, Ordering::AcqRel);
        if previous >= WEB_MAX_CLIENTS {
            active.fetch_sub(1, Ordering::AcqRel);
            let _ = json_reply(
                &mut client,
                "503 Service Unavailable",
                &serde_json::json!({"error":"connection capacity reached"}),
            );
            continue;
        }
        let worker_state = Arc::clone(&state);
        let counter = Arc::clone(&active);
        let launched = thread::Builder::new()
            .name("meta-scan-web".into())
            .stack_size(2 * 1024 * 1024)
            .spawn(move || {
                struct Release(Arc<AtomicUsize>);
                impl Drop for Release {
                    fn drop(&mut self) {
                        self.0.fetch_sub(1, Ordering::AcqRel);
                    }
                }
                let _guard = Release(counter);
                serve_client(client, &worker_state, address.port(), timeout);
            });
        if launched.is_err() {
            active.fetch_sub(1, Ordering::AcqRel);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_decoding_rejects_duplicate_fields_and_bad_percent_encoding() {
        let valid = decode_form(b"handles=NASA%0AHackUnderway&mode=indexed").unwrap();
        assert_eq!(
            valid.get("handles").map(String::as_str),
            Some("NASA\nHackUnderway")
        );
        assert!(decode_form(b"mode=indexed&mode=provider").is_err());
        assert!(decode_form(b"handles=%GG").is_err());
        assert!(decode_form(b"handles=%").is_err());
    }

    #[test]
    fn username_batch_deduplicates_case_insensitively_and_bounds_size() {
        assert_eq!(
            checked_handles("NASA\nnasa\nHackUnderway").unwrap().len(),
            2
        );
        let too_many = (0..21)
            .map(|i| format!("account{i}"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(checked_handles(&too_many).is_err());
        assert!(checked_handles("valid\ninvalid/path").is_err());
    }

    #[test]
    fn renderer_escapes_hostile_provider_text() {
        let malicious = "<script>alert('x') & \"unsafe\"</script>";
        assert_eq!(
            html_escape(malicious),
            "&lt;script&gt;alert(&#39;x&#39;) &amp; &quot;unsafe&quot;&lt;/script&gt;"
        );
    }

    #[test]
    fn rust_rendering_uses_native_forms_with_no_browser_application_scripts() {
        let state = WebState {
            csrf: "test_token".to_owned(),
            saved: Mutex::new(Saved::default()),
        };
        let page = render_page(&state, None);
        assert!(page.contains("action=\"/scan\""));
        assert!(!page.contains("action=\"/export\""));
        assert!(page.contains("name=\"csrf\" value=\"test_token\""));
        assert!(!page.contains("<script"));
        assert!(!page.contains("javascript:"));
    }

    #[test]
    fn form_submissions_require_matching_per_process_token() {
        let state = WebState {
            csrf: "good_token".to_owned(),
            saved: Mutex::new(Saved::default()),
        };
        let request = HttpRequest {
            method: "POST".to_owned(),
            path: "/scan".to_owned(),
            headers: vec![(
                "Content-Type".to_owned(),
                "application/x-www-form-urlencoded".to_owned(),
            )],
            body: b"csrf=bad_token&handles=nasa&mode=indexed".to_vec(),
        };
        assert!(checked_form(&request, &state, 8787).is_err());
        let mut correct = request;
        correct.body = b"csrf=good_token&handles=nasa&mode=indexed".to_vec();
        assert!(checked_form(&correct, &state, 8787).is_ok());
    }

    #[test]
    fn token_is_random_and_fixed_length() {
        let first = secret_token().unwrap();
        let second = secret_token().unwrap();
        assert_eq!(first.len(), 32);
        assert_ne!(first, second);
    }
}
