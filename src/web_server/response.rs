//! HTTP response construction for the router: status lines, headers, bodies and the one
//! bounded JSON error and success shapes. Every answer's Content-Security-Policy is chosen here.
//! Behaviour is unchanged from the helpers that lived in `web_server.rs`.

use super::page::{DOSSIER_POLICY, OTHER_POLICY, PAGE_POLICY};

/// The answer to a protected request without the server's token. It names the remedy, because the
/// page shows it as it is and a bare `unauthorized` left the operator nowhere to go.
pub(super) const UNAUTHORIZED: &str = "{\"error\":\"unauthorized: this server was started with HSE_AUTH_TOKEN set; enter that value in the token field under About\"}\n";

pub(super) fn json_error(status: u16, message: &str) -> String {
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
pub(super) fn json_ok(body: &str, head: bool) -> String {
    response(
        200,
        "application/json; charset=utf-8",
        &format!("{body}\n"),
        head,
    )
}

pub(super) fn response(status: u16, content_type: &str, body: &str, head: bool) -> String {
    response_with(status, content_type, body, head, "")
}

/// [`response`] with `extra`, whole `Name: value\r\n` header lines, after the standard ones.
pub(super) fn response_with(
    status: u16,
    content_type: &str,
    body: &str,
    head: bool,
    extra: &str,
) -> String {
    let mut out = response_head(status, content_type, body.len(), extra);
    if !head {
        out.push_str(body);
    }
    out
}

/// [`response_with`] for a body of bytes, such as an Excel export.
pub(super) fn response_bytes(
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
pub(super) fn response_head(
    status: u16,
    content_type: &str,
    content_length: usize,
    extra: &str,
) -> String {
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
