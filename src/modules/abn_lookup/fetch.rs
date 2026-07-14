//! HTTP fetch helpers for the ABR JSONP API.

use std::time::Duration;

use serde_json::Value;
use tokio::process::Command;

use crate::core::error::{Error, Result};

use super::{BASE_URL, SRC};

/// Fetch the ABR record for an exact 11-digit ABN (`AbnDetails.aspx`).
/// `Ok(None)` when the API is unreachable or returns a 4xx other than the
/// auth/rate-limit cases that [`fetch_jsonp`] promotes to errors. The ABN is
/// pre-validated as digits-only by the caller, so it needs no URL-encoding.
pub(super) async fn fetch_abn(guid: &str, abn: &str) -> Result<Option<Value>> {
    let url = format!("{BASE_URL}/AbnDetails.aspx?abn={abn}&callback=cb&guid={guid}");
    fetch_jsonp(&url).await
}

/// Fetch the ABR record for an exact 9-digit ACN (`AcnDetails.aspx`). The ABR
/// resolves the ACN to its parent ABN, so the payload parses through the same
/// [`parse::parse_abn_result`](super::parse::parse_abn_result) path as an ABN
/// hit. See [`fetch_abn`] for the `Ok(None)` / error contract.
pub(super) async fn fetch_acn(guid: &str, acn: &str) -> Result<Option<Value>> {
    let url = format!("{BASE_URL}/AcnDetails.aspx?acn={acn}&callback=cb&guid={guid}");
    fetch_jsonp(&url).await
}

/// Fuzzy-match an organisation or person name against the register
/// (`MatchingNames.aspx`), returning up to the API's ranked candidate set for
/// [`parse::parse_name_results`](super::parse::parse_name_results). Unlike the
/// ABN/ACN paths the name is free text, so it is URL-encoded before
/// interpolation. See [`fetch_abn`] for the `Ok(None)` / error contract.
pub(super) async fn fetch_name(guid: &str, name: &str) -> Result<Option<Value>> {
    let encoded = crate::util::http::urlencode(name);
    let url = format!("{BASE_URL}/MatchingNames.aspx?name={encoded}&callback=cb&guid={guid}");
    fetch_jsonp(&url).await
}

/// Fetch `url` via the system `curl`, returning `(body, http_status,
/// retry_after_header)`.
///
/// The ABR API blocks default reqwest-style clients, so the lookup shells out
/// to `curl` with a mobile UA and browser-like Accept headers (the same
/// pattern the other scraping modules use). `-D -` dumps the response headers
/// to stdout ahead of the body (so a real `Retry-After` on a 429 is readable
/// at all — previously only the status code was captured, not headers, so a
/// 429 always used a hardcoded 5s sleep regardless of what the server asked
/// for); `-w "\n%{http_code}"` appends the status as a trailing line.
/// [`fetch_jsonp`] splits the combined output back into headers/body/status.
/// Honours `HUNTSMAN_SEARCH_PROXY` and kills the child on drop. `None` when
/// curl can't be spawned, the outer tokio timeout (`timeout_ms + 2000`)
/// fires, or stdout is not UTF-8 — every failure mode degrades to "no
/// signal".
async fn curl_with_status(url: &str, timeout_ms: u64) -> Option<(String, u16, Option<String>)> {
    let secs = (timeout_ms / 1000).max(3).to_string();
    let mut cmd = Command::new("curl");
    cmd.args([
        "-s",
        "--max-time",
        &secs,
        "-A",
        crate::util::curl::UA_MOBILE,
        "-H",
        "Accept: text/html,application/xhtml+xml,application/json",
        "-H",
        "Accept-Language: en-US,en;q=0.9",
        "-D",
        "-",
        "-w",
        "\n%{http_code}",
        "-L",
    ]);
    // Single-sourced SSRF/OOM hardening (proto/proto-redir/max-redirs +
    // `--max-filesize` 32 MiB), so a hostile/huge ABR response can't exhaust a
    // low-RAM Termux device's memory — the same cap `curl_exec`/`curl_client`
    // already apply. Must precede the `--` terminator below (after `--`, curl
    // treats every token as a URL).
    cmd.args(crate::util::curl::FETCH_HARDENING_ARGS);

    if let Ok(proxy) = std::env::var("HUNTSMAN_SEARCH_PROXY")
        && !proxy.is_empty()
    {
        cmd.args(["-x", &proxy]);
    }

    // The `--` end-of-options terminator and the URL come LAST, after every
    // option (hardening + optional proxy), so none is mis-parsed as a URL.
    cmd.args(["--", url]);

    cmd.kill_on_drop(true);

    let output = tokio::time::timeout(Duration::from_millis(timeout_ms + 2000), cmd.output())
        .await
        .ok()?
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let raw = String::from_utf8(output.stdout).ok()?;
    let (headers_and_body, code_str) = raw.rsplit_once('\n')?;
    let code: u16 = code_str.trim().parse().unwrap_or(0);
    let (body, retry_after) = split_curl_headers(headers_and_body);
    Some((body, code, retry_after))
}

/// Split `-D -`'s combined header+body stdout into the real response body
/// and, if present, the final response's `Retry-After` header value.
///
/// With `-L` (follow redirects), curl dumps ONE header block per hop, so the
/// text can contain several `HTTP/…` status lines before the body — only the
/// LAST block belongs to the response actually returned; earlier hops'
/// headers are deliberately ignored. Falls back to treating the whole input
/// as body (no Retry-After) if no header block is found at all, so a
/// malformed/absent header dump degrades to the pre-header-capture
/// behaviour rather than losing the body.
pub(super) fn split_curl_headers(headers_and_body: &str) -> (String, Option<String>) {
    let Some(status_line_idx) = headers_and_body
        .rmatch_indices("HTTP/")
        .map(|(i, _)| i)
        .next()
    else {
        return (headers_and_body.to_string(), None);
    };
    let from_status = &headers_and_body[status_line_idx..];
    let (block, body) = if let Some(i) = from_status.find("\r\n\r\n") {
        (&from_status[..i], &from_status[i + 4..])
    } else if let Some(i) = from_status.find("\n\n") {
        (&from_status[..i], &from_status[i + 2..])
    } else {
        (from_status, "")
    };
    let retry_after = block.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("retry-after")
            .then(|| value.trim().to_string())
    });
    (body.to_string(), retry_after)
}

/// Unwrap the ABR's JSONP envelope `cb({...})` to the inner JSON `Value`.
/// `None` when the body isn't wrapped in the expected `cb(` / `)` callback
/// padding or the inner text isn't valid JSON — so a truncated or HTML error
/// page (e.g. a WAF block) parses to "no data" rather than propagating.
pub(super) fn parse_jsonp_body(body: &str) -> Option<Value> {
    let json_str = body.strip_prefix("cb(").and_then(|s| s.strip_suffix(')'))?;
    serde_json::from_str(json_str).ok()
}

/// Drive one ABR JSONP request through its full status-handling policy.
///
/// On a `429` it honours a real server `Retry-After` when present (falling
/// back to a 5s default, clamped to 8s — this fetch runs inside a module
/// `process()` call the engine kills at its own timeout budget, so the wait
/// can't be unbounded) and retries once; a second `429` becomes a hard
/// module error (so the orchestrator can back off rather than silently
/// dropping data). `401`/`403` are surfaced as errors — they signal a bad or
/// unregistered GUID, which is operator-actionable, not a transient miss. Any
/// other `>= 400` degrades to `Ok(None)` ("no record"). A success body is
/// handed to [`parse_jsonp_body`]. A curl/transport failure ([`curl_with_status`]
/// returning `None`) is also `Ok(None)`.
async fn fetch_jsonp(url: &str) -> Result<Option<Value>> {
    let (body, status, retry_after) = match curl_with_status(url, 10_000).await {
        Some(triple) => triple,
        None => return Ok(None),
    };

    if status == 429 {
        let delay = crate::util::http::parse_retry_after_secs(retry_after.as_deref(), 5, 8);
        tokio::time::sleep(Duration::from_secs(delay)).await;
        let (body, status, _) = match curl_with_status(url, 10_000).await {
            Some(triple) => triple,
            None => return Ok(None),
        };
        if status == 429 {
            return Err(Error::module(SRC, "rate-limited (429) after retry"));
        }
        if status == 401 || status == 403 {
            return Err(Error::module(
                SRC,
                format!("HTTP {status}: unauthorized or forbidden"),
            ));
        }
        if status >= 400 {
            return Ok(None);
        }
        return Ok(parse_jsonp_body(&body));
    }

    if status == 401 || status == 403 {
        return Err(Error::module(
            SRC,
            format!("HTTP {status}: unauthorized or forbidden"),
        ));
    }

    if status >= 400 {
        return Ok(None);
    }

    Ok(parse_jsonp_body(&body))
}
