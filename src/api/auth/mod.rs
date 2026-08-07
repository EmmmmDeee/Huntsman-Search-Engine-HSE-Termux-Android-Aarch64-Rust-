//! Bearer-token authentication for a **non-loopback** bind.
//!
//! # Why this exists
//!
//! Until this module, `hse serve --bind 0.0.0.0:8080` exposed the whole console
//! to the local network with **no authentication**. The only safeguard was a
//! startup `warn!`. That is a materially different exposure from "someone can
//! read my scan results":
//!
//!   * every scan's entities, relations and evidence — the subject's PII — was
//!     readable by any LAN peer;
//!   * `POST /api/v1/scans` and `/scan/auto` could be dispatched by anyone,
//!     burning the operator's paid API-key quota;
//!   * `radar` could be triggered, activating the **device's own** WiFi /
//!     Bluetooth / cell / GPS sensor sweep from off-device.
//!
//! The existing controls do not cover this. The per-handler
//! `peer.ip().is_loopback()` gate protects only the key/settings routes. CORS
//! blocks a *browser* from reading a cross-origin response, not a direct client.
//! `routes::enforce_csrf` blocks the drive-by-POST class, but its own doc notes
//! a CLI client simply sends `-H 'X-HSE-CSRF: 1'` — it is a cross-*site*
//! control, not an authentication one. The Host allowlist is applied to
//! loopback binds only.
//!
//! # Shape of the control
//!
//! Authentication is **bind-conditional**, mirroring how the Host allowlist is
//! applied (`routes::host_allowlist`):
//!
//!   * **loopback bind** (the `127.0.0.1:8080` default) — no token, no
//!     enforcement, byte-identical behaviour to before. The on-device Termux
//!     workflow, which is the primary target, is untouched: an operator who
//!     never leaves the default never sees a token.
//!   * **non-loopback bind** — a token is required on every request. The
//!     operator supplies one with `--auth-token` / `HSE_AUTH_TOKEN`, or HSE
//!     generates a 256-bit one and prints it once at startup together with a
//!     ready-to-open URL.
//!
//! Opting out is explicit and must be typed: `--allow-unauthenticated`. That
//! keeps the old behaviour reachable for a deliberately public read-only
//! deployment without making it the accident-prone default.
//!
//! # Credential presentation
//!
//! Four forms are accepted, so both browsers and scripts work without a
//! separate login page (which would need state, a form, and a CSRF dance):
//!
//! | Form | Used by |
//! |---|---|
//! | `Authorization: Bearer <token>` | `curl`, scripts, the standard |
//! | `X-HSE-Auth: <token>` | clients that cannot set `Authorization` |
//! | `Cookie: hse_auth=<token>` | the browser, after bootstrap |
//! | `?t=<token>` in the query | the browser's **first** navigation |
//!
//! The `?t=` form is the bootstrap: HSE answers it with a redirect to the same
//! path minus `t`, setting `hse_auth` as an `HttpOnly; SameSite=Strict` cookie.
//! The token therefore leaves the address bar (and the browser history, and any
//! `Referer`) after one hop, and every later request — including the SPA's
//! `fetch` calls and the SSE stream, which cannot set headers on
//! `EventSource` — carries the cookie automatically. `SameSite=Strict` means a
//! cross-site page cannot ride the cookie, and the existing `X-HSE-CSRF`
//! requirement still applies to mutating methods on top of it.
//!
//! # Comparison is constant-time
//!
//! Tokens are compared as SHA-256 digests through [`ct_eq`], never with `==` on
//! the raw strings. Digesting first makes the compared length constant
//! regardless of what the client sent, so neither the token's length nor its
//! matching prefix is observable through response timing.

use std::sync::Arc;

use axum::{
    body::Body,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use sha2::{Digest, Sha256};

use crate::core::error::{Error, Result};

/// Cookie name carrying the bootstrapped token.
const COOKIE: &str = "hse_auth";

/// Query parameter accepted for the one-shot browser bootstrap.
const QUERY_KEY: &str = "t";

/// Bytes of entropy in a generated token. 32 bytes = 256 bits, rendered as 64
/// hex characters — far beyond brute-force over a LAN, and still short enough
/// to retype from a phone screen onto a laptop if the operator must.
const TOKEN_BYTES: usize = 32;

/// A resolved bearer token, held only by the auth middleware.
///
/// Deliberately **not** placed on `AppState`: every handler receives that, and
/// the secret has no business being reachable from request handling. The
/// middleware closure captures this `Arc` the same way the Host allowlist
/// captures its set.
///
/// `Debug` is implemented by hand so the secret cannot reach a log line through
/// a derived formatter.
pub struct AuthToken {
    /// The SHA-256 of the token. The plaintext is kept only in `display`, and
    /// only so startup can print it once.
    digest: [u8; 32],
    /// The plaintext, for the single deliberate startup disclosure.
    display: String,
}

impl std::fmt::Debug for AuthToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthToken(<redacted>)")
    }
}

impl AuthToken {
    /// Wrap an operator-supplied token.
    pub fn new(token: String) -> Self {
        Self {
            digest: Sha256::digest(token.as_bytes()).into(),
            display: token,
        }
    }

    /// The plaintext token, for the one-time startup disclosure only.
    ///
    /// Every other read path must go through [`Self::matches`]. Nothing else in
    /// the tree calls this.
    pub fn reveal(&self) -> &str {
        &self.display
    }

    /// Constant-time check of a presented credential.
    pub fn matches(&self, presented: &str) -> bool {
        let got: [u8; 32] = Sha256::digest(presented.as_bytes()).into();
        ct_eq(&self.digest, &got)
    }
}

/// Constant-time byte-slice equality.
///
/// Accumulates the difference of every byte pair with `|=` and compares once at
/// the end, so the loop runs the full length whatever the inputs are and cannot
/// return early on the first mismatching byte. Callers pass SHA-256 digests, so
/// both slices are always 32 bytes; the length check is a correctness guard, not
/// a timing-visible branch on secret data.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Generate a fresh 256-bit token, hex-encoded.
///
/// Reads `/dev/urandom` directly rather than pulling in a RNG crate. That file
/// is present on Linux and on every Android/Termux device HSE targets, it is
/// the kernel CSPRNG (non-blocking after boot, which is long past by the time a
/// user runs `hse serve`), and using it keeps the dependency graph — which must
/// cross-compile to `aarch64-linux-android` — unchanged.
///
/// A short read is treated as failure rather than silently yielding a
/// low-entropy token.
pub fn generate_token() -> Result<String> {
    use std::io::Read;

    let mut buf = [0u8; TOKEN_BYTES];
    let mut f = std::fs::File::open("/dev/urandom").map_err(|e| {
        Error::Other(format!(
            "cannot open /dev/urandom to mint an auth token: {e}"
        ))
    })?;
    f.read_exact(&mut buf)
        .map_err(|e| Error::Other(format!("cannot read {TOKEN_BYTES} bytes of entropy: {e}")))?;
    Ok(hex::encode(buf))
}

/// Decide the auth posture for a bind.
///
/// Returns `Ok(None)` when no enforcement applies — a loopback bind, or an
/// explicit `--allow-unauthenticated` opt-out. Returns `Ok(Some(token))` when
/// the middleware must be installed.
///
/// `supplied` is the `--auth-token` / `HSE_AUTH_TOKEN` value. An empty or
/// whitespace-only value is rejected rather than silently accepted as a token
/// nobody can guess but everybody can send.
pub fn resolve(
    bind: &str,
    supplied: Option<String>,
    allow_unauthenticated: bool,
) -> Result<Option<AuthToken>> {
    if super::routes::is_loopback_bind(bind) {
        // The default path. A token supplied anyway is honoured — an operator
        // may want it for defence in depth behind a reverse proxy.
        return Ok(supplied.map(AuthToken::new));
    }
    if allow_unauthenticated {
        return Ok(None);
    }
    match supplied {
        Some(t) if t.trim().is_empty() => Err(Error::Other(
            "--auth-token / HSE_AUTH_TOKEN is empty. Supply a real token, or pass \
             --allow-unauthenticated to expose this bind deliberately."
                .to_string(),
        )),
        Some(t) => Ok(Some(AuthToken::new(t))),
        None => Ok(Some(AuthToken::new(generate_token()?))),
    }
}

/// Pull the presented credential out of a request, in precedence order.
///
/// Header forms win over the cookie so a script can override a stale cookie,
/// and the cookie wins over `?t=` so the bootstrap redirect is not re-run on
/// every navigation.
fn presented(req: &axum::extract::Request) -> Option<String> {
    let h = req.headers();

    if let Some(v) = h
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    {
        return Some(v.trim().to_string());
    }
    if let Some(v) = h.get("x-hse-auth").and_then(|v| v.to_str().ok()) {
        return Some(v.trim().to_string());
    }
    if let Some(v) = h
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(cookie_value)
    {
        return Some(v);
    }
    query_token(req.uri().query()?).map(|(t, _)| t)
}

/// Extract `hse_auth` from a `Cookie` header value.
///
/// Cookies are `;`-separated `name=value` pairs. A value is not URL-decoded:
/// the token is hex (or whatever the operator supplied) and is set by this
/// server verbatim.
fn cookie_value(raw: &str) -> Option<String> {
    raw.split(';')
        .filter_map(|pair| pair.split_once('='))
        .find(|(k, _)| k.trim() == COOKIE)
        .map(|(_, v)| v.trim().to_string())
}

/// Split a query string into the `t` token and the query with `t` removed.
///
/// The remainder is returned so the bootstrap redirect can preserve any other
/// parameters the operator's deep link carried.
fn query_token(query: &str) -> Option<(String, String)> {
    let mut token = None;
    let mut rest: Vec<&str> = Vec::new();
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        match pair.split_once('=') {
            Some((QUERY_KEY, v)) if token.is_none() => token = Some(v.to_string()),
            _ => rest.push(pair),
        }
    }
    token.map(|t| (t, rest.join("&")))
}

/// The `Set-Cookie` value that pins the bootstrapped token to this origin.
///
/// `HttpOnly` keeps it away from any script (including an injected one),
/// `SameSite=Strict` stops a cross-site page from riding it, and `Path=/`
/// covers the API, the SPA and `/static`. No `Secure`: HSE serves plain HTTP on
/// a LAN, and marking it `Secure` would make the browser drop it outright.
/// No `Max-Age` — it is a session cookie, gone when the browser closes.
fn set_cookie(token: &str) -> String {
    format!("{COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict")
}

/// Reject an unauthenticated request.
///
/// `WWW-Authenticate: Bearer` makes the 401 self-describing to a standard
/// client. The body names the two ways in, without echoing anything the client
/// sent (so a bad token is never reflected into a log or a proxy's history).
fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [
            (header::WWW_AUTHENTICATE, "Bearer"),
            (header::CONTENT_TYPE, "application/json"),
        ],
        r#"{"error":"authentication required — this bind is not loopback. Send 'Authorization: Bearer <token>', or open the URL printed at startup (it carries ?t=<token> once)."}"#,
    )
        .into_response()
}

/// Redirect a successful `?t=` bootstrap to the same path without the token,
/// setting the session cookie.
///
/// `303 See Other` (not 302) so the follow-up is always a `GET` regardless of
/// the original method — a bootstrap link is always a navigation.
fn bootstrap_redirect(path: &str, rest: &str, token: &str) -> Response {
    let location = if rest.is_empty() {
        path.to_string()
    } else {
        format!("{path}?{rest}")
    };
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(header::LOCATION, location)
        .header(header::SET_COOKIE, set_cookie(token))
        .body(Body::empty())
        .map_or_else(|_| unauthorized(), IntoResponse::into_response)
}

/// Require a valid token on every request.
///
/// Installed only for a non-loopback bind. `OPTIONS` is exempt: a CORS preflight
/// carries neither credentials nor side effects, and failing it would surface in
/// the browser as an opaque CORS error instead of the 401 that tells the
/// operator what is actually wrong.
pub async fn enforce_auth(
    token: Arc<AuthToken>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    if req.method() == axum::http::Method::OPTIONS {
        return next.run(req).await;
    }

    let Some(got) = presented(&req) else {
        return unauthorized();
    };
    if !token.matches(&got) {
        return unauthorized();
    }

    // A valid `?t=` that did NOT come from a header or cookie is the browser's
    // first navigation: strip it from the URL and pin the cookie instead.
    if req.headers().get(header::AUTHORIZATION).is_none()
        && req.headers().get("x-hse-auth").is_none()
        && !req
            .headers()
            .get(header::COOKIE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|c| cookie_value(c).is_some())
        && let Some((t, rest)) = req.uri().query().and_then(query_token)
    {
        return bootstrap_redirect(req.uri().path(), &rest, &t);
    }

    next.run(req).await
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
