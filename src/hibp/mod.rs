//! Opt-in, blocking HIBP v3 and OAuth clients. No scan automatically uses paid sources.
//! Passwords and account hashes are computed locally; tests use fake transports.

pub mod client;
pub mod error;
pub mod key;
mod md4;
pub mod oauth;
pub mod passwords;
pub mod rate_limit;
pub mod types;

pub use client::{Auth, HibpClient, HibpConfig};
pub use error::HibpError;
pub use key::{ApiKey, KeyLoader};

use crate::http::{Request, Response, Transport};

fn send(http: &dyn Transport, request: Request) -> Result<Response, HibpError> {
    let result = crate::fetch::fetch(
        http,
        request,
        None,
        &crate::fetch::FetchOptions::no_redirects(),
        "hibp",
        0,
    )
    .map_err(|_| HibpError::Transport("request failed".into()))?;
    let response = result
        .response
        .ok_or_else(|| HibpError::Transport("request failed".into()))?;
    if response.truncated {
        return Err(HibpError::Decode("response exceeds body limit".into()));
    }
    Ok(response)
}

fn trusted_url(url: &str) -> Result<(), HibpError> {
    let uri = crate::http::parse_http_uri(url)
        .map_err(|_| HibpError::InvalidInput("invalid HTTPS endpoint".into()))?;
    if uri.scheme_str() != Some("https")
        || uri.authority().is_none_or(|a| a.as_str().contains('@'))
        || uri.port_u16().is_some_and(|p| p != 443)
        || url.contains('#')
        || !matches!(
            uri.host(),
            Some("haveibeenpwned.com" | "api.pwnedpasswords.com")
        )
    {
        return Err(HibpError::InvalidInput("untrusted endpoint origin".into()));
    }
    Ok(())
}

fn encode(value: &str) -> String {
    let mut out = String::new();
    use std::fmt::Write;
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

#[cfg(test)]
mod tests;
