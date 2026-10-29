//! Opt-in, blocking HIBP v3 and OAuth clients. No scan automatically uses paid sources.
//! Passwords and account hashes are computed locally; tests use fake transports.
//! The binary reaches the client only through the explicit `hibp` command ([`cli`]).

pub mod cli;
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
use crate::source_outcome::SourceOutcomeKind;

/// One request through [`crate::fetch::fetch`], redirects off. A request the guarded egress
/// refused before sending is [`HibpError::Refused`] (fetch's `Err`); a request that was attempted
/// but got no response is [`HibpError::Transport`] carrying the fetch's cause; a 2xx challenge page
/// is [`HibpError::NotAnAnswer`]; any other status is the caller's to map, so a 404 "not found"
/// still reaches it. Nothing the transport said is kept, since it can name the request.
fn send(http: &dyn Transport, request: Request) -> Result<Response, HibpError> {
    send_with(http, request, None)
}

/// [`send`] with `credential`, which [`crate::fetch::fetch`] puts on the request only while it
/// goes to the credential's own origin.
fn send_with(
    http: &dyn Transport,
    request: Request,
    credential: Option<&crate::fetch::Credential>,
) -> Result<Response, HibpError> {
    let transport = |kind| HibpError::Transport {
        message: "request failed".into(),
        kind,
    };
    // `fetch` returns `Err` only when the request was refused before it was sent: the egress
    // policy blocked the destination, or the endpoint URL could not be parsed. Every request that
    // was actually attempted comes back as a `Fetched` — with its response, or with none and the
    // fetch's cause when there was no response (handled just below).
    let fetched = crate::fetch::fetch(
        http,
        request,
        credential,
        &crate::fetch::FetchOptions::no_redirects(),
        "hibp",
        crate::clock::unix_now(),
    )
    .map_err(|_| HibpError::Refused)?;
    let Some(response) = fetched.response else {
        return Err(transport(fetched.outcome.kind));
    };
    if response.truncated {
        return Err(HibpError::Decode("response exceeds body limit".into()));
    }
    if (200..300).contains(&response.status)
        && fetched.outcome.kind != SourceOutcomeKind::Inconclusive
    {
        return Err(HibpError::NotAnAnswer(fetched.outcome.kind));
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

#[cfg(test)]
mod tests;
