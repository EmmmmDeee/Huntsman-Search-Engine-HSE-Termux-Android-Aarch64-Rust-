//! The crate-wide error type and `Result` alias.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("storage: {0}")]
    Storage(#[from] rusqlite::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    /// A transport/`reqwest` failure, carrying an **already-URL-stripped**
    /// message (see the `From<reqwest::Error>` impl below). Deliberately NOT
    /// `#[from]` a live `reqwest::Error`: that error's Display embeds the request
    /// URL, and the redaction happens in the conversion instead so the stored
    /// value can never leak.
    #[error("http: {0}")]
    Http(String),
    #[error("invalid target: {0}")]
    InvalidTarget(String),
    #[error("missing key: {0}")]
    MissingKey(String),
    #[error("[{module}] {message}")]
    Module { module: String, message: String },
    /// A transient rate-limit response (a burst throttle, NOT exhausted
    /// quota/credits) from a paid API client — distinct so a retry loop can
    /// back off and retry (`util::backoff::BackoffPolicy`) instead of
    /// treating it as a hard failure or a permanent quota-exhausted latch.
    /// Diagnosed against a real bug: `util::see_know`/`util::oathnet`
    /// previously classified a rate-limit response identically to true daily
    /// quota exhaustion, silently abandoning the provider for the rest of
    /// the scan with zero backoff.
    #[error("rate limited: {0}")]
    RateLimited(String),
    #[error("{0}")]
    Other(String),
}

impl Error {
    /// Construct a [`Error::Module`] error attributed to a named module — the form
    /// a module returns so a failure is reported as `[module] message`, naming the
    /// source rather than a bare string.
    pub fn module(module: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Module {
            module: module.into(),
            message: message.into(),
        }
    }
}

impl From<reqwest::Error> for Error {
    /// Convert a `reqwest` transport error into a crate [`enum@Error`],
    /// **stripping the request URL first**.
    ///
    /// reqwest 0.12's `Error` Display appends `for url (<url>)`, and HSE's
    /// request URLs carry the upstream API key and the target's PII in their
    /// query string (`?apikey=…&q=user@example.com`; e.g. `shodan`, `hunter_io`,
    /// `hlr_cnam`, `cell_intel`). This crate error's Display reaches operator-
    /// observable sinks — the `ModuleError` SSE event and persisted dossier
    /// (`core::engine::dispatch`), plus the downloadable verbose log
    /// (`/api/v1/logs`) — so a bare `?` on a reqwest call inside a `Result`
    /// function would otherwise route that secret straight there.
    ///
    /// Redacting in the conversion makes the safe path the **default**: even
    /// code that does not go through [`crate::util::http`]'s `send_tagged` /
    /// `redact_credentials` helpers (which strip the URL the same way) cannot
    /// leak a credential via `?`. `without_url()` consumes the error, so the
    /// redacted message is stored rather than the live error — dropping the
    /// typed source chain is the deliberate trade for a leak-proof Display.
    fn from(e: reqwest::Error) -> Self {
        Error::Http(e.without_url().to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
