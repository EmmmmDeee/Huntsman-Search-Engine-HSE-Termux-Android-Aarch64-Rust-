//! Client for the `DeHashed` v2 search endpoint.
//!
//! One call is one exact-match search for one identifier, declared with a
//! [`Purpose`]. The endpoint is fixed to `https://api.dehashed.com`: there is
//! no base-URL override in production, so a configuration value cannot send
//! the API key elsewhere. Redirects are not followed.
//!
//! | Method | Path | Auth |
//! | --- | --- | --- |
//! | [`DehashedClient::search`] | `POST /v2/search` | `Dehashed-Api-Key` header |
//!
//! Errors never carry the queried identifier or any response body text, so a
//! failure cannot write personal data into a log line.

use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;
use thiserror::Error;

use super::query::{Purpose, Selector};
use super::types::{Entry, SearchResponse};
use crate::fetch::{FetchOptions, fetch};
use crate::hibp::rate_limit::{DEFAULT_REQUESTS_PER_MINUTE, RateLimiter};
use crate::http::{Request, Response, Transport};
use crate::keys::{Keys, Secret};
use crate::sha256::{hex32, sha256};

/// The only origin the key is ever sent to.
pub const DEHASHED_API_BASE: &str = "https://api.dehashed.com/v2";
/// Header that carries the API key. Redacted in `Debug` output by the HTTP layer.
pub const API_KEY_HEADER: &str = "Dehashed-Api-Key";
/// Environment variable holding the API key.
pub const API_KEY_ENV: &str = crate::environment::DEHASHED_KEY_ENV;
/// Results per page used when the caller does not choose.
pub const DEFAULT_PAGE_SIZE: u32 = 10;
/// Largest page this client will request. Bounds one call's output.
pub const MAX_PAGE_SIZE: u32 = 100;
/// Largest page number this client will request.
pub const MAX_PAGE: u32 = 1_000;

#[derive(Debug, Error)]
pub enum DehashedError {
    #[error("dehashed: invalid query: {0}")]
    Query(#[from] super::query::QueryError),
    #[error("dehashed: no API key (set {API_KEY_ENV} in ~/.huntsman.env or the environment, or ~/.config/dehashed/api_key)")]
    MissingKey,
    #[error(
        "dehashed: the key file was refused: it must be a regular file (not a symlink) owned by you with mode 0600"
    )]
    KeyFilePermissions,
    #[error("dehashed: size must be between 1 and {MAX_PAGE_SIZE}, got {0}")]
    InvalidSize(u32),
    #[error("dehashed: page must be between 1 and {MAX_PAGE}, got {0}")]
    InvalidPage(u32),
    #[error("dehashed: unauthorised (HTTP 401): the key was rejected")]
    Unauthorized,
    #[error("dehashed: forbidden (HTTP 403): the key's plan does not allow this search")]
    Forbidden,
    #[error("dehashed: bad request (HTTP 400)")]
    BadRequest,
    #[error("dehashed: rate limited (HTTP 429), retry after {}", describe_retry(*.retry_after))]
    RateLimited { retry_after: Option<Duration> },
    #[error("dehashed: server error (HTTP {0})")]
    Server(u16),
    #[error("dehashed: unexpected HTTP {0}")]
    Unexpected(u16),
    #[error("dehashed: transport error: request failed")]
    Transport,
    #[error("dehashed: could not decode response: {0}")]
    Decode(String),
}

fn describe_retry(retry_after: Option<Duration>) -> String {
    retry_after.map_or_else(|| "unknown".into(), |d| format!("{}s", d.as_secs()))
}

/// One search. `purpose` is required by construction: there is no way to
/// search without declaring why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchRequest {
    pub selector: Selector,
    pub purpose: Purpose,
    pub size: u32,
    pub page: u32,
}

impl SearchRequest {
    /// A first-page search with the default page size.
    #[must_use]
    pub const fn new(selector: Selector, purpose: Purpose) -> Self {
        Self {
            selector,
            purpose,
            size: DEFAULT_PAGE_SIZE,
            page: 1,
        }
    }

    /// Check bounds that the request body depends on.
    ///
    /// # Errors
    /// [`DehashedError::InvalidSize`] or [`DehashedError::InvalidPage`].
    pub fn validate(&self) -> Result<(), DehashedError> {
        if !(1..=MAX_PAGE_SIZE).contains(&self.size) {
            return Err(DehashedError::InvalidSize(self.size));
        }
        if !(1..=MAX_PAGE).contains(&self.page) {
            return Err(DehashedError::InvalidPage(self.page));
        }
        Ok(())
    }
}

/// The parsed result of one search, with the request's audit fields.
#[derive(Clone, PartialEq, Eq)]
pub struct SearchOutcome {
    pub query: String,
    pub purpose: Purpose,
    pub page: u32,
    pub size: u32,
    pub total: Option<u64>,
    /// SHA-256 of the raw response body, for the audit receipt.
    pub response_sha256: String,
    pub entries: Vec<Entry>,
}

impl fmt::Debug for SearchOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SearchOutcome")
            .field("purpose", &self.purpose)
            .field("page", &self.page)
            .field("size", &self.size)
            .field("total", &self.total)
            .field("entries", &self.entries.len())
            .finish_non_exhaustive()
    }
}

#[derive(Serialize)]
struct SearchBody<'a> {
    query: &'a str,
    page: u32,
    size: u32,
    de_dupe: bool,
    regex: bool,
    wildcard: bool,
}

/// The `DeHashed` client. Cheap to clone; clones share one rate limiter.
#[derive(Clone)]
pub struct DehashedClient {
    http: Arc<dyn Transport + Send + Sync>,
    key: Secret,
    limiter: Arc<Mutex<RateLimiter>>,
}

impl fmt::Debug for DehashedClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DehashedClient").finish_non_exhaustive()
    }
}

impl DehashedClient {
    /// A client over `http` authenticating with `key`, limited to the default
    /// requests-per-minute budget.
    #[must_use]
    pub fn new(http: Arc<dyn Transport + Send + Sync>, key: Secret) -> Self {
        Self::with_limiter(
            http,
            key,
            RateLimiter::per_minute(DEFAULT_REQUESTS_PER_MINUTE),
        )
    }

    /// A client with an explicit limiter (used by tests and callers that
    /// share a budget across clients).
    #[must_use]
    pub fn with_limiter(
        http: Arc<dyn Transport + Send + Sync>,
        key: Secret,
        limiter: RateLimiter,
    ) -> Self {
        Self {
            http,
            key,
            limiter: Arc::new(Mutex::new(limiter)),
        }
    }

    /// Run one exact-match search.
    ///
    /// # Errors
    /// Validation errors before any request, then transport, status and
    /// decode errors, each named by [`DehashedError`].
    pub fn search(&self, request: &SearchRequest) -> Result<SearchOutcome, DehashedError> {
        request.validate()?;
        let query = request.selector.query();
        let body = serde_json::to_vec(&SearchBody {
            query: &query,
            page: request.page,
            size: request.size,
            de_dupe: true,
            regex: false,
            wildcard: false,
        })
        .map_err(|_| DehashedError::Decode("could not encode request".into()))?;

        // A poisoned limiter still holds valid state; recover it rather than
        // dropping the budget guarantee.
        self.limiter
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .acquire();

        let http_request = Request::post(format!("{DEHASHED_API_BASE}/search"), body)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .header(API_KEY_HEADER, self.key.expose());
        let response = send(self.http.as_ref(), http_request)?;
        let response_sha256 = hex32(&sha256(&response.body));
        let parsed = decode(&response)?;

        Ok(SearchOutcome {
            query,
            purpose: request.purpose,
            page: request.page,
            size: request.size,
            total: parsed.total,
            response_sha256,
            entries: parsed.entries,
        })
    }
}

fn send(http: &dyn Transport, request: Request) -> Result<Response, DehashedError> {
    let result = fetch(
        http,
        request,
        None,
        &FetchOptions::no_redirects(),
        "dehashed",
        0,
    )
    .map_err(|_| DehashedError::Transport)?;
    let response = result.response.ok_or(DehashedError::Transport)?;
    if response.truncated {
        return Err(DehashedError::Decode("response exceeds body limit".into()));
    }
    Ok(response)
}

fn decode(response: &Response) -> Result<SearchResponse, DehashedError> {
    match response.status {
        200 => serde_json::from_slice(&response.body).map_err(|_| {
            // The body is deliberately not echoed: it holds personal data.
            DehashedError::Decode("unexpected response shape".into())
        }),
        400 => Err(DehashedError::BadRequest),
        401 => Err(DehashedError::Unauthorized),
        403 => Err(DehashedError::Forbidden),
        429 => Err(DehashedError::RateLimited {
            retry_after: response
                .header_value("retry-after")
                .and_then(|v| v.trim().parse::<u64>().ok())
                .map(Duration::from_secs),
        }),
        500..=599 => Err(DehashedError::Server(response.status)),
        other => Err(DehashedError::Unexpected(other)),
    }
}

/// Resolve a provider credential from the shared lookup keys first, then from the
/// legacy private DeHashed key file. The caller supplies `Keys::for_lookup` so
/// `~/.huntsman.env` and individual environment slots use the same precedence
/// as every other provider. No secret is printed or exposed in diagnostics.
///
/// # Errors
/// The same errors as [`key_from_environment`] when the shared keys contain
/// no DeHashed credential.
pub fn key_from_sources(keys: &Keys) -> Result<Secret, DehashedError> {
    keys.get(API_KEY_ENV)
        .map_or_else(key_from_environment, Ok)
}

/// Load the API key from [`API_KEY_ENV`], then from `~/.config/dehashed/api_key`.
///
/// The file must be private (no group or other permission bits) on Unix.
/// A file that exists but is readable by others is refused, not used.
///
/// # Errors
/// [`DehashedError::MissingKey`] when neither source holds a valid key, or
/// [`DehashedError::KeyFilePermissions`] when the file is too open.
pub fn key_from_environment() -> Result<Secret, DehashedError> {
    if let Some(raw) = crate::environment::variable(API_KEY_ENV) {
        if let Ok(secret) = Secret::new(raw) {
            return Ok(secret);
        }
    }
    let Some(home) = crate::environment::home() else {
        return Err(DehashedError::MissingKey);
    };
    let path = std::path::PathBuf::from(home)
        .join(".config")
        .join("dehashed")
        .join("api_key");
    let bytes = match crate::keys::read_private_file(&path, 4096) {
        Ok(Some(Ok(bytes))) => bytes,
        Ok(Some(Err(_refusal))) => return Err(DehashedError::KeyFilePermissions),
        Ok(None) | Err(_) => return Err(DehashedError::MissingKey),
    };
    let raw = String::from_utf8(bytes).map_err(|_| DehashedError::MissingKey)?;
    Secret::new(raw).map_err(|_| DehashedError::MissingKey)
}
