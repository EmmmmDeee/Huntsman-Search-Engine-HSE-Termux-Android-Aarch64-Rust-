//! Typed errors for the HIBP library client.

use std::time::Duration;

/// Everything the HIBP client can fail with. No variant ever carries an API
/// key or token: upstream bodies are redacted before they get here.
#[derive(Debug, thiserror::Error)]
pub enum HibpError {
    /// No key configured for an endpoint that needs one.
    #[error(
        "hibp: no API key for this keyed lookup (set HIBP_API_KEY, HUNTSMAN_HIBP_KEY or ~/.config/hibp/api_key)"
    )]
    MissingKey,
    /// 401: the key or token was rejected.
    #[error("hibp: unauthorised (HTTP 401): {0}")]
    Unauthorized(String),
    /// 403: forbidden (missing user agent, unverified domain, or plan tier).
    #[error("hibp: forbidden (HTTP 403): {0}")]
    Forbidden(String),
    /// The plan does not include this feature; checked client-side from
    /// `/subscription/status`, so no request to the gated endpoint was sent.
    #[error("hibp: plan '{plan}' does not include {feature}")]
    PlanNotEntitled {
        /// Plan name from the subscription status.
        plan: String,
        /// The missing entitlement.
        feature: &'static str,
    },
    /// 400: the request was malformed.
    #[error("hibp: bad request (HTTP 400): {0}")]
    BadRequest(String),
    /// 429 after the retry budget was spent.
    #[error("hibp: rate limited (HTTP 429), retry after {retry_after:?}")]
    RateLimited {
        /// The server's `retry-after`, when given.
        retry_after: Option<Duration>,
    },
    /// 5xx (503 is usually Cloudflare).
    #[error("hibp: server error (HTTP {status}): {body}")]
    Server {
        /// HTTP status.
        status: u16,
        /// Redacted, truncated body.
        body: String,
    },
    /// Any other unexpected status.
    #[error("hibp: unexpected HTTP {status}: {body}")]
    UnexpectedStatus {
        /// HTTP status.
        status: u16,
        /// Redacted, truncated body.
        body: String,
    },
    /// Invalid input rejected before any request (bad prefix, empty email…).
    #[error("hibp: invalid input: {0}")]
    InvalidInput(String),
    /// Transport failure.
    #[error("hibp: transport error: {0}")]
    Transport(String),
    /// The body did not decode as the documented shape.
    #[error("hibp: could not decode response: {0}")]
    Decode(String),
    /// OAuth flow failure.
    #[error("hibp oauth: {0}")]
    OAuth(String),
}

impl From<HibpError> for crate::error::Error {
    fn from(e: HibpError) -> Self {
        Self::Network(e.to_string())
    }
}
