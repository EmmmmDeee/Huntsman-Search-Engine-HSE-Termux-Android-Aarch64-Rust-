//! Typed errors for the HIBP library client.

use std::time::Duration;

use crate::source_outcome::SourceOutcomeKind;

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
    /// Transport failure: the request was sent (or attempted) but no response came back.
    #[error("hibp: transport error: {message}")]
    Transport {
        /// What failed, without the URL, the identifier or any secret.
        message: String,
        /// The cause the fetch observed (DNS, connect, TLS, a timeout).
        kind: SourceOutcomeKind,
    },
    /// The guarded egress refused the request before it was sent: the policy dropped every address
    /// of the destination, or the endpoint URL could not be parsed into a sendable https request.
    /// Nothing reached the network, so it says nothing about the identifier.
    #[error("hibp: request refused before sending")]
    Refused,
    /// A 2xx that is not an API answer: a challenge page served in its place.
    #[error("hibp: response is not an API answer ({0:?})")]
    NotAnAnswer(SourceOutcomeKind),
    /// The body did not decode as the documented shape.
    #[error("hibp: could not decode response: {0}")]
    Decode(String),
    /// OAuth flow failure.
    #[error("hibp oauth: {0}")]
    OAuth(String),
}

impl HibpError {
    /// The HTTP status behind the failure, when there was one.
    #[must_use]
    pub const fn http_status(&self) -> Option<u16> {
        match self {
            Self::BadRequest(_) => Some(400),
            Self::Unauthorized(_) => Some(401),
            Self::Forbidden(_) => Some(403),
            Self::RateLimited { .. } => Some(429),
            Self::Server { status, .. } | Self::UnexpectedStatus { status, .. } => Some(*status),
            _ => None,
        }
    }
}

impl From<HibpError> for crate::error::Error {
    fn from(e: HibpError) -> Self {
        Self::Network(e.to_string())
    }
}
