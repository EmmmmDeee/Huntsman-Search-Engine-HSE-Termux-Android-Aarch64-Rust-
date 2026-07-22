//! HTTP error types for See-Know client

use std::fmt;

/// HTTP error kind
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpErrorKind {
    /// Connection failed
    ConnectionFailed,
    /// Timeout
    Timeout,
    /// 4xx client error
    ClientError,
    /// 5xx server error
    ServerError,
    /// Rate limited (429)
    RateLimited,
    /// Invalid API key (401)
    Unauthorized,
    /// Request canceled
    Canceled,
}

/// HTTP error with detailed context
#[derive(Debug, Clone)]
pub struct HttpError {
    pub kind: HttpErrorKind,
    pub status: Option<u16>,
    pub message: String,
    pub retryable: bool,
}

impl HttpError {
    pub fn new(kind: HttpErrorKind, message: impl Into<String>) -> Self {
        let retryable = matches!(kind, HttpErrorKind::ServerError | HttpErrorKind::RateLimited);
        Self {
            kind,
            status: None,
            message: message.into(),
            retryable,
        }
    }

    pub fn with_status(mut self, status: u16) -> Self {
        self.status = Some(status);
        self
    }
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.message)
    }
}

impl std::error::Error for HttpError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_retryable() {
        let err = HttpError::new(HttpErrorKind::RateLimited, "429 Too Many Requests");
        assert!(err.retryable);

        let err = HttpError::new(HttpErrorKind::ClientError, "400 Bad Request");
        assert!(!err.retryable);
    }
}
