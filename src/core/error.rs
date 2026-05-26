//! Crate-wide error type. Modules raise `Error::module(name, msg)` for
//! API-specific failures; everything else uses `From` conversions.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("storage: {0}")]
    Storage(#[from] rusqlite::Error),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("http: {0}")]
    Http(#[from] reqwest::Error),

    #[error("invalid target: {0}")]
    InvalidTarget(String),

    #[error("missing key: {0}")]
    MissingKey(String),

    #[error("[{module}] {message}")]
    Module { module: String, message: String },

    #[error("{0}")]
    Other(String),
}

impl Error {
    /// Convenience constructor for module-specific errors.
    pub fn module(module: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Module {
            module: module.into(),
            message: message.into(),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_module_constructor() {
        let e = Error::module("dns_resolver", "connection refused");
        let s = e.to_string();
        assert!(s.contains("dns_resolver"));
        assert!(s.contains("connection refused"));
    }

    #[test]
    fn error_missing_key_display() {
        let e = Error::MissingKey("HUNTSMAN_SHODAN_KEY".into());
        assert!(e.to_string().contains("HUNTSMAN_SHODAN_KEY"));
    }

    #[test]
    fn error_invalid_target_display() {
        let e = Error::InvalidTarget("bad kind".into());
        assert!(e.to_string().contains("bad kind"));
    }

    #[test]
    fn error_other_display() {
        let e = Error::Other("something went wrong".into());
        assert_eq!(e.to_string(), "something went wrong");
    }

    #[test]
    fn error_from_json() {
        let bad = serde_json::from_str::<serde_json::Value>("not json");
        let e: Error = bad.unwrap_err().into();
        assert!(e.to_string().contains("json"));
    }
}
