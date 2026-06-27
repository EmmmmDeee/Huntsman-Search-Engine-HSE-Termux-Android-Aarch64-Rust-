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

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
