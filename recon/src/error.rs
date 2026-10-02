//! Library errors. No fail-open path.

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("missing field: {0}")]
    MissingField(String),
    #[error("terminate refused: {0}")]
    TerminateRefused(String),
    #[error("invalid input: {0}")]
    Invalid(String),
    #[error("store: {0}")]
    Store(String),
}
