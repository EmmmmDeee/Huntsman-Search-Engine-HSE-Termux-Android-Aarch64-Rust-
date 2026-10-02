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
    /// A request was refused before or during transport (bad URL, egress policy,
    /// redirect loop). Transport *outcomes* such as a timeout are not errors: they
    /// are `SourceOutcomeKind` values on a fetch result.
    #[error("network: {0}")]
    Network(String),
}
