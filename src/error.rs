//! Library errors. No fail-open path.
//!
//! Transport outcomes stay in `SourceOutcomeKind`. This type is only for a refusal
//! or a broken local contract. Display text is part of the contract.

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    /// A required text field was empty after trimming.
    #[error("missing field: {0}")]
    MissingField(String),
    /// A close or stop was refused because a gap or a non-hash tip remained.
    #[error("terminate refused: {0}")]
    TerminateRefused(String),
    /// The input failed a local contract. This is not a network outcome.
    #[error("invalid input: {0}")]
    Invalid(String),
    /// Local persistence failed. The message must not contain a secret.
    #[error("store: {0}")]
    Store(String),
    /// A request was refused before or during transport (bad URL, egress policy,
    /// redirect loop). Transport *outcomes* such as a timeout are not errors: they
    /// are `SourceOutcomeKind` values on a fetch result.
    #[error("network: {0}")]
    Network(String),
}

impl Error {
    /// Refuse a blank required field.
    #[must_use]
    pub fn missing_field(name: impl Into<String>) -> Self {
        Self::MissingField(name.into())
    }

    /// Refuse termination.
    #[must_use]
    pub fn terminate_refused(reason: impl Into<String>) -> Self {
        Self::TerminateRefused(reason.into())
    }

    /// Reject input that fails a local contract.
    #[must_use]
    pub fn invalid(reason: impl Into<String>) -> Self {
        Self::Invalid(reason.into())
    }

    /// Record a local store failure.
    #[must_use]
    pub fn store(reason: impl Into<String>) -> Self {
        Self::Store(reason.into())
    }

    /// Refuse a request before or during transport.
    #[must_use]
    pub fn network(reason: impl Into<String>) -> Self {
        Self::Network(reason.into())
    }

    /// True when this is a local contract failure, not a transport refusal.
    #[must_use]
    pub const fn is_local_contract(&self) -> bool {
        matches!(self, Self::MissingField(_) | Self::Invalid(_) | Self::TerminateRefused(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_text_is_stable() {
        assert_eq!(
            Error::missing_field("seed").to_string(),
            "missing field: seed"
        );
        assert_eq!(
            Error::terminate_refused("open gap").to_string(),
            "terminate refused: open gap"
        );
        assert_eq!(
            Error::invalid("meta-plan refused: inherited fallback").to_string(),
            "invalid input: meta-plan refused: inherited fallback"
        );
        assert_eq!(Error::store("io").to_string(), "store: io");
        assert_eq!(Error::network("egress-policy").to_string(), "network: egress-policy");
    }

    #[test]
    fn local_contract_is_not_a_network_refusal() {
        assert!(Error::invalid("x").is_local_contract());
        assert!(!Error::network("x").is_local_contract());
        assert!(!Error::store("x").is_local_contract());
    }
}
