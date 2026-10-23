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
    /// A supplied value (an address, handle or number) could not be canonicalised. The usage
    /// was correct, so the value is what to fix. The display text is the same as `Invalid`.
    #[error("invalid input: {0}")]
    InvalidValue(String),
    /// A required credential is absent or blank. Entry points exit 66 for it, as they do for a
    /// missing key elsewhere.
    #[error("missing credential: {0}")]
    MissingCredential(String),
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
    /// Reject input that fails a local contract.
    #[must_use]
    pub fn invalid(reason: impl Into<String>) -> Self {
        Self::Invalid(reason.into())
    }

    /// Reject a supplied value that cannot be canonicalised.
    #[must_use]
    pub fn invalid_value(reason: impl Into<String>) -> Self {
        Self::InvalidValue(reason.into())
    }

    /// Refuse an operation whose required credential is absent or blank.
    #[must_use]
    pub fn missing_credential(reason: impl Into<String>) -> Self {
        Self::MissingCredential(reason.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_text_is_stable() {
        assert_eq!(
            Error::MissingField("seed".into()).to_string(),
            "missing field: seed"
        );
        assert_eq!(
            Error::TerminateRefused("open gap".into()).to_string(),
            "terminate refused: open gap"
        );
        assert_eq!(
            Error::invalid("meta-plan refused: inherited fallback").to_string(),
            "invalid input: meta-plan refused: inherited fallback"
        );
        assert_eq!(
            Error::invalid_value("invalid email address").to_string(),
            "invalid input: invalid email address"
        );
        assert_eq!(
            Error::missing_credential("HSE_AUTH_TOKEN").to_string(),
            "missing credential: HSE_AUTH_TOKEN"
        );
        assert_eq!(Error::Store("io".into()).to_string(), "store: io");
        assert_eq!(
            Error::Network("egress-policy".into()).to_string(),
            "network: egress-policy"
        );
    }
}
