//! Typed source-execution outcomes.
//!
//! This module makes the failure layer explicit so "HTTP 200", "parser ran",
//! "zero rows", and "verified finding" can no longer collapse into one generic
//! success/failure bit.  It is deliberately transport/provider agnostic: modules
//! may refine an outcome after their provider contract validates the response.

use serde::{Deserialize, Serialize};

/// Causal outcome of one provider execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceOutcomeKind {
    Success,
    ValidZero,
    AuthRequired,
    AuthRejected,
    RateLimited,
    BotWaf,
    DnsFailure,
    ConnectFailure,
    TlsFailure,
    TtfbTimeout,
    BodyTimeout,
    Upstream4xx,
    Upstream5xx,
    RedirectChanged,
    ProtocolDrift,
    InteractionDrift,
    SchemaDrift,
    ParserDrift,
    SemanticDrift,
    ZeroYieldAnomaly,
    ConfirmedDead,
    Inconclusive,
}

impl SourceOutcomeKind {
    #[must_use]
    pub const fn is_accepted(self) -> bool {
        matches!(self, Self::Success | Self::ValidZero)
    }

    #[must_use]
    pub const fn is_auth(self) -> bool {
        matches!(self, Self::AuthRequired | Self::AuthRejected)
    }

    #[must_use]
    pub const fn is_contract_drift(self) -> bool {
        matches!(
            self,
            Self::RedirectChanged
                | Self::ProtocolDrift
                | Self::InteractionDrift
                | Self::SchemaDrift
                | Self::ParserDrift
                | Self::SemanticDrift
        )
    }

    #[must_use]
    pub const fn is_transport_failure(self) -> bool {
        matches!(
            self,
            Self::DnsFailure
                | Self::ConnectFailure
                | Self::TlsFailure
                | Self::TtfbTimeout
                | Self::BodyTimeout
        )
    }

    #[must_use]
    pub const fn normally_retryable(self) -> bool {
        matches!(
            self,
            Self::RateLimited
                | Self::DnsFailure
                | Self::ConnectFailure
                | Self::TtfbTimeout
                | Self::BodyTimeout
                | Self::Upstream5xx
                | Self::BotWaf
                | Self::Inconclusive
        )
    }
}

/// One observed execution result.  `detail` is diagnostic text, not evidence
/// that a target is present or absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceExecutionOutcome {
    pub module: String,
    pub kind: SourceOutcomeKind,
    pub observed_at_unix: u64,
    pub http_status: Option<u16>,
    pub found: Option<usize>,
    pub retry_after_secs: Option<u64>,
    pub detail: Option<String>,
}

impl SourceExecutionOutcome {
    #[must_use]
    pub fn success(module: impl Into<String>, observed_at_unix: u64, found: usize) -> Self {
        Self {
            module: module.into(),
            kind: if found == 0 {
                SourceOutcomeKind::ValidZero
            } else {
                SourceOutcomeKind::Success
            },
            observed_at_unix,
            http_status: None,
            found: Some(found),
            retry_after_secs: None,
            detail: None,
        }
    }

    #[must_use]
    pub fn with_http_status(mut self, status: u16) -> Self {
        self.http_status = Some(status);
        self
    }

    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    #[must_use]
    pub fn with_retry_after(mut self, seconds: u64) -> Self {
        self.retry_after_secs = Some(seconds);
        self
    }
}

/// Dispatch action derived from a causal source outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceHealthAction {
    Accept,
    Retry,
    Backoff,
    RequireCredential,
    Quarantine,
    RequireContractVerification,
    Investigate,
}

/// Conservative default policy. Provider-specific logic may be stricter, never
/// less truthful than the causal outcome itself.
#[must_use]
pub const fn recommended_action(kind: SourceOutcomeKind) -> SourceHealthAction {
    match kind {
        SourceOutcomeKind::Success | SourceOutcomeKind::ValidZero => SourceHealthAction::Accept,
        SourceOutcomeKind::AuthRequired | SourceOutcomeKind::AuthRejected => {
            SourceHealthAction::RequireCredential
        }
        SourceOutcomeKind::RateLimited | SourceOutcomeKind::BotWaf => SourceHealthAction::Backoff,
        SourceOutcomeKind::DnsFailure
        | SourceOutcomeKind::ConnectFailure
        | SourceOutcomeKind::TtfbTimeout
        | SourceOutcomeKind::BodyTimeout
        | SourceOutcomeKind::Upstream5xx
        | SourceOutcomeKind::Inconclusive => SourceHealthAction::Retry,
        SourceOutcomeKind::TlsFailure | SourceOutcomeKind::Upstream4xx => {
            SourceHealthAction::Investigate
        }
        SourceOutcomeKind::RedirectChanged
        | SourceOutcomeKind::ProtocolDrift
        | SourceOutcomeKind::InteractionDrift
        | SourceOutcomeKind::SchemaDrift
        | SourceOutcomeKind::ParserDrift
        | SourceOutcomeKind::SemanticDrift => SourceHealthAction::RequireContractVerification,
        SourceOutcomeKind::ZeroYieldAnomaly | SourceOutcomeKind::ConfirmedDead => {
            SourceHealthAction::Quarantine
        }
    }
}

/// Coarse mapping for generic HTTP transport before a provider contract refines
/// the result.  A 2xx is deliberately `Inconclusive`: an HTTP success is not
/// evidence that the query executed or the parser understood the response.
#[must_use]
pub const fn classify_http_status(status: u16) -> SourceOutcomeKind {
    match status {
        401 => SourceOutcomeKind::AuthRequired,
        403 => SourceOutcomeKind::AuthRejected,
        408 => SourceOutcomeKind::TtfbTimeout,
        429 => SourceOutcomeKind::RateLimited,
        300..=399 => SourceOutcomeKind::RedirectChanged,
        400..=499 => SourceOutcomeKind::Upstream4xx,
        500..=599 => SourceOutcomeKind::Upstream5xx,
        200..=299 => SourceOutcomeKind::Inconclusive,
        _ => SourceOutcomeKind::ProtocolDrift,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_200_never_means_verified_success_by_itself() {
        assert_eq!(classify_http_status(200), SourceOutcomeKind::Inconclusive);
    }

    #[test]
    fn auth_and_rate_limits_are_not_parser_drift() {
        assert_eq!(classify_http_status(401), SourceOutcomeKind::AuthRequired);
        assert_eq!(classify_http_status(403), SourceOutcomeKind::AuthRejected);
        assert_eq!(classify_http_status(429), SourceOutcomeKind::RateLimited);
    }

    #[test]
    fn contract_drift_requires_contract_verification() {
        for kind in [
            SourceOutcomeKind::RedirectChanged,
            SourceOutcomeKind::ProtocolDrift,
            SourceOutcomeKind::InteractionDrift,
            SourceOutcomeKind::SchemaDrift,
            SourceOutcomeKind::ParserDrift,
            SourceOutcomeKind::SemanticDrift,
        ] {
            assert!(kind.is_contract_drift());
            assert_eq!(
                recommended_action(kind),
                SourceHealthAction::RequireContractVerification
            );
        }
    }

    #[test]
    fn zero_is_only_accepted_when_the_provider_contract_says_valid_zero() {
        let accepted = SourceExecutionOutcome::success("fixture", 1, 0);
        assert_eq!(accepted.kind, SourceOutcomeKind::ValidZero);

        let anomaly = SourceExecutionOutcome {
            module: "fixture".into(),
            kind: SourceOutcomeKind::ZeroYieldAnomaly,
            observed_at_unix: 1,
            http_status: Some(200),
            found: Some(0),
            retry_after_secs: None,
            detail: None,
        };
        assert_eq!(
            recommended_action(anomaly.kind),
            SourceHealthAction::Quarantine
        );
    }
}
