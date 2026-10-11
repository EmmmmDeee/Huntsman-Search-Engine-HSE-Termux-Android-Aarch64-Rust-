//! Typed source-execution outcomes. From refactor overlay feef60a (P2).
//!
//! This module makes the failure layer explicit so "HTTP 200", "parser ran",
//! "zero rows", and "verified finding" can no longer collapse into one generic
//! success/failure bit.  It is deliberately transport/provider agnostic: modules
//! may refine an outcome after their provider contract validates the response.
//! Body-aware classification reuses `classify`: a challenge page is `BotWaf`, never auth.

use serde::{Deserialize, Serialize};

use crate::classify::is_challenge;

/// Causal outcome of one provider execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceOutcomeKind {
    Success,
    ValidZero,
    AuthRequired,
    AuthRejected,
    EntitlementDenied,
    QuotaExhausted,
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
    fn new(
        module: impl Into<String>,
        kind: SourceOutcomeKind,
        observed_at_unix: u64,
        found: usize,
    ) -> Self {
        Self {
            module: module.into(),
            kind,
            observed_at_unix,
            http_status: None,
            found: Some(found),
            retry_after_secs: None,
            detail: None,
        }
    }

    /// Rows were parsed. Zero rows here is `Inconclusive`: an empty parse is not proof
    /// of absence until the provider contract says so through [`Self::valid_zero`].
    #[must_use]
    pub fn success(module: impl Into<String>, observed_at_unix: u64, found: usize) -> Self {
        let kind = if found == 0 {
            SourceOutcomeKind::Inconclusive
        } else {
            SourceOutcomeKind::Success
        };
        Self::new(module, kind, observed_at_unix, found)
    }

    /// The provider contract validated that the query executed and genuinely matched nothing.
    #[must_use]
    pub fn valid_zero(module: impl Into<String>, observed_at_unix: u64) -> Self {
        Self::new(module, SourceOutcomeKind::ValidZero, observed_at_unix, 0)
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
        SourceOutcomeKind::QuotaExhausted
        | SourceOutcomeKind::RateLimited
        | SourceOutcomeKind::BotWaf => SourceHealthAction::Backoff,
        SourceOutcomeKind::DnsFailure
        | SourceOutcomeKind::ConnectFailure
        | SourceOutcomeKind::TtfbTimeout
        | SourceOutcomeKind::BodyTimeout
        | SourceOutcomeKind::Upstream5xx
        | SourceOutcomeKind::Inconclusive => SourceHealthAction::Retry,
        SourceOutcomeKind::EntitlementDenied
        | SourceOutcomeKind::TlsFailure
        | SourceOutcomeKind::Upstream4xx => SourceHealthAction::Investigate,
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

/// Status-only coarse mapping, used when no body is available. A 2xx is
/// `Inconclusive`: HTTP success is not evidence the query executed. A bare 403 is
/// `Upstream4xx` (investigate): without the body it may be a WAF, not an auth refusal.
#[must_use]
pub const fn classify_http_status(status: u16) -> SourceOutcomeKind {
    match status {
        401 => SourceOutcomeKind::AuthRequired,
        408 => SourceOutcomeKind::TtfbTimeout,
        429 => SourceOutcomeKind::RateLimited,
        300..=399 => SourceOutcomeKind::RedirectChanged,
        400..=499 => SourceOutcomeKind::Upstream4xx,
        500..=599 => SourceOutcomeKind::Upstream5xx,
        200..=299 => SourceOutcomeKind::Inconclusive,
        _ => SourceOutcomeKind::ProtocolDrift,
    }
}

/// Status plus body. 429 beats a vendor string. A challenge page is `BotWaf` at any
/// status, so a 403 or 200 challenge is never `AuthRejected` or `Inconclusive`.
/// A 403 without a challenge signature is `AuthRejected`.
#[must_use]
pub fn classify_fetch(status: u16, body: &str) -> SourceOutcomeKind {
    if status == 429 {
        SourceOutcomeKind::RateLimited
    } else if is_challenge(body) {
        SourceOutcomeKind::BotWaf
    } else if status == 403 {
        SourceOutcomeKind::AuthRejected
    } else {
        classify_http_status(status)
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
        assert_eq!(
            classify_fetch(403, "forbidden: key revoked"),
            SourceOutcomeKind::AuthRejected
        );
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
        let accepted = SourceExecutionOutcome::valid_zero("fixture", 1);
        assert_eq!(accepted.kind, SourceOutcomeKind::ValidZero);
        assert!(accepted.kind.is_accepted());

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

    #[test]
    fn falsify_unvalidated_zero_is_not_accepted() {
        assert!(
            !SourceExecutionOutcome::success("m", 1, 0)
                .kind
                .is_accepted()
        );
    }

    #[test]
    fn falsify_challenge_403_does_not_demand_credentials() {
        let status_only = recommended_action(classify_http_status(403));
        assert_ne!(
            status_only,
            SourceHealthAction::RequireCredential,
            "a WAF page is not an auth failure"
        );
        let wall = classify_fetch(403, "<html>checking your browser cloudflare</html>");
        assert_eq!(wall, SourceOutcomeKind::BotWaf);
        assert_eq!(recommended_action(wall), SourceHealthAction::Backoff);
        assert_eq!(
            classify_fetch(200, "<html>just a moment cloudflare</html>"),
            SourceOutcomeKind::BotWaf
        );
        assert_eq!(
            classify_fetch(429, "challenges.cloudflare.com"),
            SourceOutcomeKind::RateLimited
        );
    }

    #[test]
    fn agrees_with_fetch_classifier_on_walls_and_throttles() {
        use crate::classify::classify_response;
        let bodies = [
            "<html>just a moment cloudflare</html>",
            "plain text",
            r#"{"u":"https://challenges.cloudflare.com/x"}"#,
        ];
        for status in [200, 401, 403, 404, 429, 503] {
            for body in bodies {
                let fetch = classify_response(status, body);
                let kind = classify_fetch(status, body);
                assert_eq!(
                    fetch.is_wall(),
                    kind == SourceOutcomeKind::BotWaf,
                    "{status} {body}"
                );
                assert_eq!(
                    fetch.is_throttle(),
                    kind == SourceOutcomeKind::RateLimited,
                    "{status} {body}"
                );
                assert!(
                    !kind.is_accepted(),
                    "a fetch alone is never accepted: {status} {body}"
                );
            }
        }
    }
}
