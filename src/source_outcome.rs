//! Typed source-execution outcomes. From refactor overlay feef60a (P2).
//!
//! This module makes the failure layer explicit so "HTTP 200", "parser ran",
//! "zero rows", and "verified finding" can no longer collapse into one generic
//! success/failure bit.  It is deliberately transport/provider agnostic: modules
//! may refine an outcome after their provider contract validates the response.
//! Body-aware classification reuses `classify`: a challenge page is `BotWaf`, never auth.

use serde::{Deserialize, Serialize};

use crate::classify::is_challenge_at;

/// Causal outcome of one provider execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceOutcomeKind {
    Success,
    ValidZero,
    AuthRequired,
    /// A keyed source that made no request because no key is configured for it. This is an
    /// expected state the operator can fix, not a failure: the outcome is kept whole, and a scan
    /// logs it as information rather than an error.
    NotConfigured,
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
    /// The wire label, as serde writes it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::ValidZero => "valid_zero",
            Self::AuthRequired => "auth_required",
            Self::NotConfigured => "not_configured",
            Self::AuthRejected => "auth_rejected",
            Self::EntitlementDenied => "entitlement_denied",
            Self::QuotaExhausted => "quota_exhausted",
            Self::RateLimited => "rate_limited",
            Self::BotWaf => "bot_waf",
            Self::DnsFailure => "dns_failure",
            Self::ConnectFailure => "connect_failure",
            Self::TlsFailure => "tls_failure",
            Self::TtfbTimeout => "ttfb_timeout",
            Self::BodyTimeout => "body_timeout",
            Self::Upstream4xx => "upstream4xx",
            Self::Upstream5xx => "upstream5xx",
            Self::RedirectChanged => "redirect_changed",
            Self::ProtocolDrift => "protocol_drift",
            Self::InteractionDrift => "interaction_drift",
            Self::SchemaDrift => "schema_drift",
            Self::ParserDrift => "parser_drift",
            Self::SemanticDrift => "semantic_drift",
            Self::ZeroYieldAnomaly => "zero_yield_anomaly",
            Self::ConfirmedDead => "confirmed_dead",
            Self::Inconclusive => "inconclusive",
        }
    }

    #[must_use]
    pub const fn is_accepted(self) -> bool {
        matches!(self, Self::Success | Self::ValidZero)
    }

    #[must_use]
    pub const fn is_auth(self) -> bool {
        matches!(self, Self::AuthRequired | Self::AuthRejected)
    }

    /// Whether the source made no request because no key is configured: an expected skip, not a
    /// failure, so a scan does not count it as an error.
    #[must_use]
    pub const fn is_not_configured(self) -> bool {
        matches!(self, Self::NotConfigured)
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

    /// Every field a run records. A parser that read rows passes their count as `found`. Callers
    /// with no row count use [`Self::failed`] or [`Self::inconclusive`]. Outside this module an
    /// outcome is built through these constructors; `tests/architecture_boundaries.rs` refuses a
    /// struct literal anywhere else.
    #[must_use]
    pub fn observed(
        module: impl Into<String>,
        observed_at_unix: u64,
        kind: SourceOutcomeKind,
        http_status: Option<u16>,
        found: Option<usize>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            module: module.into(),
            kind,
            observed_at_unix,
            http_status,
            found,
            retry_after_secs: None,
            detail: Some(detail.into()),
        }
    }

    /// A run that produced no answer. `kind` says why, `http_status` is the response status when
    /// there was one, and `detail` is diagnostic text. No row count is recorded.
    #[must_use]
    pub fn failed(
        module: impl Into<String>,
        observed_at_unix: u64,
        kind: SourceOutcomeKind,
        http_status: Option<u16>,
        detail: impl Into<String>,
    ) -> Self {
        Self::observed(module, observed_at_unix, kind, http_status, None, detail)
    }

    /// The run completed without a verdict. `detail` says why.
    #[must_use]
    pub fn inconclusive(
        module: impl Into<String>,
        observed_at_unix: u64,
        detail: impl Into<String>,
    ) -> Self {
        Self::failed(
            module,
            observed_at_unix,
            SourceOutcomeKind::Inconclusive,
            None,
            detail,
        )
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

/// The result of one single-source CLI run: the rendered report, a network refusal, or a failure
/// the sources gave. Each source's `…Run` type is this over its own report, so the three outcomes
/// have one definition.
#[derive(Debug, Clone, PartialEq)]
pub enum SourceRun<R> {
    Printed { text: String, report: R },
    Network(String),
    Failed(String),
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

impl SourceHealthAction {
    /// The wire label, as serde writes it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accept => "accept",
            Self::Retry => "retry",
            Self::Backoff => "backoff",
            Self::RequireCredential => "require_credential",
            Self::Quarantine => "quarantine",
            Self::RequireContractVerification => "require_contract_verification",
            Self::Investigate => "investigate",
        }
    }
}

/// Conservative default policy. Provider-specific logic may be stricter, never
/// less truthful than the causal outcome itself.
#[must_use]
pub const fn recommended_action(kind: SourceOutcomeKind) -> SourceHealthAction {
    match kind {
        SourceOutcomeKind::Success | SourceOutcomeKind::ValidZero => SourceHealthAction::Accept,
        SourceOutcomeKind::AuthRequired
        | SourceOutcomeKind::NotConfigured
        | SourceOutcomeKind::AuthRejected => SourceHealthAction::RequireCredential,
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
/// status, so a 403 or 200 interstitial is never `AuthRejected` or `Inconclusive`; a 200
/// content page that embeds a CAPTCHA widget or a bot-management sensor is content
/// (`Inconclusive`), see [`crate::classify::is_served_challenge`]. A 403 without a challenge
/// signature is `AuthRejected`.
#[must_use]
pub fn classify_fetch(status: u16, body: &str) -> SourceOutcomeKind {
    if status == 429 {
        SourceOutcomeKind::RateLimited
    } else if is_challenge_at(status, body) {
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
    fn failure_constructors_record_no_row_count_and_keep_their_fields() {
        let failed = SourceExecutionOutcome::failed(
            "fixture",
            7,
            SourceOutcomeKind::ParserDrift,
            Some(503),
            "rows unusable",
        );
        assert_eq!(failed.module, "fixture");
        assert_eq!(failed.kind, SourceOutcomeKind::ParserDrift);
        assert_eq!(failed.observed_at_unix, 7);
        assert_eq!(failed.http_status, Some(503));
        assert_eq!(failed.found, None);
        assert_eq!(failed.retry_after_secs, None);
        assert_eq!(failed.detail.as_deref(), Some("rows unusable"));

        let inconclusive = SourceExecutionOutcome::inconclusive("fixture", 7, "no verdict");
        assert_eq!(inconclusive.kind, SourceOutcomeKind::Inconclusive);
        assert_eq!(inconclusive.http_status, None);
        assert_eq!(inconclusive.found, None);
        assert_eq!(inconclusive.detail.as_deref(), Some("no verdict"));

        let observed = SourceExecutionOutcome::observed(
            "fixture",
            7,
            SourceOutcomeKind::Success,
            Some(200),
            Some(3),
            "three rows",
        );
        assert_eq!(observed.kind, SourceOutcomeKind::Success);
        assert_eq!(observed.http_status, Some(200));
        assert_eq!(observed.found, Some(3));
        assert_eq!(observed.detail.as_deref(), Some("three rows"));
    }

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
    fn a_missing_key_is_a_not_configured_skip_that_asks_for_a_credential_but_is_not_auth() {
        let skipped = SourceOutcomeKind::NotConfigured;
        assert!(skipped.is_not_configured());
        assert!(!SourceOutcomeKind::AuthRequired.is_not_configured());
        assert!(!skipped.is_auth());
        assert!(!skipped.is_accepted());
        assert_eq!(
            recommended_action(skipped),
            SourceHealthAction::RequireCredential
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
    fn a_served_page_with_a_captcha_widget_is_content_and_a_refused_one_is_a_wall() {
        let login = "<html><script src=\"https://www.google.com/recaptcha/api.js\"></script><div class=\"g-recaptcha\"></div><h1>Sign in</h1></html>";
        assert_eq!(classify_fetch(200, login), SourceOutcomeKind::Inconclusive);
        assert_eq!(classify_fetch(403, login), SourceOutcomeKind::BotWaf);
        assert_eq!(classify_fetch(503, login), SourceOutcomeKind::BotWaf);
    }

    #[test]
    fn labels_are_the_serde_wire_names() {
        use SourceHealthAction as A;
        use SourceOutcomeKind as K;
        const KINDS: [SourceOutcomeKind; 25] = [
            K::Success,
            K::ValidZero,
            K::AuthRequired,
            K::NotConfigured,
            K::AuthRejected,
            K::EntitlementDenied,
            K::QuotaExhausted,
            K::RateLimited,
            K::BotWaf,
            K::DnsFailure,
            K::ConnectFailure,
            K::TlsFailure,
            K::TtfbTimeout,
            K::BodyTimeout,
            K::Upstream4xx,
            K::Upstream5xx,
            K::RedirectChanged,
            K::ProtocolDrift,
            K::InteractionDrift,
            K::SchemaDrift,
            K::ParserDrift,
            K::SemanticDrift,
            K::ZeroYieldAnomaly,
            K::ConfirmedDead,
            K::Inconclusive,
        ];
        const ACTIONS: [SourceHealthAction; 7] = [
            A::Accept,
            A::Retry,
            A::Backoff,
            A::RequireCredential,
            A::Quarantine,
            A::RequireContractVerification,
            A::Investigate,
        ];
        for kind in KINDS {
            // A new variant fails to compile until this match names it; add it to `KINDS` too.
            match kind {
                K::Success
                | K::ValidZero
                | K::AuthRequired
                | K::NotConfigured
                | K::AuthRejected
                | K::EntitlementDenied
                | K::QuotaExhausted
                | K::RateLimited
                | K::BotWaf
                | K::DnsFailure
                | K::ConnectFailure
                | K::TlsFailure
                | K::TtfbTimeout
                | K::BodyTimeout
                | K::Upstream4xx
                | K::Upstream5xx
                | K::RedirectChanged
                | K::ProtocolDrift
                | K::InteractionDrift
                | K::SchemaDrift
                | K::ParserDrift
                | K::SemanticDrift
                | K::ZeroYieldAnomaly
                | K::ConfirmedDead
                | K::Inconclusive => {}
            }
            let wire = serde_json::to_value(kind).expect("a kind serialises");
            assert_eq!(wire.as_str(), Some(kind.as_str()), "{kind:?}");
        }
        for action in ACTIONS {
            match action {
                A::Accept
                | A::Retry
                | A::Backoff
                | A::RequireCredential
                | A::Quarantine
                | A::RequireContractVerification
                | A::Investigate => {}
            }
            let wire = serde_json::to_value(action).expect("an action serialises");
            assert_eq!(wire.as_str(), Some(action.as_str()), "{action:?}");
        }
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
