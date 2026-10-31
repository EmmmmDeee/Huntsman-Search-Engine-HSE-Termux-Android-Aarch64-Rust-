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
    /// Huntsman's guarded request path sent nothing: the egress policy dropped every address of
    /// the destination, or the URL, a redirect target or the credential's origin binding could not
    /// be sent safely (fetch's `Error::Network`, `LegError::Refused`). It says nothing about the
    /// selector. [`SourceReach`] reads a lookup with no accepted row and one of these as a refusal
    /// (exit 77).
    RefusedBeforeSending,
    /// The run completed without a verdict. A kind label this build does not know, read back
    /// from a saved scan or report written by a newer build, reads as this kind, which is never
    /// accepted, so an older build can still open that scan and treats the row as unresolved.
    #[serde(other)]
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
            Self::RefusedBeforeSending => "refused_before_sending",
            Self::Inconclusive => "inconclusive",
        }
    }

    #[must_use]
    pub const fn is_accepted(self) -> bool {
        matches!(self, Self::Success | Self::ValidZero)
    }

    /// Whether the source made no request because no key is configured: an expected skip, not a
    /// failure, so a scan does not count it as an error.
    #[must_use]
    pub const fn is_not_configured(self) -> bool {
        matches!(self, Self::NotConfigured)
    }

    /// Whether Huntsman's guarded request path refused the request, so nothing was sent. It is
    /// never accepted and never a transport failure: the source was not asked at all.
    #[must_use]
    pub const fn is_refused_before_sending(self) -> bool {
        matches!(self, Self::RefusedBeforeSending)
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
}

/// What one of the endpoints a source is asked through (a blocklist zone, a threat feed, a
/// filtering resolver) said, as [`SourceExecutionOutcome::joined`] counts it into the source's row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointAnswer {
    /// It answered, finding the subject this many times. `Found(0)` says the subject is absent no
    /// more than [`Self::Unvouched`] does; an endpoint that says so is [`Self::Absent`].
    Found(usize),
    /// It answered that the subject is absent from it.
    Absent,
    /// It answered without finding the subject, but cannot say the subject is absent from it now,
    /// as a list that stopped updating cannot.
    Unvouched,
    /// It gave no answer that can be trusted, for this reason.
    Failed(SourceOutcomeKind),
}

/// What a source asked through several endpoints answered, joining what each said
/// ([`Self::of`]); [`SourceExecutionOutcome::joined`] is its row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Joined {
    /// The endpoints found the subject this many times in all.
    Found(usize),
    /// Every endpoint said the subject is absent from it.
    Absent,
    /// No endpoint answered: the row takes the failure of the endpoint at `index`, the first that
    /// is not a refusal, else the first, so it is refused only when every endpoint was.
    Unanswered {
        index: usize,
        kind: SourceOutcomeKind,
    },
    /// Some endpoint found nothing beside others that did not answer, or answered for no present.
    Inconclusive,
}

impl Joined {
    /// The answer of a source from what each of its endpoints said, in the order asked: what they
    /// found when any found the subject; else "absent" only when every endpoint said so, as one
    /// that did not answer, or cannot vouch for its answer, cannot; else, when none answered, why
    /// not; else inconclusive. **Pure.**
    #[must_use]
    pub fn of(answers: &[EndpointAnswer]) -> Self {
        let found: usize = answers
            .iter()
            .map(|answer| match answer {
                EndpointAnswer::Found(count) => *count,
                _ => 0,
            })
            .sum();
        if found > 0 {
            return Self::Found(found);
        }
        if !answers.is_empty()
            && answers
                .iter()
                .all(|answer| *answer == EndpointAnswer::Absent)
        {
            return Self::Absent;
        }
        let failures: Vec<(usize, SourceOutcomeKind)> = answers
            .iter()
            .enumerate()
            .filter_map(|(index, answer)| match answer {
                EndpointAnswer::Failed(kind) => Some((index, *kind)),
                _ => None,
            })
            .collect();
        let why = failures
            .iter()
            .find(|(_, kind)| *kind != SourceOutcomeKind::RefusedBeforeSending)
            .or_else(|| failures.first());
        match why {
            Some(&(index, kind)) if failures.len() == answers.len() => {
                Self::Unanswered { index, kind }
            }
            _ => Self::Inconclusive,
        }
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

/// What a keyed source's row says when its key slot is empty.
pub const NO_KEY_DETAIL: &str = "no operator key configured; no request made";

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

    /// The row a keyed source leaves when a lookup asks it and its key slot is empty: no request
    /// was made, and the Sources table says so instead of leaving no row, as every keyed leg does.
    #[must_use]
    pub fn not_configured(module: impl Into<String>, observed_at_unix: u64) -> Self {
        Self::failed(
            module,
            observed_at_unix,
            SourceOutcomeKind::NotConfigured,
            None,
            NO_KEY_DETAIL,
        )
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

    /// A request Huntsman's guarded path refused, so nothing was sent
    /// ([`SourceOutcomeKind::RefusedBeforeSending`]). `detail` keeps the exact cause.
    #[must_use]
    pub fn refused_before_sending(
        module: impl Into<String>,
        observed_at_unix: u64,
        detail: impl Into<String>,
    ) -> Self {
        Self::failed(
            module,
            observed_at_unix,
            SourceOutcomeKind::RefusedBeforeSending,
            None,
            detail,
        )
    }

    /// The row of a source asked through several endpoints, from what each said (`answers`, in
    /// the order asked, read by [`Joined::of`]), with `detail` saying what each said: what they
    /// found; "nothing found" ([`Self::valid_zero`]) only when every endpoint said the subject is
    /// absent from it; the failure that stopped it when no endpoint answered; else
    /// [`Self::inconclusive`].
    #[must_use]
    pub fn joined(
        module: impl Into<String>,
        observed_at_unix: u64,
        answers: &[EndpointAnswer],
        detail: impl Into<String>,
    ) -> Self {
        match Joined::of(answers) {
            Joined::Found(found) => {
                Self::success(module, observed_at_unix, found).with_detail(detail)
            }
            Joined::Absent => Self::valid_zero(module, observed_at_unix).with_detail(detail),
            Joined::Unanswered { kind, .. } => {
                Self::failed(module, observed_at_unix, kind, None, detail)
            }
            Joined::Inconclusive => Self::inconclusive(module, observed_at_unix, detail),
        }
    }

    /// `module: detail`, without repeating the module when `detail` already starts
    /// `"{module}: "` (the `api_leg`, crt.sh, `WiGLE` and stolen.tax details do), and
    /// `module: <kind label>` when there is no detail. Presentation only, never classification.
    #[must_use]
    pub fn reason(&self) -> String {
        let detail = self.detail.as_deref().unwrap_or(self.kind.as_str());
        let repeats = detail
            .strip_prefix(self.module.as_str())
            .is_some_and(|rest| rest.starts_with(": "));
        if repeats {
            detail.to_owned()
        } else {
            format!("{}: {detail}", self.module)
        }
    }
}

/// How far a lookup's sources got, read from its outcome rows in order, and so whether a lookup
/// with no accepted row was refused (exit 77) or got no response (exit 69):
///
/// - any accepted row is `Answered`;
/// - otherwise the first [`SourceOutcomeKind::RefusedBeforeSending`] row is `Refused`;
/// - otherwise the first transport-failure row is `NoResponse`;
/// - otherwise `Failed`, with the first row that is not `NotConfigured`, else the first row, else
///   nothing.
///
/// Each reason is that row's [`SourceExecutionOutcome::reason`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceReach {
    Answered,
    Refused(String),
    NoResponse(String),
    Failed(Option<String>),
}

impl SourceReach {
    #[must_use]
    pub fn of(outcomes: &[SourceExecutionOutcome]) -> Self {
        if outcomes.iter().any(|o| o.kind.is_accepted()) {
            return Self::Answered;
        }
        let first = |pick: fn(SourceOutcomeKind) -> bool| {
            outcomes
                .iter()
                .find(|o| pick(o.kind))
                .map(SourceExecutionOutcome::reason)
        };
        if let Some(why) = first(SourceOutcomeKind::is_refused_before_sending) {
            return Self::Refused(why);
        }
        if let Some(why) = first(SourceOutcomeKind::is_transport_failure) {
            return Self::NoResponse(why);
        }
        Self::Failed(
            first(|kind| !kind.is_not_configured())
                .or_else(|| outcomes.first().map(SourceExecutionOutcome::reason)),
        )
    }

    /// Stops only for a refusal ([`SourceRun::Network`], exit 77) or no response
    /// ([`SourceRun::Failed`] led by `lead`, exit 69); sources that answered with errors print
    /// (`None`).
    #[must_use]
    pub fn stopped<R>(&self, lead: &str) -> Option<SourceRun<R>> {
        match self {
            Self::Refused(why) => Some(SourceRun::Network(why.clone())),
            Self::NoResponse(why) => Some(SourceRun::Failed(format!("{lead}: {why}"))),
            Self::Answered | Self::Failed(_) => None,
        }
    }

    /// As [`Self::stopped`], and a lookup with no accepted row always fails (exit 69). With no
    /// row at all the message is `lead` alone.
    #[must_use]
    pub fn unanswered<R>(&self, lead: &str) -> Option<SourceRun<R>> {
        match self {
            Self::Failed(Some(why)) => Some(SourceRun::Failed(format!("{lead}: {why}"))),
            Self::Failed(None) => Some(SourceRun::Failed(lead.to_owned())),
            other => other.stopped(lead),
        }
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

/// Why one page of `records` breach records is not the whole answer, or `None` when it is: the
/// source says it holds more (`has_more`), or its `total` is more than the page read.
#[must_use]
pub fn partial_page_note(records: usize, total: Option<u64>, has_more: bool) -> Option<String> {
    let more_than_read = total.is_some_and(|total| total > records as u64);
    if !(has_more || more_than_read) {
        return None;
    }
    let total = total.map_or_else(|| "an unreported number".to_owned(), |t| t.to_string());
    Some(format!(
        "partial: read the first {records} of {total} matching records; absence of a breach here \
         is not evidence of absence"
    ))
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
        | SourceOutcomeKind::Upstream4xx
        | SourceOutcomeKind::RefusedBeforeSending => SourceHealthAction::Investigate,
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
/// signature is the provider refusing the request (`Upstream4xx`): only a sent credential can be
/// rejected, and [`crate::fetch`], which knows whether one was sent, makes it `AuthRejected` then.
#[must_use]
pub fn classify_fetch(status: u16, body: &str) -> SourceOutcomeKind {
    if status == 429 {
        SourceOutcomeKind::RateLimited
    } else if is_challenge_at(status, body) {
        SourceOutcomeKind::BotWaf
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
            SourceOutcomeKind::Upstream4xx
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

    /// A source asked through several endpoints finds what any of them found, says "nothing
    /// found" only when every one said the subject is absent, says why when none answered, and is
    /// otherwise inconclusive: one endpoint not answering beside others that found nothing is no
    /// clean negative.
    #[test]
    fn a_source_row_is_a_clean_negative_only_when_every_endpoint_vouched_for_it() {
        use EndpointAnswer::{Absent, Failed, Found, Unvouched};
        use SourceOutcomeKind as K;
        let joined = |answers: &[EndpointAnswer]| {
            let row = SourceExecutionOutcome::joined("m", 1, answers, "what each said");
            assert_eq!(row.detail.as_deref(), Some("what each said"), "{answers:?}");
            (row.kind, row.found)
        };
        let dns = Failed(K::DnsFailure);
        let refused = Failed(K::RefusedBeforeSending);
        assert_eq!(joined(&[Found(2), dns, Found(1)]), (K::Success, Some(3)));
        assert_eq!(joined(&[Found(1), Unvouched]), (K::Success, Some(1)));
        assert_eq!(joined(&[Absent, Absent]), (K::ValidZero, Some(0)));
        assert_eq!(joined(&[dns, Absent, Absent]), (K::Inconclusive, None));
        assert_eq!(joined(&[Absent, refused]), (K::Inconclusive, None));
        assert_eq!(joined(&[Absent, Unvouched]), (K::Inconclusive, None));
        assert_eq!(joined(&[Found(0), Absent]), (K::Inconclusive, None));
        assert_eq!(joined(&[refused, dns]), (K::DnsFailure, None));
        assert_eq!(joined(&[refused, refused]), (K::RefusedBeforeSending, None));
        assert_eq!(joined(&[]), (K::Inconclusive, None));
    }

    #[test]
    fn a_missing_key_is_a_not_configured_skip_that_asks_for_a_credential_but_is_not_auth() {
        let skipped = SourceOutcomeKind::NotConfigured;
        assert!(skipped.is_not_configured());
        assert!(!SourceOutcomeKind::AuthRequired.is_not_configured());
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
        const KINDS: [SourceOutcomeKind; 26] = [
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
            K::RefusedBeforeSending,
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
                | K::RefusedBeforeSending
                | K::Inconclusive => {}
            }
            let wire = serde_json::to_value(kind).expect("a kind serialises");
            assert_eq!(wire.as_str(), Some(kind.as_str()), "{kind:?}");
            // Every known label reads back as itself, never as the `Inconclusive` fallback.
            let back: SourceOutcomeKind =
                serde_json::from_value(wire).expect("a known label reads");
            assert_eq!(back, kind, "{kind:?}");
        }
        assert_eq!(
            serde_json::to_string(&K::RefusedBeforeSending).expect("serialises"),
            "\"refused_before_sending\""
        );
        assert_eq!(
            serde_json::from_str::<SourceOutcomeKind>("\"refused_before_sending\"").expect("reads"),
            K::RefusedBeforeSending
        );
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
    fn an_unknown_kind_label_reads_as_inconclusive() {
        let unknown: SourceOutcomeKind =
            serde_json::from_str("\"some_future_kind\"").expect("an unknown label reads");
        assert_eq!(unknown, SourceOutcomeKind::Inconclusive);
        assert_eq!(
            serde_json::to_string(&SourceOutcomeKind::Inconclusive).expect("serialises"),
            "\"inconclusive\""
        );
        // A known label is never swallowed by the fallback.
        for kind in [
            SourceOutcomeKind::Success,
            SourceOutcomeKind::ValidZero,
            SourceOutcomeKind::NotConfigured,
            SourceOutcomeKind::ConnectFailure,
            SourceOutcomeKind::ConfirmedDead,
        ] {
            let wire = serde_json::to_string(&kind).expect("serialises");
            assert_eq!(
                serde_json::from_str::<SourceOutcomeKind>(&wire).expect("reads"),
                kind
            );
        }
        // A whole saved row with a newer kind still reads, as an unresolved row.
        let row: SourceExecutionOutcome = serde_json::from_str(
            r#"{"module":"rdap","kind":"some_future_kind","observed_at_unix":7,"http_status":null,"found":null,"retry_after_secs":null,"detail":"x"}"#,
        )
        .expect("a row with an unknown kind reads");
        assert_eq!(row.kind, SourceOutcomeKind::Inconclusive);
        assert!(!row.kind.is_accepted());
    }

    #[test]
    fn a_plain_row_serialises_byte_for_byte() {
        let found = SourceExecutionOutcome::success("rdap", 7, 2).with_http_status(200);
        assert_eq!(
            serde_json::to_string(&found).expect("serialises"),
            r#"{"module":"rdap","kind":"success","observed_at_unix":7,"http_status":200,"found":2,"retry_after_secs":null,"detail":null}"#
        );
        let failed = SourceExecutionOutcome::failed(
            "rdap",
            7,
            SourceOutcomeKind::ConnectFailure,
            None,
            "no route",
        );
        assert_eq!(
            serde_json::to_string(&failed).expect("serialises"),
            r#"{"module":"rdap","kind":"connect_failure","observed_at_unix":7,"http_status":null,"found":null,"retry_after_secs":null,"detail":"no route"}"#
        );
    }

    fn row(module: &str, kind: SourceOutcomeKind, detail: &str) -> SourceExecutionOutcome {
        SourceExecutionOutcome::failed(module, 7, kind, None, detail)
    }

    fn refused(module: &str) -> SourceExecutionOutcome {
        SourceExecutionOutcome::refused_before_sending(
            module,
            7,
            format!("{module}: request refused before sending: network: egress-policy"),
        )
    }

    type Run = SourceRun<()>;

    #[test]
    fn a_refused_row_is_neither_accepted_nor_a_transport_failure_and_is_investigated() {
        let kind = SourceOutcomeKind::RefusedBeforeSending;
        assert!(kind.is_refused_before_sending());
        assert!(!kind.is_accepted());
        assert!(!kind.is_transport_failure());
        assert!(!kind.is_not_configured());
        assert_eq!(recommended_action(kind), SourceHealthAction::Investigate);
        for other in [
            SourceOutcomeKind::ConnectFailure,
            SourceOutcomeKind::EntitlementDenied,
            SourceOutcomeKind::Inconclusive,
        ] {
            assert!(!other.is_refused_before_sending(), "{other:?}");
        }

        let row = SourceExecutionOutcome::refused_before_sending("rdap", 7, "network: egress");
        assert_eq!(row.module, "rdap");
        assert_eq!(row.kind, kind);
        assert_eq!(row.observed_at_unix, 7);
        assert_eq!(row.http_status, None);
        assert_eq!(row.found, None);
        assert_eq!(row.retry_after_secs, None);
        assert_eq!(row.detail.as_deref(), Some("network: egress"));
    }

    #[test]
    fn a_reason_names_the_module_once() {
        let kept = row(
            "mnemonic",
            SourceOutcomeKind::ConnectFailure,
            "mnemonic: no response (ConnectFailure)",
        );
        assert_eq!(kept.reason(), "mnemonic: no response (ConnectFailure)");
        let longer = row(
            "mnemonic",
            SourceOutcomeKind::ConnectFailure,
            "mnemonicx: y",
        );
        assert_eq!(longer.reason(), "mnemonic: mnemonicx: y");
        let unspaced = row("mnemonic", SourceOutcomeKind::ConnectFailure, "mnemonic:y");
        assert_eq!(unspaced.reason(), "mnemonic: mnemonic:y");
        let mut bare = row("mnemonic", SourceOutcomeKind::ConnectFailure, "");
        bare.detail = None;
        assert_eq!(bare.reason(), "mnemonic: connect_failure");
    }

    #[test]
    fn no_row_at_all_fails_with_the_lead_alone_and_never_stops_a_printing_lookup() {
        let reach = SourceReach::of(&[]);
        assert_eq!(reach, SourceReach::Failed(None));
        assert_eq!(reach.unanswered::<()>("L"), Some(Run::Failed("L".into())));
        assert_eq!(reach.stopped::<()>("L"), None);
    }

    #[test]
    fn an_accepted_row_answers_beside_a_refused_one() {
        let zero = SourceExecutionOutcome::valid_zero("internetdb", 7);
        for rows in [
            vec![zero.clone(), refused("rdap")],
            vec![refused("rdap"), zero.clone()],
        ] {
            let reach = SourceReach::of(&rows);
            assert_eq!(reach, SourceReach::Answered, "{rows:?}");
            assert_eq!(reach.unanswered::<()>("L"), None);
            assert_eq!(reach.stopped::<()>("L"), None);
        }
    }

    #[test]
    fn a_refused_row_outranks_a_transport_failure_in_either_order() {
        let silent = row(
            "rdap",
            SourceOutcomeKind::ConnectFailure,
            "rdap: no route to host",
        );
        let why = "ripestat: request refused before sending: network: egress-policy".to_owned();
        for rows in [
            vec![silent.clone(), refused("ripestat")],
            vec![refused("ripestat"), silent.clone()],
        ] {
            let reach = SourceReach::of(&rows);
            assert_eq!(reach, SourceReach::Refused(why.clone()), "{rows:?}");
            assert_eq!(reach.stopped::<()>("L"), Some(Run::Network(why.clone())));
            assert_eq!(reach.unanswered::<()>("L"), Some(Run::Network(why.clone())));
        }
    }

    #[test]
    fn two_refused_rows_give_the_first_reason() {
        let reach = SourceReach::of(&[refused("rdap"), refused("ripestat")]);
        assert_eq!(
            reach,
            SourceReach::Refused(
                "rdap: request refused before sending: network: egress-policy".into()
            )
        );
    }

    #[test]
    fn a_transport_failure_after_an_unresolved_row_is_no_response_with_its_reason() {
        let rows = [
            row("mnemonic", SourceOutcomeKind::Inconclusive, "no verdict"),
            row(
                "rdap",
                SourceOutcomeKind::TtfbTimeout,
                "no response (TtfbTimeout)",
            ),
        ];
        let reach = SourceReach::of(&rows);
        let why = "rdap: no response (TtfbTimeout)";
        assert_eq!(reach, SourceReach::NoResponse(why.into()));
        let failed = Some(Run::Failed(format!("L: {why}")));
        assert_eq!(reach.stopped::<()>("L"), failed);
        assert_eq!(reach.unanswered::<()>("L"), failed);
    }

    #[test]
    fn a_failure_reason_skips_a_not_configured_row_unless_it_is_all_there_is() {
        let skipped = row(
            "greynoise",
            SourceOutcomeKind::NotConfigured,
            "no key configured",
        );
        let reach = SourceReach::of(&[
            skipped.clone(),
            row("rdap", SourceOutcomeKind::Upstream5xx, "HTTP 503"),
        ]);
        assert_eq!(reach, SourceReach::Failed(Some("rdap: HTTP 503".into())));
        assert_eq!(reach.stopped::<()>("L"), None);
        assert_eq!(
            reach.unanswered::<()>("L"),
            Some(Run::Failed("L: rdap: HTTP 503".into()))
        );

        let only = SourceReach::of(&[skipped]);
        assert_eq!(
            only,
            SourceReach::Failed(Some("greynoise: no key configured".into()))
        );
        assert_eq!(only.stopped::<()>("L"), None);
        assert_eq!(
            only.unanswered::<()>("L"),
            Some(Run::Failed("L: greynoise: no key configured".into()))
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

    #[test]
    fn a_page_is_partial_when_the_source_holds_more_than_it_read() {
        assert_eq!(partial_page_note(3, Some(3), false), None);
        assert_eq!(partial_page_note(3, None, false), None);
        assert_eq!(
            partial_page_note(3, Some(7), false).as_deref(),
            Some(
                "partial: read the first 3 of 7 matching records; absence of a breach here is \
                 not evidence of absence"
            )
        );
        assert!(
            partial_page_note(200, None, true)
                .is_some_and(|note| note.contains("first 200 of an unreported number"))
        );
    }
}
