//! Guarded provider boundary for IP investigations.
//!
//! Providers describe requests and parse responses. Network execution stays in the
//! crate's existing `fetch` boundary so egress, redirect, credential, timeout, and
//! causal source-outcome semantics remain single-owned.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::fetch::{FetchOptions, fetch};
use crate::http::{Request, Response, Transport};
use crate::module::ProviderDescriptor;
use crate::source_outcome::SourceOutcomeKind;

use super::model::{IpFailure, IpFailureKind, IpObservation, IpTarget};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpCapability {
    Allocation,
    Routing,
    ReverseDns,
    HistoricalDns,
    Certificate,
    Service,
    Reputation,
    Anonymization,
    Geolocation,
    InfrastructureClass,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpProviderAction {
    pub action_id: String,
    pub capability: IpCapability,
    pub request: Request,
    /// Identity of the upstream evidentiary root, not merely the collector name.
    pub lineage_family: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IpProviderParseError {
    #[error("parse failure: {0}")]
    Parse(String),
    #[error("schema failure: {0}")]
    Schema(String),
}

pub trait IpProvider {
    fn id(&self) -> &'static str;
    fn descriptor(&self) -> ProviderDescriptor;
    fn capabilities(&self) -> &'static [IpCapability];
    fn lineage_family(&self) -> &'static str;
    fn plan(&self, target: &IpTarget) -> Vec<IpProviderAction>;
    fn parse(
        &self,
        action: &IpProviderAction,
        response: &Response,
        retrieved_at_unix: u64,
    ) -> Result<Vec<IpObservation>, IpProviderParseError>;
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IpProviderResult {
    pub observations: Vec<IpObservation>,
    pub failures: Vec<IpFailure>,
}

/// Execute one provider action through the shared guarded fetch boundary.
///
/// Parser output is admitted only from a complete 2xx response whose causal fetch
/// state permits parsing. Transport, HTTP, truncation, and parser failures remain
/// explicit failures and never become negative evidence.
#[must_use]
pub fn execute_provider_action<T: Transport + ?Sized>(
    transport: &T,
    provider: &dyn IpProvider,
    action: &IpProviderAction,
    now_unix: u64,
) -> IpProviderResult {
    let fetched = match fetch(
        transport,
        action.request.clone(),
        None,
        &FetchOptions::default(),
        provider.id(),
        now_unix,
    ) {
        Ok(fetched) => fetched,
        Err(error) => {
            return single_failure(
                provider.id(),
                IpFailureKind::Network,
                error.to_string(),
                None,
            );
        }
    };

    let outcome = fetched.outcome.kind;
    let Some(response) = fetched.response else {
        return single_failure(
            provider.id(),
            failure_kind(outcome),
            fetched
                .outcome
                .detail
                .unwrap_or_else(|| "provider produced no HTTP response".into()),
            Some(outcome),
        );
    };

    if response.truncated {
        return single_failure(
            provider.id(),
            IpFailureKind::Partial,
            "response body exceeded configured byte limit",
            Some(outcome),
        );
    }

    if !(200..=299).contains(&response.status) || !parseable_outcome(outcome) {
        return single_failure(
            provider.id(),
            failure_kind(outcome),
            fetched.outcome.detail.unwrap_or_else(|| {
                format!("provider response status={}", response.status)
            }),
            Some(outcome),
        );
    }

    match provider.parse(action, &response, now_unix) {
        Ok(observations) if observations.is_empty() => single_failure(
            provider.id(),
            IpFailureKind::Empty,
            "provider parser returned no observations",
            Some(outcome),
        ),
        Ok(observations) => IpProviderResult {
            observations,
            failures: Vec::new(),
        },
        Err(IpProviderParseError::Parse(detail)) => single_failure(
            provider.id(),
            IpFailureKind::Parse,
            detail,
            Some(outcome),
        ),
        Err(IpProviderParseError::Schema(detail)) => single_failure(
            provider.id(),
            IpFailureKind::Schema,
            detail,
            Some(outcome),
        ),
    }
}

const fn parseable_outcome(kind: SourceOutcomeKind) -> bool {
    matches!(
        kind,
        SourceOutcomeKind::Success | SourceOutcomeKind::ValidZero | SourceOutcomeKind::Inconclusive
    )
}

const fn failure_kind(kind: SourceOutcomeKind) -> IpFailureKind {
    match kind {
        SourceOutcomeKind::DnsFailure => IpFailureKind::Dns,
        SourceOutcomeKind::ConnectFailure | SourceOutcomeKind::TlsFailure => IpFailureKind::Network,
        SourceOutcomeKind::TtfbTimeout | SourceOutcomeKind::BodyTimeout => IpFailureKind::Timeout,
        SourceOutcomeKind::AuthRequired => IpFailureKind::AuthRequired,
        SourceOutcomeKind::AuthRejected => IpFailureKind::AuthRejected,
        SourceOutcomeKind::RateLimited => IpFailureKind::RateLimited,
        SourceOutcomeKind::SchemaDrift => IpFailureKind::Schema,
        SourceOutcomeKind::ParserDrift => IpFailureKind::Parse,
        SourceOutcomeKind::ZeroYieldAnomaly => IpFailureKind::Empty,
        SourceOutcomeKind::Success
        | SourceOutcomeKind::ValidZero
        | SourceOutcomeKind::BotWaf
        | SourceOutcomeKind::Upstream4xx
        | SourceOutcomeKind::Upstream5xx
        | SourceOutcomeKind::RedirectChanged
        | SourceOutcomeKind::ProtocolDrift
        | SourceOutcomeKind::InteractionDrift
        | SourceOutcomeKind::SemanticDrift
        | SourceOutcomeKind::ConfirmedDead
        | SourceOutcomeKind::Inconclusive => IpFailureKind::Provider,
    }
}

fn single_failure(
    provider_id: &str,
    kind: IpFailureKind,
    detail: impl Into<String>,
    source_outcome: Option<SourceOutcomeKind>,
) -> IpProviderResult {
    IpProviderResult {
        observations: Vec::new(),
        failures: vec![IpFailure {
            provider_id: provider_id.to_owned(),
            kind,
            detail: detail.into(),
            source_outcome,
        }],
    }
}
