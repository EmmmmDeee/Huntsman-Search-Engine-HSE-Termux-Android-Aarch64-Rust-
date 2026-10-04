//! IP CLI parsing and live investigation assembly.
//!
//! This module keeps process-independent command semantics in the library. Public
//! targets use the existing guarded transport, official IANA RDAP bootstrap, and
//! bounded orchestrator. Non-public targets terminate before any network call.

use std::net::IpAddr;

use thiserror::Error;

use crate::fetch::{FetchOptions, fetch};
use crate::http::{Request, Transport, UreqTransport};
use crate::source_outcome::SourceOutcomeKind;

use super::orchestrator::{IpBudget, IpMode, run_investigation};
use super::providers::doh_ptr::CloudflarePtrProvider;
use super::providers::rdap::{
    IANA_RDAP_IPV4_BOOTSTRAP, IANA_RDAP_IPV6_BOOTSTRAP, RdapBootstrap, RdapProvider,
};
use super::providers::ripestat::RipeStatNetworkInfoProvider;
use super::render::{render_json, render_text, render_text_with_evidence};
use super::{
    IpFailure, IpFailureKind, IpInvestigation, IpProvider, IpProviderParseError, IpTarget,
};

pub const IP_USAGE: &str = "usage: huntsman-recon ip <IP> [--json] [--deep] [--evidence]";

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IpCliError {
    #[error("{0}")]
    Usage(String),
    #[error("{0}")]
    Data(String),
    #[error("{0}")]
    Runtime(String),
}

impl IpCliError {
    #[must_use]
    pub const fn exit_code(&self) -> u8 {
        match self {
            Self::Usage(_) => 64,
            Self::Data(_) => 65,
            Self::Runtime(_) => 74,
        }
    }
}

/// Parse IP-subcommand arguments and execute the bounded investigation.
///
/// # Errors
/// Returns a usage error for unknown/missing flags, a data error for malformed IP
/// input, or a runtime error if serialization fails.
pub fn run_ip_cli(args: &[String], now_unix: u64) -> Result<String, IpCliError> {
    let Some(raw_target) = args.first() else {
        return Err(IpCliError::Usage(IP_USAGE.into()));
    };
    if raw_target.starts_with('-') {
        return Err(IpCliError::Usage(IP_USAGE.into()));
    }

    let target =
        IpTarget::parse(raw_target).map_err(|error| IpCliError::Data(error.to_string()))?;
    let mut json = false;
    let mut deep = false;
    let mut evidence = false;
    for flag in &args[1..] {
        match flag.as_str() {
            "--json" => json = true,
            "--deep" => deep = true,
            "--evidence" => evidence = true,
            _ => {
                return Err(IpCliError::Usage(format!(
                    "unknown ip option: {flag}\n{IP_USAGE}"
                )));
            }
        }
    }

    let mode = if deep { IpMode::Deep } else { IpMode::Base };
    let investigation = if target.is_public() {
        let transport = UreqTransport::default();
        investigate_ip(&transport, target, mode, IpBudget::default(), now_unix)
    } else {
        let mut investigation = IpInvestigation::new(target);
        investigation.termination_reason = Some("non_public_target".into());
        investigation
    };

    if json {
        render_json(&investigation).map_err(|error| IpCliError::Runtime(error.to_string()))
    } else if evidence {
        Ok(render_text_with_evidence(&investigation))
    } else {
        Ok(render_text(&investigation))
    }
}

/// Assemble live providers and execute one bounded public-IP investigation.
///
/// The IANA bootstrap consumes one request-budget unit. Bootstrap failure is retained
/// as an explicit failure while independent RIPEstat/PTR actions remain eligible.
#[must_use]
pub fn investigate_ip<T: Transport + ?Sized>(
    transport: &T,
    target: IpTarget,
    mode: IpMode,
    budget: IpBudget,
    now_unix: u64,
) -> IpInvestigation {
    if !target.is_public() {
        let mut investigation = IpInvestigation::new(target);
        investigation.termination_reason = Some("non_public_target".into());
        return investigation;
    }

    let ripe = RipeStatNetworkInfoProvider;
    let ptr = CloudflarePtrProvider;
    let mut bootstrap_failure = None;
    let mut bootstrap_call = 0;
    let rdap = if budget.max_calls == 0 {
        None
    } else {
        bootstrap_call = 1;
        match discover_rdap_provider(transport, &target, now_unix) {
            Ok(provider) => Some(provider),
            Err(failure) => {
                bootstrap_failure = Some(failure);
                None
            }
        }
    };

    let mut providers: Vec<&dyn IpProvider> = Vec::with_capacity(3);
    if let Some(provider) = rdap.as_ref() {
        providers.push(provider);
    }
    providers.push(&ripe);
    providers.push(&ptr);

    let provider_budget = IpBudget {
        max_calls: budget.max_calls.saturating_sub(bootstrap_call),
        ..budget
    };
    let mut investigation = run_investigation(
        transport,
        target,
        &providers,
        mode,
        provider_budget,
        now_unix.saturating_add(u64::from(bootstrap_call)),
    );
    investigation.budget_used.calls = investigation
        .budget_used
        .calls
        .saturating_add(bootstrap_call);
    if let Some(failure) = bootstrap_failure {
        investigation.failures.insert(0, failure);
    }
    investigation
}

fn discover_rdap_provider<T: Transport + ?Sized>(
    transport: &T,
    target: &IpTarget,
    now_unix: u64,
) -> Result<RdapProvider, IpFailure> {
    let url = match target.address {
        IpAddr::V4(_) => IANA_RDAP_IPV4_BOOTSTRAP,
        IpAddr::V6(_) => IANA_RDAP_IPV6_BOOTSTRAP,
    };
    let fetched = fetch(
        transport,
        Request::get(url),
        None,
        &FetchOptions::default(),
        "iana_rdap_bootstrap",
        now_unix,
    )
    .map_err(|error| bootstrap_failure(IpFailureKind::Network, error.to_string(), None))?;

    let outcome = fetched.outcome.kind;
    let detail = fetched.outcome.detail.clone();
    let response = fetched.response.ok_or_else(|| {
        bootstrap_failure(
            bootstrap_failure_kind(outcome),
            detail.unwrap_or_else(|| "IANA RDAP bootstrap produced no HTTP response".into()),
            Some(outcome),
        )
    })?;
    if response.truncated {
        return Err(bootstrap_failure(
            IpFailureKind::Partial,
            "IANA RDAP bootstrap exceeded configured byte limit",
            Some(outcome),
        ));
    }
    if !(200..=299).contains(&response.status) || !bootstrap_parseable(outcome) {
        return Err(bootstrap_failure(
            bootstrap_failure_kind(outcome),
            detail.unwrap_or_else(|| format!("IANA RDAP bootstrap status={}", response.status)),
            Some(outcome),
        ));
    }

    let bootstrap = RdapBootstrap::parse(&response.body).map_err(|error| {
        let kind = match error {
            IpProviderParseError::Parse(_) => IpFailureKind::Parse,
            IpProviderParseError::Schema(_) => IpFailureKind::Schema,
        };
        bootstrap_failure(kind, error.to_string(), Some(outcome))
    })?;
    let base_url = bootstrap.base_url_for(target.address).ok_or_else(|| {
        bootstrap_failure(
            IpFailureKind::Schema,
            format!(
                "IANA RDAP bootstrap has no route for {}",
                target.canonical()
            ),
            Some(outcome),
        )
    })?;
    RdapProvider::new(base_url).map_err(|error| {
        let kind = match error {
            IpProviderParseError::Parse(_) => IpFailureKind::Parse,
            IpProviderParseError::Schema(_) => IpFailureKind::Schema,
        };
        bootstrap_failure(kind, error.to_string(), Some(outcome))
    })
}

const fn bootstrap_parseable(kind: SourceOutcomeKind) -> bool {
    matches!(
        kind,
        SourceOutcomeKind::Success | SourceOutcomeKind::ValidZero | SourceOutcomeKind::Inconclusive
    )
}

const fn bootstrap_failure_kind(kind: SourceOutcomeKind) -> IpFailureKind {
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

fn bootstrap_failure(
    kind: IpFailureKind,
    detail: impl Into<String>,
    source_outcome: Option<SourceOutcomeKind>,
) -> IpFailure {
    IpFailure {
        provider_id: "iana_rdap_bootstrap".into(),
        kind,
        detail: detail.into(),
        source_outcome,
    }
}
