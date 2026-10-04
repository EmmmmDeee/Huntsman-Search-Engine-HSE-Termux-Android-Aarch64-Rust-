//! Pure IP-investigation state. Provider/network code lives above this model.

use std::collections::BTreeMap;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::source_outcome::SourceOutcomeKind;
use crate::validation::{is_bogus_ip, is_non_routable_ip};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpScope {
    Public,
    Private,
    Loopback,
    LinkLocal,
    Multicast,
    DocumentationOrReserved,
    Unspecified,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IpInputError {
    #[error("invalid IP address: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpTarget {
    pub original: String,
    pub address: IpAddr,
    pub scope: IpScope,
}

impl IpTarget {
    /// Parse and canonicalise an IP target. IPv4-mapped IPv6 is collapsed to IPv4 so
    /// the same network endpoint cannot enter the investigation under two identities.
    pub fn parse(raw: &str) -> Result<Self, IpInputError> {
        let trimmed = raw.trim();
        let parsed = trimmed
            .parse::<IpAddr>()
            .map_err(|_| IpInputError::Invalid(raw.to_owned()))?;
        let address = match parsed {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
            v4 @ IpAddr::V4(_) => v4,
        };
        Ok(Self {
            original: raw.to_owned(),
            scope: classify_scope(address),
            address,
        })
    }

    #[must_use]
    pub fn canonical(&self) -> String {
        self.address.to_string()
    }

    #[must_use]
    pub const fn is_public(&self) -> bool {
        matches!(self.scope, IpScope::Public)
    }
}

fn classify_scope(address: IpAddr) -> IpScope {
    match address {
        IpAddr::V4(v4) => {
            if v4.is_unspecified() {
                return IpScope::Unspecified;
            }
            if v4.is_loopback() {
                return IpScope::Loopback;
            }
            if v4.is_private() {
                return IpScope::Private;
            }
            if v4.is_link_local() {
                return IpScope::LinkLocal;
            }
            if v4.is_multicast() {
                return IpScope::Multicast;
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_unspecified() {
                return IpScope::Unspecified;
            }
            if v6.is_loopback() {
                return IpScope::Loopback;
            }
            if v6.is_multicast() {
                return IpScope::Multicast;
            }
            let octets = v6.octets();
            if (octets[0] & 0xfe) == 0xfc {
                return IpScope::Private;
            }
            if octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80 {
                return IpScope::LinkLocal;
            }
        }
    }

    let canonical = address.to_string();
    if is_bogus_ip(&canonical) || is_non_routable_ip(&canonical) {
        IpScope::DocumentationOrReserved
    } else {
        IpScope::Public
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpObservationKind {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpClaimKind {
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

impl IpClaimKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allocation => "allocation",
            Self::Routing => "routing",
            Self::ReverseDns => "reverse_dns",
            Self::HistoricalDns => "historical_dns",
            Self::Certificate => "certificate",
            Self::Service => "service",
            Self::Reputation => "reputation",
            Self::Anonymization => "anonymization",
            Self::Geolocation => "geolocation",
            Self::InfrastructureClass => "infrastructure_class",
        }
    }
}

pub const ALL_IP_CLAIM_KINDS: &[IpClaimKind] = &[
    IpClaimKind::Allocation,
    IpClaimKind::Routing,
    IpClaimKind::ReverseDns,
    IpClaimKind::HistoricalDns,
    IpClaimKind::Certificate,
    IpClaimKind::Service,
    IpClaimKind::Reputation,
    IpClaimKind::Anonymization,
    IpClaimKind::Geolocation,
    IpClaimKind::InfrastructureClass,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TemporalState {
    Current,
    Recent,
    Historical,
    Stale,
    UnknownCurrent,
    Invalidated,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpObservation {
    pub id: String,
    pub provider_id: String,
    pub source_family: String,
    pub kind: IpObservationKind,
    pub summary: String,
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_at_unix: Option<u64>,
    pub retrieved_at_unix: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_digest: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpFailureKind {
    Unsupported,
    Dns,
    Network,
    Timeout,
    AuthRequired,
    AuthRejected,
    RateLimited,
    QuotaExhausted,
    Provider,
    Schema,
    Parse,
    Empty,
    Stale,
    Partial,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpFailure {
    pub provider_id: String,
    pub kind: IpFailureKind,
    pub detail: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_outcome: Option<SourceOutcomeKind>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpClaimState {
    Unknown,
    Supported,
    Contradicted,
    Invalidated,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpClaim {
    pub kind: IpClaimKind,
    pub state: IpClaimState,
    pub temporal: TemporalState,
    #[serde(default)]
    pub support_ids: Vec<String>,
    #[serde(default)]
    pub contradiction_ids: Vec<String>,
    #[serde(default)]
    pub dependency_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpActionRecord {
    pub provider_id: String,
    pub action_id: String,
    pub reason: String,
    pub executed: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpBudgetUsage {
    pub calls: u32,
    pub actions: u32,
    pub max_depth_reached: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpInvestigation {
    pub target: IpTarget,
    #[serde(default)]
    pub observations: Vec<IpObservation>,
    #[serde(default)]
    pub failures: Vec<IpFailure>,
    #[serde(default)]
    pub claims: Vec<IpClaim>,
    #[serde(default)]
    pub actions_considered: Vec<IpActionRecord>,
    #[serde(default)]
    pub budget_used: IpBudgetUsage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub termination_reason: Option<String>,
}

impl IpInvestigation {
    #[must_use]
    pub fn new(target: IpTarget) -> Self {
        Self {
            target,
            observations: Vec::new(),
            failures: Vec::new(),
            claims: Vec::new(),
            actions_considered: Vec::new(),
            budget_used: IpBudgetUsage::default(),
            termination_reason: None,
        }
    }
}
