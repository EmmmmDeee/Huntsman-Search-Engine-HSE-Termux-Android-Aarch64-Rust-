//! Authoritative capability metadata and pivot routing.
//!
//! A descriptor counts as runtime coverage only when it is registered here. Pivot-only
//! capabilities are discovery aids and are structurally forbidden from claiming an
//! evidence-bearing role.

use std::collections::BTreeSet;

use crate::canonical::canonical_domain;
use crate::dependency::ModuleCategory;
use crate::entity::EntityKind;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetrievalMode {
    Local,
    HttpApi,
    HttpPage,
    PivotOnly,
    Dns,
    Sensor,
}

impl RetrievalMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::HttpApi => "http_api",
            Self::HttpPage => "http_page",
            Self::PivotOnly => "pivot_only",
            Self::Dns => "dns",
            Self::Sensor => "sensor",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessClass {
    Public,
    FreeAccount,
    ApiKey,
    Paid,
    Enterprise,
}

impl AccessClass {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::FreeAccount => "free_account",
            Self::ApiKey => "api_key",
            Self::Paid => "paid",
            Self::Enterprise => "enterprise",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueTransform {
    Preserve,
    CanonicalDomain,
    BareUsername,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceRole {
    LeadOnly,
    EvidenceBearing,
}

impl EvidenceRole {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LeadOnly => "lead_only",
            Self::EvidenceBearing => "evidence_bearing",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum VerificationLevel {
    ReferenceOnly,
    Reachable,
    QueryAccepted,
    ResultParsed,
    EvidenceVerified,
}

impl VerificationLevel {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReferenceOnly => "reference_only",
            Self::Reachable => "reachable",
            Self::QueryAccepted => "query_accepted",
            Self::ResultParsed => "result_parsed",
            Self::EvidenceVerified => "evidence_verified",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilityDescriptor {
    pub id: &'static str,
    pub name: &'static str,
    pub category: ModuleCategory,
    pub accepted_kinds: &'static [EntityKind],
    pub emitted_kinds: &'static [EntityKind],
    pub mode: RetrievalMode,
    pub access: AccessClass,
    pub transform: ValueTransform,
    pub evidence_role: EvidenceRole,
    pub route_template: Option<&'static str>,
    pub reference_url: &'static str,
    pub verification: VerificationLevel,
    pub verified_at_unix: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityRoute {
    pub capability_id: &'static str,
    pub capability_name: &'static str,
    pub category: ModuleCategory,
    pub mode: RetrievalMode,
    pub access: AccessClass,
    pub evidence_role: EvidenceRole,
    pub verification: VerificationLevel,
    pub verified_at_unix: Option<u64>,
    pub reference_url: &'static str,
    pub url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RegistryError {
    #[error("capability id is empty")]
    EmptyId,
    #[error("duplicate capability id: {0}")]
    DuplicateId(&'static str),
    #[error("pivot-only capability must be lead-only: {0}")]
    PivotMustBeLeadOnly(&'static str),
    #[error("pivot-only capability must not declare emitted evidence kinds: {0}")]
    PivotMustNotEmit(&'static str),
    #[error("pivot-only capability needs exactly one {{value}} route template: {0}")]
    InvalidPivotTemplate(&'static str),
    #[error("capability accepts no seed kinds: {0}")]
    NoAcceptedKinds(&'static str),
    #[error("verified capability state is missing an observation time: {0}")]
    MissingVerificationTime(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityRegistry {
    capabilities: Vec<CapabilityDescriptor>,
}

impl CapabilityRegistry {
    pub fn new(capabilities: &[CapabilityDescriptor]) -> Result<Self, RegistryError> {
        let mut ids = BTreeSet::new();
        for descriptor in capabilities {
            validate_descriptor(descriptor)?;
            if !ids.insert(descriptor.id) {
                return Err(RegistryError::DuplicateId(descriptor.id));
            }
        }
        Ok(Self {
            capabilities: capabilities.to_vec(),
        })
    }

    #[must_use]
    pub fn capabilities(&self) -> &[CapabilityDescriptor] {
        &self.capabilities
    }

    #[must_use]
    pub fn routes_for(&self, kind: &EntityKind, value: &str) -> Vec<CapabilityRoute> {
        self.capabilities
            .iter()
            .filter(|descriptor| {
                descriptor.mode == RetrievalMode::PivotOnly
                    && descriptor.accepted_kinds.iter().any(|candidate| candidate == kind)
            })
            .filter_map(|descriptor| render_route(descriptor, value))
            .collect()
    }
}

fn validate_descriptor(descriptor: &CapabilityDescriptor) -> Result<(), RegistryError> {
    if descriptor.id.trim().is_empty() {
        return Err(RegistryError::EmptyId);
    }
    if descriptor.accepted_kinds.is_empty() {
        return Err(RegistryError::NoAcceptedKinds(descriptor.id));
    }
    if descriptor.verification > VerificationLevel::ReferenceOnly
        && descriptor.verified_at_unix.is_none()
    {
        return Err(RegistryError::MissingVerificationTime(descriptor.id));
    }
    if descriptor.mode == RetrievalMode::PivotOnly {
        if descriptor.evidence_role != EvidenceRole::LeadOnly {
            return Err(RegistryError::PivotMustBeLeadOnly(descriptor.id));
        }
        if !descriptor.emitted_kinds.is_empty() {
            return Err(RegistryError::PivotMustNotEmit(descriptor.id));
        }
        if descriptor
            .route_template
            .is_none_or(|template| template.matches("{value}").count() != 1)
        {
            return Err(RegistryError::InvalidPivotTemplate(descriptor.id));
        }
    }
    Ok(())
}

fn render_route(descriptor: &CapabilityDescriptor, raw: &str) -> Option<CapabilityRoute> {
    let value = transform_value(descriptor.transform, raw)?;
    if value.is_empty() {
        return None;
    }
    let encoded = percent_encode_component(&value);
    let template = descriptor.route_template?;
    Some(CapabilityRoute {
        capability_id: descriptor.id,
        capability_name: descriptor.name,
        category: descriptor.category,
        mode: descriptor.mode,
        access: descriptor.access,
        evidence_role: descriptor.evidence_role,
        verification: descriptor.verification,
        verified_at_unix: descriptor.verified_at_unix,
        reference_url: descriptor.reference_url,
        url: template.replace("{value}", &encoded),
    })
}

fn transform_value(transform: ValueTransform, raw: &str) -> Option<String> {
    match transform {
        ValueTransform::Preserve => {
            let value = raw.trim();
            (!value.is_empty()).then(|| value.to_string())
        }
        ValueTransform::CanonicalDomain => canonical_domain(raw),
        ValueTransform::BareUsername => {
            let value = raw.trim();
            let bare = value.strip_prefix('@').unwrap_or(value);
            if bare.is_empty()
                || bare.starts_with('@')
                || bare.chars().any(char::is_whitespace)
            {
                None
            } else {
                Some(bare.to_string())
            }
        }
    }
}

fn percent_encode_component(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in raw.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push(char::from(HEX[usize::from(byte >> 4)]));
            out.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOMAINS: &[EntityKind] = &[EntityKind::Domain];

    fn descriptor() -> CapabilityDescriptor {
        CapabilityDescriptor {
            id: "domain",
            name: "Domain pivot",
            category: ModuleCategory::Search,
            accepted_kinds: DOMAINS,
            emitted_kinds: &[],
            mode: RetrievalMode::PivotOnly,
            access: AccessClass::Public,
            transform: ValueTransform::CanonicalDomain,
            evidence_role: EvidenceRole::LeadOnly,
            route_template: Some("https://example.test/{value}"),
            reference_url: "https://example.test/",
            verification: VerificationLevel::ReferenceOnly,
            verified_at_unix: None,
        }
    }

    #[test]
    fn higher_verification_states_require_observation_time() {
        let mut item = descriptor();
        item.verification = VerificationLevel::Reachable;
        assert_eq!(
            CapabilityRegistry::new(&[item]),
            Err(RegistryError::MissingVerificationTime("domain"))
        );
        item.verified_at_unix = Some(1);
        assert!(CapabilityRegistry::new(&[item]).is_ok());
    }

    #[test]
    fn malformed_bare_username_is_not_guessed() {
        assert_eq!(transform_value(ValueTransform::BareUsername, "@@octocat"), None);
        assert_eq!(transform_value(ValueTransform::BareUsername, "@"), None);
        assert_eq!(
            transform_value(ValueTransform::BareUsername, "@octocat"),
            Some("octocat".to_string())
        );
    }
}
