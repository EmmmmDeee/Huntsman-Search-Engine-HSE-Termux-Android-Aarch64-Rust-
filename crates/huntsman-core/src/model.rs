//! Entity types, canonicalization, and immutable provenance primitives.

use crate::error::HuntsmanError;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// 256-bit cryptographic identifier derived deterministically.
pub type EntityId = [u8; 32];

/// Epistemic validation tier for ingested indicators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EpistemicLevel {
    /// Directly observed over the wire (handshakes, protocol banners, active DNS).
    DirectObservation,
    /// Extracted from append-only cryptographic systems (Certificate Transparency).
    ProtocolLog,
    /// Observational evidence node from third-party indexes or exposure dumps.
    ThirdPartyIndex,
}

/// Immutable provenance ledger envelope attached to every observed entity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceEnvelope {
    /// Deterministic node identifier.
    pub entity_id: EntityId,
    /// Originating module identifier.
    pub source_module: String,
    /// UTC timestamp in microseconds since Unix epoch.
    pub observed_at_utc: u64,
    /// BLAKE3 digest of the raw wire payload.
    pub raw_evidence_hash: [u8; 32],
    /// Epistemic classification of this artifact.
    pub epistemic_level: EpistemicLevel,
}

impl ProvenanceEnvelope {
    /// Creates a verified provenance envelope, computing the deterministic entity ID from the
    /// entity's type tag and canonical value and the evidence digest from the raw payload.
    #[must_use]
    pub fn new(
        source_module: &'static str,
        observed_at_utc: u64,
        raw_payload: &[u8],
        kind: &EntityKind,
        epistemic_level: EpistemicLevel,
    ) -> Self {
        let evidence_hash = blake3::hash(raw_payload);
        let mut hasher = blake3::Hasher::new();
        hasher.update(kind.type_tag().as_bytes());
        hasher.update(b":");
        hasher.update(kind.canonical_value().as_bytes());
        let entity_id = *hasher.finalize().as_bytes();

        Self {
            entity_id,
            source_module: source_module.to_string(),
            observed_at_utc,
            raw_evidence_hash: *evidence_hash.as_bytes(),
            epistemic_level,
        }
    }
}

/// Canonical entity variants recognized by the correlation engine.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EntityKind {
    /// Fully qualified domain name (Punycode normalized, ASCII lowercased).
    Domain(String),
    /// Canonical IPv4 or IPv6 address.
    Ip(IpAddr),
    /// Autonomous System Number.
    Asn(u32),
    /// Service banner or cleartext daemon response.
    ServiceBanner {
        /// Target port number.
        port: u16,
        /// Hex-encoded or sanitized representation of banner bytes.
        banner: String,
    },
    /// Observational credential exposure artifact.
    CredentialExposure {
        /// Account identifier or email address.
        identity: String,
        /// Public breach or dump origin descriptor.
        source_dataset: String,
    },
}

impl EntityKind {
    /// Static string representation of the underlying entity variant.
    #[must_use]
    pub fn type_tag(&self) -> &'static str {
        match self {
            Self::Domain(_) => "DOMAIN",
            Self::Ip(_) => "IP",
            Self::Asn(_) => "ASN",
            Self::ServiceBanner { .. } => "BANNER",
            Self::CredentialExposure { .. } => "EXPOSURE",
        }
    }

    /// Serialized canonical string value used for deterministic deduplication.
    #[must_use]
    pub fn canonical_value(&self) -> String {
        match self {
            Self::Domain(d) => d.to_ascii_lowercase(),
            Self::Ip(ip) => ip.to_string(),
            Self::Asn(asn) => format!("AS{asn}"),
            Self::ServiceBanner { port, banner } => format!("{port}:{banner}"),
            Self::CredentialExposure {
                identity,
                source_dataset,
            } => {
                format!("{}:{}", identity.to_ascii_lowercase(), source_dataset)
            }
        }
    }

    /// Construct a canonical domain entity with RFC 1035/5891 normalization.
    ///
    /// # Errors
    /// [`HuntsmanError::Protocol`] when the label is empty or exceeds the RFC 1035 length limit.
    pub fn new_domain(raw: &str) -> Result<Self, HuntsmanError> {
        let trimmed = raw.trim().trim_end_matches('.');
        if trimmed.is_empty() || trimmed.len() > 253 {
            return Err(HuntsmanError::Protocol(format!(
                "Invalid domain length: {trimmed}"
            )));
        }
        Ok(Self::Domain(trimmed.to_ascii_lowercase()))
    }
}

/// Fully qualified observed entity carrying its provenance envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entity {
    /// Invariant provenance envelope.
    pub provenance: ProvenanceEnvelope,
    /// Canonical entity descriptor.
    pub kind: EntityKind,
    /// Graph traversal depth from original seed (0-indexed).
    pub hop_depth: u8,
}
