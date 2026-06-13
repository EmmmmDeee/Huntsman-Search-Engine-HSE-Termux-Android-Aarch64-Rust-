use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::core::entity::{EntityKind, unix_now};

/// The typed edge between two entities. Stable snake_case serde tags so the
/// (future) SPA force-graph can switch on `rel.kind` directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationKind {
    /// `from` (a Domain) is a subdomain of `to` (its closest present parent).
    SubdomainOf,
    /// `from` (an Email) belongs to `to` (the Domain of its address).
    BelongsToDomain,
    /// `from` (a Url) is hosted on `to` (the Domain of its host).
    HostedOn,
    /// `from` (a Domain) resolves to `to` (an IpAddress) — derived from DNS
    /// evidence on the IP entity (A/AAAA records).
    ResolvesTo,
    /// `from` (a Domain) is registered by `to` (an Organisation or Email) —
    /// derived from WHOIS registrant evidence on the Domain entity.
    RegisteredBy,
    /// `from` and `to` are Coordinates within `CO_LOCATION_KM` of each other —
    /// the same locality, surfaced by independent sources.
    CoLocatedWith,
    /// `from` was discovered by pivoting on `to` during expansion (lineage).
    DerivedFrom,
}

impl RelationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SubdomainOf => "subdomain_of",
            Self::BelongsToDomain => "belongs_to_domain",
            Self::HostedOn => "hosted_on",
            Self::ResolvesTo => "resolves_to",
            Self::RegisteredBy => "registered_by",
            Self::CoLocatedWith => "co_located_with",
            Self::DerivedFrom => "derived_from",
        }
    }
}

impl std::fmt::Display for RelationKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A directed, typed edge between two entities (referenced by UID).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Relation {
    /// Deterministic id: `hex(SHA-256("from|kind|to|scan"))`. Lets storage
    /// upsert idempotently so re-scans don't duplicate edges.
    pub id: String,
    pub from_uid: String,
    pub to_uid: String,
    pub kind: RelationKind,
    /// Edge confidence — the weaker of the two endpoints' base confidence,
    /// clamped to [0, 1]. The structural fact itself is certain; this carries
    /// the trust of the endpoints it connects.
    pub confidence: f64,
    pub scan_id: String,
    pub observed_at: u64,
}

impl Relation {
    pub fn new(
        from_uid: impl Into<String>,
        to_uid: impl Into<String>,
        kind: RelationKind,
        confidence: f64,
        scan_id: impl Into<String>,
    ) -> Self {
        let from_uid = from_uid.into();
        let to_uid = to_uid.into();
        let scan_id = scan_id.into();
        let mut h = Sha256::new();
        h.update(from_uid.as_bytes());
        h.update(b"|");
        h.update(kind.as_str().as_bytes());
        h.update(b"|");
        h.update(to_uid.as_bytes());
        h.update(b"|");
        h.update(scan_id.as_bytes());
        Self {
            id: hex::encode(h.finalize()),
            from_uid,
            to_uid,
            kind,
            confidence: confidence.clamp(0.0, 1.0),
            scan_id,
            observed_at: unix_now(),
        }
    }
}

/// Normalise a host/domain string the same way `EntityKind::Domain` does for
/// entity values, so an Email/Url's domain matches the stored Domain entity
/// value. Delegates to the entity normaliser itself rather than re-implementing
/// it: a hand-rolled copy here had already drifted (single `www.` strip vs the
/// normaliser's fixed-point strip, ASCII-only vs full Unicode lowercase), so a
/// `www.www.example.com` URL host silently failed to match the `example.com`
/// Domain entity and the edge was never derived.
pub(super) fn domain_key(raw: &str) -> String {
    crate::core::entity::normalise(&EntityKind::Domain, raw)
}
