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
    /// `from` (a Person) is identified by `to` (an Email / Username / Phone) — an
    /// identifier bound to the person either by an owner/name field in the
    /// identifier's own evidence, or by an identity-fingerprint match to the
    /// subject. The edge that turns a pile of orphan handles into *one person's*
    /// account footprint.
    IdentifiedBy,
    /// `from` and `to` are the same online persona — an Email and a Username, or
    /// two Emails, sharing one normalised handle / local-part. The cross-platform
    /// "same username everywhere" pivot. Symmetric; emitted smaller-UID → larger.
    AliasOf,
    /// `from` (a Person) is located at `to` (an Address or Coordinates) — bound by
    /// an owner / resident field in the place's evidence, or because the place
    /// exactly matched the subject's name during the scan (`exact-name-match`).
    LocatedAt,
    /// `from` and `to` are associated people — a kinship / associate *candidate*
    /// bound by a shared surname. Symmetric; emitted smaller-UID → larger. A lead
    /// (carries a damped confidence) for the operator to confirm, surfacing the
    /// subject's human network the way the infra builders surface their estate.
    AssociatedWith,
    /// `from` and `to` are the SAME real-world entity observed in two disparate
    /// contexts — a reflexive self-pairing the canonical resolver
    /// ([`crate::core::resolve`]) proved: a Gmail address and its dotted / `+tag`
    /// variant, one phone in two formats, a name and its reordering. Distinct from
    /// [`AliasOf`](RelationKind::AliasOf) (a shared persona across DIFFERENT
    /// identifiers): `SameAs` asserts ONE identity in two representations, the
    /// edge that collapses contextual variants of a seed into a single node for
    /// traversal. Symmetric; emitted smaller-UID → larger.
    SameAs,
    /// `from` and `to` (both Domain entities) share the same operator — inferred
    /// from a shared WHOIS registrant, shared dedicated IP, or shared web-analytics
    /// ID (GA/GTM/pixel). The infrastructure-layer counterpart of
    /// [`AssociatedWith`](RelationKind::AssociatedWith): where that links *people*
    /// a document co-names, this links *domains* an operator co-controls. Symmetric;
    /// emitted smaller-UID → larger.
    SameOperator,
    /// `from` (a [`Username`](crate::core::entity::EntityKind::Username)) is the
    /// authenticated identity behind `to` (a [`Url`](crate::core::entity::EntityKind::Url)
    /// that is a social-platform profile page). The edge that makes the identity hub
    /// explicit in the graph: a Username entity and the profile URL whose embedded
    /// handle matches it — case-insensitively, across every supported social platform.
    /// Directed `Username → Url`.
    SameIdentity,
    /// `from` and `to` (both Email or Username entities) are proven tied to
    /// ONE controller by a reused, individuating secret — a salted password
    /// hash, session token, wallet address, API key, or a plaintext password
    /// corroborated across ≥2 independent sources (the same admission gate
    /// the AU-047 correlation fires on; see
    /// [`Secret::classify`](crate::core::correlator::Secret::classify)).
    /// Distinct from [`AssociatedWith`](RelationKind::AssociatedWith) (a
    /// damped, lower-confidence *candidate* tie): this edge asserts a proven
    /// shared-secret link, the graph-native counterpart of the "controller
    /// behind reused secrets" correlator finding. Symmetric; emitted
    /// smaller-UID → larger.
    SharesSecretWith,
}

impl RelationKind {
    /// The edge kind's stable snake_case tag — identical to the serde wire form
    /// and the stored `relations.kind` column, so the DB value and the API/SPA
    /// edge label can never drift (pinned by a test).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SubdomainOf => "subdomain_of",
            Self::BelongsToDomain => "belongs_to_domain",
            Self::HostedOn => "hosted_on",
            Self::ResolvesTo => "resolves_to",
            Self::RegisteredBy => "registered_by",
            Self::CoLocatedWith => "co_located_with",
            Self::DerivedFrom => "derived_from",
            Self::IdentifiedBy => "identified_by",
            Self::AliasOf => "alias_of",
            Self::LocatedAt => "located_at",
            Self::AssociatedWith => "associated_with",
            Self::SameAs => "same_as",
            Self::SameOperator => "same_operator",
            Self::SameIdentity => "same_identity",
            Self::SharesSecretWith => "shares_secret_with",
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
    /// A typed edge `from → to` of `kind`, with a deterministic id
    /// (`hex(SHA-256("from|kind|to|scan"))`) so storage upserts idempotently — a
    /// re-scan never duplicates an edge. `confidence` is clamped to `0.0..=1.0`.
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
