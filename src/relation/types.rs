use serde::{Deserialize, Serialize};

use crate::entity::{EntityKind, normalise, unix_now};
use crate::sha256::{hex32, sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationKind {
    SubdomainOf,
    BelongsToDomain,
    HostedOn,
    ResolvesTo,
    RegisteredBy,
    CoLocatedWith,
    DerivedFrom,
    IdentifiedBy,
    AliasOf,
    LocatedAt,
    AssociatedWith,
    SameAs,
    SameOperator,
    SameIdentity,
    SharesSecretWith,
    EmployedBy,
    OfficerOf,
    MemberOf,
    ControlledBy,
    OperatedBy,
}

impl RelationKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
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
            Self::EmployedBy => "employed_by",
            Self::OfficerOf => "officer_of",
            Self::MemberOf => "member_of",
            Self::ControlledBy => "controlled_by",
            Self::OperatedBy => "operated_by",
        }
    }

    #[must_use]
    pub const fn binds_identity(self) -> bool {
        !matches!(
            self,
            Self::AssociatedWith
                | Self::EmployedBy
                | Self::OfficerOf
                | Self::MemberOf
                | Self::LocatedAt
                | Self::ControlledBy
                | Self::OperatedBy
                | Self::SameOperator
        )
    }
}

impl std::fmt::Display for RelationKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Relation {
    pub id: String,
    pub from_uid: String,
    pub to_uid: String,
    pub kind: RelationKind,
    pub confidence: f64,
    pub scan_id: String,
    pub observed_at: u64,
}

impl Relation {
    #[must_use]
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
        let material = format!("{from_uid}|{}|{to_uid}|{scan_id}", kind.as_str());
        Self {
            id: hex32(&sha256(material.as_bytes())),
            from_uid,
            to_uid,
            kind,
            confidence: if confidence.is_finite() {
                confidence.clamp(0.0, 1.0)
            } else {
                0.0
            },
            scan_id,
            observed_at: unix_now(),
        }
    }
}

#[must_use]
pub fn domain_key(raw: &str) -> String {
    normalise(&EntityKind::Domain, raw)
}

#[must_use]
pub fn is_identity_kind(kind: &EntityKind) -> bool {
    matches!(
        kind,
        EntityKind::Person
            | EntityKind::Email
            | EntityKind::Username
            | EntityKind::Phone
            | EntityKind::Document
            | EntityKind::Credential
            | EntityKind::ApiKey
    )
}
