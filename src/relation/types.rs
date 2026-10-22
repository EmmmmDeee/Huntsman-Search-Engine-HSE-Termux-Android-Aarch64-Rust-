use serde::{Deserialize, Serialize};

use crate::clock;
use crate::entity::{Entity, EntityKind, normalise};
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

    /// Whether the relation says its two ends are one identity, so that identity resolution may
    /// merge them and the identity-path rules may walk it.
    ///
    /// An alias, a same-identity assertion, an identifier of a person and a shared secret do. A
    /// shared domain, subdomain, host, address, registrant or location relates different people,
    /// as a shared employer does, and a handle guessed from a name may belong to anyone with
    /// that name, so none of these merges identities. Every kind is named, so a new kind does
    /// not build until it is classified here.
    #[must_use]
    pub const fn binds_identity(self) -> bool {
        match self {
            Self::IdentifiedBy
            | Self::AliasOf
            | Self::SameAs
            | Self::SameIdentity
            | Self::SharesSecretWith => true,
            Self::SubdomainOf
            | Self::BelongsToDomain
            | Self::HostedOn
            | Self::ResolvesTo
            | Self::RegisteredBy
            | Self::CoLocatedWith
            | Self::DerivedFrom
            | Self::LocatedAt
            | Self::AssociatedWith
            | Self::SameOperator
            | Self::EmployedBy
            | Self::OfficerOf
            | Self::MemberOf
            | Self::ControlledBy
            | Self::OperatedBy => false,
        }
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
    /// The one piece of evidence this relation rests on with others, named `kind:value`, such as
    /// `handle:jsmith` for a handle that many addresses share: every two of them are aliases, and
    /// each of those relations rests on the handle. Pathway counting counts a basis once, however
    /// many relations rest on it. `None` means the relation rests on the link between its own two
    /// entities.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub basis: Option<String>,
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
            observed_at: clock::unix_now(),
            basis: None,
        }
    }

    /// This relation, resting on `basis` (see [`Relation::basis`]).
    #[must_use]
    pub fn with_basis(mut self, basis: impl Into<String>) -> Self {
        self.basis = Some(basis.into());
        self
    }

    /// What this relation rests on: its named basis, or else the link between its two entities,
    /// the same whichever way round the relation runs. Relations that rest on the same thing are
    /// one piece of evidence, however many there are and whatever their kinds.
    #[must_use]
    pub fn rests_on(&self) -> Basis<'_> {
        match self.basis.as_deref() {
            Some(name) => Basis::Named(name),
            None if self.from_uid <= self.to_uid => Basis::Link(&self.from_uid, &self.to_uid),
            None => Basis::Link(&self.to_uid, &self.from_uid),
        }
    }
}

/// What a relation rests on (see [`Relation::rests_on`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Basis<'r> {
    /// A basis that relations name, such as `handle:jsmith`.
    Named(&'r str),
    /// The link between two entities, the smaller uid first, which a relation without a named
    /// basis rests on.
    Link(&'r str, &'r str),
}

/// How strong a relation derived between `left` and `right` may be: as strong as the weaker of
/// the two entities it joins.
pub(super) fn endpoint_confidence(left: &Entity, right: &Entity) -> f64 {
    left.confidence.min(right.confidence)
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A relation without a named basis rests on the link between its two entities, whichever
    /// way round it runs and whatever its kind; one with a named basis rests on that.
    #[test]
    fn a_relation_rests_on_its_basis_or_else_its_link() {
        let forward = Relation::new("a", "b", RelationKind::AliasOf, 0.9, "s");
        let back = Relation::new("b", "a", RelationKind::SameAs, 0.9, "s");
        assert_eq!(forward.rests_on(), Basis::Link("a", "b"));
        assert_eq!(back.rests_on(), forward.rests_on());
        let named = back.clone().with_basis("handle:jsmith");
        assert_eq!(named.rests_on(), Basis::Named("handle:jsmith"));
        assert_ne!(named.rests_on(), back.rests_on());
    }

    /// A relation derived between two entities is as strong as the weaker of them, whichever
    /// way round it runs.
    #[test]
    fn a_derived_relation_is_as_strong_as_its_weaker_end() {
        let strong = Entity::new(EntityKind::Email, "ann@example.com", 0.9, "s");
        let weak = Entity::new(EntityKind::Username, "ann", 0.4, "s");
        assert!((endpoint_confidence(&strong, &weak) - 0.4).abs() < 1e-12);
        assert!((endpoint_confidence(&weak, &strong) - 0.4).abs() < 1e-12);
        assert!((endpoint_confidence(&strong, &strong) - 0.9).abs() < 1e-12);
    }
}
