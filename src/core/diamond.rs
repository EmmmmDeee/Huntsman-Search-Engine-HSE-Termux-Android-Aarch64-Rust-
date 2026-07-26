//! Diamond Model vertex classification — the objective, deterministic mapping
//! from an [`EntityKind`] to its role in the **Diamond Model of Intrusion
//! Analysis** (Caltagirone, Pendergast & Betz, 2013), applied to the
//! subject-centric OSINT this engine performs.
//!
//! The Diamond Model's power for OSINT is that its atomic operation is
//! *pivoting* across four vertices — Adversary, Capability, Infrastructure,
//! Victim — which is exactly what the correlator's relation graph does. Tagging
//! every entity with the vertex it populates turns a flat entity list into a
//! Diamond-structured attribution view.
//!
//! Scope, stated honestly: this is a **deterministic** classifier — the same
//! kind always yields the same vertex, with no per-run analyst judgment. That is
//! NOT the same as the *taxonomy* being objective: which vertex each kind belongs
//! to is a modelling choice frozen into the match arms below, and a few are
//! genuinely arguable (a `CryptoAddress` as Infrastructure vs Capability; a
//! `Coordinates` as Infrastructure vs a Victim attribute). The
//! `GET /scans/{id}/diamond` endpoint surfaces the per-kind breakdown precisely
//! so those calls are inspectable against real output rather than hidden inside a
//! vertex total. Determinism is the guarantee; correctness of the taxonomy is a
//! reviewable convention, not a theorem.
//!
//! ## Mapping rationale (subject-centric adaptation)
//!
//! The classic Diamond is adversary-centric (characterising an attacker); HSE
//! characterises a *subject*, so the vertices are read as:
//!   * [`Victim`](DiamondVertex::Victim) — the identity being characterised: the
//!     subject and any co-referent identity facet (person, email, phone, handle,
//!     organisation).
//!   * [`Infrastructure`](DiamondVertex::Infrastructure) — the assets, locations,
//!     devices, network artefacts and pivotable account identifiers the subject
//!     uses or is placed by.
//!   * [`Capability`](DiamondVertex::Capability) — the exposed secrets that can be
//!     leveraged (credentials, API keys, passwords): the subject's *exposure
//!     surface*.
//!   * [`Adversary`](DiamondVertex::Adversary) — deliberately **not** produced by
//!     this kind-based classifier. In subject-centric OSINT no entity *kind* is
//!     intrinsically the adversary; that role is **relational** — an associate
//!     `Person` becomes Adversary-adjacent only through a declared relationship,
//!     which the relation layer assigns, not the entity taxonomy. Keeping it out
//!     of the total function is the honest choice: the classifier never fabricates
//!     an adversary it cannot objectively derive.

use serde::{Deserialize, Serialize};

use super::entity::{Entity, EntityKind};

/// The four canonical vertices of the Diamond Model. Ordered
/// (`Adversary < Capability < Infrastructure < Victim`) so it is a usable
/// `BTreeMap` key for a deterministic, vertex-grouped view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiamondVertex {
    /// A distinct actor. Not assigned by [`EntityKind::diamond_vertex`] — it is a
    /// relational role (see the module doc), reachable only via the relation graph.
    Adversary,
    /// A leverageable exposed secret — the subject's exposure surface.
    Capability,
    /// An asset, location, device, network artefact, or pivotable account id.
    Infrastructure,
    /// An identity facet of the subject being characterised.
    Victim,
}

impl DiamondVertex {
    /// Stable lowercase identifier — the serialised form, safe to embed in JSON
    /// output, tags, and reports. Kept in sync with the `serde` rename.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Adversary => "adversary",
            Self::Capability => "capability",
            Self::Infrastructure => "infrastructure",
            Self::Victim => "victim",
        }
    }
}

impl std::fmt::Display for DiamondVertex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl EntityKind {
    /// This kind's Diamond Model vertex — a total, deterministic classification
    /// requiring no analyst judgment. The match is **exhaustive with no wildcard
    /// arm on purpose**: adding a new `EntityKind` is then a compile error until
    /// its vertex is assigned, so the mapping can never silently fall out of date.
    ///
    /// Never returns [`DiamondVertex::Adversary`] — that vertex is relational, not
    /// intrinsic to a kind (see the module documentation).
    #[must_use]
    pub fn diamond_vertex(&self) -> DiamondVertex {
        match self {
            // Identity facets of the subject under characterisation — including
            // government identity documents, which name WHO the subject is.
            Self::Person
            | Self::Email
            | Self::Phone
            | Self::Username
            | Self::Organisation
            | Self::AbnAcn
            | Self::Passport
            | Self::DriverLicence
            | Self::TaxId
            | Self::NationalId
            | Self::DateOfBirth => DiamondVertex::Victim,

            // Leverageable exposed secrets — the exposure surface.
            Self::Credential | Self::ApiKey | Self::Password => DiamondVertex::Capability,

            // Assets, locations, devices, network artefacts, and pivotable
            // account identifiers (a tracking id / wallet is a linking artefact,
            // not a secret — it pivots like a domain or handle).
            Self::IpAddress
            | Self::Domain
            | Self::Url
            | Self::Asn
            | Self::Cidr
            | Self::Address
            | Self::Coordinates
            | Self::MacAddress
            | Self::DeviceId
            | Self::Ssid
            | Self::TrackingId
            | Self::CryptoAddress
            // Financial rails, vehicle assets, and digital artefacts are all
            // same-owner linking artefacts that pivot like a wallet/domain — not
            // secrets and not identity facets.
            | Self::Iban
            | Self::PayId
            | Self::BankAccount
            | Self::CreditCard
            | Self::SwiftBic
            | Self::VehicleRegistration
            | Self::Vin
            | Self::FileHash
            | Self::Imei => DiamondVertex::Infrastructure,

            // Catch-all kind: an unclassified artefact in the picture defaults to
            // Infrastructure (the neutral "a node in the graph" role) rather than
            // over-claiming it as an identity or a secret.
            Self::Other(_) => DiamondVertex::Infrastructure,
        }
    }
}

impl Entity {
    /// This entity's Diamond Model vertex — a convenience delegate to
    /// [`EntityKind::diamond_vertex`].
    #[must_use]
    pub fn diamond_vertex(&self) -> DiamondVertex {
        self.kind.diamond_vertex()
    }
}

/// Partition entities by their Diamond vertex, preserving input order within
/// each vertex. Deterministic (`BTreeMap` keyed by the ordered vertex) — the
/// vertex-grouped analytic view an OSINT product renders over a scan's graph.
#[must_use]
pub fn partition_by_vertex(
    entities: &[Entity],
) -> std::collections::BTreeMap<DiamondVertex, Vec<&Entity>> {
    let mut out: std::collections::BTreeMap<DiamondVertex, Vec<&Entity>> =
        std::collections::BTreeMap::new();
    for e in entities {
        out.entry(e.diamond_vertex()).or_default().push(e);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ent(kind: EntityKind) -> Entity {
        Entity::new(kind, "v", 0.5, "s")
    }

    #[test]
    fn identity_kinds_are_victim() {
        for k in [
            EntityKind::Person,
            EntityKind::Email,
            EntityKind::Phone,
            EntityKind::Username,
            EntityKind::Organisation,
            EntityKind::AbnAcn,
        ] {
            assert_eq!(k.diamond_vertex(), DiamondVertex::Victim, "{k:?}");
        }
    }

    #[test]
    fn exposed_secret_kinds_are_capability() {
        for k in [
            EntityKind::Credential,
            EntityKind::ApiKey,
            EntityKind::Password,
        ] {
            assert_eq!(k.diamond_vertex(), DiamondVertex::Capability, "{k:?}");
        }
    }

    #[test]
    fn asset_and_pivot_kinds_are_infrastructure() {
        for k in [
            EntityKind::IpAddress,
            EntityKind::Domain,
            EntityKind::Url,
            EntityKind::Asn,
            EntityKind::Cidr,
            EntityKind::Address,
            EntityKind::Coordinates,
            EntityKind::MacAddress,
            EntityKind::DeviceId,
            EntityKind::Ssid,
            EntityKind::TrackingId,
            EntityKind::CryptoAddress,
            EntityKind::Other("x".into()),
        ] {
            assert_eq!(k.diamond_vertex(), DiamondVertex::Infrastructure, "{k:?}");
        }
    }

    #[test]
    fn classifier_never_emits_adversary() {
        // Adversary is relational, never intrinsic to a kind — a property callers
        // rely on when they add the relational refinement layer on top.
        for k in [
            EntityKind::Person,
            EntityKind::Email,
            EntityKind::Password,
            EntityKind::IpAddress,
            EntityKind::CryptoAddress,
            EntityKind::Other("x".into()),
        ] {
            assert_ne!(k.diamond_vertex(), DiamondVertex::Adversary, "{k:?}");
        }
    }

    #[test]
    fn as_str_matches_serde_rename() {
        assert_eq!(DiamondVertex::Adversary.as_str(), "adversary");
        assert_eq!(DiamondVertex::Capability.as_str(), "capability");
        assert_eq!(DiamondVertex::Infrastructure.as_str(), "infrastructure");
        assert_eq!(DiamondVertex::Victim.as_str(), "victim");
        // Display delegates to as_str.
        assert_eq!(DiamondVertex::Victim.to_string(), "victim");
    }

    #[test]
    fn partition_groups_by_vertex_in_input_order() {
        let ents = [
            ent(EntityKind::Person),
            ent(EntityKind::Domain),
            ent(EntityKind::Email),
            ent(EntityKind::Password),
        ];
        let by = partition_by_vertex(&ents);
        assert_eq!(by[&DiamondVertex::Victim].len(), 2); // Person + Email
        assert_eq!(by[&DiamondVertex::Infrastructure].len(), 1); // Domain
        assert_eq!(by[&DiamondVertex::Capability].len(), 1); // Password
        assert!(!by.contains_key(&DiamondVertex::Adversary));
    }
}
