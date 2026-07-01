//! `core::relation` — typed entity-to-entity edges: the attribution-pathway
//! layer of the entity graph.
//!
//! # Determinism (architecture invariant)
//! Like the correlator, this layer is **pure, reproducible math** — no LLM, no
//! free inference. Every edge is derived from concrete normalised entity values
//! and recorded evidence, so the same entity set always produces the same edge
//! set + ids. The identity layer reuses the engine's own dictionary-free identity
//! primitives ([`crate::core::scan::identity_overlaps`] / surname keys); the two
//! signals that are inherently candidates (fingerprint ownership, surname
//! kinship) are carried at a *damped* confidence so a lead never reads as a
//! certainty — they remain fully deterministic.
//!
//! # Edge families
//! **Infrastructure** — `derive_structural` links entities by canonical value
//! (`SubdomainOf`, `BelongsToDomain`, `HostedOn`); `derive_colocation` links
//! `CoLocatedWith` between nearby Coordinates (Haversine via `util::geohash`);
//! `derive_resolution` links `ResolvesTo` (Domain → IpAddress) from DNS evidence;
//! `derive_registration` links `RegisteredBy` (Domain → Org/Email) from WHOIS;
//! `derive_name_lineage` links `DerivedFrom` for name-permuted handles.
//!
//! **Identity** (the person-centric graph — otherwise a person scan has nodes but
//! no edges):
//!   - `AliasOf`        — Email/Username sharing one persona key (`derive_handles`)
//!   - `IdentifiedBy`   — Person → their Email/Username/Phone (`derive_identity_ownership`)
//!   - `LocatedAt`      — Person → Address/Coordinates (`derive_residency`)
//!   - `AssociatedWith` — Person ↔ Person: a surname kinship candidate
//!     (`derive_kinship`), a household co-resident at one specific address
//!     (`derive_co_residence` — the DIFFERENT-surname family the surname angle
//!     can't reach), or a DECLARED relative / co-owner
//!     (`derive_declared_associations`, evidence-grounded). They corroborate, so
//!     the family graph forms from any seed angle and from any of the signals.
//!
//! `DerivedFrom` (child → the entity whose expansion surfaced it) is also
//! **lineage** — recorded by the engine's `run_expansion` (not a post-scan
//! builder) and persisted alongside the above. `derive_all` runs every post-scan
//! builder, so the live and import paths produce the identical graph.

pub(crate) mod builders;
pub mod graph;
pub(crate) mod types;

#[cfg(test)]
mod tests;

pub use builders::{
    CO_LOCATION_KM, DERIVE_BUDGET, derive_all, derive_all_within, derive_canonical_identities,
    derive_co_mention, derive_co_ownership, derive_co_residence, derive_colocation,
    derive_coreferences, derive_declared_associations, derive_handles, derive_identity_ownership,
    derive_kinship, derive_name_lineage, derive_profile_links, derive_regional_kinship,
    derive_registration, derive_residency, derive_resolution, derive_shared_selector,
    derive_structural,
};
pub use graph::{
    Adjacency, ConnectionBroker, ConnectionTemplate, IdentityClusterResult, IdentityPath,
    MAX_IDENTITY_UIDS_FOR_PAIRWISE_SEARCH, PathStep, connection_brokers, connection_templates,
    disjoint_pathways, disjoint_pathways_in, identity_paths, identity_uids, is_identity_kind,
    reachable_count, resolve_identity_clusters, sorted_confined_adjacency, strongest_path,
    strongest_path_in, undirected_adjacency,
};
pub use types::{Relation, RelationKind};
