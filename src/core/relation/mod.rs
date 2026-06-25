//! `core::relation` — typed entity-to-entity edges: the attribution-pathway
//! layer of the entity graph.
//!
//! # Determinism (architecture invariant)
//! Like the correlator, this layer is **pure open math** — no inference, no
//! fuzzy matching, no LLM. Every edge is derived from concrete, normalised
//! entity values, so the same entity set always produces the same relations.
//!
//! # Edge families
//! Post-scan **structural** builder (`derive_structural`) links entities by
//! canonical value:
//!   - `SubdomainOf`     — Domain → its closest present parent Domain
//!   - `BelongsToDomain` — Email  → the Domain of its address
//!   - `HostedOn`        — Url    → the Domain of its host
//!
//! `derive_colocation` links `CoLocatedWith` between Coordinates within
//! `CO_LOCATION_KM` (Haversine via `util::geohash`). `derive_resolution` links
//! `ResolvesTo` (Domain → IpAddress) by matching an IP entity's DNS evidence
//! against present Domain nodes. `derive_registration` links `RegisteredBy`
//! (Domain → registrant Organisation/Email) from WHOIS evidence.
//! `derive_co_ownership` links `SameOperator` (Domain ↔ Domain, canonical
//! min-uid direction) from shared registrant, shared dedicated IP, or shared
//! web-analytics ID evidence. `derive_profile_links` links `SameIdentity`
//! (Username → social-platform profile Url) by matching the embedded handle
//! in the URL against present Username entities. All run in `finalise_scan`
//! via `derive_all`.
//!
//! `DerivedFrom` (child → the entity whose expansion surfaced it) is **lineage**
//! — recorded by the engine's `run_expansion` (not a post-scan builder) and
//! persisted alongside the above.

pub(crate) mod builders;
pub(crate) mod types;

#[cfg(test)]
mod tests;

pub use builders::{
    CO_LOCATION_KM, derive_all, derive_co_ownership, derive_colocation, derive_name_lineage,
    derive_profile_links, derive_registration, derive_resolution, derive_structural,
};
pub use types::{Relation, RelationKind};
