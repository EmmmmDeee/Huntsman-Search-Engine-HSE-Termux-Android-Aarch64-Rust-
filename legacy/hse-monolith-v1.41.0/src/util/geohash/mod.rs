//! Geospatial enrichment helpers — geohash, address normalisation,
//! timezone inference, all offline (no API calls, no deps).
//!
//! These functions feed the geo-precision pipeline: every Coordinates
//! entity gets a geohash and timezone attached as evidence; every
//! Address entity gets parsed into structured components so downstream
//! geocode/overpass can resolve it more reliably.

pub mod address;
pub mod country;
pub mod distance;
pub mod encode;
pub mod timezone;

pub use address::{AddressComponents, parse_address};
pub use country::{country_name_for_iso, reverse_country_iso};
pub use distance::haversine_km;
pub use encode::{geohash, parse_coords};
pub use timezone::timezone_for;

/// Coordinates farther apart than this (km) are different localities, not
/// corroborating fixes of the same place — the shared "is this really one
/// consistent location claim, or scattered evidence?" gate.
///
/// Single canonical source for two independent consumers that each state, in
/// their own doc comments, that they match the other: `audit::analysis`'s
/// private self-audit `geo_consistency` check flags a scan's own coordinates
/// as mutually divergent past this radius, and the correlator's AU-098
/// (`rule_au_098_residency_consensus`) suppresses its multi-source residency
/// verdict when the coordinate class's fixes are scattered past it. Before
/// being pointed here, AU-098 independently re-derived this as a hardcoded
/// `300.0` literal that had silently drifted to 2× this value.
pub const GEO_OUTLIER_KM: f64 = 150.0;

#[cfg(test)]
mod tests;
