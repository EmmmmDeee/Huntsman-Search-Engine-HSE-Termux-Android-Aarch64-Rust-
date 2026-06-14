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

#[cfg(test)]
mod tests;
