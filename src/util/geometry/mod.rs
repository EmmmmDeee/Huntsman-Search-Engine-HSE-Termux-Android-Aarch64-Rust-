//! Planar computational geometry over `(lat, lon)` coordinates.
//!
//! The convex location-estimation toolkit, split out of [`super::geohash`] so the
//! geospatial-*encoding* concerns (geohash, timezone, address parsing) and the
//! convex-*geometry* estimators each live in one focused module:
//!
//!   * [`geo_footprint`] — convex hull (Andrew's monotone chain) + centroid + diameter
//!   * [`min_enclosing_circle`] — Welzl's 1-centre (Chebyshev / L∞)
//!   * [`geometric_median`] / [`weighted_geometric_median`] — Weiszfeld's
//!     algorithm (Weber point / L1, robust; the weighted form is also
//!     confidence-aware)
//!   * [`weighted_centroid`] — confidence-weighted convex combination
//!   * [`location_fix`] — every estimator bundled, with consistent fallbacks
//!   * [`point_in_convex_hull`] — hull-membership test
//!
//! The hull and circle are fitted in planar (lon, lat) degree space — exact for
//! the bounding question at city/region scale — while every *distance* is the
//! true great-circle kilometre via the spherical [`super::geohash::haversine_km`].
//! All functions are pure, deterministic, and dependency-free.

pub(crate) mod footprint;
pub(crate) mod circle;
pub(crate) mod median;
pub(crate) mod fix;

#[cfg(test)]
mod tests;

// Re-export all public items so callers use `util::geometry::*` as before.
pub use footprint::{GeoFootprint, geo_footprint};
pub use circle::{EnclosingCircle, min_enclosing_circle};
pub use median::{geometric_median, weighted_geometric_median, median_distance_km, weighted_centroid};
pub use fix::{point_in_convex_hull, LocationFix, location_fix};
