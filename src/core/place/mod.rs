//! `core::place` — what a `Coordinates` value can honestly be said to locate.
//!
//! A coordinate is always printed to six decimals, which reads as a point
//! good to a doorway. Most of the coordinates a scan holds are nothing of the
//! kind: a gazetteer CENTROID standing in for a city (`-27.4698,153.0251` is
//! the tabulated Brisbane centroid, whatever address was geocoded to it), a
//! forward geocode that can be no finer than the words it was asked about, a
//! postcode's representative point, a named map feature near something else.
//! Printing any of those as "123 Adelaide St" — the street that happens to
//! contain the centroid — manufactures a precision nobody observed.
//!
//! This module is the ONE authority on that precision:
//! [`grain::assess`] grades a coordinate from the provenance of its evidence
//! (who produced it, and what they said they matched) onto a fixed ladder
//! ([`grain::FixGrain`]: point, street, suburb, locality, region, country), and
//! says what a centroid STANDS FOR. The engine's admission-time stamp
//! (`engine::enrich::enrich_geospatial`), its pivot gate (`is_coarse_geo`) and
//! the correlator's fusion radius (`best_precision_radius_m`) all read it, so
//! "is this an area?" and "how precise is this?" have one answer everywhere
//! (REQ-GEOLABEL-001).

pub mod grain;

pub use grain::{FixBasis, FixGrain, FixPrecision, StandsFor, assess};

#[cfg(test)]
mod tests;
