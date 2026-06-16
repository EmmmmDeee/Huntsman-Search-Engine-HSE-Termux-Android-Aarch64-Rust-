//! GEOINT correlation rules, split by domain:
//!
//! * [`jurisdiction`] — country/region/state inference and the coordinate ↔
//!   address jurisdiction cross-check, plus profile-derived locality
//!   (AU-056, AU-058).
//! * [`cluster`] — spatial clustering / convergence of `Coordinates` entities
//!   (AU-014, AU-017, AU-032, AU-057).
//! * [`chain`] — cross-kind geolocation chains and multi-source address /
//!   locality consolidation (AU-013, AU-016, AU-018, AU-026, AU-027, AU-030).
//!
//! See `super::super` (rules/mod.rs) for the shared helpers; every rule reaches
//! them through the `use super::*` → `geo/mod.rs` → `use super::*` chain.

use super::*;

/// Join short tokens (e.g. AU state codes) with `/` for human-readable evidence
/// summaries, preserving the iterator's order. Used by the jurisdiction
/// cross-check to render the per-class state sets a coordinate fix and an
/// address disagree (or agree) on.
fn join_slash<'a>(tokens: impl IntoIterator<Item = &'a str>) -> String {
    let mut acc = String::new();
    for (i, s) in tokens.into_iter().enumerate() {
        if i > 0 {
            acc.push('/');
        }
        acc.push_str(s);
    }
    acc
}

mod chain;
mod cluster;
mod jurisdiction;

pub(in crate::core::correlator) use chain::*;
pub(in crate::core::correlator) use cluster::*;
pub(in crate::core::correlator) use jurisdiction::*;
