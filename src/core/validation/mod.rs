//! Entity-invariant validation framework.
//!
//! Centralises the small-but-frequent validation checks that used to
//! live scattered across modules (phone normalisation in
//! `util::address_au`, IP private-range filtering in `oathnet_pro`,
//! local-domain skip in `oathnet_pro`, coordinate bounds in
//! `util::geohash::parse_coords`, address state/postcode plausibility
//! in `util::address_au`). Each validator returns a [`ValidationReport`]
//! so modules can decide whether to accept, downgrade, or drop the
//! candidate entity uniformly.
//!
//! Design properties:
//!
//!  * Pure functions; no I/O, no allocation in the hot path beyond
//!    what the caller provides.
//!  * Fail-explicit: every rejection carries a machine-readable
//!    `reason` plus a human-readable `detail`.
//!  * Validators compose: a caller may run multiple validators and
//!    union the resulting reports.
//!  * Stable: adding a new validator does not change existing
//!    validator signatures, preserving binary compatibility for
//!    downstream modules.

mod composite;
mod coordinates;
mod domain;
mod email;
mod ip;
mod phone;
mod placeholder;
mod report;

#[cfg(test)]
mod tests;

pub use composite::validate_for_kind;
pub use coordinates::validate_coordinates;
pub use domain::validate_domain_shape;
pub use email::validate_email_syntax;
pub use ip::{is_bogus_ip, is_cdn_edge_ip, is_non_routable_ip};
pub use phone::validate_phone_e164;
pub use placeholder::{
    is_fragment_value, is_placeholder_domain, is_placeholder_entity, is_specific_residence,
};
pub use report::ValidationReport;
