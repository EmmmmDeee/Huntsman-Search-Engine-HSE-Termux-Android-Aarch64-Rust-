//! Entity-invariant validation framework.
//!
//! Centralises the small-but-frequent validation checks that used to
//! live scattered across modules (phone normalisation in
//! `util::address_au`, IP private-range filtering in `oathnet_pro`,
//! local-domain skip in `oathnet_pro`, address state/postcode plausibility
//! in `util::address_au`). Each validator returns a [`ValidationReport`]
//! so modules can decide whether to accept, downgrade, or drop the
//! candidate entity uniformly.
//!
//! Coordinate bounds and domain-shape checking were never actually
//! centralised here in practice, despite an earlier version of this doc
//! comment claiming otherwise: every real caller already used (and still
//! uses) `util::geo::is_valid_coords`/`util::geohash::parse_coords` and
//! `util::domains`'s own shape checks directly. Pass 25 removed the two
//! resulting zero-caller validators (`validate_coordinates`,
//! `validate_domain_shape`) rather than leave a plausible-looking second
//! authority that nothing actually called — see `git log` on this file
//! for the deleted implementations if one is ever needed again.
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

mod confusable;
mod domain;
mod email;
mod ip;
mod phone;
mod placeholder;
mod report;

#[cfg(test)]
mod tests;

pub use confusable::{
    is_confusable_mixed_script, looks_like_gibberish_name, skeleton, strip_invisible,
};
pub use domain::is_onion_url;
pub use email::{email_local, is_role_mailbox, validate_email_syntax};
pub use ip::{is_bogus_ip, is_cdn_edge_ip, is_non_routable_ip, untrusted_ip_geo_reason};
pub use phone::{to_e164_au, validate_phone_e164};
pub use placeholder::{
    is_fragment_value, is_placeholder_domain, is_placeholder_entity, is_specific_residence,
    is_username_derived_name, is_whois_privacy_placeholder,
};
pub use report::ValidationReport;
