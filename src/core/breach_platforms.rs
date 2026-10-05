//! The social platforms whose handles breach/stealer records carry as their own
//! columns — the ONE list behind two consumers that must agree:
//!
//! * `modules::breach_rich` mints each present handle as a `platform:handle`
//!   `Username` pivot (tagged `breach`) so the platform-specific modules can
//!   resolve it; and
//! * the correlator's AU-108 (`rules::identity::account::broker`) counts the
//!   DISTINCT platforms among those breach-listed handles as the subject's
//!   cross-platform footprint.
//!
//! They used to be two hand-copied lists. `breach_rich` gained `github`,
//! `tiktok` and `reddit` (real handle columns in both providers' records) and
//! AU-108's copy — whose doc claimed it was "kept in lockstep" — never
//! followed, so a subject whose breach data named exactly those platforms
//! silently never produced the footprint finding. One constant, no drift.

/// Platform names as they appear both as provider record columns and as the
/// value prefix of the minted `platform:handle` Username.
pub const BREACH_SOCIAL_PLATFORMS: &[&str] = &[
    "telegram",
    "skype",
    "facebook",
    "instagram",
    "twitter",
    "linkedin",
    "vk",
    "snapchat",
    "github",
    "tiktok",
    "reddit",
];
