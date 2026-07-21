//! Shared binding for the GitHub REST API modules — a `pub(crate)` HELPER (no
//! `Module` impl), so `github_user`, `github_code_search`, and `github_commits`
//! pin the same API version from one place. A version bump becomes a one-line
//! change here instead of a seven-site hunt in which one call is easily missed
//! and left sending a stale schema header.
//!
//! Like `breach_rich`, this stays `pub(crate)` so it is not caught by the
//! `every_declared_module_is_registered` architecture guard (which flags an
//! unregistered `pub mod` as dead-at-runtime).

/// The pinned GitHub REST API version, sent as the `X-GitHub-Api-Version`
/// header on every request so responses stay on one stable, tested schema.
pub(crate) const API_VERSION: &str = "2022-11-28";
