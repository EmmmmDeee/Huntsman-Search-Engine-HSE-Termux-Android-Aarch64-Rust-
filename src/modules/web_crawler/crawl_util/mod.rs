//! Crawler helpers, split by concern:
//!
//! - [`discovery`] — network reconnaissance and link/asset discovery
//!   (seed resolution, `robots.txt`, the config-leak prober, link
//!   classification).
//! - [`extract`] — pure content extractors over a page body or header map
//!   (emails, phones, social handles, tracking ids, frameworks, page types,
//!   security headers).
//!
//! The parent module pulls these in with `use crawl_util::*`; everything is
//! re-exported below so call sites stay flat.

// Bring the parent-module items the submodules depend on into scope so
// `discovery`/`extract` can reach them through `super::{…}`.
use super::{BINARY_EXTENSIONS, CrawlState, MAX_DEPTH, MAX_PAGES};

mod discovery;
mod extract;

// Re-export the helpers the parent module (`web_crawler`) calls via
// `use crawl_util::*`.
pub(super) use discovery::{
    extract_links, fetch_robots, is_disallowed, probe_config_leaks, resolve_seed,
};
pub(super) use extract::{
    SocialHandle, audit_security_headers, detect_frameworks, detect_page_types,
    extract_api_keys_from_body, extract_emails, extract_phones, extract_social_handles,
    extract_tracking_ids,
};

// Items exercised only by the parent module's `#[cfg(test)]` suite (which pulls
// them in via `use crawl_util::*`). In a non-test lib build that usage is
// invisible, so the re-export would warn as unused — gate the lint, not the
// re-export, so the test build still sees them.
#[cfg_attr(not(test), allow(unused_imports))]
pub(super) use discovery::{LinkIter, extract_registrable_domain, is_binary_url};

// ---------------------------------------------------------------------------
// Tests — pure parsers were previously uncovered; these lock in their
// observed behaviour as a regression guard (the crawler and several other
// modules rely on this extraction logic).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
