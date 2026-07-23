//! Shared HTTP client builder. Rustls-only — no native TLS, no openssl,
//! no native deps at all.
//!
//! No client-level total timeout is set: the engine wraps every
//! `Module::process()` call in `tokio::time::timeout(...)` (see
//! `src/core/engine/dispatch.rs`), capped at whichever of the user
//! override (`ScanOptions::module_timeout_ms`) or each module's
//! `max_timeout_ms()` is larger. A blanket client-level cap of
//! `MODULE_TIMEOUT_MS = 3 s` previously short-circuited every module
//! that declared a larger budget (whois 8 s, wigle 12 s, and other
//! multi-stage network modules) — at least one module has an explicit
//! unit test asserting `max_timeout_ms() > MODULE_TIMEOUT_MS`,
//! proving that the override was expected to apply.
//!
//! A short `connect_timeout` is still set so that attempts to reach
//! firewalled or otherwise-unresponsive hosts fail fast and free up
//! the engine's concurrency slot, instead of consuming the module's
//! full budget waiting on the OS-level TCP connect.

mod client;
mod fetch;
mod keys;
mod redact;
mod ssrf;
#[cfg(test)]
mod tests;
mod url;

pub use client::{build_client, build_client_with_trace};
pub use fetch::{
    JSON_BODY_CAP, error_snippet, fetch_json, fetch_json_or_404, fetch_json_or_absent,
    fetch_json_probe, fetch_keyed_json, handle_keyed_error, http_status_error,
    is_auth_failure_400_body, is_keyed_error_status, keyed_ok_or_404, note_keyed_error,
    parse_retry_after_secs, read_body_capped, read_text, retry_after_secs,
};
pub use keys::{scan_for_api_keys, scan_for_api_keys_with_source};
pub(crate) use redact::redact_credentials;
pub(crate) use ssrf::resolve_public_ips;
pub(crate) use url::RequestBuilderExt;
pub use url::{json_decode, json_scanned, urldecode, urlencode};

/// Browser User-Agent presented by the AU directory/registry scrapers
/// (`asic_director`, `au_property`, `au_people`, `au_electoral`) so scraper
/// detection on those sites doesn't short-circuit the request. Single source of
/// truth — bump the Chrome version once here, not in four modules. Distinct from
/// [`crate::util::curl::UA_POOL`], which rotates UAs for the curl fallback.
pub const UA_BROWSER: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";

/// Honest identifying User-Agent for keyed/polite APIs that ask callers to
/// describe themselves (`github_user`, `reddit_user`, `hacker_news`).
pub const UA_OSINT: &str = "HSE/1.0 OSINT research tool";
