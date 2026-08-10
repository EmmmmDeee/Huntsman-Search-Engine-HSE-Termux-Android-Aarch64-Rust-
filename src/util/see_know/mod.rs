//! Shared SeekNow (see-know.ru) API client — a direct OathNet competitor
//! with its own daily-lookup pool.
//!
//! Endpoint surface (primary `https://see-know.ru/api/v1`; `.xyz`/`.eu`/`.icu`
//! fallback in [`client::all_base_urls`]):
//!
//!   POST /search                — universal search: breach + stealer + external
//!                                 records unified in one call, with
//!                                 breach_count/stealer_count/external_count.
//!                                 The broadest, most comprehensive endpoint, so
//!                                 it is the primary call for every target kind.
//!   GET  /network/email-check   — email existence + service map
//!   GET  /network/ip            — IP geolocation + ASN
//!   GET  /network/phone         — phone number enrichment
//!   GET  /domain/intel          — domain intel
//!   GET  /domain/whois          — WHOIS data
//!   GET  /discord/user          — Discord user info
//!   GET  /discord/to-roblox     — Discord-Roblox linkage
//!   GET  /gaming/{minecraft,roblox,xbox}
//!   GET  /username/{github,reddit,social,tiktok,twitter,history}
//!   GET  /credits               — remaining daily quota
//!
//! Auth: `X-API-Key: <key>` header (per the see-know.eu spec).
//!
//! Quota model: 5000 daily lookups on premiumhq plan, resets at midnight UTC.
//! Per-process budget mirrors the OathNet client's pattern.

mod budget;
mod client;
pub mod config;
pub mod data_log;
mod endpoints;

// Enterprise plan parameters (the 15,000-daily-credit budget config the live
// `budget` module reads via `enterprise_config::ENTERPRISE`).
pub mod enterprise_config;

#[cfg(test)]
mod tests;

// Honest coverage ledger for SeekNow's documented API surface vs. what HSE
// actually calls (see the file's own doc comment for the "previously made a
// false comprehensive-coverage claim, now self-consistency-checked with
// citations" history). Was orphaned — present on disk but never declared as a
// module — since the `dc4fb56` restructure; restored so its 3 real assertions
// (endpoint ledger counts, credit-cost coverage, per-target-type wiring) run
// again instead of silently doing nothing.
#[cfg(test)]
mod integration_tests;

// Budget / quota management — includes BudgetSnapshot re-export so external
// consumers (`api::handlers::stats`) keep working through the original path.
pub use budget::{
    BudgetSnapshot, budget_remaining, budget_snapshot, is_key_invalid, is_quota_exhausted,
    refresh_round_budget, release_quota_probe, reset_budget, scale_scan_cap_from_daily,
    scan_budget_remaining, set_scan_cap_override, should_probe_quota,
};

// Key helpers + the resolved API base host (so `hse doctor` can show WHICH
// host a failing probe tried — the single most useful fact when the failure is
// DNS host-resolution, the observed live symptom).
pub use client::{base_url, key_fingerprint};

// Endpoint functions
pub(crate) use endpoints::get_path;
pub use endpoints::{
    CreditsProbe, credits_probe, discord_to_roblox, discord_user, query_credits, search,
    search_deep, steam_profile,
};

/// Extract a string field from a JSON Value.
// Shared JSON helper — single definition in `util::json`, re-exported here so
// existing `crate::util::see_know::val_str` call sites are unchanged.
pub use crate::util::json::val_str;

pub const KEY_ENV: &str = "HUNTSMAN_SEEKNOW_KEY";
