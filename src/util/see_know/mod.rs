//! Shared SeekNow (see-know.icu) API client — a direct OathNet competitor
//! with its own daily-lookup pool.
//!
//! Endpoint surface (all under `https://see-know.icu/api/v1`):
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
//! Auth: `X-API-Key: <key>` header (per the see-know.icu spec).
//!
//! Quota model: 5000 daily lookups on premiumhq plan, resets at midnight UTC.
//! Per-process budget mirrors the OathNet client's pattern.

mod budget;
mod client;
mod endpoints;

// Enterprise configuration consumed by the budget/quota layer.
pub mod enterprise_config;

#[cfg(test)]
mod tests;

// Budget / quota management — includes BudgetSnapshot re-export so external
// consumers (`api::handlers::stats`) keep working through the original path.
pub use budget::{
    BudgetSnapshot, budget_remaining, budget_snapshot, is_key_invalid, is_quota_exhausted,
    refresh_round_budget, reset_budget, scale_scan_cap_from_daily, scan_budget_remaining,
    set_scan_cap_override, should_probe_quota,
};

// Key helpers
pub use client::{key_fingerprint, resolve_key};

// Endpoint functions
pub(crate) use endpoints::get_path;
pub use endpoints::{discord_to_roblox, discord_user, query_credits, search, steam_profile};

/// Extract a string field from a JSON Value.
// Shared JSON helper — single definition in `util::json`, re-exported here so
// existing `crate::util::see_know::val_str` call sites are unchanged.
pub use crate::util::json::val_str;

pub const KEY_ENV: &str = "HUNTSMAN_SEEKNOW_KEY";
