//! SeekNow endpoint matrix — the per-target dispatch plan and the call enum.
//!
//! This module owns *what to call*: the [`EndpointCall`] table (the single
//! source of truth mapping each variant to its `(label, path, param)` spec),
//! the per-target [`plan_endpoints`] matrix, the quota-conservation filter
//! ([`effective_plan`] drops the single-origin presence checks free username
//! search already covers), and the concurrent [`dispatch_plan`] fan-out.
//!
//! The parent (`mod`) owns *what to do with the responses* (entity/geo
//! extraction, key harvest, identity pivots), so the dependency direction
//! stays one-way (`mod → endpoints`). Cross-platform ID heuristics live in
//! the sibling `pivots` module; the username plan reuses them to decide
//! whether to prepend the discord/steam resolution endpoints.

use futures::future::join_all;
use serde_json::Value;

use crate::core::error::Result;
use crate::core::scan::TargetKind;
use crate::util::see_know;

use super::pivots::{looks_like_discord_id, looks_like_steam_id};

/// SeekNow endpoints that check username presence on a single third-party
/// site. The free `username_search` module also confirms existence across
/// 600+ sites, but SeekNow's per-platform calls add what the free stack
/// cannot: platform-specific profile depth (bios, follower counts, linked
/// accounts) and breach/stealer context tied to THAT platform account.
///
/// These are NOT filtered out. The operator's standing directive is to use
/// see-know.icu MAXIMALLY — SeekNow's 5,000-daily quota vastly exceeds what
/// HSE can realistically spend, so every endpoint that returns richer data
/// than the free stack should fire. The budget cap (300/scan, 4,500/session)
/// is the only rate limiter. Kept as a named constant for documentation and
/// in case a future env-flag wants to restore conservative mode.
const FREE_COVERED_SINGLE_ORIGIN: &[EndpointCall] = &[
    EndpointCall::GithubProfile,
    EndpointCall::TwitterProfile,
    EndpointCall::RedditProfile,
    EndpointCall::TiktokProfile,
    EndpointCall::RobloxProfile,
    EndpointCall::XboxProfile,
    EndpointCall::MinecraftProfile,
];

/// The plan actually dispatched: the full [`plan_endpoints`] matrix.
///
/// Previously this filtered out [`FREE_COVERED_SINGLE_ORIGIN`] to conserve
/// quota. The operator's maximisation directive (SeekNow is the highest-
/// priority paid source; its 5,000-daily pool is effectively unlimited for
/// a single-operator deployment) means every endpoint that adds platform-
/// specific profile depth or breach context should fire. Budget caps bound
/// total spend; platform-presence filtering no longer does.
pub(super) fn effective_plan(kind: TargetKind, value: &str) -> Vec<EndpointCall> {
    plan_endpoints(kind, value)
}

/// True if `call` is a platform-presence check that SeekNow covers at
/// platform-profile depth. Retained for documentation and future policy
/// control; not used by [`effective_plan`].
#[allow(dead_code)]
fn is_free_covered_single_origin(call: EndpointCall) -> bool {
    FREE_COVERED_SINGLE_ORIGIN.contains(&call)
}

/// Per-target endpoint plan — names that will be dispatched concurrently
/// by `dispatch_plan`. Order is meaningful only for tiebreakers when
/// the per-scan budget cuts the plan short; high-yield endpoints come
/// first. [`effective_plan`] dispatches this matrix UNFILTERED (the
/// single-origin members are no longer stripped — see its doc for why);
/// [`is_free_covered_single_origin`] and [`FREE_COVERED_SINGLE_ORIGIN`]
/// stay retained so that filtering policy is one flip away, not deleted.
fn plan_endpoints(kind: TargetKind, value: &str) -> Vec<EndpointCall> {
    match kind {
        // Breach + stealer + external records all come back from the universal
        // `/search` (run before this plan), which returns them unified with
        // breach_count/stealer_count/external_count in ONE paid call — the
        // broadest, most comprehensive endpoint. So the per-kind plan adds only
        // what `/search` does NOT cover. `email-check` adds the account/service
        // existence map (distinct data), so it's the only email add-on.
        TargetKind::Email => vec![EndpointCall::EmailCheck],
        TargetKind::Username => {
            let mut plan = vec![
                EndpointCall::SocialAggregate,
                EndpointCall::GithubProfile,
                EndpointCall::TwitterProfile,
                EndpointCall::RedditProfile,
                EndpointCall::TiktokProfile,
                EndpointCall::UsernameHistory,
                EndpointCall::RobloxProfile,
                EndpointCall::XboxProfile,
                EndpointCall::MinecraftProfile,
            ];
            // Discord IDs land here too (stored as `discord:<id>` by the
            // extractor). When the value already looks like a Discord
            // snowflake, prepend the discord-specific endpoints instead.
            if looks_like_discord_id(value) {
                plan.insert(0, EndpointCall::DiscordUser);
                plan.insert(1, EndpointCall::DiscordToRoblox);
            }
            if looks_like_steam_id(value) {
                plan.insert(0, EndpointCall::SteamProfile);
            }
            plan
        }
        // Phone breach/stealer records come from the universal `/search`
        // (typed phone); `network/phone` adds carrier/line enrichment `/search`
        // doesn't. Name breach/stealer likewise come from `/search` auto-detect,
        // so FullName needs no add-on endpoint.
        TargetKind::Phone => vec![EndpointCall::PhoneInfo],
        TargetKind::IpAddress => vec![EndpointCall::IpInfo],
        TargetKind::Domain => vec![EndpointCall::DomainIntel, EndpointCall::Whois],
        TargetKind::FullName => Vec::new(),
        _ => Vec::new(),
    }
}

/// Dispatch every endpoint in `plan` concurrently. Returns
/// `(endpoint_name, items)` pairs in plan order so downstream
/// extractors stay deterministic.
///
/// Budget enforcement happens inside each endpoint helper at the
/// `util::see_know` layer — both the response cache and the
/// `budget_remaining` gate short-circuit before any HTTP call. The
/// previous implementation pre-trimmed `plan[..budget]` here, but
/// that suppressed legitimate cached calls when the scan was near
/// (but not at) its budget. Letting the util layer enforce the
/// budget restores that free corroboration.
pub(super) async fn dispatch_plan(
    key: &str,
    value: &str,
    plan: &[EndpointCall],
) -> Vec<(&'static str, Vec<Value>)> {
    let futures = plan.iter().copied().map(|call| {
        let value_owned = value.to_string();
        async move {
            let items = call.invoke(key, &value_owned).await.unwrap_or_default();
            (call.label(), items)
        }
    });
    join_all(futures).await
}

/// Enum of SeekNow endpoints the module can target. Centralising them
/// here makes the per-target dispatch plan trivially extensible — to
/// wire up a new endpoint, add a variant + a match arm in
/// `invoke()`/`label()`/`argument()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EndpointCall {
    EmailCheck,
    SocialAggregate,
    GithubProfile,
    TwitterProfile,
    RedditProfile,
    TiktokProfile,
    UsernameHistory,
    RobloxProfile,
    XboxProfile,
    MinecraftProfile,
    SteamProfile,
    DiscordUser,
    DiscordToRoblox,
    PhoneInfo,
    IpInfo,
    DomainIntel,
    Whois,
}

impl EndpointCall {
    /// The endpoint's `(label, path, param)` spec. `label` is the stable
    /// identifier `extract_geo_entities` uses to pick endpoint-specific geo
    /// extractors; `path` and `param` form the SeekNow `/api/v1/<path>?<param>=`
    /// single-parameter GET. This one table is the single source of truth that
    /// drives both [`label`](Self::label) and [`invoke`](Self::invoke).
    fn spec(self) -> (&'static str, &'static str, &'static str) {
        match self {
            Self::EmailCheck => ("email_check", "network/email-check", "email"),
            Self::SocialAggregate => ("social", "username/social", "username"),
            Self::GithubProfile => ("github", "username/github", "username"),
            Self::TwitterProfile => ("twitter", "username/twitter", "username"),
            Self::RedditProfile => ("reddit", "username/reddit", "username"),
            Self::TiktokProfile => ("tiktok", "username/tiktok", "username"),
            Self::UsernameHistory => ("username_history", "username/history", "username"),
            Self::RobloxProfile => ("roblox", "gaming/roblox", "username"),
            Self::XboxProfile => ("xbox", "gaming/xbox", "gamertag"),
            Self::MinecraftProfile => ("minecraft", "gaming/minecraft", "username"),
            Self::SteamProfile => ("steam", "gaming/steam", "id"),
            Self::DiscordUser => ("discord_user", "discord/user", "id"),
            Self::DiscordToRoblox => ("discord_to_roblox", "discord/to-roblox", "id"),
            Self::PhoneInfo => ("phone_info", "network/phone", "phone"),
            Self::IpInfo => ("ip_info", "network/ip", "ip"),
            Self::DomainIntel => ("domain_intel", "domain/intel", "domain"),
            Self::Whois => ("whois", "domain/whois", "domain"),
        }
    }

    /// Stable identifier used by `extract_geo_entities` to choose
    /// endpoint-specific geo extractors (e.g. WHOIS registrant fields).
    fn label(self) -> &'static str {
        self.spec().0
    }

    async fn invoke(self, key: &str, value: &str) -> Result<Vec<Value>> {
        let (_, path, param) = self.spec();
        see_know::get_path(key, path, &[(param, value)]).await
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
