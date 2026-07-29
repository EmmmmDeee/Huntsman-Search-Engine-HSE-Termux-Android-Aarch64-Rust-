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
/// see-know.eu MAXIMALLY — SeekNow's 15,000-daily quota vastly exceeds what
/// HSE can realistically spend, so every endpoint that returns richer data
/// than the free stack should fire. The budget cap (default 300/scan,
/// dynamically scaled up to 750; 100,000/session — see
/// `util::see_know::enterprise_config::ENTERPRISE`, the single source of
/// truth) and per-call exponential backoff on a transient rate-limit
/// (`util::see_know::endpoints::RATE_LIMIT_BACKOFF`) are the rate limiters.
/// Kept as a named constant for documentation and in case a future env-flag
/// wants to restore conservative mode.
#[allow(dead_code)]
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
/// priority paid source; its 15,000-daily pool is effectively unlimited for
/// a single-operator deployment) means every endpoint that adds platform-
/// specific profile depth or breach context should fire. Budget caps bound
/// total spend; platform-presence filtering no longer does.
pub(super) fn effective_plan(kind: TargetKind, value: &str, scan_id: &str) -> Vec<EndpointCall> {
    order_by_roi(plan_endpoints(kind, value), target_type_str(kind), scan_id)
}

/// Map a target kind to the value scorer's `target_type` discriminator so the
/// hit-rate/coverage dimensions score against the right column.
fn target_type_str(kind: TargetKind) -> &'static str {
    match kind {
        TargetKind::Email => "email",
        TargetKind::Username => "username",
        TargetKind::Phone => "phone",
        TargetKind::IpAddress => "ip",
        TargetKind::Domain => "domain",
        TargetKind::FullName => "name",
        _ => "",
    }
}

/// Order a per-target plan by ROI (value ÷ effective-cost), highest first —
/// the live realisation of the High-Value Query System. The SET of endpoints is
/// unchanged (so credit totals and every membership guarantee hold); only the
/// order changes, which matters solely for budget-cut tiebreaks — high-yield
/// endpoints now run first automatically instead of by a hand-maintained list.
///
/// The data-log feedback loop is closed here: endpoints that have historically
/// produced data for this operator (`data_log::yield_counts`) get a saturating
/// boost, so a repeat scan favours what has actually paid off before.
/// `scan_id` scopes `yield_counts`' per-scan memoization — this runs once per
/// seed, so without it a scan touching hundreds of seeds would re-read and
/// re-parse the on-disk log hundreds of times over for the same answer.
fn order_by_roi(plan: Vec<EndpointCall>, target_type: &str, scan_id: &str) -> Vec<EndpointCall> {
    if plan.len() < 2 {
        return plan;
    }
    use super::query_optimizer::cost_analyzer::CostAnalyzer;
    use super::query_optimizer::roi_router::RoiRouter;
    use super::query_optimizer::value_scorer::ValueScorer;

    let scorer = ValueScorer::new();
    let coster = CostAnalyzer::new();
    let router = RoiRouter::new();
    let yields = see_know::data_log::yield_counts(scan_id);

    // Neutral budget/time: budget-pressure and time-stress are identical for
    // every endpoint in one plan, so they cannot change RELATIVE order — the
    // ordering is purely value/cost plus the historical-yield feedback.
    const NEUTRAL_TIME_SECS: u32 = 3600;
    const NEUTRAL_BUDGET: u32 = 1000;
    const PLAN_LATENCY_MS: u32 = 15_000;

    let mut scored: Vec<(EndpointCall, f32)> = plan
        .into_iter()
        .map(|call| {
            let path = call.canonical_path();
            let value = scorer
                .calculate_composite_value(&path, target_type, None, 0.8)
                .composite;
            let cost = coster
                .calculate_effective_cost(
                    &path,
                    1,
                    None,
                    PLAN_LATENCY_MS,
                    NEUTRAL_TIME_SECS,
                    NEUTRAL_BUDGET,
                )
                .effective_cost;
            let mut roi = router.calculate_roi(value, cost);
            // Saturating yield boost (1 prior hit ≈ +7%, 10 ≈ +24%): a
            // tiebreaker that rewards proven endpoints without letting history
            // dominate the value/cost signal.
            if let Some(&hits) = yields.get(path.as_str()) {
                roi *= 1.0 + (hits as f32).ln_1p() * 0.1;
            }
            (call, roi)
        })
        .collect();

    // Stable sort: equal-ROI endpoints keep plan_endpoints' order, preserving
    // the discord/steam ID-resolution prepend for ties.
    scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    scored.into_iter().map(|(call, _)| call).collect()
}

/// True if `call` is a platform-presence check that SeekNow covers at
/// platform-profile depth. Retained for documentation and future policy
/// control; not used by [`effective_plan`].
#[expect(dead_code)]
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

    /// Canonical API path (`/{path}`) — the key shared by the value/cost
    /// registry (`query_optimizer::types`) and the on-device data-log store, so
    /// ROI ordering and yield feedback line up with what actually gets called.
    fn canonical_path(self) -> String {
        format!("/{}", self.spec().1)
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
