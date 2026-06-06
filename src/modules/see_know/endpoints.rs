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

/// SeekNow endpoints that hit a SINGLE third-party site to check username
/// presence — exactly what the FREE `username_search` module already covers
/// across 600+ sites (GitHub, X/Twitter, Reddit, TikTok, Roblox, Xbox,
/// Minecraft, …). Spending a paid SeekNow lookup to re-confirm one of these is
/// pure waste, so [`effective_plan`] strips them from every plan by default.
///
/// They are deliberately NOT deleted: the response extractors stay intact and
/// the capability remains one filter-flip away, but the standing policy is
/// "free breadth first, paid quota only for what free can't do" — breach /
/// stealer / username-history aggregation and cross-platform ID resolution
/// (Discord/Steam), which `SocialAggregate` (one multi-platform call) and the
/// breach endpoints provide. Search-engine scraping (`search_engines`) and
/// `social_probe` are the other free breadth methods layered alongside
/// `username_search`; SeekNow sits on top of all of them as the paid multiplier.
const FREE_COVERED_SINGLE_ORIGIN: &[EndpointCall] = &[
    EndpointCall::GithubProfile,
    EndpointCall::TwitterProfile,
    EndpointCall::RedditProfile,
    EndpointCall::TiktokProfile,
    EndpointCall::RobloxProfile,
    EndpointCall::XboxProfile,
    EndpointCall::MinecraftProfile,
];

/// True if `call` is a single-origin presence check the free username stack
/// already covers (see [`FREE_COVERED_SINGLE_ORIGIN`]).
fn is_free_covered_single_origin(call: EndpointCall) -> bool {
    FREE_COVERED_SINGLE_ORIGIN.contains(&call)
}

/// The plan actually dispatched: [`plan_endpoints`] minus the single-origin
/// endpoints free username search already covers. Centralised so the
/// quota-conservation policy is enforced in exactly one place and is unit
/// testable without an HTTP client.
pub(super) fn effective_plan(kind: TargetKind, value: &str) -> Vec<EndpointCall> {
    let mut plan = plan_endpoints(kind, value);
    plan.retain(|&c| !is_free_covered_single_origin(c));
    plan
}

/// Per-target endpoint plan — names that will be dispatched concurrently
/// by `dispatch_plan`. Order is meaningful only for tiebreakers when
/// the per-scan budget cuts the plan short; high-yield endpoints come
/// first. The single-origin members are filtered out by [`effective_plan`]
/// before dispatch — they remain here so the matrix stays self-documenting
/// and the capability is one policy-flip away.
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
    use super::*;

    #[test]
    fn endpoint_call_labels_are_unique() {
        // Sanity check: every variant must have a distinct label so
        // the dispatch + geo extractor can route by string identity.
        let all = [
            EndpointCall::EmailCheck,
            EndpointCall::SocialAggregate,
            EndpointCall::GithubProfile,
            EndpointCall::TwitterProfile,
            EndpointCall::RedditProfile,
            EndpointCall::TiktokProfile,
            EndpointCall::UsernameHistory,
            EndpointCall::RobloxProfile,
            EndpointCall::XboxProfile,
            EndpointCall::MinecraftProfile,
            EndpointCall::DiscordUser,
            EndpointCall::DiscordToRoblox,
            EndpointCall::PhoneInfo,
            EndpointCall::IpInfo,
            EndpointCall::DomainIntel,
            EndpointCall::Whois,
        ];
        let mut labels: Vec<&str> = all.iter().map(|c| c.label()).collect();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), all.len(), "duplicate endpoint labels");
    }

    #[test]
    fn plan_email_addon_is_only_email_check() {
        // Breach/stealer/external all come from the universal `/search` (run
        // separately), so the email plan adds only the distinct account/service
        // existence map. The dead, redundant `/stealer` + `/breachhub/search`
        // endpoints (live-verified 404) must NOT be planned.
        let plan = plan_endpoints(TargetKind::Email, "a@b.com");
        let labels: Vec<&str> = plan.iter().map(|c| c.label()).collect();
        assert!(labels.contains(&"email_check"), "got {labels:?}");
        assert!(!labels.contains(&"stealer"), "404 endpoint must be gone");
        assert!(!labels.contains(&"breachhub"), "404 endpoint must be gone");
    }

    #[test]
    fn plan_username_covers_social_and_gaming_endpoints() {
        // Regression guard so we don't accidentally trim the username breadth.
        // The dead `/stealer` + `/breachhub/search` (404) are gone — their
        // breach/stealer coverage is served by the universal `/search`.
        let plan = plan_endpoints(TargetKind::Username, "alice");
        let labels: Vec<&str> = plan.iter().map(|c| c.label()).collect();
        for ep in [
            "social",
            "github",
            "twitter",
            "reddit",
            "tiktok",
            "username_history",
            "roblox",
            "xbox",
            "minecraft",
        ] {
            assert!(
                labels.contains(&ep),
                "username plan missing endpoint {ep}; got {labels:?}"
            );
        }
        assert!(!labels.contains(&"stealer"), "404 endpoint must be gone");
        assert!(!labels.contains(&"breachhub"), "404 endpoint must be gone");
    }

    #[test]
    fn effective_plan_drops_free_covered_single_origin_endpoints() {
        // Quota conservation: SeekNow must not spend a paid lookup on a
        // single-origin presence check the free username_search stack already
        // covers. effective_plan() is what actually dispatches.
        let labels: Vec<&str> = effective_plan(TargetKind::Username, "alice")
            .iter()
            .map(|c| c.label())
            .collect();
        for dropped in [
            "github",
            "twitter",
            "reddit",
            "tiktok",
            "roblox",
            "xbox",
            "minecraft",
        ] {
            assert!(
                !labels.contains(&dropped),
                "effective plan must DROP free-covered '{dropped}'; got {labels:?}"
            );
        }
        // …while keeping the paid-unique value: username-history plus the
        // multi-platform aggregate (one call across many sites — not single-origin).
        for kept in ["social", "username_history"] {
            assert!(
                labels.contains(&kept),
                "effective plan must KEEP paid-unique '{kept}'; got {labels:?}"
            );
        }
        // The full matrix stays self-documenting — only dispatch is gated.
        assert!(
            plan_endpoints(TargetKind::Username, "alice")
                .iter()
                .any(|c| c.label() == "github"),
            "plan_endpoints retains the capability (one policy-flip away)"
        );
    }

    #[test]
    fn effective_plan_keeps_id_resolution_pivots() {
        // Discord/Steam ID resolution is cross-platform identity linkage, NOT
        // single-origin enumeration — it survives the filter even though the
        // paths live under discord/ and gaming/.
        let labels: Vec<&str> = effective_plan(TargetKind::Username, "359023095012345678")
            .iter()
            .map(|c| c.label())
            .collect();
        assert!(
            labels.contains(&"discord_user") && labels.contains(&"discord_to_roblox"),
            "ID-resolution pivots must survive; got {labels:?}"
        );
    }

    #[test]
    fn plan_username_with_discord_id_prepends_discord_endpoints() {
        // 18-digit discord snowflake (typical len 17–19).
        let plan = plan_endpoints(TargetKind::Username, "359023095012345678");
        let labels: Vec<&str> = plan.iter().map(|c| c.label()).collect();
        // discord_user + discord_to_roblox should be at the head of the
        // plan so they run even if the per-scan budget cuts the tail.
        assert_eq!(labels[0], "discord_user");
        assert_eq!(labels[1], "discord_to_roblox");
    }

    #[test]
    fn plan_domain_covers_intel_and_whois() {
        let plan = plan_endpoints(TargetKind::Domain, "example.com");
        let labels: Vec<&str> = plan.iter().map(|c| c.label()).collect();
        assert!(labels.contains(&"domain_intel"));
        assert!(labels.contains(&"whois"));
    }

    #[tokio::test]
    async fn dispatch_plan_returns_empty_for_empty_plan() {
        // An empty plan never reaches the util layer; this path must
        // short-circuit without any HTTP regardless of budget state.
        // (Per-endpoint budget gating is exercised by the util-level
        // tests in `crate::util::see_know::tests`.)
        let out = dispatch_plan("key", "alice", &[]).await;
        assert!(out.is_empty());
    }

    #[test]
    fn plan_username_with_steam_id_prepends_steam_endpoint() {
        let plan = plan_endpoints(TargetKind::Username, "76561198000000000");
        let first = plan.first().expect("steam plan must be non-empty");
        assert_eq!(first.label(), "steam");
    }

    #[test]
    fn endpoint_call_steam_round_trips_via_label() {
        // Ensure the new variant appears in the unique-label set.
        let labels: Vec<&str> = [
            EndpointCall::EmailCheck,
            EndpointCall::SocialAggregate,
            EndpointCall::GithubProfile,
            EndpointCall::TwitterProfile,
            EndpointCall::RedditProfile,
            EndpointCall::TiktokProfile,
            EndpointCall::UsernameHistory,
            EndpointCall::RobloxProfile,
            EndpointCall::XboxProfile,
            EndpointCall::MinecraftProfile,
            EndpointCall::SteamProfile,
            EndpointCall::DiscordUser,
            EndpointCall::DiscordToRoblox,
            EndpointCall::PhoneInfo,
            EndpointCall::IpInfo,
            EndpointCall::DomainIntel,
            EndpointCall::Whois,
        ]
        .iter()
        .map(|c| c.label())
        .collect();
        assert!(labels.contains(&"steam"));
    }
}
