//! SeekNow (see-know.eu) — parallel breach + stealer + OSINT pool.
//!
//! Direct OathNet competitor with its own 5,000-lookup daily quota.
//! Runs alongside oathnet_pro so each scan effectively gets 2 parallel
//! Multiplier-tier pools (separate quotas, overlapping but distinct
//! data corpora — combining them maximises coverage).
//!
//! Per-target endpoint routing:
//!
//!   Email      → /search + /stealer + /network/email-check
//!   Username   → /search + /stealer
//!   Phone      → /network/phone
//!   Domain     → /domain/intel
//!   IpAddress  → /network/ip
//!   FullName   → /search (auto-detect)
//!
//! Each scan spends 1-3 SeekNow lookups (bounded by MAX_QUERIES_PER_SCAN).
//! Discovered credentials feed the same key-harvest pipeline as oathnet_pro
//! — extract_api_keys_from_item recognises the same 80+ prefix patterns.

use std::collections::HashSet;

use async_trait::async_trait;
use futures::future::join_all;
use serde_json::Value;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
    tags,
};
use crate::modules::oathnet_pro::key_harvest::{extract_api_keys_from_item, store_api_credential};
use crate::util::preflight::{is_local_domain, is_placeholder_username, is_private_ip};
use crate::util::see_know::{self, val_str};

const SRC: &str = "see_know";

/// Re-export budget reset for the engine.
pub fn reset_budget() {
    crate::util::see_know::reset_budget();
}

pub struct SeekNow;

#[async_trait]
impl Module for SeekNow {
    fn name(&self) -> &'static str {
        "see_know"
    }

    fn description(&self) -> &'static str {
        "SeekNow (see-know.eu) — full 18-endpoint OSINT/breach pool with discord/gaming pivots"
    }

    fn priority(&self) -> u8 {
        // Runs right after oathnet_pro (127). Both are Multiplier-tier
        // Paid modules. Phase 1 in concurrent dispatch covers both.
        126
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Paid
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Breach
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Email,
            EntityKind::Username,
            EntityKind::Phone,
            EntityKind::Person,
            EntityKind::IpAddress,
            EntityKind::Domain,
            EntityKind::Address,
            EntityKind::Coordinates,
            EntityKind::Organisation,
            EntityKind::Asn,
            EntityKind::Credential,
            EntityKind::ApiKey,
        ];
        KINDS
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(
            t.kind,
            TargetKind::Email
                | TargetKind::Username
                | TargetKind::Phone
                | TargetKind::FullName
                | TargetKind::IpAddress
                | TargetKind::Domain
        )
    }

    fn max_timeout_ms(&self) -> u64 {
        // Concurrent endpoint dispatch lets us call ~10 endpoints in
        // ~the time of one — but the upper bound is still gated by the
        // slowest individual lookup. 45s leaves room for stealer +
        // breachhub (the heaviest paths) on slow upstreams.
        45_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let key = see_know::resolve_key(ctx.key_opt(see_know::KEY_ENV));

        let mut result = ModuleResult::new();
        let mut seen: HashSet<String> = HashSet::new();
        seen.insert(target.value.to_lowercase());
        let v = target.value.trim();

        // Pre-flight skips — same pattern as oathnet_pro. Catching junk
        // before any HTTP call saves quota and pool noise.
        match target.kind {
            TargetKind::Email => {
                if let Some((_, host)) = v.split_once('@')
                    && is_local_domain(host)
                {
                    return Ok(result);
                }
            }
            TargetKind::Username => {
                if v.len() < 4
                    || v.chars().all(|c| c.is_ascii_digit())
                    || is_placeholder_username(v)
                {
                    return Ok(result);
                }
            }
            TargetKind::Phone => {
                let digits = v.chars().filter(|c| c.is_ascii_digit()).count();
                if digits < 6 {
                    return Ok(result);
                }
            }
            TargetKind::FullName => {
                if !v.contains(' ') || v.len() < 5 {
                    return Ok(result);
                }
            }
            TargetKind::IpAddress => {
                if is_private_ip(v) {
                    return Ok(result);
                }
            }
            TargetKind::Domain => {
                if is_local_domain(v) {
                    return Ok(result);
                }
            }
            _ => return Ok(result),
        }

        // ── Query 1: universal /search ─────────────────────────────────
        // Single endpoint that auto-routes to the highest-yield specialised
        // path internally. Most efficient first query for ALL target kinds.
        let qtype = match target.kind {
            TargetKind::Email => "email",
            TargetKind::Username => "username",
            TargetKind::Phone => "phone",
            TargetKind::Domain => "domain",
            TargetKind::IpAddress => "ip",
            TargetKind::FullName => "", // auto-detect
            _ => "",
        };
        let items = see_know::search(key, v, qtype).await?;
        let total = items.len();

        if total > 0 {
            let mut parent = target.to_entity(0.85, &ctx.scan_id);
            parent.tag(tags::BREACH);
            parent.tag("see-know");
            parent.add_evidence(
                Evidence::new(SRC, format!("SeekNow: {total} record(s) via /search"))
                    .with_attr("hits", total.to_string())
                    .with_attr("endpoint", "/api/v1/search"),
            );
            result.push(parent);

            for item in &items {
                extract_entities(item, v, &ctx.scan_id, &mut seen, &mut result);
                store_api_credential(item);
                extract_api_keys_from_item(item, &ctx.scan_id, &mut seen, &mut result);
            }
        }

        // ── Per-seed endpoint matrix: maximise SeekNow API coverage ──
        //
        // Each target kind plans the FULL set of relevant SeekNow
        // endpoints, then dispatches them concurrently (bounded by
        // remaining scan + session budget). The previous implementation
        // ran 2-4 endpoints sequentially per target, leaving 99%+ of
        // the daily quota unused. The remodel:
        //
        //   Email     → stealer, breachhub, email-check
        //   Username  → stealer, social aggregate, github, twitter,
        //               reddit, tiktok, history, gaming/{roblox, xbox,
        //               minecraft}, breachhub, discord/user
        //               (the latter when the value parses as a
        //               Discord ID; see `looks_like_discord_id`).
        //   Phone     → phone_info, breachhub, search(typed phone)
        //   Domain    → domain/intel, domain/whois
        //   IpAddress → network/ip
        //   FullName  → /search auto + breachhub
        //
        // Within each plan, calls run via `join_all` — the wall-time
        // collapses to the slowest single endpoint instead of summing
        // every call's latency. Budget gates inside util::see_know
        // turn no-quota calls into instant empty-vec returns.
        if !ctx.cancel.is_cancelled() && see_know::budget_remaining() {
            let plan = plan_endpoints(target.kind, v);
            let endpoint_results = dispatch_plan(key, v, &plan).await;

            for (endpoint, items) in &endpoint_results {
                for item in items {
                    extract_entities(item, v, &ctx.scan_id, &mut seen, &mut result);
                    store_api_credential(item);
                    extract_api_keys_from_item(item, &ctx.scan_id, &mut seen, &mut result);
                    // Geo-specific extraction — pull coordinates/timezone/
                    // location directly when the endpoint returns them.
                    extract_geo_entities(item, endpoint, &ctx.scan_id, &mut seen, &mut result);
                }
            }

            // Identity-pivot pass: any Discord ID or Steam ID
            // surfaced by the entity extractor triggers its respective
            // gaming/identity endpoint so the graph closes within one
            // scan. Both pivot kinds run concurrently and are bounded
            // by the remaining per-scan budget.
            if !ctx.cancel.is_cancelled() && see_know::budget_remaining() {
                let mut pivot_results: Vec<(&'static str, Vec<Value>)> = Vec::new();
                let discord_pivots = discover_discord_pivots(&result);
                if !discord_pivots.is_empty() {
                    pivot_results.extend(dispatch_discord_pivots(key, discord_pivots).await);
                }
                let steam_pivots = discover_steam_pivots(&result);
                if !steam_pivots.is_empty() && see_know::budget_remaining() {
                    pivot_results.extend(dispatch_steam_pivots(key, steam_pivots).await);
                }
                for (endpoint, items) in &pivot_results {
                    for item in items {
                        extract_entities(item, v, &ctx.scan_id, &mut seen, &mut result);
                        extract_geo_entities(item, endpoint, &ctx.scan_id, &mut seen, &mut result);
                    }
                }
            }
        }

        Ok(result)
    }
}

/// Per-target endpoint plan — names that will be dispatched concurrently
/// by `dispatch_plan`. Order is meaningful only for tiebreakers when
/// the per-scan budget cuts the plan short; high-yield endpoints come
/// first.
fn plan_endpoints(kind: TargetKind, value: &str) -> Vec<EndpointCall> {
    match kind {
        TargetKind::Email => vec![
            EndpointCall::Stealer,
            EndpointCall::BreachHub,
            EndpointCall::EmailCheck,
        ],
        TargetKind::Username => {
            let mut plan = vec![
                EndpointCall::Stealer,
                EndpointCall::SocialAggregate,
                EndpointCall::GithubProfile,
                EndpointCall::TwitterProfile,
                EndpointCall::RedditProfile,
                EndpointCall::TiktokProfile,
                EndpointCall::UsernameHistory,
                EndpointCall::BreachHub,
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
        TargetKind::Phone => vec![EndpointCall::PhoneInfo, EndpointCall::BreachHub],
        TargetKind::IpAddress => vec![EndpointCall::IpInfo],
        TargetKind::Domain => vec![EndpointCall::DomainIntel, EndpointCall::Whois],
        TargetKind::FullName => vec![EndpointCall::BreachHub],
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
async fn dispatch_plan(
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

/// Discord IDs (the 17–20 digit `discord:<snowflake>` strings emitted
/// by the entity extractor) → pairs of (id, EndpointCall) for the two
/// discord pivots.
fn discover_discord_pivots(result: &ModuleResult) -> Vec<String> {
    discover_prefixed_ids(result, "discord:", looks_like_discord_id)
}

/// Steam ID64s surfaced from breach data — emitted by the entity
/// extractor as `steam:<17-digit-id>` Username entities. Pivoted
/// through gaming/steam to pull the public profile.
fn discover_steam_pivots(result: &ModuleResult) -> Vec<String> {
    discover_prefixed_ids(result, "steam:", looks_like_steam_id)
}

/// Generalised prefix-based ID collector. Iterates extracted Username
/// entities, strips the prefix, validates the rest with `validator`,
/// and dedupes preserving first-seen order.
fn discover_prefixed_ids(
    result: &ModuleResult,
    prefix: &str,
    validator: fn(&str) -> bool,
) -> Vec<String> {
    let mut ids: Vec<String> = Vec::new();
    for e in &result.entities {
        if matches!(e.kind, EntityKind::Username)
            && let Some(rest) = e.value.strip_prefix(prefix)
            && validator(rest)
            && !ids.iter().any(|x| x == rest)
        {
            ids.push(rest.to_string());
        }
    }
    ids
}

/// Concurrent discord/user + discord/to-roblox dispatch for every
/// discovered Discord ID. Each ID consumes up to two budget slots;
/// when the budget can fit only one of the pair the `discord_user`
/// call takes priority (it's higher-yield).
///
/// User and to-roblox calls are pushed to separate per-endpoint Vecs
/// so each Vec is homogeneously typed for `join_all`; both vecs are
/// then awaited concurrently via `tokio::join!`.
async fn dispatch_discord_pivots(key: &str, ids: Vec<String>) -> Vec<(&'static str, Vec<Value>)> {
    let budget = see_know::scan_budget_remaining() as usize;
    if budget == 0 || ids.is_empty() {
        return Vec::new();
    }
    let mut user_futures = Vec::new();
    let mut roblox_futures = Vec::new();
    let mut used = 0usize;
    for id in &ids {
        if used >= budget {
            break;
        }
        let id_for_user = id.clone();
        user_futures.push(async move {
            let items = see_know::discord_user(key, &id_for_user)
                .await
                .unwrap_or_default();
            ("discord_user", items)
        });
        used += 1;
        if used >= budget {
            break;
        }
        let id_for_roblox = id.clone();
        roblox_futures.push(async move {
            let items = see_know::discord_to_roblox(key, &id_for_roblox)
                .await
                .unwrap_or_default();
            ("discord_to_roblox", items)
        });
        used += 1;
    }
    let (mut user_results, roblox_results) =
        tokio::join!(join_all(user_futures), join_all(roblox_futures));
    user_results.extend(roblox_results);
    user_results
}

/// Concurrent gaming/steam dispatch for every discovered Steam ID.
/// Mirrors the discord-pivot shape so the caller can compose both.
async fn dispatch_steam_pivots(key: &str, ids: Vec<String>) -> Vec<(&'static str, Vec<Value>)> {
    let budget = see_know::scan_budget_remaining() as usize;
    if budget == 0 || ids.is_empty() {
        return Vec::new();
    }
    let mut futures = Vec::new();
    for id in &ids {
        if futures.len() >= budget {
            break;
        }
        let call = {
            let id = id.clone();
            async move {
                let items = see_know::steam_profile(key, &id).await.unwrap_or_default();
                ("steam", items)
            }
        };
        futures.push(call);
    }
    join_all(futures).await
}

/// Discord snowflake heuristic — 17 to 20 decimal digits, no leading
/// zero. Strict enough to reject usernames that happen to be all
/// digits (typical 6-12 chars).
fn looks_like_discord_id(s: &str) -> bool {
    let len = s.len();
    (17..=20).contains(&len) && s.chars().all(|c| c.is_ascii_digit()) && !s.starts_with('0')
}

/// Steam ID64 heuristic — exactly 17 decimal digits, the public
/// account universe always starts with "765611979..." (steamID64
/// base = 76561197960265728). We don't enforce that prefix here so
/// edge-case accounts still pivot, but the length + no-leading-zero
/// pair is enough to reject usernames that happen to be 16-digit
/// breach IDs.
fn looks_like_steam_id(s: &str) -> bool {
    s.len() == 17 && s.chars().all(|c| c.is_ascii_digit()) && !s.starts_with('0')
}

/// Enum of SeekNow endpoints the module can target. Centralising them
/// here makes the per-target dispatch plan trivially extensible — to
/// wire up a new endpoint, add a variant + a match arm in
/// `invoke()`/`label()`/`argument()`.
#[derive(Debug, Clone, Copy)]
enum EndpointCall {
    Stealer,
    BreachHub,
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
    /// Stable identifier used by `extract_geo_entities` to choose
    /// endpoint-specific geo extractors (e.g. WHOIS registrant fields).
    fn label(self) -> &'static str {
        match self {
            Self::Stealer => "stealer",
            Self::BreachHub => "breachhub",
            Self::EmailCheck => "email_check",
            Self::SocialAggregate => "social",
            Self::GithubProfile => "github",
            Self::TwitterProfile => "twitter",
            Self::RedditProfile => "reddit",
            Self::TiktokProfile => "tiktok",
            Self::UsernameHistory => "username_history",
            Self::RobloxProfile => "roblox",
            Self::XboxProfile => "xbox",
            Self::MinecraftProfile => "minecraft",
            Self::SteamProfile => "steam",
            Self::DiscordUser => "discord_user",
            Self::DiscordToRoblox => "discord_to_roblox",
            Self::PhoneInfo => "phone_info",
            Self::IpInfo => "ip_info",
            Self::DomainIntel => "domain_intel",
            Self::Whois => "whois",
        }
    }

    async fn invoke(self, key: &str, value: &str) -> Result<Vec<Value>> {
        match self {
            Self::Stealer => see_know::stealer(key, value).await,
            Self::BreachHub => see_know::breachhub(key, value).await,
            Self::EmailCheck => see_know::email_check(key, value).await,
            Self::SocialAggregate => see_know::social_aggregate(key, value).await,
            Self::GithubProfile => see_know::github_profile(key, value).await,
            Self::TwitterProfile => see_know::twitter_profile(key, value).await,
            Self::RedditProfile => see_know::reddit_profile(key, value).await,
            Self::TiktokProfile => see_know::tiktok_profile(key, value).await,
            Self::UsernameHistory => see_know::username_history(key, value).await,
            Self::RobloxProfile => see_know::roblox_profile(key, value).await,
            Self::XboxProfile => see_know::xbox_profile(key, value).await,
            Self::MinecraftProfile => see_know::minecraft_profile(key, value).await,
            Self::SteamProfile => see_know::steam_profile(key, value).await,
            Self::DiscordUser => see_know::discord_user(key, value).await,
            Self::DiscordToRoblox => see_know::discord_to_roblox(key, value).await,
            Self::PhoneInfo => see_know::phone_info(key, value).await,
            Self::IpInfo => see_know::ip_info(key, value).await,
            Self::DomainIntel => see_know::domain_intel(key, value).await,
            Self::Whois => see_know::whois(key, value).await,
        }
    }
}

/// Geo-conscious extraction — surface coordinates, timezones, and
/// location-bearing fields from any SeekNow endpoint response so the
/// downstream geocode/overpass/wigle modules can converge.
fn extract_geo_entities(
    item: &Value,
    endpoint: &str,
    scan_id: &str,
    seen: &mut HashSet<String>,
    result: &mut ModuleResult,
) {
    // Direct coordinate fields — some endpoints (ip_info, phone_info)
    // return lat/lon pairs directly.
    let lat = item
        .get("latitude")
        .or_else(|| item.get("lat"))
        .and_then(|v| v.as_f64())
        .or_else(|| {
            item.get("latitude")
                .or_else(|| item.get("lat"))
                .and_then(|v| v.as_str()?.parse().ok())
        });
    let lon = item
        .get("longitude")
        .or_else(|| item.get("lon"))
        .or_else(|| item.get("lng"))
        .and_then(|v| v.as_f64())
        .or_else(|| {
            item.get("longitude")
                .or_else(|| item.get("lon"))
                .or_else(|| item.get("lng"))
                .and_then(|v| v.as_str()?.parse().ok())
        });
    if let (Some(la), Some(lo)) = (lat, lon)
        && (-90.0..=90.0).contains(&la)
        && (-180.0..=180.0).contains(&lo)
    {
        let coord_val = format!("{la:.5},{lo:.5}");
        if seen.insert(format!("@coord:{coord_val}")) {
            let mut e = Entity::new(EntityKind::Coordinates, &coord_val, 0.75, scan_id);
            e.tag("see-know");
            e.tag(format!("via:{endpoint}"));
            e.add_evidence(
                Evidence::new(SRC, format!("Coordinates from SeekNow /{endpoint}"))
                    .with_attr("lat", la.to_string())
                    .with_attr("lon", lo.to_string()),
            );
            result.push(e);
        }
    }

    // Location string fields — profile bios often contain "Sydney, NSW"-
    // style city/region strings that geocode can resolve.
    for field in ["location", "city_state", "region", "place", "hometown"] {
        if let Some(loc) = val_str(item, field)
            && loc.len() >= 3
            && seen.insert(format!("@loc:{}", loc.to_lowercase()))
        {
            let mut e = Entity::new(EntityKind::Address, &loc, 0.55, scan_id);
            e.tag("see-know");
            e.tag(format!("via:{endpoint}"));
            e.tag("geo-hint");
            e.add_evidence(
                Evidence::new(SRC, format!("Location hint from {endpoint}.{field}"))
                    .with_attr("raw_field", field),
            );
            result.push(e);
        }
    }

    // Timezone — feeds the breach_timezone correlator for chronolocation.
    if let Some(tz) = val_str(item, "timezone").or_else(|| val_str(item, "tz"))
        && tz.len() >= 3
        && seen.insert(format!("@tz:{}", tz.to_lowercase()))
    {
        // Timezones don't have their own EntityKind; surface as evidence
        // on a low-confidence Address so the correlator can join.
        let mut e = Entity::new(EntityKind::Address, format!("tz:{tz}"), 0.40, scan_id);
        e.tag("see-know");
        e.tag("timezone");
        e.tag(format!("via:{endpoint}"));
        e.add_evidence(
            Evidence::new(SRC, format!("Timezone from {endpoint}")).with_attr("timezone", &tz),
        );
        result.push(e);
    }

    // ASN / ISP / Organisation — only emit when endpoint is ip_info.
    if endpoint == "ip_info" {
        if let Some(asn) = val_str(item, "asn")
            && seen.insert(format!("@asn:{asn}"))
        {
            let mut e = Entity::new(EntityKind::Asn, &asn, 0.75, scan_id);
            e.tag("see-know");
            e.add_evidence(Evidence::new(SRC, "ASN from SeekNow /network/ip"));
            result.push(e);
        }
        if let Some(org) = val_str(item, "org")
            .or_else(|| val_str(item, "isp"))
            .or_else(|| val_str(item, "company"))
            && seen.insert(format!("@org:{}", org.to_lowercase()))
        {
            let mut e = Entity::new(EntityKind::Organisation, &org, 0.65, scan_id);
            e.tag("see-know");
            e.add_evidence(Evidence::new(SRC, "Organisation from SeekNow /network/ip"));
            result.push(e);
        }
    }

    // WHOIS registrant address (Domain target via /whois endpoint).
    if endpoint == "whois" {
        let parts: Vec<String> = [
            "registrant_street",
            "registrant_city",
            "registrant_state",
            "registrant_postal",
            "registrant_country",
        ]
        .iter()
        .filter_map(|f| val_str(item, f))
        .collect();
        if parts.len() >= 2 {
            let addr = parts.join(", ");
            if seen.insert(format!("@whois-addr:{}", addr.to_lowercase())) {
                let mut e = Entity::new(EntityKind::Address, &addr, 0.70, scan_id);
                e.tag("see-know");
                e.tag("whois-registrant");
                e.add_evidence(Evidence::new(SRC, "Domain WHOIS registrant address"));
                result.push(e);
            }
        }
    }
}

// ─── Entity extraction ─────────────────────────────────────────────────────
//
// SeekNow records share most field names with OathNet's V2 schema. We extract
// the same surface set: email, username, phone, full_name, ip, country,
// city, state, address, dbname, discord_id, plus URL+credential pairs from
// stealer items.

fn extract_entities(
    item: &Value,
    target_value: &str,
    scan_id: &str,
    seen: &mut HashSet<String>,
    result: &mut ModuleResult,
) {
    let dbname = val_str(item, "dbname")
        .or_else(|| val_str(item, "source"))
        .unwrap_or_else(|| "see-know".to_string());
    let ev =
        Evidence::new(SRC, format!("SeekNow record from {dbname}")).with_attr("source", &dbname);

    let target_lower = target_value.to_lowercase();

    if let Some(email) = val_str(item, "email") {
        let lower = email.to_lowercase();
        if lower.contains('@') && seen.insert(lower) {
            let mut e = Entity::new(EntityKind::Email, &email, 0.70, scan_id);
            e.tag(tags::BREACH);
            e.tag("see-know");
            e.add_evidence(ev.clone());
            result.push(e);
        }
    }
    if let Some(uname) = val_str(item, "username") {
        let lower = uname.to_lowercase();
        if lower.len() >= 3 && seen.insert(lower) {
            let mut e = Entity::new(EntityKind::Username, &uname, 0.65, scan_id);
            e.tag(tags::BREACH);
            e.tag("see-know");
            e.add_evidence(ev.clone());
            result.push(e);
        }
    }
    if let Some(phone) = val_str(item, "phone").or_else(|| val_str(item, "phone_number"))
        && phone.len() >= 7
        && seen.insert(phone.to_lowercase())
    {
        let conf = if phone.to_lowercase() == target_lower {
            0.70
        } else {
            0.55
        };
        let mut e = Entity::new(EntityKind::Phone, &phone, conf, scan_id);
        e.tag(tags::BREACH);
        e.tag("see-know");
        e.add_evidence(ev.clone());
        result.push(e);
    }
    if let Some(name) = val_str(item, "full_name").or_else(|| val_str(item, "name"))
        && name.trim().contains(' ')
        && seen.insert(name.to_lowercase())
    {
        let mut e = Entity::new(EntityKind::Person, name.trim(), 0.65, scan_id);
        e.tag(tags::BREACH);
        e.tag("see-know");
        e.add_evidence(ev.clone());
        result.push(e);
    }
    if let Some(ip) = val_str(item, "ip")
        && ip.len() >= 7
        && seen.insert(ip.clone())
    {
        let mut e = Entity::new(EntityKind::IpAddress, &ip, 0.60, scan_id);
        e.tag(tags::BREACH);
        e.tag("see-know");
        e.tag("geolocation-lead");
        e.add_evidence(ev.clone());
        result.push(e);
    }
    if let Some(country) = val_str(item, "country")
        && seen.insert(format!("@country:{country}"))
    {
        let mut e = Entity::new(EntityKind::Address, &country, 0.55, scan_id);
        e.tag(tags::BREACH);
        e.tag("see-know");
        e.add_evidence(ev.clone());
        result.push(e);
    }
    if let Some(did) = val_str(item, "discord_id").or_else(|| val_str(item, "discordid"))
        && seen.insert(format!("@discord:{did}"))
    {
        let mut e = Entity::new(
            EntityKind::Username,
            format!("discord:{did}"),
            0.60,
            scan_id,
        );
        e.tag(tags::BREACH);
        e.tag("see-know");
        e.tag("discord");
        e.add_evidence(ev.clone());
        result.push(e);
    }
    // Steam ID — 17-digit 64-bit SteamIDs (steamID64). Surface as a
    // Username with `steam:<id>` prefix so the gaming endpoint pivot
    // can find it without colliding with normal usernames. Matches
    // the discord-pivot pattern.
    if let Some(sid) = val_str(item, "steam_id")
        .or_else(|| val_str(item, "steamid"))
        .or_else(|| val_str(item, "steam_id64"))
        && looks_like_steam_id(&sid)
        && seen.insert(format!("@steam:{sid}"))
    {
        let mut e = Entity::new(EntityKind::Username, format!("steam:{sid}"), 0.60, scan_id);
        e.tag(tags::BREACH);
        e.tag("see-know");
        e.tag("steam");
        e.add_evidence(ev.clone());
        result.push(e);
    }
    if let Some(domain) = val_str(item, "domain")
        && domain.contains('.')
        && seen.insert(domain.to_lowercase())
    {
        let mut e = Entity::new(EntityKind::Domain, &domain, 0.55, scan_id);
        e.tag("see-know");
        e.add_evidence(ev);
        result.push(e);
    }
}

// Pre-flight validators (`is_private_ip`, `is_local_domain`,
// `is_placeholder_username`) live in `crate::util::preflight` —
// shared with the oathnet_pro module so a target rejected by one
// provider is rejected by the other.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_six_target_kinds() {
        let m = SeekNow;
        for k in [
            TargetKind::Email,
            TargetKind::Username,
            TargetKind::Phone,
            TargetKind::IpAddress,
            TargetKind::Domain,
            TargetKind::FullName,
        ] {
            assert!(m.accepts(&Target::new(k, "x")));
        }
    }

    #[test]
    fn cost_is_paid() {
        assert!(matches!(SeekNow.cost(), ModuleCost::Paid));
    }

    #[test]
    fn priority_below_oathnet_pro() {
        assert!(SeekNow.priority() < 127);
        assert!(SeekNow.priority() >= 120);
    }

    #[test]
    fn category_is_breach() {
        assert_eq!(SeekNow.category(), ModuleCategory::Breach);
    }

    #[test]
    fn produces_includes_geo_and_identity_kinds() {
        let kinds = SeekNow.produces();
        assert!(kinds.contains(&EntityKind::Coordinates));
        assert!(kinds.contains(&EntityKind::Address));
        assert!(kinds.contains(&EntityKind::Email));
        assert!(kinds.contains(&EntityKind::Username));
        assert!(kinds.contains(&EntityKind::Phone));
        assert!(kinds.contains(&EntityKind::ApiKey));
    }

    #[test]
    fn endpoint_call_labels_are_unique() {
        // Sanity check: every variant must have a distinct label so
        // the dispatch + geo extractor can route by string identity.
        let all = [
            EndpointCall::Stealer,
            EndpointCall::BreachHub,
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
    fn plan_email_covers_three_high_yield_endpoints() {
        let plan = plan_endpoints(TargetKind::Email, "a@b.com");
        let labels: Vec<&str> = plan.iter().map(|c| c.label()).collect();
        for ep in ["stealer", "breachhub", "email_check"] {
            assert!(labels.contains(&ep), "email plan missing endpoint {ep}");
        }
    }

    #[test]
    fn plan_username_covers_all_social_and_gaming_endpoints() {
        // The remodel widens username dispatch to 11 endpoints (was 4).
        // Regression guard so we don't accidentally trim it.
        let plan = plan_endpoints(TargetKind::Username, "alice");
        let labels: Vec<&str> = plan.iter().map(|c| c.label()).collect();
        for ep in [
            "stealer",
            "social",
            "github",
            "twitter",
            "reddit",
            "tiktok",
            "username_history",
            "breachhub",
            "roblox",
            "xbox",
            "minecraft",
        ] {
            assert!(
                labels.contains(&ep),
                "username plan missing endpoint {ep}; got {labels:?}"
            );
        }
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

    #[test]
    fn looks_like_discord_id_strict_heuristic() {
        // 17–20 digits, no leading zero.
        assert!(looks_like_discord_id("12345678901234567"));
        assert!(looks_like_discord_id("12345678901234567890"));
        // Too short, too long, leading-zero, non-digit — all reject.
        assert!(!looks_like_discord_id("1234567890123456")); // 16 digits
        assert!(!looks_like_discord_id("123456789012345678901")); // 21 digits
        assert!(!looks_like_discord_id("0123456789012345678")); // leading zero
        assert!(!looks_like_discord_id("alice1234567890"));
        assert!(!looks_like_discord_id(""));
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
    fn discover_discord_pivots_extracts_unique_ids() {
        let mut r = ModuleResult::new();
        r.push(Entity::new(
            EntityKind::Username,
            "discord:359023095012345678",
            0.6,
            "test",
        ));
        // Duplicate ID — must be deduplicated.
        r.push(Entity::new(
            EntityKind::Username,
            "discord:359023095012345678",
            0.6,
            "test",
        ));
        // Non-Discord username — must be skipped.
        r.push(Entity::new(EntityKind::Username, "alice", 0.7, "test"));
        // Non-Username entity with `discord:` prefix — must be skipped.
        r.push(Entity::new(
            EntityKind::Email,
            "discord:foo@bar",
            0.5,
            "test",
        ));
        let ids = discover_discord_pivots(&r);
        assert_eq!(ids, vec!["359023095012345678".to_string()]);
    }

    #[test]
    fn looks_like_steam_id_strict_heuristic() {
        // Exactly 17 digits, no leading zero.
        assert!(looks_like_steam_id("76561198000000000"));
        assert!(looks_like_steam_id("76561198123456789"));
        // 16 / 18 digits, leading-zero, non-digit — all reject.
        assert!(!looks_like_steam_id("7656119800000000")); // 16
        assert!(!looks_like_steam_id("765611980000000000")); // 18
        assert!(!looks_like_steam_id("07561198000000000")); // leading zero
        assert!(!looks_like_steam_id("765611x8000000000"));
        assert!(!looks_like_steam_id(""));
    }

    #[test]
    fn discover_steam_pivots_extracts_unique_ids() {
        let mut r = ModuleResult::new();
        r.push(Entity::new(
            EntityKind::Username,
            "steam:76561198000000000",
            0.6,
            "test",
        ));
        r.push(Entity::new(
            EntityKind::Username,
            "steam:76561198000000000",
            0.6,
            "test",
        ));
        // Mixed-in discord entity — must be ignored by the steam
        // pivot collector.
        r.push(Entity::new(
            EntityKind::Username,
            "discord:359023095012345678",
            0.6,
            "test",
        ));
        let ids = discover_steam_pivots(&r);
        assert_eq!(ids, vec!["76561198000000000".to_string()]);
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
            EndpointCall::Stealer,
            EndpointCall::BreachHub,
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
