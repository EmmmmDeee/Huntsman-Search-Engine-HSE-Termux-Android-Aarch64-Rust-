//! SeekNow (see-know.eu) — parallel breach + stealer + OSINT pool.
//!
//! Direct OathNet competitor with its own 5,000-lookup daily quota.
//! Runs alongside oathnet_pro so each scan effectively gets 2 parallel
//! Multiplier-tier pools (separate quotas, overlapping but distinct
//! data corpora — combining them maximises coverage).
//!
//! Per-target endpoint routing (paid quota spent only where free can't reach):
//!
//!   Email      → /search + /stealer + /breachhub + /network/email-check
//!   Username   → /search + /stealer + /username/social + /username/history
//!                + /breachhub  (+ discord/steam ID-resolution pivots)
//!   Phone      → /search + /network/phone + /breachhub
//!   Domain     → /domain/intel + /domain/whois
//!   IpAddress  → /network/ip
//!   FullName   → /search (auto-detect) + /breachhub
//!
//! Single-origin presence checks (github/twitter/reddit/tiktok/roblox/xbox/
//! minecraft) are deliberately NOT dispatched — the free `username_search`
//! stack (600+ sites), `social_probe`, and `search_engines` scraping already
//! cover those, so SeekNow's paid lookups go only to breach / stealer /
//! username-history aggregation and cross-platform ID resolution. See
//! [`FREE_COVERED_SINGLE_ORIGIN`] / [`effective_plan`].
//!
//! Each scan spends up to HUNTSMAN_SEEKNOW_SCAN_CAP lookups (default 160).
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
use crate::util::geo::is_valid_coords;
use crate::util::preflight::{is_local_domain, is_placeholder_username, is_private_ip};
use crate::util::see_know::{self, val_str};

mod pivots;

use pivots::{
    discover_discord_pivots, discover_steam_pivots, dispatch_discord_pivots, dispatch_steam_pivots,
    looks_like_discord_id, looks_like_steam_id,
};

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
        // The name/auto `/search` path has a ~55s server cap and routinely
        // takes 50–60s to return real data. The module budget must exceed both
        // that cap and the 78s curl-client outer timeout so the engine does not
        // abort see_know before the upstream responds. 80s gives headroom while
        // staying bounded.
        80_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let key = see_know::resolve_key(ctx.key_opt(see_know::KEY_ENV));

        let mut result = ModuleResult::new();
        let mut seen: HashSet<String> = HashSet::new();
        seen.insert(target.value.to_lowercase());
        let v = target.value.trim();

        // Pre-flight skip — junk seeds (local domains, too-short usernames,
        // placeholder values, private IPs, unsupported kinds) never reach an
        // HTTP call, saving quota and pool noise.
        if should_skip_seed(target.kind, v) {
            return Ok(result);
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

        // ── Per-seed endpoint matrix: maximise SeekNow's UNIQUE coverage ──
        //
        // Each target kind plans the relevant SeekNow endpoints, then
        // `effective_plan` strips the single-origin presence checks the free
        // username stack already covers, and the remainder dispatch
        // concurrently (bounded by remaining scan + session budget). What
        // actually runs:
        //
        //   Email     → stealer, breachhub, email-check
        //   Username  → stealer, social (multi-platform aggregate, 1 call),
        //               username-history, breachhub
        //               (+ discord/user + discord-to-roblox when the value
        //                parses as a Discord ID; + steam when a Steam ID —
        //                ID resolution, not single-site enumeration)
        //   Phone     → phone_info, breachhub, search(typed phone)
        //   Domain    → domain/intel, domain/whois
        //   IpAddress → network/ip
        //   FullName  → /search auto + breachhub
        //
        // The single-origin github/twitter/reddit/tiktok/roblox/xbox/minecraft
        // endpoints are filtered out — free `username_search` handles those, so
        // paid quota isn't wasted re-confirming them.
        //
        // Within each plan, calls run via `join_all` — the wall-time
        // collapses to the slowest single endpoint instead of summing
        // every call's latency. Budget gates inside util::see_know
        // turn no-quota calls into instant empty-vec returns.
        if !ctx.cancel.is_cancelled() && see_know::budget_remaining() {
            // effective_plan() drops single-origin endpoints the free
            // username stack already covers, so paid quota is spent only on
            // breach / history / multi-platform aggregation and ID pivots.
            let plan = effective_plan(target.kind, v);
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

            // Identity-pivot pass — SeekNow's unique edge over the free
            // username stack. Discord/Steam IDs surfaced by the extractor are
            // resolved to their LINKED accounts, and because those links chain
            // (discord → roblox → steam → …) we chase them across MULTIPLE hops
            // within budget rather than a single round. See [`resolve_identity_pivots`].
            if !ctx.cancel.is_cancelled() {
                resolve_identity_pivots(key, v, &ctx.scan_id, &mut seen, &mut result).await;
            }
        }

        Ok(result)
    }
}

/// Maximum cross-platform identity-pivot hops per scan. Each hop resolves the
/// IDs surfaced by the previous one; 3 covers the realistic chains
/// (discord → roblox → steam, …) without unbounded fan-out, and the per-scan
/// SeekNow budget + a visited-set guarantee termination regardless.
const MAX_PIVOT_HOPS: usize = 3;

/// Iteratively resolve cross-platform identity pivots — SeekNow's unique value.
///
/// Each hop scans the accumulated `result` for Discord/Steam IDs not yet
/// resolved, dispatches the unresolved ones concurrently, folds the responses
/// (entities + geo) back into the graph, and repeats. It stops when no new IDs
/// appear, a hop yields no new entities, the per-scan budget is spent, or
/// [`MAX_PIVOT_HOPS`] is reached — so it always halts. Free modules can
/// enumerate a username across sites; only a breach/identity pool turns a
/// Discord snowflake or SteamID64 into its linked accounts, and those links
/// chain — so we chase them hard, within budget. Replaces the prior single-pass
/// pivot so a discord → roblox → steam chain closes inside one scan.
async fn resolve_identity_pivots(
    key: &str,
    seed_value: &str,
    scan_id: &str,
    seen: &mut HashSet<String>,
    result: &mut ModuleResult,
) {
    // Distinct IDs already dispatched, so a chain that loops back never
    // re-resolves the same account. Namespaced by kind ("d:"/"s:") so a numeric
    // collision across platforms can't suppress a real pivot.
    let mut resolved: HashSet<String> = HashSet::new();
    for _hop in 0..MAX_PIVOT_HOPS {
        if !see_know::budget_remaining() {
            break;
        }
        let discord: Vec<String> = discover_discord_pivots(result)
            .into_iter()
            .filter(|id| resolved.insert(format!("d:{id}")))
            .collect();
        let steam: Vec<String> = discover_steam_pivots(result)
            .into_iter()
            .filter(|id| resolved.insert(format!("s:{id}")))
            .collect();
        if discord.is_empty() && steam.is_empty() {
            break; // converged — no unresolved IDs left
        }

        let mut pivot_results: Vec<(&'static str, Vec<Value>)> = Vec::new();
        if !discord.is_empty() {
            pivot_results.extend(dispatch_discord_pivots(key, discord).await);
        }
        if !steam.is_empty() && see_know::budget_remaining() {
            pivot_results.extend(dispatch_steam_pivots(key, steam).await);
        }

        let before = result.entities.len();
        for (endpoint, items) in &pivot_results {
            for item in items {
                extract_entities(item, seed_value, scan_id, seen, result);
                extract_geo_entities(item, endpoint, scan_id, seen, result);
            }
        }
        if result.entities.len() == before {
            break; // a hop that surfaced nothing new — stop chasing
        }
    }
}

/// True if a seed is junk that should never reach a SeekNow HTTP call — local
/// domains, too-short / all-digit / placeholder usernames, under-length phones
/// and names, private IPs, and any unsupported target kind. Pure function of
/// `(kind, value)` so the skip policy is testable in isolation.
fn should_skip_seed(kind: TargetKind, v: &str) -> bool {
    match kind {
        TargetKind::Email => v
            .split_once('@')
            .is_some_and(|(_, host)| is_local_domain(host)),
        TargetKind::Username => {
            v.len() < 4 || v.chars().all(|c| c.is_ascii_digit()) || is_placeholder_username(v)
        }
        TargetKind::Phone => v.chars().filter(|c| c.is_ascii_digit()).count() < 6,
        TargetKind::FullName => !v.contains(' ') || v.len() < 5,
        TargetKind::IpAddress => is_private_ip(v),
        TargetKind::Domain => is_local_domain(v),
        _ => true,
    }
}

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
fn effective_plan(kind: TargetKind, value: &str) -> Vec<EndpointCall> {
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

/// Enum of SeekNow endpoints the module can target. Centralising them
/// here makes the per-target dispatch plan trivially extensible — to
/// wire up a new endpoint, add a variant + a match arm in
/// `invoke()`/`label()`/`argument()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    /// The endpoint's `(label, path, param)` spec. `label` is the stable
    /// identifier `extract_geo_entities` uses to pick endpoint-specific geo
    /// extractors; `path` and `param` form the SeekNow `/api/v1/<path>?<param>=`
    /// single-parameter GET. This one table is the single source of truth that
    /// drives both [`label`](Self::label) and [`invoke`](Self::invoke).
    fn spec(self) -> (&'static str, &'static str, &'static str) {
        match self {
            Self::Stealer => ("stealer", "stealer", "q"),
            Self::BreachHub => ("breachhub", "breachhub/search", "q"),
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

/// Geo-conscious extraction — surface coordinates, timezones, and
/// location-bearing fields from any SeekNow endpoint response so the
/// downstream geocode/overpass/wigle modules can converge.
/// First-present-of-`keys` coordinate value, accepting either a JSON number or
/// a numeric string (some SeekNow endpoints serialise lat/lon as strings).
/// Preserves the original semantics: pick the first present key, then read it as
/// an f64 or, failing that, parse its string form.
fn parse_coord(item: &Value, keys: &[&str]) -> Option<f64> {
    let v = keys.iter().find_map(|k| item.get(*k))?;
    v.as_f64().or_else(|| v.as_str()?.parse().ok())
}

fn extract_geo_entities(
    item: &Value,
    endpoint: &str,
    scan_id: &str,
    seen: &mut HashSet<String>,
    result: &mut ModuleResult,
) {
    // Direct coordinate fields — some endpoints (ip_info, phone_info)
    // return lat/lon pairs directly, as a JSON number or a numeric string.
    let lat = parse_coord(item, &["latitude", "lat"]);
    let lon = parse_coord(item, &["longitude", "lon", "lng"]);
    // Shared validator: finite + in-range + not-Null-Island. Breach/OSINT
    // aggregators commonly carry 0,0 as a null-location value in records,
    // which the prior range-only check admitted as a false Coordinates entity.
    if let (Some(la), Some(lo)) = (lat, lon)
        && is_valid_coords(la, lo)
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
            push_breach_entity(
                result,
                Entity::new(EntityKind::Email, &email, 0.70, scan_id),
                &ev,
                &[],
            );
        }
    }
    if let Some(uname) = val_str(item, "username") {
        let lower = uname.to_lowercase();
        if lower.len() >= 3 && seen.insert(lower) {
            push_breach_entity(
                result,
                Entity::new(EntityKind::Username, &uname, 0.65, scan_id),
                &ev,
                &[],
            );
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
        push_breach_entity(
            result,
            Entity::new(EntityKind::Phone, &phone, conf, scan_id),
            &ev,
            &[],
        );
    }
    if let Some(name) = val_str(item, "full_name").or_else(|| val_str(item, "name"))
        && name.trim().contains(' ')
        && seen.insert(name.to_lowercase())
    {
        push_breach_entity(
            result,
            Entity::new(EntityKind::Person, name.trim(), 0.65, scan_id),
            &ev,
            &[],
        );
    }
    if let Some(ip) = val_str(item, "ip")
        && ip.len() >= 7
        && seen.insert(ip.clone())
    {
        push_breach_entity(
            result,
            Entity::new(EntityKind::IpAddress, &ip, 0.60, scan_id),
            &ev,
            &["geolocation-lead"],
        );
    }
    if let Some(country) = val_str(item, "country")
        && seen.insert(format!("@country:{country}"))
    {
        push_breach_entity(
            result,
            Entity::new(EntityKind::Address, &country, 0.55, scan_id),
            &ev,
            &[],
        );
    }
    if let Some(did) = val_str(item, "discord_id").or_else(|| val_str(item, "discordid"))
        && seen.insert(format!("@discord:{did}"))
    {
        push_breach_entity(
            result,
            Entity::new(
                EntityKind::Username,
                format!("discord:{did}"),
                0.60,
                scan_id,
            ),
            &ev,
            &["discord"],
        );
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
        push_breach_entity(
            result,
            Entity::new(EntityKind::Username, format!("steam:{sid}"), 0.60, scan_id),
            &ev,
            &["steam"],
        );
    }
    // Domain is infrastructure, not a leaked credential, so it is the one kind
    // NOT tagged `breach` — keep its inline tail (and consume the last `ev`).
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

/// Apply see_know's standard breach tags (`breach`, `see-know`, plus any
/// endpoint-specific `extra_tags`) and a cloned evidence record to `e`, then
/// push it onto `result`. Centralises the tag+evidence+push tail that every
/// breach-derived entity kind shares.
fn push_breach_entity(
    result: &mut ModuleResult,
    mut e: Entity,
    ev: &Evidence,
    extra_tags: &[&str],
) {
    e.tag(tags::BREACH);
    e.tag("see-know");
    for t in extra_tags {
        e.tag(*t);
    }
    e.add_evidence(ev.clone());
    result.push(e);
}

// Pre-flight validators (`is_private_ip`, `is_local_domain`,
// `is_placeholder_username`) live in `crate::util::preflight` —
// shared with the oathnet_pro module so a target rejected by one
// provider is rejected by the other.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_timeout_exceeds_seeknow_curl_outer_budget() {
        // Regression: the engine aborts a module at max_timeout_ms. see_know's
        // name/auto search legitimately takes ~55s (server cap) and the curl
        // client's outer timeout is 78s; the module budget must exceed that so
        // the engine doesn't kill see_know before the upstream responds. Was
        // 45s — below the cap — which guaranteed truncation on name seeds.
        assert!(
            SeekNow.max_timeout_ms() >= 78_000,
            "see_know max_timeout_ms {} must be >= 78_000 (curl-client outer timeout)",
            SeekNow.max_timeout_ms()
        );
    }

    #[test]
    fn should_skip_seed_matches_preflight_policy() {
        // Skipped (junk) seeds.
        assert!(should_skip_seed(TargetKind::Email, "x@localhost"));
        assert!(should_skip_seed(TargetKind::Username, "abc")); // < 4
        assert!(should_skip_seed(TargetKind::Username, "12345")); // all digits
        assert!(should_skip_seed(TargetKind::Phone, "12345")); // < 6 digits
        assert!(should_skip_seed(TargetKind::FullName, "Jordan")); // no space
        assert!(should_skip_seed(TargetKind::IpAddress, "192.168.1.1"));
        assert!(should_skip_seed(TargetKind::Coordinates, "0,0")); // unsupported kind
        // Accepted (real) seeds.
        assert!(!should_skip_seed(
            TargetKind::Email,
            "jordan.meyer@wartburg.edu"
        ));
        assert!(!should_skip_seed(TargetKind::Username, "jmeyer82291"));
        assert!(!should_skip_seed(TargetKind::Phone, "+15551234567"));
        assert!(!should_skip_seed(TargetKind::FullName, "Jordan Meyer"));
        assert!(!should_skip_seed(TargetKind::IpAddress, "8.8.8.8"));
        assert!(!should_skip_seed(TargetKind::Domain, "example.com"));
    }

    #[test]
    fn extract_entities_characterization() {
        use serde_json::json;
        let item = json!({
            "dbname": "TestBreach",
            "email": "Jordan.Meyer@Example.com",
            "username": "jmeyer",
            "phone": "15551234567",
            "full_name": "Jordan Meyer",
            "ip": "8.8.8.8",
            "country": "US",
            "discord_id": "123456789012345678",
            "steam_id": "76561198000000000",
            "domain": "example.com"
        });
        let mut seen = HashSet::new();
        let mut result = ModuleResult::new();
        extract_entities(&item, "15551234567", "scan", &mut seen, &mut result);

        // One entity per recognised field.
        assert_eq!(
            result.entities.len(),
            9,
            "kinds: {:?}",
            result
                .entities
                .iter()
                .map(|e| (e.kind.to_string(), e.value.clone()))
                .collect::<Vec<_>>()
        );
        // Every entity carries `see-know`; all but the Domain carry `breach`.
        for e in &result.entities {
            assert!(e.has_tag("see-know"), "{} missing see-know", e.value);
            assert_eq!(
                e.has_tag("breach"),
                e.kind != EntityKind::Domain,
                "breach tag policy wrong for {} ({})",
                e.value,
                e.kind
            );
        }
        // Kind-specific values + endpoint-specific tags.
        let has =
            |k: EntityKind, v: &str| result.entities.iter().any(|e| e.kind == k && e.value == v);
        assert!(has(EntityKind::Email, "jordan.meyer@example.com"));
        assert!(has(EntityKind::Username, "jmeyer"));
        assert!(has(EntityKind::Phone, "15551234567"));
        assert!(has(EntityKind::Person, "Jordan Meyer"));
        assert!(has(EntityKind::Address, "US"));
        assert!(has(EntityKind::Domain, "example.com"));
        assert!(
            result
                .entities
                .iter()
                .any(|e| e.kind == EntityKind::IpAddress && e.has_tag("geolocation-lead"))
        );
        assert!(
            result
                .entities
                .iter()
                .any(|e| e.value == "discord:123456789012345678" && e.has_tag("discord"))
        );
        assert!(
            result
                .entities
                .iter()
                .any(|e| e.value == "steam:76561198000000000" && e.has_tag("steam"))
        );
    }

    #[test]
    fn extract_geo_entities_characterization() {
        use serde_json::json;

        // Coordinates from f64 fields, tagged with the endpoint.
        {
            let (mut seen, mut r) = (HashSet::new(), ModuleResult::new());
            extract_geo_entities(
                &json!({"lat": 40.7128, "lon": -74.0060}),
                "ip_info",
                "s",
                &mut seen,
                &mut r,
            );
            assert!(
                r.entities
                    .iter()
                    .any(|e| e.kind == EntityKind::Coordinates && e.has_tag("via:ip_info")),
                "f64 coords"
            );
        }
        // Coordinates from STRING fields (the dual f64/str parse path).
        {
            let (mut seen, mut r) = (HashSet::new(), ModuleResult::new());
            extract_geo_entities(
                &json!({"latitude": "51.5", "longitude": "-0.12"}),
                "phone_info",
                "s",
                &mut seen,
                &mut r,
            );
            assert!(
                r.entities.iter().any(|e| e.kind == EntityKind::Coordinates),
                "string coords"
            );
        }
        // Out-of-range coordinates are rejected.
        {
            let (mut seen, mut r) = (HashSet::new(), ModuleResult::new());
            extract_geo_entities(
                &json!({"lat": 999.0, "lon": 0.0}),
                "ip_info",
                "s",
                &mut seen,
                &mut r,
            );
            assert!(
                !r.entities.iter().any(|e| e.kind == EntityKind::Coordinates),
                "out-of-range rejected"
            );
        }
        // Null Island (0,0) is rejected — common null-location value in breach
        // aggregator records; the shared validator drops it.
        {
            let (mut seen, mut r) = (HashSet::new(), ModuleResult::new());
            extract_geo_entities(
                &json!({"lat": 0.0, "lon": 0.0}),
                "ip_info",
                "s",
                &mut seen,
                &mut r,
            );
            assert!(
                !r.entities.iter().any(|e| e.kind == EntityKind::Coordinates),
                "Null Island rejected"
            );
        }
        // Location hint, timezone, ASN + org (ip_info only).
        {
            let (mut seen, mut r) = (HashSet::new(), ModuleResult::new());
            extract_geo_entities(
                &json!({"location": "Sydney, NSW", "timezone": "Australia/Sydney", "asn": "AS15169", "org": "Google"}),
                "ip_info",
                "s",
                &mut seen,
                &mut r,
            );
            assert!(
                r.entities
                    .iter()
                    .any(|e| e.value == "Sydney, NSW" && e.has_tag("geo-hint"))
            );
            assert!(
                r.entities
                    .iter()
                    .any(|e| e.value == "tz:Australia/Sydney" && e.has_tag("timezone"))
            );
            assert!(
                r.entities
                    .iter()
                    .any(|e| e.kind == EntityKind::Asn && e.value == "AS15169")
            );
            assert!(
                r.entities
                    .iter()
                    .any(|e| e.kind == EntityKind::Organisation)
            );
        }
        // ASN/org gated to the ip_info endpoint.
        {
            let (mut seen, mut r) = (HashSet::new(), ModuleResult::new());
            extract_geo_entities(&json!({"asn": "AS1"}), "phone_info", "s", &mut seen, &mut r);
            assert!(!r.entities.iter().any(|e| e.kind == EntityKind::Asn));
        }
        // WHOIS registrant address (>= 2 parts) on the whois endpoint.
        {
            let (mut seen, mut r) = (HashSet::new(), ModuleResult::new());
            extract_geo_entities(
                &json!({"registrant_city": "Reno", "registrant_state": "NV", "registrant_country": "US"}),
                "whois",
                "s",
                &mut seen,
                &mut r,
            );
            assert!(
                r.entities
                    .iter()
                    .any(|e| e.value == "Reno, NV, US" && e.has_tag("whois-registrant"))
            );
        }
    }

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
        // …while keeping the paid-unique value: breach/stealer/history plus the
        // multi-platform aggregate (one call across many sites — not single-origin).
        for kept in ["stealer", "social", "username_history", "breachhub"] {
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

    #[tokio::test]
    async fn resolve_identity_pivots_is_noop_and_terminates_without_ids() {
        // A graph with no discord:/steam: IDs converges on the first hop with
        // no HTTP and no new entities — the termination guarantee on the empty
        // case (the multi-hop network behaviour is covered at the util layer).
        crate::util::see_know::reset_budget();
        let mut seen = HashSet::new();
        let mut result = ModuleResult::new();
        result.push(Entity::new(EntityKind::Email, "a@b.com", 0.8, "t"));
        let before = result.entities.len();
        resolve_identity_pivots("key", "seed", "t", &mut seen, &mut result).await;
        assert_eq!(
            result.entities.len(),
            before,
            "no pivot IDs ⇒ no dispatch, no growth, clean halt"
        );
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
