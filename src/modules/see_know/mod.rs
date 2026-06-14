//! SeekNow (see-know.eu) — parallel breach + stealer + OSINT pool.
//!
//! Direct OathNet competitor with its own 5,000-lookup daily quota.
//! Runs alongside oathnet_pro so each scan effectively gets 2 parallel
//! Multiplier-tier pools (separate quotas, overlapping but distinct
//! data corpora — combining them maximises coverage).
//!
//! Per-target endpoint routing. The universal `/search` is the broadest, most
//! comprehensive endpoint — it returns breach + stealer + external records
//! unified in ONE paid call (with breach_count/stealer_count/external_count) —
//! so it is the primary call for EVERY target kind. Per-kind add-ons only cover
//! data `/search` does not return. (The standalone `/stealer` and
//! `/breachhub/search` paths were removed: live-verified 404, and fully
//! subsumed by `/search` — exactly the redundant "restricted searches" the
//! broad endpoint supersedes.)
//!
//!   Email      → /search + /network/email-check (account/service map)
//!   Username   → /search + /username/social + /username/history
//!                (+ discord/steam ID-resolution pivots)
//!   Phone      → /search + /network/phone (carrier/line enrichment)
//!   Domain     → /search + /domain/intel + /domain/whois
//!   IpAddress  → /search + /network/ip
//!   FullName   → /search (auto-detect) — no add-on needed
//!
//! Single-origin presence checks (github/twitter/reddit/tiktok/roblox/xbox/
//! minecraft) are deliberately NOT dispatched — the free `username_search`
//! stack (600+ sites), `social_probe`, and `search_engines` scraping already
//! cover those, so SeekNow's paid lookups go only to the broad `/search`,
//! username-history aggregation, and cross-platform ID resolution. See the
//! `endpoints` submodule (`FREE_COVERED_SINGLE_ORIGIN` / `effective_plan`).
//!
//! Each scan spends up to HUNTSMAN_SEEKNOW_SCAN_CAP lookups (default 160).
//! Discovered credentials feed the same key-harvest pipeline as oathnet_pro
//! — extract_api_keys_from_item recognises the same 80+ prefix patterns.

use std::collections::HashSet;

use async_trait::async_trait;
use serde_json::Value;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
    tags,
};
use crate::modules::oathnet_pro::key_harvest::{extract_api_keys_from_item, store_api_credential};
use crate::util::extract::EMAIL_RE;
use crate::util::geo::is_valid_coords;
use crate::util::preflight::{is_local_domain, is_placeholder_username, is_private_ip};
use crate::util::see_know::{self, val_str};
use crate::util::url_util::host_from_url;

mod endpoints;
mod pivots;

use endpoints::{dispatch_plan, effective_plan};
use pivots::{
    discover_discord_pivots, discover_steam_pivots, dispatch_discord_pivots, dispatch_steam_pivots,
    looks_like_steam_id,
};

const SRC: &str = "see_know";

/// Matches `<@id>` and `<@!id>` Discord user-mention shapes.
static MESSAGE_MENTION_RE: std::sync::LazyLock<regex::Regex> =
    std::sync::LazyLock::new(|| regex::Regex::new(r"<@!?(\d{17,20})>").unwrap());

/// Re-export budget reset for the engine.
pub fn reset_budget() {
    crate::util::see_know::reset_budget();
}

/// Re-export the per-round budget refresh for the engine's expansion loop, so
/// SeekNow is utilised in every iteration of a scan.
pub fn refresh_round_budget() {
    crate::util::see_know::refresh_round_budget();
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
        // Runs BEFORE oathnet_pro (127). Operator directive: SeekNow is always
        // prioritised above OathNet — its corpus already incorporates OathNet's
        // and supersedes it in most ways, so it must query first and seed the
        // graph (and the per-target dispatch cache) ahead of OathNet, which then
        // only adds whatever marginal records SeekNow didn't already return.
        // Both are Multiplier-tier Paid modules in Phase 1 of concurrent
        // dispatch; Phase 1 runs Paid modules in priority order, so 128 > 127
        // guarantees SeekNow goes first.
        128
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Paid
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Breach
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // SeekNow's broad breach + stealer + OSINT corpus is the widest single
        // Reconnaissance surface in HSE. Beyond the Breach-category default
        // (credentials + email) its extractors gather employee names, physical
        // locations, org/employer relationships, social-media handles, network
        // IP/ASN records, and host device fingerprints — so it declares the
        // precise (additive) superset and the per-scan coverage report credits
        // every technique its extraction actually exercises, not just two.
        &[
            "T1589.001", // Credentials — leaked passwords / hashes (Password, credential)
            "T1589.002", // Email Addresses
            "T1589.003", // Employee Names — full_name / first+last → Person
            "T1590.005", // IP Addresses — ip / ASN / network records
            "T1591.001", // Determine Physical Locations — address / coords / city-state
            "T1591.002", // Business Relationships — company / employer / org
            "T1592",     // Gather Victim Host Information — MAC / HWID / hostname / device_id
            "T1593.001", // Social Media — telegram / facebook / instagram / … handles
        ]
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
            EntityKind::Url,
            EntityKind::ApiKey,
            EntityKind::MacAddress,
            EntityKind::DeviceId,
            EntityKind::Password,
            // Plus `Other(<field>)` for every remaining raw field — see
            // `extract_rich_detail` (an unbounded set, so not enumerable here).
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
        // Stable origin fingerprint of the exact key in use — stamped onto every
        // entity this module produces so each finding declares which API key
        // (and provider) returned it. Computed once per scan.
        let key_fp = see_know::key_fingerprint(key);

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
                    .with_attr("endpoint", "/api/v1/search")
                    .with_attr("provider", "see-know.eu")
                    .with_attr("api_key_origin", &key_fp),
            );
            result.push(parent);

            for item in &items {
                extract_entities(
                    item,
                    v,
                    &ctx.scan_id,
                    "search",
                    &key_fp,
                    &mut seen,
                    &mut result,
                );
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
        // (breach + stealer + external records already arrived via the broad
        // `/search` above; these add-ons only cover what `/search` does not):
        //
        //   Email     → email-check (account/service existence map)
        //   Username  → social (multi-platform aggregate, 1 call),
        //               username-history
        //               (+ discord/user + discord-to-roblox when the value
        //                parses as a Discord ID; + steam when a Steam ID —
        //                ID resolution, not single-site enumeration)
        //   Phone     → phone_info (carrier/line enrichment)
        //   Domain    → domain/intel, domain/whois
        //   IpAddress → network/ip
        //   FullName  → (none — `/search` auto-detect already covers it)
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
                    extract_entities(
                        item,
                        v,
                        &ctx.scan_id,
                        endpoint,
                        &key_fp,
                        &mut seen,
                        &mut result,
                    );
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
                resolve_identity_pivots(key, &key_fp, v, &ctx.scan_id, &mut seen, &mut result)
                    .await;
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
    key_fp: &str,
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
                extract_entities(item, seed_value, scan_id, endpoint, key_fp, seen, result);
                extract_geo_entities(item, endpoint, scan_id, seen, result);
                if *endpoint == "discord_messages" {
                    extract_message_emails(item, scan_id, seen, result);
                    extract_message_mentions(item, scan_id, seen, result);
                }
            }
        }
        if result.entities.len() == before {
            break; // a hop that surfaced nothing new — stop chasing
        }
    }
}

/// Mine a `discord_messages` item's free-text `content` for embedded emails
/// and emit each as a low-confidence `Email` entity (0.30 — below pivot floor).
fn extract_message_emails(
    item: &Value,
    scan_id: &str,
    seen: &mut HashSet<String>,
    result: &mut ModuleResult,
) {
    let Some(content) = val_str(item, "content") else {
        return;
    };
    let ev = Evidence::new(SRC, "SeekNow discord_messages content")
        .with_attr("source", "discord_messages");
    for m in EMAIL_RE.find_iter(&content) {
        let email = m.as_str().to_lowercase();
        if seen.insert(email.clone()) {
            let mut e = Entity::new(EntityKind::Email, &email, 0.30, scan_id);
            e.tag("see-know");
            e.tag("discord-message");
            e.tag("weak-lead");
            e.add_evidence(ev.clone());
            result.push(e);
        }
    }
}

/// Mine a `discord_messages` item's free-text `content` for `<@id>` / `<@!id>`
/// Discord user-mention snowflakes and emit each as a low-confidence `Username`
/// entity (`discord:<id>`, 0.30 — below pivot floor).
fn extract_message_mentions(
    item: &Value,
    scan_id: &str,
    seen: &mut HashSet<String>,
    result: &mut ModuleResult,
) {
    let Some(content) = val_str(item, "content") else {
        return;
    };
    let ev = Evidence::new(SRC, "SeekNow discord_messages content")
        .with_attr("source", "discord_messages");
    for caps in MESSAGE_MENTION_RE.captures_iter(&content) {
        let id = &caps[1];
        if seen.insert(format!("@discord:{id}")) {
            let mut e = Entity::new(EntityKind::Username, format!("discord:{id}"), 0.30, scan_id);
            e.tag("see-know");
            e.tag("discord-message");
            e.tag("weak-lead");
            e.tag("mention");
            e.add_evidence(ev.clone());
            result.push(e);
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

/// Build an [`Evidence`] record that preserves EVERY field of the raw source
/// record `item` as an attribute — full fidelity, nothing redacted or omitted
/// (operator data-fidelity policy). Scalars are stored as-is; nested
/// objects/arrays as compact JSON. This is what makes a result traceable to its
/// actual raw source record rather than just a module name + entity hash.
fn record_evidence(item: &Value, dbname: &str, endpoint: &str, key_fp: &str) -> Evidence {
    let ev = Evidence::new(SRC, format!("SeekNow record from {dbname}"))
        .with_attr("source", dbname)
        // Provenance: which provider, which exact API key, and which endpoint
        // returned this record. Stamped on EVERY record so a finding always
        // declares its origin (operator directive: specify the API key origin).
        .with_attr("provider", "see-know.eu")
        .with_attr("api_key_origin", key_fp)
        .with_attr("via_endpoint", endpoint);
    let Some(obj) = item.as_object() else {
        return ev;
    };
    obj.iter().fold(ev, |ev, (k, v)| {
        let val = match v {
            Value::Null => return ev,
            Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        if val.is_empty() {
            return ev;
        }
        // Don't clobber the canonical "source" attribute set above.
        let key = if k == "source" {
            "source_db"
        } else {
            k.as_str()
        };
        ev.with_attr(key, val)
    })
}

fn extract_entities(
    item: &Value,
    target_value: &str,
    scan_id: &str,
    endpoint: &str,
    key_fp: &str,
    seen: &mut HashSet<String>,
    result: &mut ModuleResult,
) {
    let dbname = val_str(item, "dbname")
        .or_else(|| val_str(item, "source"))
        .unwrap_or_else(|| "see-know".to_string());
    // Full raw record on the evidence chain — every entity derived from this
    // record carries the complete source data plus its provenance (provider,
    // API-key origin, endpoint) for traceability.
    let ev = record_evidence(item, &dbname, endpoint, key_fp);

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
    // Leaked credentials were previously dropped entirely — capture them as
    // first-class Password entities (operator policy: never redacted). The full
    // record (including any hash) is already on `ev`, so nothing is lost even
    // when several credential fields coexist; one pivotable entity is enough.
    for field in [
        "password",
        "passwordHash",
        "password_hash",
        "hashed_password",
        "hash",
    ] {
        if let Some(pw) = val_str(item, field)
            && !pw.is_empty()
            && seen.insert(format!("@pw:{pw}"))
        {
            push_breach_entity(
                result,
                Entity::new(EntityKind::Password, &pw, 0.75, scan_id),
                &ev,
                &["credential"],
            );
            break;
        }
    }

    // ── Stealer-log saved-credential URL ──────────────────────────────────
    //
    // The single most OSINT-valuable artifact in a stealer record is the URL
    // the victim had a saved credential for. SeekNow's /stealer endpoint (and
    // the /search auto-route into it) carries it as `url`/`url_str`. Spider it
    // into three pivotable entities — exactly OathNet's proven stealer model —
    // so the rest of the graph (domain enumeration, credential correlation,
    // login-surface mapping) can converge on it:
    //
    //   • the Url itself (the captured login surface);
    //   • its registrable host as a Domain pivot (drives crt.sh, DNS, whois);
    //   • a `<username>@<url>` Credential when a login accompanies the URL.
    //
    // None are tagged `breach`: a saved-login URL is credential CONTEXT /
    // infrastructure, not leaked PII — the same policy `extract_stealer_entities`
    // applies in oathnet_pro, and the same policy the Domain block below uses.
    if let Some(url) = val_str(item, "url").or_else(|| val_str(item, "url_str")) {
        if url.len() >= 4 && seen.insert(format!("@url:{}", url.to_lowercase())) {
            let mut e = Entity::new(EntityKind::Url, &url, 0.60, scan_id);
            e.tag("see-know");
            e.tag("stealer");
            e.add_evidence(ev.clone());
            result.push(e);
        }
        // The URL's host → Domain pivot (eTLD-aware host extraction; dotless /
        // private / scheme-less junk is dropped by `host_from_url`).
        if let Some(host) = host_from_url(&url)
            && seen.insert(format!("@stealer-dom:{host}"))
        {
            let mut e = Entity::new(EntityKind::Domain, &host, 0.55, scan_id);
            e.tag("see-know");
            e.tag("stealer");
            e.add_evidence(
                Evidence::new(SRC, format!("Stealer credential captured for {host}"))
                    .with_attr("url", &url),
            );
            result.push(e);
        }
        // `<username>@<url>` Credential — the login↔surface binding, surfaced as
        // a first-class pivotable entity (operator policy: never redacted).
        if let Some(uname) = val_str(item, "username") {
            let cred_val = format!("{uname}@{url}");
            if seen.insert(format!("@cred:{}", cred_val.to_lowercase())) {
                let mut e = Entity::new(EntityKind::Credential, &cred_val, 0.60, scan_id);
                e.tag("see-know");
                e.tag("stealer");
                e.add_evidence(ev.clone());
                result.push(e);
            }
        }
    }

    // Maximum-raw-data pass: surface the long tail of the record (names, full
    // address, organisation, device fingerprints, extra social handles, DOB,
    // and EVERY remaining scalar field) as first-class entities so nothing
    // valuable stays locked inside the evidence blob. Operator directive: "I
    // want everything. Maximum raw data."
    extract_rich_detail(item, scan_id, &ev, seen, result);

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

/// Field names already turned into typed entities by `extract_entities` (or
/// deliberately suppressed as structural/metadata noise). The catch-all pass
/// skips these so it only emits the *long tail* — every other value-bearing
/// field — without duplicating a node already created or surfacing envelope
/// bookkeeping. Lower-cased compare so schema casing variants can't leak through.
const RICH_DETAIL_SKIP: &[&str] = &[
    // Already typed above.
    "email",
    "username",
    "phone",
    "phone_number",
    "full_name",
    "name",
    "ip",
    "country",
    "discord_id",
    "discordid",
    "steam_id",
    "steamid",
    "steam_id64",
    "password",
    "passwordhash",
    "password_hash",
    "hashed_password",
    "hash",
    "url",
    "url_str",
    "domain",
    // Composed/typed in the rich pass itself.
    "first_name",
    "firstname",
    "last_name",
    "lastname",
    "company",
    "employer",
    "organization",
    "organisation",
    "org",
    "mac",
    "mac_address",
    "bssid",
    "hwid",
    "machine_id",
    "device_id",
    "uuid",
    "guid",
    "computer_name",
    "machine",
    "hostname",
    "telegram",
    "skype",
    "facebook",
    "instagram",
    "twitter",
    "linkedin",
    "vk",
    "snapchat",
    "city",
    "state",
    "region",
    "province",
    "zip",
    "zipcode",
    "postal",
    "postal_code",
    "postcode",
    "street",
    "address",
    "address_line",
    // Structural / metadata / provenance bookkeeping (kept verbatim on evidence,
    // but not worth a standalone graph node).
    "source",
    "source_db",
    "dbname",
    "_origin",
    "id",
    "_id",
    "log_id",
    "log",
    "salt",
    "response_time_ms",
    "type",
    "success",
    "total",
    "breach_count",
    "stealer_count",
    "external_count",
    "index",
    "score",
    "_score",
    // Domain WHOIS/RDAP metadata — surfaced as Domain *attributes* by
    // `rdap_domain` / `whoisxml`, not worth duplicating as standalone graph
    // nodes (and `dns` is a record map, never an entity value).
    "registrar",
    "dns",
    "nameservers",
    "name_servers",
    "created",
    "created_date",
    "creation_date",
    "updated",
    "updated_date",
    "last_changed",
    "expires",
    "expiry",
    "expiration_date",
    "status",
    "whois",
];

/// Push a stealer/infrastructure-CONTEXT entity: tags `see-know` plus any
/// `extra_tags`, but deliberately NOT `breach`. Device fingerprints (MAC, HWID,
/// hostname, …) are infrastructure/context, not leaked PII — the same policy the
/// URL/Domain/Credential spidering follows — so they must not carry the `breach`
/// tag that [`push_breach_entity`] forces.
fn push_context_entity(
    result: &mut ModuleResult,
    mut e: Entity,
    ev: &Evidence,
    extra_tags: &[&str],
) {
    e.tag("see-know");
    for t in extra_tags {
        e.tag(*t);
    }
    e.add_evidence(ev.clone());
    result.push(e);
}

/// Maximum-raw-data extractor: turn the long tail of a breach/stealer record
/// into first-class, pivotable entities. Typed where a kind fits (Person,
/// Organisation, Address, MacAddress, DeviceId, platform Usernames), and
/// `Other(field)` for everything else — so EVERY value-bearing field of the raw
/// response becomes a node, not just an evidence attribute. Confidences are
/// modest (secondary, record-derived) so this breadth never outranks the
/// primary identity entities.
fn extract_rich_detail(
    item: &Value,
    scan_id: &str,
    ev: &Evidence,
    seen: &mut HashSet<String>,
    result: &mut ModuleResult,
) {
    let Some(obj) = item.as_object() else {
        return;
    };

    // ── Names: first + last → a composed Person (the bare `name`/`full_name`
    // path above only fires when the value already contains a space). ──
    let first = val_str(item, "first_name").or_else(|| val_str(item, "firstname"));
    let last = val_str(item, "last_name").or_else(|| val_str(item, "lastname"));
    if let (Some(f), Some(l)) = (&first, &last) {
        let full = format!("{} {}", f.trim(), l.trim());
        if full.len() >= 3 && seen.insert(format!("@person:{}", full.to_lowercase())) {
            push_breach_entity(
                result,
                Entity::new(EntityKind::Person, &full, 0.60, scan_id),
                ev,
                &[],
            );
        }
    }

    // ── Organisation / employer. ──
    for k in ["company", "employer", "organization", "organisation", "org"] {
        if let Some(o) = val_str(item, k)
            && o.len() >= 2
            && seen.insert(format!("@org:{}", o.to_lowercase()))
        {
            push_breach_entity(
                result,
                Entity::new(EntityKind::Organisation, &o, 0.50, scan_id),
                ev,
                &[],
            );
        }
    }

    // ── Device fingerprints — strong stealer-log pivots. ──
    for k in ["mac", "mac_address", "bssid"] {
        if let Some(m) = val_str(item, k)
            && m.len() >= 12
            && seen.insert(format!("@mac:{}", m.to_lowercase()))
        {
            push_context_entity(
                result,
                Entity::new(EntityKind::MacAddress, &m, 0.60, scan_id),
                ev,
                &["device"],
            );
        }
    }
    for k in [
        "hwid",
        "machine_id",
        "device_id",
        "uuid",
        "guid",
        "computer_name",
        "machine",
        "hostname",
    ] {
        if let Some(d) = val_str(item, k)
            && d.len() >= 3
            && seen.insert(format!("@device:{k}:{}", d.to_lowercase()))
        {
            push_context_entity(
                result,
                Entity::new(EntityKind::DeviceId, &d, 0.55, scan_id),
                ev,
                &["device", "stealer"],
            );
        }
    }

    // ── Extra social handles → platform-prefixed Username pivots. ──
    for (k, plat) in [
        ("telegram", "telegram"),
        ("skype", "skype"),
        ("facebook", "facebook"),
        ("instagram", "instagram"),
        ("twitter", "twitter"),
        ("linkedin", "linkedin"),
        ("vk", "vk"),
        ("snapchat", "snapchat"),
    ] {
        if let Some(h) = val_str(item, k)
            && h.len() >= 2
            && seen.insert(format!("@{plat}:{}", h.to_lowercase()))
        {
            push_breach_entity(
                result,
                Entity::new(EntityKind::Username, format!("{plat}:{h}"), 0.55, scan_id),
                ev,
                &[plat],
            );
        }
    }

    // ── Physical location: each part as its own geo-hint Address, plus a
    // composed multi-part address (street/city/state/postal/country). ──
    let mut addr_parts: Vec<String> = Vec::new();
    for k in [
        "street",
        "address",
        "address_line",
        "city",
        "state",
        "region",
        "province",
        "zip",
        "zipcode",
        "postal",
        "postal_code",
        "postcode",
    ] {
        if let Some(p) = val_str(item, k)
            && p.len() >= 2
        {
            if seen.insert(format!("@addr-part:{k}:{}", p.to_lowercase())) {
                push_breach_entity(
                    result,
                    Entity::new(EntityKind::Address, &p, 0.45, scan_id),
                    ev,
                    &["geo-hint"],
                );
            }
            addr_parts.push(p);
        }
    }
    if addr_parts.len() >= 2 {
        if let Some(c) = val_str(item, "country") {
            addr_parts.push(c);
        }
        let composed = addr_parts.join(", ");
        if seen.insert(format!("@addr:{}", composed.to_lowercase())) {
            push_breach_entity(
                result,
                Entity::new(EntityKind::Address, &composed, 0.55, scan_id),
                ev,
                &["geo-hint", "composed-address"],
            );
        }
    }

    // ── Catch-all: every remaining value-bearing SCALAR field becomes an
    // `Other(field)` node, so no atomic data point in the raw record is left
    // un-surfaced. Nested objects/arrays are NOT turned into entities — a
    // stringified JSON blob (e.g. a `dns` record map) is not a meaningful graph
    // node and only pollutes the entity set; its atomic contents are surfaced by
    // the typed paths above and by the dedicated DNS/RDAP modules. ──
    for (k, v) in obj {
        if RICH_DETAIL_SKIP.contains(&k.to_lowercase().as_str()) {
            continue;
        }
        let val = match v {
            Value::Null | Value::Array(_) | Value::Object(_) => continue,
            Value::String(s) => s.clone(),
            Value::Bool(b) => b.to_string(),
            Value::Number(n) => n.to_string(),
        };
        if val.is_empty() || val.len() > 2000 {
            continue;
        }
        if seen.insert(format!("@other:{k}:{}", val.to_lowercase())) {
            push_breach_entity(
                result,
                Entity::new(EntityKind::Other(k.clone()), &val, 0.40, scan_id),
                ev,
                &["raw-field"],
            );
        }
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
    include!("tests.rs");
}
