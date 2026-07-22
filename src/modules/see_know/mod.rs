//! SeekNow (see-know.xyz) — parallel breach + stealer + OSINT pool.
//!
//! Direct OathNet competitor with its own 15,000-lookup daily quota
//! (`util::see_know::enterprise_config::ENTERPRISE` — the single source of
//! truth for this and every other quota figure quoted in this file).
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
//! minecraft) ARE dispatched for every Username target, alongside the free
//! `username_search` stack (600+ sites)/`social_probe`/`search_engines`
//! scraping that also covers those platforms — the operator's maximisation
//! directive means every endpoint adding platform-specific profile depth or
//! breach context fires, with the per-scan budget cap as the only rate
//! limiter, not a platform-presence filter. (An OLDER revision of this
//! comment described a filter, `FREE_COVERED_SINGLE_ORIGIN`, that stripped
//! these before dispatch — that filter was removed; the constant is kept
//! `#[allow(dead_code)]` for documentation/future policy control, but
//! `effective_plan()` no longer applies it. See the `endpoints` submodule's
//! own, up-to-date doc comments.)
//!
//! Each scan spends up to HUNTSMAN_SEEKNOW_SCAN_CAP lookups (default 300,
//! dynamically scaled up to 750 after the per-scan `/credits` probe —
//! `clamp(daily_limit / 20, 300, 2500)`; session ceiling 100,000).
//! Discovered credentials feed the same key-harvest pipeline as oathnet_pro
//! — extract_api_keys_from_item recognises the same 80+ prefix patterns.
//!
//! ROI-optimized multi-hop discovery (`resolve_identity_pivots`): beyond
//! resolving Discord/Steam IDs to their linked accounts, the pivot loop runs a
//! CASCADE-DETECTION pass from Hop 2 onward — emails surfaced by prior hops are
//! re-queried through the Tier-1 `/network/email-check` endpoint (3–8 new
//! entities per credit) to catch service registrations that appeared *after*
//! the seed's initial `/search`. Administrative mailboxes (admin@/info@/…) and
//! wildcards are filtered out first, and cascade queries are capped at 3 per
//! hop, so each credit spent chases the highest-yield unexplored link — the
//! most convex return per query within the per-scan budget.

use std::collections::HashSet;

use async_trait::async_trait;
use serde_json::Value;

use crate::core::{
    confidence,
    entity::{EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
    tags,
};
use crate::util::key_harvest::{extract_api_keys_from_item, store_api_credential};
use crate::util::preflight::{is_local_domain, is_placeholder_username, is_private_ip};
use crate::util::see_know;
use crate::util::target_match::TargetMatch;

mod endpoints;
mod extract;
mod pivots;

use endpoints::{dispatch_plan, effective_plan};
use extract::{extract_entities, extract_geo_entities};
use pivots::{
    discover_discord_pivots, discover_steam_pivots, dispatch_discord_pivots, dispatch_steam_pivots,
};

pub(super) const SRC: &str = "see_know";

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
        "SeekNow (see-know.xyz) — sweeps the full 18-endpoint OSINT/breach pool with discord and gaming pivots"
    }

    fn priority(&self) -> u8 {
        // Operator directive: SeekNow is the HIGHEST-PRIORITY API at all times —
        // its corpus incorporates OathNet's and supersedes it, and it is the one
        // paid source that returns relatives/associates (the family graph). So it
        // is pinned to `u8::MAX`: it queries first in Phase 1 (Paid modules run in
        // priority order), seeding the graph and the per-target dispatch cache
        // ahead of every other module, and gets first claim on the per-round paid
        // budget. No other module should out-rank it; 255 leaves headroom above
        // the next-highest (200) so this holds even as priorities are retuned.
        u8::MAX
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Paid
    }

    fn cache_ttl_secs(&self) -> u64 {
        // Breach / stealer / OSINT corpus is stable within the 24h C9 window —
        // the same bracket the other paid, finite-allowance modules already use
        // (censys / netlas / hlr_cnam / opencellid / trove_au). SeekNow is the
        // highest-priority AND highest-spend paid provider (priority u8::MAX,
        // per-scan cap clamp(daily/20, 300, 2500)), and it fires on the seed
        // plus every email/username discovered during expansion — so an operator
        // iterating on the same subject is the common case. Persisting the
        // derived entities lets a repeat scan within the window replay them for
        // FREE instead of re-spending the entire per-scan credit budget, which
        // is the single largest per-query saving available. Replay re-stamps the
        // scan_id and re-runs key extraction (see dispatch::replay_cached_result),
        // so discovered credentials/keys still surface; no live call means no
        // budget spend. A first scan that was itself budget-clamped replays its
        // partial result for the window — the accepted C9 stable-within-window
        // tradeoff every other cached paid module already carries, and exactly
        // the "don't re-spend on a repeat" behaviour the operator's maximisation
        // directive wants.
        86_400
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
            "T1597.002", // Purchase Technical Data — a paid, closed breach/OSINT corpus
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
            // `CryptoAddress` is emitted by the same shared key_harvest path as
            // `ApiKey` (extract_api_keys_from_item) but was omitted here.
            EntityKind::CryptoAddress,
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
        // Two independent worst cases share this one governor (the engine
        // aborts the WHOLE process() call at this budget, covering however
        // many sequential HTTP calls happen inside it — each individual curl
        // call gets its own fresh 75s/78s allowance from `CLIENT`, so chaining
        // calls doesn't starve either one; only their SUM matters here):
        //
        //  - the name/auto `/search` path alone: a ~55s server cap, routinely
        //    50–60s to return real data (unaffected by the deep-search
        //    fallback below — it's excluded for auto/name queries, see
        //    `process`'s own comment on why).
        //  - a TYPED query whose fast `/search` draws a blank, triggering the
        //    `/search/deep` fallback: fast typed (~15s budgeted, well above
        //    the ~5s FAQ-documented typical) + deep (~45s budgeted, above the
        //    documented ~40s server cap) ≈ 60s combined.
        //
        // 110s covers the larger of the two with real headroom (the same
        // cap-plus-headroom ratio the original single-call 80s budget used),
        // without inviting the class of spurious-timeout evidentiary false
        // negative this project has repeatedly had to fix elsewhere.
        110_000
    }

    fn termux_timeout_cap_exempt(&self) -> bool {
        // see_know's /search has a ~55s server-side cap and answers in 50–60s,
        // and a typed miss can now chain into a ~40s /search/deep fallback on
        // top of that. The 45s Termux module cap would kill EVERY phone scan
        // with a timeout-exit and zero data — silently wasting the operator's
        // highest-priority paid source on the very platform HSE targets. As
        // the operator explicitly enabled this key, keep its full (still-
        // bounded) 110s budget on Termux too so the upstream response is
        // actually awaited.
        true
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

        // Once per scan: probe the daily quota and scale the per-round scan cap
        // to the operator's actual plan allocation. Fires only on the first
        // target this scan (QUOTA_PROBED latch); subsequent seeds skip the
        // extra HTTP call. Does NOT consume a budget slot.
        if see_know::should_probe_quota() && !ctx.cancel.is_cancelled() {
            match see_know::query_credits(key).await {
                Some((remaining, daily_limit)) => {
                    // No daily_limit field — estimate from remaining assuming
                    // typical mid-scan usage (≤25% spent so far).
                    let limit =
                        daily_limit.unwrap_or_else(|| remaining.saturating_mul(4).min(500_000));
                    see_know::scale_scan_cap_from_daily(limit);
                    tracing::info!(
                        credits_remaining = remaining,
                        daily_limit = ?daily_limit,
                        scan_cap = see_know::scan_budget_remaining(),
                        "see_know quota probed — scan cap scaled to plan allocation"
                    );
                }
                // The probe FAILED (transient DNS/timeout, or a not-yet-valid
                // key). Release the one-shot latch so a later seed re-probes,
                // instead of pinning the WHOLE scan to the un-scaled default cap
                // (~60% under-provisioned on a large plan) after a single blip.
                // `/credits` is non-billable, so re-probing costs no quota.
                None => see_know::release_quota_probe(),
            }
        }

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
            absorb_search_hits(
                &items,
                target,
                v,
                "/api/v1/search",
                "search",
                &key_fp,
                &ctx.scan_id,
                &mut seen,
                &mut result,
            );
        } else if should_try_deep_search(total, qtype, ctx.cancel.is_cancelled()) {
            // ── Query 1b: /search/deep fallback — fast search drew a blank ──
            // Deep search trawls slower, higher-yield databases fast search
            // skips (server cap ~40s vs. fast's ~5s typical) — the largest
            // documented, previously-unwired SeekNow coverage gap
            // (`docs/SEEKNOW_SETUP.md`: "HSE always calls fast /search, never
            // deep"). Only worth the extra latency on a genuine miss (never
            // spent when fast already found something) and only for TYPED
            // queries (`qtype` non-empty) — the auto/name path already
            // consumes most of this module's timeout budget on the fast call
            // alone (see `max_timeout_ms`'s doc comment for the worst-case
            // arithmetic this exclusion protects).
            let deep_items = see_know::search_deep(key, v, qtype).await?;
            if !deep_items.is_empty() {
                absorb_search_hits(
                    &deep_items,
                    target,
                    v,
                    "/api/v1/search/deep",
                    "search/deep",
                    &key_fp,
                    &ctx.scan_id,
                    &mut seen,
                    &mut result,
                );
            }
        }

        // ── Per-seed endpoint matrix: maximise SeekNow's UNIQUE coverage ──
        //
        // Each target kind plans the relevant SeekNow endpoints via
        // `effective_plan` (an unfiltered pass-through of `plan_endpoints`
        // — see the `endpoints` submodule's own doc comments for why the
        // single-origin filter this comment used to describe was removed),
        // and the whole plan dispatches concurrently (bounded by remaining
        // scan + session budget). What actually runs:
        //
        // (breach + stealer + external records already arrived via the broad
        // `/search` above; these add-ons cover what `/search` does not, PLUS
        // the single-origin platform-presence checks — see below):
        //
        //   Email     → email-check (account/service existence map)
        //   Username  → social (multi-platform aggregate, 1 call),
        //               github, twitter, reddit, tiktok, roblox, xbox,
        //               minecraft (platform-specific profile depth beyond
        //               what free `username_search`'s presence-only check
        //               returns), username-history
        //               (+ discord/user + discord-to-roblox when the value
        //                parses as a Discord ID; + steam when a Steam ID —
        //                ID resolution, not single-site enumeration)
        //   Phone     → phone_info (carrier/line enrichment)
        //   Domain    → domain/intel, domain/whois
        //   IpAddress → network/ip
        //   FullName  → (none — `/search` auto-detect already covers it)
        //
        // Within each plan, calls run via `join_all` — the wall-time
        // collapses to the slowest single endpoint instead of summing
        // every call's latency. Budget gates inside util::see_know
        // turn no-quota calls into instant empty-vec returns.
        if !ctx.cancel.is_cancelled() && see_know::budget_remaining() {
            // effective_plan() dispatches the FULL matrix, including the
            // single-origin platform checks — the maximisation directive
            // means SeekNow's platform-specific profile depth is worth the
            // quota even where free coverage exists at presence-only depth.
            let plan = effective_plan(target.kind, v);
            let endpoint_results = dispatch_plan(key, v, &plan).await;

            // Build the target matcher once for the whole result set — its
            // lowercase + term-split allocations are loop-invariant across
            // every record of every endpoint, so they must not repeat per row.
            let match_ctx = TargetMatch::new(v);
            for (endpoint, items) in &endpoint_results {
                // Per-endpoint yield tracing: surfaces which endpoints return
                // data for which target kinds in live logs, supporting the
                // operator's directive to identify advantageous SeekNow usage.
                if !items.is_empty() {
                    tracing::debug!(
                        endpoint,
                        hits = items.len(),
                        target_kind = ?target.kind,
                        "see_know endpoint yielded data"
                    );
                }
                for item in items {
                    extract_entities(
                        item,
                        v,
                        &match_ctx,
                        &ctx.scan_id,
                        endpoint,
                        &key_fp,
                        &mut seen,
                        &mut result,
                    );
                    store_api_credential(item, SRC);
                    extract_api_keys_from_item(item, &ctx.scan_id, SRC, &mut seen, &mut result);
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

/// Fold a non-empty universal-search result set (from either the fast
/// `/search` or the [`see_know::search_deep`] fallback) into `result`: a
/// subject-gated BREACH parent entity, then per-record extraction. Shared by
/// both call sites so the fast/deep paths can never drift in how a hit is
/// absorbed — only which endpoint produced it.
///
/// `endpoint_path` (e.g. `"/api/v1/search"`) names the exact API path in both
/// the evidence summary and its `endpoint` attribute; `endpoint_label` (e.g.
/// `"search"` / `"search/deep"`) is the short form `extract_entities` tags
/// each derived entity's evidence with, matching the label convention the
/// per-kind endpoint-matrix loop already uses for every other SeekNow call.
///
/// A broad seed (above all a `full_name` auto-detect, but also an
/// address-adjacent phone/IP) can return rows for strangers who merely share a
/// term with the target. Minting the confidence::HIGH_PLUSPLUS_PLUS BREACH parent off the raw hit count
/// re-affirms the seed's own UID — merging via `absorb` (GREATEST semantics)
/// straight into the pre-existing entity — even when NONE of the returned
/// rows actually identify the subject. `search_subject_present` mirrors the
/// same match gate `oathnet_pro::breach::breach_parent_entity` already applies
/// to its parent; the per-record extraction is unaffected — it demotes
/// non-matching rows individually via `is_target` inside `extract_entities`.
#[allow(clippy::too_many_arguments)]
fn absorb_search_hits(
    items: &[Value],
    target: &Target,
    target_value: &str,
    endpoint_path: &str,
    endpoint_label: &str,
    key_fp: &str,
    scan_id: &str,
    seen: &mut HashSet<String>,
    result: &mut ModuleResult,
) {
    let total = items.len();
    if search_subject_present(target_value, items) {
        let mut parent = target.to_entity(confidence::HIGH_PLUSPLUS_PLUS, scan_id);
        parent.tag(tags::BREACH);
        parent.tag("see-know");
        parent.add_evidence(
            Evidence::new(
                SRC,
                format!("SeekNow: {total} record(s) via {endpoint_path}"),
            )
            .with_attr("hits", total.to_string())
            .with_attr("endpoint", endpoint_path)
            // Domain-agnostic — SeekNow rotates across three domains (see
            // `see_know::client::all_base_urls`), so a literal TLD here would
            // misdescribe records served by a fallback and go stale on rotation.
            .with_attr("provider", "see-know")
            .with_attr("api_key_origin", key_fp),
        );
        result.push(parent);
    }

    // Each record yields at least one entity; reserve up front so the result
    // vector doesn't repeatedly realloc as records are walked.
    result.entities.reserve(total);

    // Loop-invariant matcher: built once per result set, not once per record.
    let match_ctx = TargetMatch::new(target_value);
    for item in items {
        extract_entities(
            item,
            target_value,
            &match_ctx,
            scan_id,
            endpoint_label,
            key_fp,
            seen,
            result,
        );
        store_api_credential(item, SRC);
        extract_api_keys_from_item(item, scan_id, SRC, seen, result);
        // Geo-conscious extraction — coordinates/timezone/location on a record.
        // `/search` and `/search/deep` are SeekNow's broadest, highest-yield
        // calls (they auto-route into the stealer/network corpora), yet this
        // absorption path was the ONLY one that skipped `extract_geo_entities`
        // — the per-endpoint dispatch path and the pivot path both already call
        // it. Coordinates, location bios, and timezone fields on these records
        // were silently dropped, starving the downstream geocode/overpass/
        // wigle/breach_timezone correlators of leads from the module's single
        // most productive call. `endpoint_label` ("search"/"search/deep") keeps
        // the endpoint-specific arms (ip_info/whois) inert while the generic
        // lat/lon, location-string, and timezone extraction fires.
        extract_geo_entities(item, endpoint_label, scan_id, seen, result);
    }
}

/// Maximum cross-platform identity-pivot hops per scan. Each hop resolves the
/// IDs surfaced by the previous one; 3 covers the realistic chains
/// (discord → roblox → steam, …) without unbounded fan-out, and the per-scan
/// SeekNow budget + a visited-set guarantee termination regardless.
const MAX_PIVOT_HOPS: usize = 3;

/// Iteratively resolve cross-platform identity pivots — SeekNow's unique value.
///
/// Enhanced ROI-optimized multi-hop discovery chain that not only resolves
/// Discord/Steam IDs but also chases emails discovered during pivots through
/// `/network/email-check` for cascade detection (new service registrations).
///
/// Each hop:
///  1. Discovers unresolved Discord/Steam IDs from the graph
///  2. Discovers emails surfaced by prior hops (cascade detection pass)
///  3. Dispatches all unresolved IDs + a subset of high-confidence emails
///  4. Folds responses back into the graph
///  5. Stops when no new IDs appear, a hop yields no new entities, the per-scan
///     budget is spent, or [`MAX_PIVOT_HOPS`] is reached.
///
/// The cascade-detection pass re-queries emails via `/network/email-check` to
/// find NEW service registrations that appeared *after* the initial `/search`
/// hit (e.g., a corporate email re-registered on a new platform). This is the
/// highest-ROI Tier-1 endpoint for email-type identifiers, yielding 3–8 new
/// entities per query, and closes email-to-services loops early.
///
/// Only applies the cascade check from Hop 2 onward (Hop 1's emails come from
/// the seed's initial search and would be redundant to re-query immediately).
/// Skips emails that appear to be wildcards or mailboxes (low confidence) to
/// conserve budget. Free modules can enumerate a username across sites; only a
/// breach/identity pool turns a Discord snowflake or SteamID64 into its linked
/// accounts, and those links chain — so we chase them hard, within budget.
async fn resolve_identity_pivots(
    key: &str,
    key_fp: &str,
    seed_value: &str,
    scan_id: &str,
    seen: &mut HashSet<String>,
    result: &mut ModuleResult,
) {
    // Distinct IDs actually DISPATCHED (not merely discovered), so a chain
    // that loops back never re-resolves the same account. Namespaced by kind
    // ("d:"/"s:"/"e:") so a numeric collision across platforms or email
    // duplicates can't suppress a real pivot. Only ids actually dispatched
    // (per the individual dispatch helpers' return values) are inserted.
    let mut resolved: HashSet<String> = HashSet::new();
    for hop in 0..MAX_PIVOT_HOPS {
        if !see_know::budget_remaining() {
            break;
        }
        let discord: Vec<String> = discover_discord_pivots(result)
            .into_iter()
            .filter(|id| !resolved.contains(&format!("d:{id}")))
            .collect();
        let steam: Vec<String> = discover_steam_pivots(result)
            .into_iter()
            .filter(|id| !resolved.contains(&format!("s:{id}")))
            .collect();

        // Cascade detection: re-query emails discovered in PRIOR hops (not seed)
        // through /network/email-check to find NEW service registrations.
        // Tier-1 endpoint (3–8 entities per query) so prioritize it over
        // expensive /search re-runs. Skip Hop 0 to avoid redundant re-queries of
        // the seed's initial /search results.
        let cascade_emails: Vec<String> = if hop > 0 {
            discover_high_confidence_emails(result)
                .into_iter()
                .filter(|e| !resolved.contains(&format!("e:{e}")))
                .take(3) // Limit cascade queries per hop — budget conservation
                .collect()
        } else {
            Vec::new()
        };

        if discord.is_empty() && steam.is_empty() && cascade_emails.is_empty() {
            break; // converged — no unresolved IDs left
        }

        let mut pivot_results: Vec<(&'static str, Vec<Value>)> = Vec::new();

        // Primary pivot dispatch: Discord (Tier 2: platform linkage) + Steam (Tier 2)
        if !discord.is_empty() {
            let (items, attempted) = dispatch_discord_pivots(key, discord).await;
            for id in attempted {
                resolved.insert(format!("d:{id}"));
            }
            pivot_results.extend(items);
        }
        if !steam.is_empty() && see_know::budget_remaining() {
            let (items, attempted) = dispatch_steam_pivots(key, steam).await;
            for id in attempted {
                resolved.insert(format!("s:{id}"));
            }
            pivot_results.extend(items);
        }

        // Cascade detection dispatch: re-query discovered emails via email-check
        // (Tier 1: service discovery). High ROI per credit, only on non-seed hops.
        if !cascade_emails.is_empty() && see_know::budget_remaining() {
            let (items, attempted) = dispatch_email_cascade_checks(key, cascade_emails).await;
            for email in attempted {
                resolved.insert(format!("e:{email}"));
            }
            pivot_results.extend(items);
        }

        let before = result.entities.len();
        extract_pivot_entities(&pivot_results, seed_value, scan_id, key_fp, seen, result);
        if result.entities.len() == before {
            break; // a hop that surfaced nothing new — stop chasing
        }
    }
}

/// Discover high-confidence emails already in the result graph — candidates for
/// cascade detection via `/network/email-check`. Filters to exclude:
///  - Wildcard patterns (* in local part) — low specificity
///  - Mailbox formats (general@*, admin@*, noreply@*) — administrative sinks
///  - Already-queried seeds (the seed_value itself, if it's an email)
///
/// Returns sorted, deduplicated emails in insertion order. High-confidence means
/// the email was discovered via breach/profile data, not just a template or
/// placeholder. Used to feed the cascade-detection pass so re-queries pick
/// the most likely-to-yield identifiers.
fn discover_high_confidence_emails(result: &ModuleResult) -> Vec<String> {
    use std::collections::HashSet;
    let mut seen = HashSet::new();
    let mut emails: Vec<String> = Vec::new();
    for e in &result.entities {
        if matches!(e.kind, crate::core::entity::EntityKind::Email) {
            let email = e.value.to_lowercase();
            // Skip wildcards and mailbox patterns
            if email.contains('*')
                || email.starts_with("general@")
                || email.starts_with("admin@")
                || email.starts_with("noreply@")
                || email.starts_with("support@")
                || email.starts_with("info@")
            {
                continue;
            }
            if seen.insert(email.clone()) {
                emails.push(email);
            }
        }
    }
    emails
}

/// Concurrent dispatch of `/network/email-check` for cascade detection.
/// Re-queries emails discovered during prior hops to find NEW service
/// registrations (services that didn't appear in the seed's initial `/search`).
/// This closes email-to-services loops and discovers new identity branches.
///
/// Each email consumes 1 budget slot (same as `/username/social`). Returns
/// `(endpoint_name, items)` pairs alongside exactly the emails that were
/// actually dispatched — the caller uses this to mark them resolved.
async fn dispatch_email_cascade_checks(
    key: &str,
    emails: Vec<String>,
) -> (Vec<(&'static str, Vec<Value>)>, Vec<String>) {
    let budget = see_know::scan_budget_remaining() as usize;
    if budget == 0 || emails.is_empty() {
        return (Vec::new(), Vec::new());
    }
    let attempted = emails.into_iter().take(budget).collect::<Vec<_>>();
    let futures: Vec<_> = attempted
        .iter()
        .map(|email| {
            let email = email.clone();
            async move {
                // /network/email-check returns { account_exists, services: [...] }
                // Extract the services array as new entities (linked identities).
                let items = see_know::get_path(key, "network/email-check", &[("email", &email)])
                    .await
                    .unwrap_or_default();
                ("email_check", items)
            }
        })
        .collect();
    (futures::future::join_all(futures).await, attempted)
}

/// Extract entities (identity + geo + message + API-key) from one hop's
/// worth of identity-pivot responses (discord/user, discord/to-roblox,
/// gaming/steam, email-check cascade). Split out of [`resolve_identity_pivots`]
/// — which requires live network round-trips to populate `pivot_results` — so
/// this pure mapping step is directly unit-testable against synthetic response
/// shapes.
///
/// The key-harvest pass (`store_api_credential` + `extract_api_keys_from_item`)
/// is applied uniformly across all pivot endpoints. The identity-pivot chase is
/// SeekNow's own stated "unique value" over the free username stack — a linked
/// account's own `password`/`token`/`note` field leaking a credential is caught
/// here, just as it is in every other SeekNow data-ingestion point.
fn extract_pivot_entities(
    pivot_results: &[(&'static str, Vec<Value>)],
    seed_value: &str,
    scan_id: &str,
    key_fp: &str,
    seen: &mut HashSet<String>,
    result: &mut ModuleResult,
) {
    let match_ctx = TargetMatch::new(seed_value);
    for (endpoint, items) in pivot_results {
        for item in items {
            extract_entities(
                item, seed_value, &match_ctx, scan_id, endpoint, key_fp, seen, result,
            );
            extract_geo_entities(item, endpoint, scan_id, seen, result);
            store_api_credential(item, SRC);
            extract_api_keys_from_item(item, scan_id, SRC, seen, result);
        }
    }
}

/// True if at least one `/search` row actually identifies the scan subject,
/// per the shared [`TargetMatch`] rules. Gates the top-level breach-parent
/// stamp (see `process`) so a page of term-sharing strangers doesn't
/// re-affirm the seed at full confidence; pure function of `(target_value,
/// items)` so the gate is testable without a live HTTP round-trip.
fn search_subject_present(target_value: &str, items: &[Value]) -> bool {
    let match_ctx = TargetMatch::new(target_value);
    items.iter().any(|item| match_ctx.matches(item))
}

/// Whether the `/search/deep` fallback should fire after fast `/search`
/// completed. `true` only for a genuine miss (`fast_total == 0`) on a TYPED
/// query (`query_type` non-empty — the auto/name path is excluded; see
/// `max_timeout_ms`'s doc comment for why chaining it there would risk the
/// module's timeout budget) and only while the scan hasn't been cancelled.
/// Pure function of the three decision inputs so the trigger policy is
/// unit-testable without a live scan.
fn should_try_deep_search(fast_total: usize, query_type: &str, cancelled: bool) -> bool {
    fast_total == 0 && !query_type.is_empty() && !cancelled
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
        TargetKind::Phone => v.chars().filter(char::is_ascii_digit).count() < 6,
        TargetKind::FullName => !v.contains(' ') || v.len() < 5,
        TargetKind::IpAddress => is_private_ip(v),
        TargetKind::Domain => is_local_domain(v),
        _ => true,
    }
}

// Pre-flight validators (`is_private_ip`, `is_local_domain`,
// `is_placeholder_username`) live in `crate::util::preflight` —
// shared with the oathnet_pro module so a target rejected by one
// provider is rejected by the other.

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
