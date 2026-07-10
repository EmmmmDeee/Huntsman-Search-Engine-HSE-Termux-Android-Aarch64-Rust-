//! SeekNow (see-know.icu) — parallel breach + stealer + OSINT pool.
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
//! The full per-kind endpoint matrix — including the single-origin profile
//! checks (github/twitter/reddit/tiktok/roblox/xbox/minecraft) — IS dispatched
//! (`effective_plan` returns the plan unfiltered; only the per-scan budget cap
//! bounds spend). SeekNow's breach/stealer corpus returns richer per-profile
//! data than the free `username_search` presence checks, so the standing
//! maximise-see-know.icu directive dispatches them rather than deferring to the
//! free stack. The retained `FREE_COVERED_SINGLE_ORIGIN` scaffolding in the
//! `endpoints` submodule keeps a one-flip conservative mode available but is not
//! active. See that submodule for the authoritative plan.
//!
//! Each scan spends up to HUNTSMAN_SEEKNOW_SCAN_CAP lookups — the cap is scaled
//! to the plan at scan start (`clamp(daily_limit/20, 300, 2500)`, clamped to the
//! credits actually remaining), so it floors at 300 rather than a fixed default.
//! Discovered credentials feed the same key-harvest pipeline as oathnet_pro
//! — extract_api_keys_from_item recognises the same 80+ prefix patterns.

use std::collections::HashSet;

use async_trait::async_trait;
use serde_json::Value;

use crate::core::{
    entity::{EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
    tags,
};
use crate::modules::oathnet_pro::key_harvest::{extract_api_keys_from_item, store_api_credential};
use crate::util::preflight::{is_local_domain, is_placeholder_username, is_private_ip};
use crate::util::see_know;

mod endpoints;
mod extract;
mod pivots;

use endpoints::{dispatch_plan, effective_plan};
use extract::{
    extract_entities, extract_geo_entities, extract_message_emails, extract_message_mentions,
};
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
        "SeekNow (see-know.icu) — full 18-endpoint OSINT/breach pool with discord/gaming pivots"
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
        // The name/auto `/search` path has a ~55s server cap and routinely
        // takes 50–60s to return real data. The module budget must exceed both
        // that cap and the 78s curl-client outer timeout so the engine does not
        // abort see_know before the upstream responds. 80s gives headroom while
        // staying bounded.
        80_000
    }

    fn termux_timeout_cap_exempt(&self) -> bool {
        // see_know's /search has a ~55s server-side cap and answers in 50–60s.
        // The 45s Termux module cap would kill EVERY phone scan with a
        // timeout-exit and zero data — silently wasting the operator's highest-
        // priority paid source on the very platform HSE targets. As the operator
        // explicitly enabled this key, keep its full (still-bounded) 80s budget
        // on Termux too so the upstream response is actually awaited.
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
                    // Scale to the plan AND clamp to credits actually remaining, so
                    // a near-exhausted plan is not over-spent (and a zero balance
                    // latches quota-exhausted instead of burning the first call).
                    see_know::scale_scan_cap(remaining, limit);
                    tracing::info!(
                        credits_remaining = remaining,
                        daily_limit = ?daily_limit,
                        scan_cap = see_know::scan_budget_remaining(),
                        "see_know quota probed — scan cap scaled to plan allocation"
                    );
                }
                // Transient probe failure — release the latch so the NEXT target
                // this scan retries, instead of pinning the cap at the floor.
                None => see_know::clear_quota_probe(),
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
        // Compute the endpoint plan up front (pure — derived from kind+seed, never
        // from /search output) and run the two INDEPENDENT network phases
        // CONCURRENTLY: the slow ~55s /search and the per-kind endpoint matrix.
        // Serialised (search THEN matrix) they could sum toward see_know's own 80s
        // module-timeout cap and discard the expensive /search data; running them
        // together collapses the wall to ~max(search, matrix). Extraction below
        // stays serial (both mutate `seen`/`result`). Budget-safe: both paths
        // reserve slots via the atomic `budget_try_increment`.
        let plan = effective_plan(target.kind, v);
        let run_matrix = !ctx.cancel.is_cancelled() && see_know::budget_remaining();
        let (search_res, endpoint_results) = tokio::join!(see_know::search(key, v, qtype), async {
            if run_matrix {
                dispatch_plan(key, v, &plan).await
            } else {
                Vec::new()
            }
        });
        // On a /search transport error, do NOT abort the module (the old `?` did):
        // the endpoint matrix may already hold paid data worth extracting.
        let outcome = match search_res {
            Ok(o) => o,
            Err(e) => {
                tracing::warn!(error = %e, "see_know /search errored — extracting endpoint results only");
                see_know::SearchOutcome::default()
            }
        };
        let items = outcome.items;
        let total = items.len();

        if total > 0 {
            let mut parent = target.to_entity(0.85, &ctx.scan_id);
            parent.tag(tags::BREACH);
            parent.tag("see-know");
            // Base provenance; then the server's own corpus counters when present
            // (absent on a cache hit) so coverage reporting is authoritative
            // instead of mislabeling the SEARCH_LIMIT cap as the total.
            let mut ev = Evidence::new(SRC, format!("SeekNow: {total} record(s) via /search"))
                .with_attr("hits", total.to_string())
                .with_attr("endpoint", "/api/v1/search")
                .with_attr("provider", "see-know.icu")
                .with_attr("api_key_origin", &key_fp);
            if let Some(bc) = outcome.breach_count {
                ev = ev.with_attr("breach_count", bc.to_string());
            }
            if let Some(sc) = outcome.stealer_count {
                ev = ev.with_attr("stealer_count", sc.to_string());
            }
            if let Some(ec) = outcome.external_count {
                ev = ev.with_attr("external_count", ec.to_string());
            }
            if let Some(st) = outcome.server_total {
                ev = ev.with_attr("server_total", st.to_string());
                // The server holds more records than the cap returned — surface
                // the truncation so the operator knows the corpus is larger.
                // `server_total` (not the count sum) is the guard; stealer
                // flattening can make items.len() exceed it, which only
                // under-reports truncation (never false-positives).
                if st > total as u64 {
                    parent.tag("truncated");
                    ev = ev.with_attr("records_truncated", (st - total as u64).to_string());
                }
            }
            parent.add_evidence(ev);
            result.push(parent);

            // Each record yields at least one entity; reserve up front so the
            // result vector doesn't repeatedly realloc as records are walked.
            result.entities.reserve(total);

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
                // /search records carry the same lat/lon/location/timezone fields
                // the typed endpoints do (it auto-routes to the specialised paths
                // internally), so run the geo extractor here too — otherwise those
                // coordinates were left as inert `Other()` numbers on the primary,
                // highest-volume record source. The `"search"` label fires the
                // generic (non-endpoint-gated) geo branches; the `@coord:`/`@loc:`/
                // `@tz:` seen-keys don't collide with the country centroid.
                extract_geo_entities(item, "search", &ctx.scan_id, &mut seen, &mut result);
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
        // `endpoint_results` was fetched CONCURRENTLY with /search above (empty
        // when the matrix was skipped for cancel/budget). Extract it here, serially
        // — even if the budget is now spent, these records are already paid for.
        {
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
            // Budget re-checked here (the outer guard moved to the concurrent
            // fetch above), so a spent budget skips the extra pivot calls.
            if !ctx.cancel.is_cancelled() && see_know::budget_remaining() {
                resolve_identity_pivots(key, &key_fp, v, &ctx.scan_id, &mut seen, &mut result)
                    .await;
            }
        }

        // Reflect a confirmed dead/spent key into the shared pool so (a) a
        // harvested `seek-` key sitting usable in the pool becomes reachable next
        // scan — the env var is always present so `resolve_through_pool` only
        // rotates to it once the primary is marked unhealthy — and (b) a
        // permanently-dead embedded key stops being re-tested every scan. The
        // single-key case is safe: `resolve_through_pool` fail-opens to the env
        // value when no alternate is usable, and `hse doctor`'s live re-validation
        // flips a recovered key back to Active.
        sync_key_status_to_pool(&ctx.scan_id, key);

        Ok(result)
    }
}

/// Persist a confirmed-terminal SeekNow key status into the global pool at the
/// end of a scan. Auth rejection → `Invalid`; daily-quota exhaustion →
/// `Exhausted` (deliberately NOT `report_key_exhausted`'s 17s `RateLimited`,
/// which would wrongly re-enable a daily-spent key inside the per-minute
/// cooldown). A no-op when the key is still healthy. Skips unit-test scan ids so
/// tests never mutate the persisted global pool (mirrors the `key_harvest::emit`
/// guard).
fn sync_key_status_to_pool(scan_id: &str, key: &str) {
    use crate::util::key_pool::{global_pool, save_pool_best_effort};
    if scan_id == "test" || scan_id == "scan" || scan_id.starts_with("test-") {
        return;
    }
    let Some(status) =
        terminal_pool_status(see_know::is_key_invalid(), see_know::is_quota_exhausted())
    else {
        return;
    };
    let pool = global_pool();
    pool.mark_status("see_know", key, status);
    save_pool_best_effort(&pool);
}

/// Pure: the pool status a scan should persist for the held key given the two
/// terminal latches, or `None` when the key is still healthy. Auth rejection wins
/// over quota (a rejected key is dead regardless of balance); daily-quota
/// exhaustion maps to `Exhausted`, never the 17s `RateLimited` cooldown.
fn terminal_pool_status(
    invalid: bool,
    quota_exhausted: bool,
) -> Option<crate::util::key_pool::KeyStatus> {
    use crate::util::key_pool::KeyStatus;
    if invalid {
        Some(KeyStatus::Invalid)
    } else if quota_exhausted {
        Some(KeyStatus::Exhausted)
    } else {
        None
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
