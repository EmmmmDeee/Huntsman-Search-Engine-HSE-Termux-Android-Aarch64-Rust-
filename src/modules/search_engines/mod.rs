//! Multi-engine search scraping — 17 search engines, zero API keys.
//!
//! Queries Yahoo, Bing, AOL, DuckDuckGo, Google, Brave, Mojeek,
//! Startpage, Yandex, Ecosia, Qwant, Dogpile, Swisscows, You,
//! Presearch, MetaGer, and SearX with OSINT dork queries and
//! extracts entities from result URLs and snippets.
//!
//! Engine selection rationale:
//!   - Yahoo/AOL: Bing-powered, most reliable from datacenter IPs,
//!     /RU= redirect URL decoding
//!   - Bing: `<cite>` tag extraction, reliable from datacenter IPs
//!   - DuckDuckGo HTML: no JS, `uddg` redirect decoded
//!   - Google: /url?q= redirect extraction (requires JS since 2025,
//!     best from residential IPs)
//!   - Brave: independent index, direct href extraction
//!   - Mojeek: independent index, CAPTCHA-resistant
//!   - Startpage: Google-sourced, POST endpoint with session warming
//!   - Yandex: independent Russian index (SmartCaptcha from DC IPs,
//!     works from residential)
//!   - Ecosia: Bing-powered, tree-planting search engine
//!   - Qwant: European privacy engine (lite endpoint)
//!   - Dogpile: Meta-aggregator (System1), aggregates multiple engines
//!   - Swisscows: Swiss privacy engine, Bing-powered
//!
//! Blocked engines are harmless — detected and skipped in <1s via
//! the interstitial/CAPTCHA detector (checks for anomaly-modal,
//! unusual traffic, consent walls, DataDome, SmartCaptcha, etc.).
//!
//! Dork query strategy per target type:
//!   - Domain: site: subdomain discovery, email harvesting, document
//!     discovery (filetype:pdf/doc/xls), login/admin exposure
//!   - Email: quoted mention search, paste-site exposure, social pivots
//!   - Username: social platform dorks (github, linkedin, twitter, reddit)
//!   - FullName: professional profile + document discovery
//!
//! Entity production:
//!   - Domain (subdomains at 0.70, external at 0.45) → triggers 15+ modules
//!   - Email (from snippet text at 0.60) → triggers breach + identity stack
//!   - Phone (from snippet text at 0.55) → triggers numverify, phone_intl

use std::collections::HashSet;

mod build;
mod engines;
mod extract;
mod fetch;
pub(crate) mod health;
mod helpers;
mod queries;

use build::build_entities;
use engines::{ENGINES, EngineSpec, reliable_engines};
use extract::{extract_family_names, extract_username_pivots, recycle_entities};
use fetch::*;
pub(crate) use helpers::SearchResult;
use helpers::*;
use queries::{build_queries, detect_region, generate_username_variants};

use async_trait::async_trait;

use crate::core::{
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
};

pub struct SearchEngines;

const MAX_RESULTS_PER_ENGINE: usize = 20;
const INTER_ENGINE_MS: u64 = 400;
const MAX_PAGES: usize = 2;
const MAX_ACCUMULATED_RESULTS: usize = 2000;

const SOCIAL_HOSTS: &[&str] = &[
    "facebook.com",
    "linkedin.com",
    "twitter.com",
    "x.com",
    "instagram.com",
    "github.com",
    "reddit.com",
    "myspace.com",
    "soundcloud.com",
    "peekyou.com",
    "youtube.com",
    "tiktok.com",
    "pinterest.com",
    "tumblr.com",
    "linktr.ee",
    "medium.com",
];

fn is_social_host(host: &str) -> bool {
    // Accept only the canonical profile-serving hosts: a social root domain or
    // its www/m/mobile alias. Arbitrary subdomains (pic., business., create.,
    // api., help., developer., …) are CDN/marketing/API endpoints whose paths
    // are NOT profile handles — accepting them via a blanket suffix match mined
    // junk usernames out of e.g. `pic.twitter.com/<imageid>`,
    // `business.pinterest.com/getting-started`, `create.pinterest.com/creators`.
    // Strip a known alias prefix (longest first so `mobile.` isn't eaten by
    // `m.`) then require an EXACT social-host match.
    let canonical = host
        .strip_prefix("www.")
        .or_else(|| host.strip_prefix("mobile."))
        .or_else(|| host.strip_prefix("m."))
        .unwrap_or(host);
    SOCIAL_HOSTS.contains(&canonical)
}

#[async_trait]
impl Module for SearchEngines {
    fn name(&self) -> &'static str {
        "search_engines"
    }

    fn description(&self) -> &'static str {
        "Multi-engine OSINT dork search across 17 engines"
    }

    fn priority(&self) -> u8 {
        // Lead the scan with free, broad discovery: this 17-engine keyless dork
        // search runs early (right behind the mandated SeekNow/OathNet enumerators
        // and the keyed registries) so its seed-specific, high-signal results —
        // URLs, emails, usernames, profiles — are in the graph before the
        // narrower free modules dispatch, giving them material to corroborate and
        // pivot on. (Was 25, which buried this broad free net near the end.)
        113
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(
            t.kind,
            TargetKind::Domain
                | TargetKind::Email
                | TargetKind::Username
                | TargetKind::FullName
                | TargetKind::Phone
                | TargetKind::IpAddress
                | TargetKind::Organisation
                | TargetKind::Address
                | TargetKind::Asn
                | TargetKind::AbnAcn
                | TargetKind::Url
                | TargetKind::Coordinates
                | TargetKind::TrackingId
        )
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Search
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Search Engines (T1593.002) is the default. SERP scraping also surfaces
        // email addresses (T1589.002), real-name Person entities (T1589.003),
        // physical addresses / coordinates (T1591.001), and organisation names
        // including corporate registrations (T1591.002) — none of which the
        // Search category default declares.
        &[
            "T1589.002",
            "T1589.003",
            "T1591.001",
            "T1591.002",
            "T1593.002",
        ]
    }

    fn produces(&self) -> &'static [EntityKind] {
        // 17-engine SERP scraping discovers a wide range of entity
        // types: identity fragments (emails, usernames), infrastructure
        // (domains, URLs, IPs), and geography (addresses).
        const KINDS: &[EntityKind] = &[
            EntityKind::Url,
            EntityKind::Domain,
            EntityKind::Email,
            EntityKind::Username,
            EntityKind::Phone,
            EntityKind::Address,
            EntityKind::Coordinates,
            EntityKind::Person,
            EntityKind::Organisation,
            EntityKind::AbnAcn,
        ];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        120_000
    }

    fn termux_timeout_ms(&self) -> u64 {
        // Live Termux scans showed this burning the full cap (60 s, now 45 s)
        // for ZERO results on a phone — mobile SERP scraping stalls behind
        // captive-portal and rate-limit walls. The happy path across 17
        // engines completes in ~20 s; 30 s preserves that recall while halving
        // the dead-wait. `process()` reads this same budget on Termux so it
        // returns whatever it gathered just under the deadline instead of
        // being hard-killed (which discards all accumulated results).
        30_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let queries = build_queries(target);
        // Structured trace (into the unified debug log) of the dork plan: how
        // many queries, and whether regional augmentation was applied. No seed
        // value logged (PII).
        tracing::debug!(
            target: "huntsman::search",
            regional = regional_enabled(),
            region = ?detect_region(target),
            queries = queries.len(),
            "built search dork set"
        );
        if queries.is_empty() {
            return Ok(ModuleResult::new());
        }

        let process_start = std::time::Instant::now();
        // Match the engine's actual deadline so the budget checks below fire
        // BEFORE the hard timeout, letting the module finalise partial results.
        // On Termux that's the trimmed budget; off Termux the full desktop one.
        let budget_ms = if crate::is_termux() {
            self.termux_timeout_ms()
        } else {
            self.max_timeout_ms()
        };
        // Reserve a quarter of the budget (min 8 s) for the secondary pivot +
        // recycler passes, scaling with the budget instead of a flat 30 s that
        // made the primary pass degenerate under the trimmed Termux budget.
        let primary_reserve_ms = (budget_ms / 4).max(8_000);
        let mut all_results: Vec<SearchResult> = Vec::new();

        // Track engines that failed on the first query so we skip them
        // on subsequent queries — avoids burning the entire timeout
        // budget on engines that are down/blocked for this session.
        let mut dead_engines: HashSet<&str> = HashSet::new();

        // ── Primary pass: run all queries against live engines ─────
        for (qi, query) in queries.iter().enumerate() {
            if ctx.cancel.is_cancelled() {
                break;
            }
            let elapsed = process_start.elapsed().as_millis() as u64;
            if elapsed > budget_ms.saturating_sub(primary_reserve_ms) {
                break;
            }

            for engine in ENGINES {
                if !engine_enabled(engine.name) {
                    continue;
                }
                if ctx.cancel.is_cancelled() {
                    break;
                }
                if qi > 0 && dead_engines.contains(engine.name) {
                    continue;
                }
                let url = (engine.build_url)(query);
                let post_body = engine.build_post.map(|f| f(query));
                if all_results.len() >= MAX_ACCUMULATED_RESULTS {
                    break;
                }
                let before = all_results.len();
                if let Some(mut results) =
                    fetch_and_parse(&url, engine, query, post_body.as_deref()).await
                {
                    let got_results = !results.is_empty();
                    all_results.append(&mut results);
                    if all_results.len() >= MAX_ACCUMULATED_RESULTS {
                        all_results.truncate(MAX_ACCUMULATED_RESULTS);
                    }
                    if got_results
                        && qi == 0
                        && let Some(paginate_fn) = engine.paginate
                    {
                        for page in 1..MAX_PAGES {
                            if ctx.cancel.is_cancelled() {
                                break;
                            }
                            tokio::time::sleep(std::time::Duration::from_millis(INTER_ENGINE_MS))
                                .await;
                            let page_url = paginate_fn(query, page);
                            if let Some(mut pr) =
                                fetch_and_parse(&page_url, engine, query, None).await
                            {
                                if pr.is_empty() {
                                    break;
                                }
                                all_results.append(&mut pr);
                            } else {
                                break;
                            }
                        }
                    }
                } else if qi == 0 {
                    dead_engines.insert(engine.name);
                }
                if all_results.len() > before {
                    tokio::time::sleep(std::time::Duration::from_millis(INTER_ENGINE_MS)).await;
                }
            }
        }

        // ── Secondary pivot: re-search discovered usernames + variants
        //    on reliable engines for cross-platform linkage ────────────
        if !ctx.cancel.is_cancelled() {
            let mut pivots = extract_username_pivots(&all_results, target);

            // Generate username variants for the strongest pivots
            // (separator swaps, trailing digits, truncations)
            let base_pivots: Vec<String> = pivots.clone();
            for base in &base_pivots {
                let raw = base.trim_matches('"');
                for variant in generate_username_variants(raw) {
                    let vq = format!("\"{variant}\"");
                    if !pivots.contains(&vq) {
                        pivots.push(vq);
                    }
                }
            }

            if !pivots.is_empty() {
                let reliable = reliable_engines();
                for pivot_query in pivots.iter().take(10) {
                    if ctx.cancel.is_cancelled() {
                        break;
                    }
                    for engine in &reliable {
                        if !engine_enabled(engine.name) {
                            continue;
                        }
                        if ctx.cancel.is_cancelled() {
                            break;
                        }
                        if dead_engines.contains(engine.name) {
                            continue;
                        }
                        let url = (engine.build_url)(pivot_query);
                        if let Some(mut results) =
                            fetch_and_parse(&url, engine, pivot_query, None).await
                        {
                            all_results.append(&mut results);
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(INTER_ENGINE_MS)).await;
                    }
                }
            }
        }

        // Deduplicate results by canonical URL before entity extraction.
        let all_results = dedup_results(all_results);

        let mut module_result = build_entities(target, &ctx.scan_id, &all_results);

        // ── Recursive entity recycler: re-search high-confidence
        //    discovered entities for geolocation and cross-linking ─────
        let elapsed_ms = process_start.elapsed().as_millis() as u64;
        let remaining_ms = budget_ms.saturating_sub(elapsed_ms);
        if !ctx.cancel.is_cancelled() && remaining_ms > 15_000 {
            recycle_entities(ctx, &mut module_result, &dead_engines, &all_results).await;
        }

        Ok(module_result)
    }
}

// ─── Recursive entity recycler ─────────────────────────────────────────────
//
// After the primary search pass produces entities, the recycler takes
// the highest-confidence discoveries and re-searches them on reliable
// engines to find geolocation cross-links. This catches the common
// OSINT pattern where an email → username → address chain only becomes
// visible when you search for the intermediate entity.

/// Regional searching toggle, set by the engine at scan start from
/// `ScanOptions::regional_search`. Off ⇒ geolocation-neutral queries only. A
/// process-global, like the see_know per-scan budget — concurrent scans in
/// `serve` share it (last writer wins for the overlap window).
static REGIONAL_SEARCH: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Enable/disable regional searching for subsequent scans.
pub(crate) fn set_regional(on: bool) {
    REGIONAL_SEARCH.store(on, std::sync::atomic::Ordering::Relaxed);
}
fn regional_enabled() -> bool {
    REGIONAL_SEARCH.load(std::sync::atomic::Ordering::Relaxed)
}

/// Whether a search engine is enabled — the first per-capability toggle of the
/// universal toggleability registry. Default on; turned off (persisted) via
/// `hse config engine.<name> off`. Checked in every engine-dispatch loop and the
/// liveness probe so a disabled engine is never queried.
pub(crate) fn engine_enabled(name: &str) -> bool {
    crate::util::settings::get_bool(&format!("engine.{name}"), true)
}

/// The per-engine on/off toggles `(key, enabled)` for all engines — backs the
/// `hse config` listing and the settings UI.
pub(crate) fn engine_toggles() -> Vec<(String, bool)> {
    ENGINES
        .iter()
        .map(|e| (format!("engine.{}", e.name), engine_enabled(e.name)))
        .collect()
}

/// True when `url` is the searched USERNAME's own profile on a canonical social
/// host — the handle path segment exactly equals the seed username (e.g. seed
/// `kylo4kylo` → `https://x.com/kylo4kylo`). This is the strongest possible
/// username-search finding (the target's actual profile, not a page that merely
/// mentions the handle), so callers emit it at elevated confidence.
fn is_confirmed_profile(target: &Target, url: &str, host: &str) -> bool {
    matches!(target.kind, TargetKind::Username)
        && is_social_host(host)
        && extract_path_username(url).is_some_and(|u| u.eq_ignore_ascii_case(target.value.trim()))
}

#[cfg(test)]
mod tests;
