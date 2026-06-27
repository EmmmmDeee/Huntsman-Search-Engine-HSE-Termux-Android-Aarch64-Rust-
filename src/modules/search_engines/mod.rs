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
use std::sync::Mutex;

mod build;
mod engines;
mod extract;
mod fetch;
pub(crate) mod health;
mod helpers;
mod queries;

use build::build_entities;
use engines::{ENGINES, EngineSpec, reliable_engines};
use extract::{
    extract_bio_aggregator_urls, extract_display_names_from_titles, extract_family_names,
    extract_username_pivots, recycle_entities,
};
use fetch::*;
pub(crate) use helpers::SearchResult;
use helpers::*;
use queries::{build_queries, detect_region, generate_username_variants};

use async_trait::async_trait;
use futures::StreamExt;

use crate::core::{
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
};

pub struct SearchEngines;

const MAX_RESULTS_PER_ENGINE: usize = 50;
const MAX_PAGES: usize = 2;
// Working-set ceiling on raw SERP rows accumulated across engines/pages before
// entity extraction. Raised 10× (was 2000) so a broad, multi-engine sweep no
// longer drops minable rows; remains a memory backstop on a phone, not a
// coverage limit for real result volumes.
const MAX_ACCUMULATED_RESULTS: usize = 20000;
/// How many engine fetches run at once in the primary pass. Bounded concurrency so
/// a scan reaches ALL engines within budget (a 17-deep serial sweep timed out
/// partway, leaving most engines untried), while staying gentle on a low-power
/// Termux radio — and strictly gentler than the health prober, which already
/// fetches every engine at once via `join_all`. Each request still self-clamps to
/// the deadline, so concurrency can never push the pass past the hard kill.
const ENGINE_CONCURRENCY: usize = 6;

/// Consecutive-empty threshold for an engine that has **never** produced a
/// result this session. From datacenter IPs `google`, `you`, `presearch`,
/// `qwant`, … return 0 results on every seed; three strikeouts is enough signal
/// that they're hard-blocked here, so stop probing them (saves ~200+ s/scan).
const SESSION_DEAD_THRESHOLD: u8 = 3;

/// Consecutive-empty threshold for an engine that **has** produced ≥1 result
/// this session ("proven live"). Intermittently-blocked engines like `bing`
/// (~48% block rate) and `ecosia` (~78%) routinely hit 3-block streaks *between*
/// real hits; the low threshold was permanently silencing them mid-scan and
/// discarding their later results (live depth-1 scan: `ecosia` was the 2nd-most
/// productive engine at 182 results, yet was silenced after a 4-block run; `bing`
/// lost its remaining hits the same way). A proven engine must miss this many
/// seeds *in a row* before we accept it has genuinely gone down — high enough to
/// ride out a normal block streak, low enough to abandon a truly dead host.
const SESSION_DEAD_THRESHOLD_PROVEN: u8 = 10;

/// Per-engine session liveness: consecutive empties and whether the engine has
/// EVER returned a result this run. Shared across all `process()` calls within
/// one binary execution; a fresh `hse` invocation starts empty.
#[derive(Default, Clone, Copy)]
struct EngineLiveness {
    consecutive_empty: u8,
    ever_hit: bool,
}

static SESSION_EMPTY_COUNTS: std::sync::LazyLock<
    Mutex<std::collections::HashMap<&'static str, EngineLiveness>>,
> = std::sync::LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));

/// The applicable dead-threshold for a liveness record: a proven-live engine
/// gets the tolerant threshold, an unproven one the aggressive default. **Pure.**
fn dead_threshold(live: EngineLiveness) -> u8 {
    if live.ever_hit {
        SESSION_DEAD_THRESHOLD_PROVEN
    } else {
        SESSION_DEAD_THRESHOLD
    }
}

/// True when `name` has missed enough consecutive seeds to be silenced — using
/// the tolerant threshold once the engine has proven it can produce results.
fn is_session_dead(name: &str) -> bool {
    let live = SESSION_EMPTY_COUNTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(name)
        .copied()
        .unwrap_or_default();
    live.consecutive_empty >= dead_threshold(live)
}

/// Increment the empty streak for `name`; log once when it crosses its
/// (proven-aware) threshold so operators know why it was silenced.
fn record_empty(name: &'static str) {
    let mut map = SESSION_EMPTY_COUNTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let live = map.entry(name).or_default();
    live.consecutive_empty = live.consecutive_empty.saturating_add(1);
    let threshold = dead_threshold(*live);
    if live.consecutive_empty == threshold {
        tracing::debug!(
            engine = name,
            threshold,
            proven = live.ever_hit,
            "search engine returned nothing for {threshold} consecutive seeds \
             — silenced for the rest of this scan"
        );
    }
}

/// Reset the empty streak for `name` when it actually returns results, and mark
/// it "proven live" so future streaks are judged against the tolerant threshold.
fn record_hit(name: &'static str) {
    let mut map = SESSION_EMPTY_COUNTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let live = map.entry(name).or_default();
    live.consecutive_empty = 0;
    live.ever_hit = true;
}

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

/// Fetch one engine's full contribution for a query — page 0 plus its own
/// pagination (first query only) — as a single future with a FIXED, owned-param
/// signature. Free function (not an inline async closure) so `buffer_unordered`
/// sees one concrete future type; the closure-per-lifetime form trips a
/// higher-ranked-lifetime bound. Each request self-clamps to `deadline`.
async fn fetch_engine(
    engine: &'static EngineSpec,
    url: String,
    post_body: Option<String>,
    query: String,
    qi: usize,
    deadline: std::time::Instant,
) -> (&'static str, Option<Vec<SearchResult>>) {
    let Some(mut acc) = fetch_and_parse(&url, engine, &query, post_body.as_deref(), deadline).await
    else {
        return (engine.name, None);
    };
    if qi == 0
        && let Some(pf) = engine.paginate
    {
        for page in 1..MAX_PAGES {
            if std::time::Instant::now() >= deadline {
                break;
            }
            match fetch_and_parse(&pf(&query, page), engine, &query, None, deadline).await {
                Some(mut pr) => acc.append(&mut pr),
                None => break,
            }
        }
    }
    (engine.name, Some(acc))
}

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
                | TargetKind::CryptoAddress
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
        // Hard fetch deadlines (as `Instant`s) enforced before EVERY request, so
        // the module always self-finalises with whatever it gathered instead of
        // being killed at the engine's hard timeout — which drops the in-flight
        // future and ALL accumulated results (the live "search_engines: timeout →
        // 0 entities" failure on every run). The primary pass stops a reserve
        // short to hand time to the pivot + recycler passes; every pass stops a
        // safety margin short of the kill so dedup + entity build still run.
        const FINALIZE_MARGIN_MS: u64 = 2_000;
        let primary_deadline = process_start
            + std::time::Duration::from_millis(budget_ms.saturating_sub(primary_reserve_ms));
        let fetch_deadline = process_start
            + std::time::Duration::from_millis(budget_ms.saturating_sub(FINALIZE_MARGIN_MS));
        let mut all_results: Vec<SearchResult> = Vec::new();

        // Track engines that failed on the first query so we skip them
        // on subsequent queries — avoids burning the entire timeout
        // budget on engines that are down/blocked for this session.
        let mut dead_engines: HashSet<&str> = HashSet::new();

        // ── Primary pass: query every live engine, fetched with BOUNDED
        //    CONCURRENCY so a scan reaches ALL engines within budget instead of
        //    timing out partway through a 17-deep serial sweep. Each request
        //    self-clamps to the deadline (see `fetch_and_parse`), so the pass can
        //    never overrun the hard kill regardless of concurrency. ──
        for (qi, query) in queries.iter().enumerate() {
            if ctx.cancel.is_cancelled()
                || std::time::Instant::now() >= primary_deadline
                || all_results.len() >= MAX_ACCUMULATED_RESULTS
            {
                break;
            }

            // Each live engine's WHOLE fetch (page 0 + its own pagination) is one
            // future; ENGINE_CONCURRENCY of them run at once. Pagination stays
            // sequential *within* an engine, concurrent *across* engines. The
            // futures are built eagerly into a Vec (each owns its inputs), then
            // streamed — so no borrow of the loop-local `query` outlives the batch.
            // The liveness filter feeds the map directly: no intermediate Vec of
            // engine refs is materialised on this per-query hot path.
            let futs: Vec<_> = ENGINES
                .iter()
                .filter(|e| {
                    engine_enabled(e.name)
                        && !is_session_dead(e.name)
                        && !(qi > 0 && dead_engines.contains(e.name))
                })
                .map(|engine| {
                    let url = (engine.build_url)(query);
                    let post_body = engine.build_post.map(|f| f(query));
                    fetch_engine(engine, url, post_body, query.clone(), qi, primary_deadline)
                })
                .collect();
            let mut batch: Vec<(&'static str, Option<Vec<SearchResult>>)> =
                futures::stream::iter(futs)
                    .buffer_unordered(ENGINE_CONCURRENCY)
                    .collect()
                    .await;

            // Completion order is racy, so order the batch by engine name before
            // appending — the persisted result must not depend on which engine
            // happened to answer first (Determinism Requirement).
            batch.sort_by(|a, b| a.0.cmp(b.0));
            for (name, res) in batch {
                match res {
                    Some(mut results) => {
                        // fetch_engine only returns Some(...) when results are
                        // non-empty (empty → None via fetch_and_parse). Reset
                        // the session-dead streak for this engine on qi == 0.
                        if qi == 0 {
                            record_hit(name);
                        }
                        all_results.append(&mut results);
                    }
                    // Nothing on the FIRST query → down/blocked for this session;
                    // skip it on subsequent queries to save the budget.
                    None if qi == 0 => {
                        dead_engines.insert(name);
                        record_empty(name);
                    }
                    None => {}
                }
            }
            if all_results.len() >= MAX_ACCUMULATED_RESULTS {
                all_results.truncate(MAX_ACCUMULATED_RESULTS);
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

            if !pivots.is_empty() && !ctx.cancel.is_cancelled() {
                // Flatten the (pivot × reliable engine) grid into one batch and
                // fetch it with the same bounded concurrency as the primary pass —
                // each request self-clamps to the deadline.
                let reliable = reliable_engines();
                let jobs: Vec<_> = pivots
                    .iter()
                    .take(10)
                    .flat_map(|pq| {
                        reliable
                            .iter()
                            .filter(|e| engine_enabled(e.name) && !dead_engines.contains(e.name))
                            .map(move |e| {
                                fetch_one(e, (e.build_url)(pq), pq.clone(), fetch_deadline)
                            })
                    })
                    .collect();
                let mut pivot_results: Vec<SearchResult> = futures::stream::iter(jobs)
                    .buffer_unordered(ENGINE_CONCURRENCY)
                    .collect::<Vec<Option<Vec<SearchResult>>>>()
                    .await
                    .into_iter()
                    .flatten()
                    .flatten()
                    .collect();
                // Determinism: racy completion order → sort the merged batch.
                pivot_results
                    .sort_by(|a, b| a.engine.cmp(b.engine).then_with(|| a.url.cmp(&b.url)));
                all_results.append(&mut pivot_results);
            }
        }

        // Re-enforce the working-set ceiling: the secondary pivot pass appends to
        // `all_results` after the primary-pass truncation, so without this the cap
        // is not a true bound. Cap again before the (super-linear) dedup + entity
        // extraction consume it.
        all_results.truncate(MAX_ACCUMULATED_RESULTS);

        // Count how many DISTINCT engines returned each canonical URL BEFORE
        // deduplication collapses the results to one `SearchResult` per URL.
        // This map carries the cross-engine corroboration signal into
        // `build_entities`; computing it after the dedup below would credit
        // every URL to a single engine and silently defeat the "multi-engine
        // corroboration boosts entity confidence" mechanism (a URL returned by
        // N engines would always score 1).
        let url_engine_count = url_engine_counts(&all_results);

        // Deduplicate results by canonical URL before entity extraction.
        let all_results = dedup_results(all_results);

        let mut module_result =
            build_entities(target, &ctx.scan_id, &all_results, &url_engine_count);

        // ── R9: social title display names + bio aggregator URLs ──────────
        // Run before the recycler so the new Person/Url entities can seed
        // additional geo/cross-platform queries in the recycler pass.
        for e in extract_display_names_from_titles(&all_results, target, &ctx.scan_id) {
            module_result.push(e);
        }
        for e in extract_bio_aggregator_urls(&all_results, target, &ctx.scan_id) {
            module_result.push(e);
        }

        // ── Recursive entity recycler: re-search high-confidence
        //    discovered entities for geolocation and cross-linking ─────
        let elapsed_ms = process_start.elapsed().as_millis() as u64;
        let remaining_ms = budget_ms.saturating_sub(elapsed_ms);
        if !ctx.cancel.is_cancelled() && remaining_ms > 15_000 {
            recycle_entities(
                ctx,
                &mut module_result,
                &dead_engines,
                &all_results,
                fetch_deadline,
            )
            .await;
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
/// True when `name` has been silenced by the session-dead tracker.
/// Exported so the `/engines/health` API can surface it per-engine.
pub(crate) fn session_dead(name: &str) -> bool {
    is_session_dead(name)
}

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
