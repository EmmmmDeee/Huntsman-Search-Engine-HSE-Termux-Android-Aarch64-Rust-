//! Multi-engine search scraping — 16 search engines, zero API keys.
//!
//! Queries Yahoo, Bing, AOL, DuckDuckGo, Google, Brave, Mojeek,
//! Startpage, Yandex, Ecosia, Qwant, Dogpile, Swisscows, Presearch,
//! MetaGer, and SearX with OSINT dork queries and extracts entities from
//! result URLs and snippets. (You.com removed: always Cloudflare-blocked.)
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
//!   - Domain (subdomains at confidence::HIGH_PLUS, external at confidence::LOW_MEDIUM) → triggers 15+ modules
//!   - Email (from snippet text at confidence::MEDIUM_PLUS) → triggers breach + identity stack
//!   - Phone (from snippet text at confidence::MEDIUM_HIGH) → triggers numverify, phone_intl

use std::collections::HashSet;
use std::sync::Mutex;

mod build;
mod engines;
mod extract;
mod fetch;
pub(crate) mod health;
mod helpers;
mod queries;
pub(crate) mod websearch;

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

/// Per-engine result ceiling for ONE fetched page. Several engines already
/// REQUEST up to 30 results per page (`bing &count=30`, `google &num=30`,
/// `yahoo &n=30`), so a cap of 20 fetched-then-discarded the extra 10 at zero
/// HTTP cost; lifting it to 30 keeps every row already on the page. Cross-engine
/// corroboration compounds the gain — more URLs accrue a multi-engine count.
const MAX_RESULTS_PER_ENGINE: usize = 30;
/// How many pages to pull from an engine that exposes a paginator (first query
/// only). `1..MAX_PAGES` ⇒ page 0 plus this many extra pages, fetched ONLY from
/// the engines with a `paginate` fn (the 6 proven ones — yahoo/bing/aol/google/
/// brave/mojeek); the keyless `paginate: None` engines are untouched. Each extra
/// page self-clamps to the deadline, so deeper paging can never overrun the
/// Termux time budget. 2→3 adds one more page of the strongest indexes.
const MAX_PAGES: usize = 3;
const MAX_ACCUMULATED_RESULTS: usize = 2000;
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
/// EVER returned a result this run. Scoped per scan under `hse serve` / `hse live`
/// to prevent concurrent scans from poisoning each other's liveness state.
#[derive(Default, Clone, Copy)]
struct EngineLiveness {
    consecutive_empty: u8,
    ever_hit: bool,
}

/// Keyed by (scan_id, engine_name) to namespace liveness per scan in concurrent
/// environments. A fresh `hse` invocation (single-scan mode) uses a constant
/// dummy scan_id; `hse serve` allocates a unique one per incoming scan.
static SESSION_EMPTY_COUNTS: std::sync::LazyLock<
    Mutex<std::collections::HashMap<(String, &'static str), EngineLiveness>>,
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
fn is_session_dead(scan_id: &str, name: &str) -> bool {
    let live = SESSION_EMPTY_COUNTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&(scan_id.to_string(), name))
        .copied()
        .unwrap_or_default();
    live.consecutive_empty >= dead_threshold(live)
}

/// Increment the empty streak for `name`; log once when it crosses its
/// (proven-aware) threshold so operators know why it was silenced.
fn record_empty(scan_id: &str, name: &'static str) {
    let mut map = SESSION_EMPTY_COUNTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let live = map.entry((scan_id.to_string(), name)).or_default();
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
fn record_hit(scan_id: &str, name: &'static str) {
    let mut map = SESSION_EMPTY_COUNTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let live = map.entry((scan_id.to_string(), name)).or_default();
    live.consecutive_empty = 0;
    live.ever_hit = true;
}

/// Clear per-engine liveness state for `scan_id`. Called once per scan (see
/// the built-in module runtime's `reset_per_scan` implementation) to ensure
/// each scan starts with a clean slate under `hse serve` / `hse live` without
/// scanning-by-scanning buildup of silenced engines and "proven live" credits.
/// The scan-id namespace (added to [`SESSION_EMPTY_COUNTS`] keys) makes this
/// surgical — only this scan's state is cleared, allowing concurrent scans to
/// maintain independent liveness records.
pub(crate) fn reset_session_liveness(scan_id: &str) {
    let mut map = SESSION_EMPTY_COUNTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    map.retain(|(sid, _), _| sid != scan_id);
}

/// Clear liveness state for all currently-disabled engines (Issue #8).
/// When an engine is toggled off, its liveness entries (silenced state, proven-live
/// credits) persist in SESSION_EMPTY_COUNTS, wasting memory and potentially
/// confusing logic if the engine is re-enabled. This function removes stale entries
/// for engines that are currently disabled, keeping the liveness map clean.
///
/// Call this periodically or when engine toggles change (e.g. after `hse config
/// engine.<name> off` or via the settings UI). Safe to call concurrently — uses
/// the same lock as record_hit/record_empty, serialized naturally.
pub(crate) fn cleanup_disabled_engine_liveness() {
    let mut map = SESSION_EMPTY_COUNTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let disabled_count = map
        .iter()
        .filter(|((_sid, name), _)| !engine_enabled(name))
        .count();
    if disabled_count > 0 {
        map.retain(|(_, name), _| engine_enabled(name));
        tracing::debug!(
            disabled_engines = disabled_count,
            "cleaned up liveness state for disabled engines"
        );
    }
}

/// Cap on the second-order (pivot / recycle) engine fan-out. The pivot grid is
/// `pivots × engines`, so this bounds the request multiplier; the per-request
/// deadline self-clamp remains the hard wall-time guarantee — this just keeps the
/// fan-out proportionate on a low-power Termux radio.
const PIVOT_ENGINE_CAP: usize = 8;

/// The engine set for the second-order pivot / recycle passes: the reliable core
/// ([`engines::reliable_engines`]) UNIONed with every engine PROVEN LIVE this
/// scan — one that returned ≥1 result, so [`record_hit`] set its `ever_hit`.
///
/// The pivot and recycle passes are where the core cross-platform OSINT linkage
/// is realised (username → profiles, email/person → address), yet they previously
/// ran through only the three static reliable engines even when yahoo / bing /
/// brave / ecosia had proven live in the primary pass this very scan. Reusing
/// every proven engine multiplies that second-order discovery. Falls back to the
/// reliable core when nothing is proven yet. Deterministic: union by name,
/// name-sorted, capped at [`PIVOT_ENGINE_CAP`] (the per-request deadline
/// self-clamp bounds wall-time regardless).
///
/// Private to the module: the sibling `extract` recycler and this module's pivot
/// pass reach it via `super::`, so it never needs `pub(super)` (which would
/// over-expose it past the module-private `EngineSpec` return type).
fn proven_live_engines(scan_id: &str) -> Vec<&'static EngineSpec> {
    pivot_engine_set(&proven_engine_names(scan_id))
}

/// Snapshot (one lock) of the engines that have returned ≥1 result this scan
/// — the `proven` input to [`order_engines_for_primary`] and
/// [`pivot_engine_set`]. Filters by scan_id to ensure concurrent scans maintain
/// independent proven sets. The OSINT primary pass, the pivot pass, and the
/// `websearch` general-search path all read liveness identically for a given scan.
fn proven_engine_names(scan_id: &str) -> std::collections::BTreeSet<&'static str> {
    SESSION_EMPTY_COUNTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .filter(|((sid, _), live)| sid == scan_id && live.ever_hit)
        .map(|((_, name), _)| *name)
        .collect()
}

/// Pure core of [`proven_live_engines`]: the reliable core UNIONed with the
/// `proven` engine names, resolved to deterministic, capped [`EngineSpec`]s.
/// Split out from the process-global liveness read so the union/sort/cap logic is
/// unit-tested without the shared `SESSION_EMPTY_COUNTS` map. An empty `proven`
/// set yields exactly the reliable core; a `proven` name absent from [`ENGINES`]
/// is silently dropped (no phantom engine). **Pure.**
fn pivot_engine_set(proven: &std::collections::BTreeSet<&'static str>) -> Vec<&'static EngineSpec> {
    if proven.is_empty() {
        // Nothing proven yet (e.g. the recycler running before any hit) — keep the
        // established reliable-core floor rather than an empty fan-out.
        return reliable_engines();
    }
    // Always include the reliable core so the pivot/recycle floor never regresses.
    let mut names: std::collections::BTreeSet<&'static str> =
        reliable_engines().iter().map(|e| e.name).collect();
    names.extend(proven.iter().copied());
    let mut specs: Vec<&'static EngineSpec> =
        ENGINES.iter().filter(|e| names.contains(e.name)).collect();
    specs.sort_by(|a, b| a.name.cmp(b.name));
    specs.truncate(PIVOT_ENGINE_CAP);
    specs
}

/// Order the primary pass's live engines so the ones already PROVEN productive
/// this run (`ever_hit`) or in the reliable core start FIRST under the bounded
/// [`ENGINE_CONCURRENCY`] fan-out. The reliable engines are declared *late* in
/// [`ENGINES`], so in raw declaration order they never make the first concurrency
/// batch and are the first cut when the per-query deadline fires; floating them
/// (and any engine proven to yield this run) to the front fills the early slots
/// with the engines whose results are most likely to land in time. A **stable**
/// partition — declaration order is preserved within each group — and the
/// downstream batch is re-sorted by name (Determinism Requirement), so this
/// changes only WHICH engines complete under a tight budget, never the persisted
/// result order. **Pure** (the liveness/reliable sets are read by the caller), so
/// the ordering is unit-tested without the shared liveness map.
fn order_engines_for_primary(
    mut live: Vec<&'static EngineSpec>,
    proven: &std::collections::BTreeSet<&'static str>,
    reliable: &std::collections::BTreeSet<&'static str>,
) -> Vec<&'static EngineSpec> {
    // Key `false` (0) sorts before `true` (1): front = proven-live ∪ reliable-core.
    live.sort_by_key(|e| u8::from(!(proven.contains(e.name) || reliable.contains(e.name))));
    live
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
    // Federated / new-social cluster — keyless, well-indexed, profile-bearing
    // paths (bsky.app/profile/<handle>, mastodon.social/@<handle>,
    // threads.net/@<handle>). Added so the username-pivot pass and
    // confirmed-profile detection mine these handles like the legacy networks.
    "bsky.app",
    "mastodon.social",
    "threads.net",
    // Profile-ROOT developer / messaging / micro-blog hosts whose FIRST path
    // segment is the user handle (gitlab.com/<h>, bitbucket.org/<h>, t.me/<h>,
    // vk.com/<h>, ok.ru/<h>, keybase.io/<h>, about.me/<h>, dev.to/<h>,
    // twitch.tv/<h>). The query ladder already dorks all of these, but the
    // EXACT-match gate below silently discarded their returned handles before any
    // Username/cross-platform-pivot/confirmed-profile/display-name extraction.
    // Deliberately EXCLUDES steamcommunity.com (/id|/profiles), stackoverflow.com
    // (/users) and gravatar.com (/avatar) — their first segment is a navigation
    // word, not the handle, so `is_navigation_path` would (correctly) drop them.
    "gitlab.com",
    "bitbucket.org",
    "t.me",
    "vk.com",
    "ok.ru",
    "keybase.io",
    "about.me",
    "dev.to",
    "twitch.tv",
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

/// Fan one query out across `engines` — already filtered and ordered by the
/// caller (via [`order_engines_for_primary`]) — with the module's bounded
/// concurrency, then return the batch name-sorted so the result never depends on
/// which engine happened to answer first (Determinism Requirement).
///
/// Single source of the map→[`fetch_engine`]→`buffer_unordered`→sort mechanism
/// shared by the OSINT primary pass ([`SearchEngines::process`]) and the general
/// [`websearch::web_search`] path, so the concurrency width and the determinism
/// sort can never drift between them. `qi` is the query index passed through to
/// `fetch_engine` (0 enables its pagination); `proven`-set snapshotting stays at
/// the caller so a multi-query scan's engine ordering is fixed once, not
/// recomputed per query.
async fn run_engine_batch(
    engines: Vec<&'static EngineSpec>,
    query: &str,
    qi: usize,
    deadline: std::time::Instant,
) -> Vec<(&'static str, Option<Vec<SearchResult>>)> {
    let futs: Vec<_> = engines
        .into_iter()
        .map(|engine| {
            let url = (engine.build_url)(query);
            let post_body = engine.build_post.map(|f| f(query));
            fetch_engine(engine, url, post_body, query.to_string(), qi, deadline)
        })
        .collect();
    let mut batch: Vec<(&'static str, Option<Vec<SearchResult>>)> = futures::stream::iter(futs)
        .buffer_unordered(ENGINE_CONCURRENCY)
        .collect()
        .await;
    batch.sort_by(|a, b| a.0.cmp(b.0));
    batch
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
        "Multi-engine dork recon — sweeps OSINT queries across 16 search engines"
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

        // Clean up liveness state for disabled engines (Issue #8). When an engine
        // is toggled off via config/settings, its liveness entries (consecutive_empty,
        // ever_hit) persist in SESSION_EMPTY_COUNTS, wasting memory and potentially
        // interfering with future scans if the engine is re-enabled. Call this at
        // the start of every scan to keep the map clean.
        cleanup_disabled_engine_liveness();

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
            // Snapshot the proven-live set once for this query (one lock), and the
            // reliable core, then order the live engines so reliable/proven engines
            // fill the bounded concurrency slots first — under a tight deadline
            // their results survive, while unproven/blocked engines no longer
            // occupy the early slots purely by declaration order.
            let proven = proven_engine_names(&ctx.scan_id);
            let reliable: std::collections::BTreeSet<&'static str> =
                reliable_engines().iter().map(|e| e.name).collect();
            let live: Vec<&'static EngineSpec> = ENGINES
                .iter()
                .filter(|e| {
                    engine_enabled(e.name)
                        && !is_session_dead(&ctx.scan_id, e.name)
                        && !(qi > 0 && dead_engines.contains(e.name))
                })
                .collect();
            // Fan out this query across the ordered live set with bounded
            // concurrency; the batch comes back name-sorted (see run_engine_batch).
            let batch = run_engine_batch(
                order_engines_for_primary(live, &proven, &reliable),
                query,
                qi,
                primary_deadline,
            )
            .await;
            for (name, res) in batch {
                match res {
                    Some(mut results) => {
                        // fetch_engine only returns Some(...) when results are
                        // non-empty (empty → None via fetch_and_parse). Reset
                        // the session-dead streak for this engine on qi == 0.
                        if qi == 0 {
                            record_hit(&ctx.scan_id, name);
                        }
                        all_results.append(&mut results);
                    }
                    // Nothing on the FIRST query → down/blocked for this session;
                    // skip it on subsequent queries to save the budget.
                    None if qi == 0 => {
                        dead_engines.insert(name);
                        record_empty(&ctx.scan_id, name);
                    }
                    None => {}
                }
            }
            // Working-set ceiling for a broad multi-dork scan on a low-RAM
            // device. The cap stays, but the drop is WARNED (as the email/phone
            // extractors are) instead of silent — later raw SERP rows that would
            // dedup into additional Domain/Email/URL entities are being discarded,
            // and the operator should be able to see coverage was bounded.
            if all_results.len() > MAX_ACCUMULATED_RESULTS {
                let excess = all_results.len() - MAX_ACCUMULATED_RESULTS;
                tracing::warn!(
                    found = all_results.len(),
                    cap = MAX_ACCUMULATED_RESULTS,
                    excess,
                    "search result accumulator exceeded cap — {} SERP rows were discarded",
                    excess
                );
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
                // Flatten the (pivot × engine) grid into one batch and fetch it
                // with the same bounded concurrency as the primary pass — each
                // request self-clamps to the deadline. The engine set is the
                // reliable core PLUS every engine proven live this scan, so the
                // cross-platform pivot runs through all the engines that actually
                // produced results, not just the static three.
                let pivot_engines = proven_live_engines(&ctx.scan_id);
                let jobs: Vec<_> = pivots
                    .iter()
                    .take(10)
                    .flat_map(|pq| {
                        pivot_engines
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
        } else if !ctx.cancel.is_cancelled() && remaining_ms <= 15_000 {
            tracing::debug!(
                elapsed_ms,
                remaining_ms,
                "recycler pass skipped: insufficient time remaining (need 15s, have {remaining_ms}ms)"
            );
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

/// Regional searching toggle for the scan currently executing on this task —
/// set by the engine at scan start from `ScanOptions::regional_search`. Off ⇒
/// geolocation-neutral queries only. Reads the per-scan task-local ambient
/// (`crate::util::regional`), not a process-global: the old `AtomicBool` was
/// shared unkeyed across `hse serve`'s concurrent scans (PROBLEM_TREE T2.11 —
/// "last writer wins for the overlap window"), so a concurrently-started scan
/// could silently flip another in-flight scan's query building. The
/// task-local ambient is inherently per-task, so this reads back only the
/// setting the ENGINE established for the scan actually executing here.
fn regional_enabled() -> bool {
    crate::util::regional::regional_enabled()
}

/// True when `name` has been silenced in ANY active scan. Used by the
/// `/engines/health` API endpoint to report global engine health across
/// all concurrent scans and background queries. Returns true if the engine
/// is dead in at least one active scan (OR across scans).
pub(crate) fn session_dead(name: &str) -> bool {
    SESSION_EMPTY_COUNTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .any(|((_, engine_name), live)| {
            *engine_name == name && live.consecutive_empty >= dead_threshold(*live)
        })
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
