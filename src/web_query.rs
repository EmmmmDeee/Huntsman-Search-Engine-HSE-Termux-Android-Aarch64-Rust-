//! Minimal keyless web meta-search front-end.
//!
//! Restores a bounded subset of the legacy multi-engine scraper through the
//! shared fetch boundary. Each engine runs independently; one blocked or broken
//! provider never erases results from another. A search asks the three default
//! engines ([`ENGINES`]) unless its caller opts in to [`EngineSet::All`], which
//! asks all thirteen in [`EXTENDED_ENGINES`] inside one shared [`Deadline`].

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::thread;
use std::time::Duration;

use serde::Serialize;

use crate::canonical::{canonical_url, canonical_whitespace};
use crate::circuit::{BackoffPolicy, ResponseCache};
use crate::deadline::{Clock, Deadline, SystemClock};
use crate::error::Error;
use crate::fetch::{FetchOptions, fetch};
use crate::http::{Request, Response, Transport, percent_encode_unreserved};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind, classify_fetch};
use crate::textnorm::{decode_html_entities, escape_controls};
use crate::value_syntax::{find_ascii_ci_bytes, percent_decode_strict};

const MAX_RESULTS_PER_ENGINE: usize = 20;
const MAX_SEARCH_QUERY_BYTES: usize = 512;
const CACHE_TTL_SECS: u64 = 300;
/// Anonymous result pages kept for reuse: at most 64 pages of at most 512 KiB each, so
/// the cache never holds more than 32 MiB of page bodies on a low-memory phone.
const CACHE_CAPACITY: usize = 64;
const MAX_CACHEABLE_BODY_BYTES: usize = 512 * 1024;
const RETRY_POLICY: BackoffPolicy = BackoffPolicy::new(2, 100, 500, true);
/// The one wall-clock budget of an [`EngineSet::All`] search: every round, engine,
/// retry pause and request of it ends inside these seconds.
const EXTENDED_BUDGET_SECS: u64 = 110;
/// The most one [`EngineSet::All`] request may take, redirects included. Each request
/// gets this or what is left of the shared budget, whichever is less.
const EXTENDED_REQUEST_SECS: u64 = 6;
/// The row of an engine a later adaptive round leaves out after it refused the baseline.
const BLOCKED_IN_BASELINE: &str = "not queried: provider blocked in baseline round";
/// The row of an engine the shared budget was spent before.
const BUDGET_SPENT: &str = "not queried: shared search time budget exhausted";

#[derive(Debug, Clone)]
struct CachedResponse {
    response: Response,
    stored_at_unix: u64,
}

static RESPONSE_CACHE: ResponseCache<CachedResponse> = ResponseCache::new(CACHE_CAPACITY);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EngineSpec {
    pub name: &'static str,
    pub base_url: &'static str,
}

pub const ENGINES: [EngineSpec; 3] = [
    EngineSpec {
        name: "bing",
        base_url: "https://www.bing.com/search",
    },
    EngineSpec {
        name: "brave",
        base_url: "https://search.brave.com/search",
    },
    EngineSpec {
        name: "mojeek",
        base_url: "https://www.mojeek.com/search",
    },
];

/// Every keyless engine, asked only on an explicit opt-in ([`EngineSet::All`]). Each is
/// a public web search page, not an API or a paid credential. Some require JavaScript or
/// challenge automated clients: those come back as typed failures, never as silent zero
/// results. Several engines may share an upstream index, so URL overlap is never
/// independent corroboration of a document or of a personal identity.
///
/// An engine is listed only when a plain fetch of its result page carries the results.
/// Qwant, Swisscows and Marginalia are not: on 2026-11-05 their pages, fetched this way,
/// held only the sites' own social, app-store and footer links, which the generic parser
/// would report as results.
pub const EXTENDED_ENGINES: [EngineSpec; 13] = [
    ENGINES[0],
    ENGINES[1],
    ENGINES[2],
    EngineSpec {
        name: "duckduckgo",
        base_url: "https://html.duckduckgo.com/html/",
    },
    EngineSpec {
        name: "google",
        base_url: "https://www.google.com/search",
    },
    EngineSpec {
        name: "yahoo",
        base_url: "https://search.yahoo.com/search",
    },
    EngineSpec {
        name: "ecosia",
        base_url: "https://www.ecosia.org/search",
    },
    EngineSpec {
        name: "startpage",
        base_url: "https://www.startpage.com/sp/search",
    },
    EngineSpec {
        name: "yandex",
        base_url: "https://yandex.com/search/",
    },
    EngineSpec {
        name: "yep",
        base_url: "https://yep.com/web",
    },
    EngineSpec {
        name: "lilo",
        base_url: "https://search.lilo.org/",
    },
    EngineSpec {
        name: "you",
        base_url: "https://you.com/search",
    },
    EngineSpec {
        name: "wiby",
        base_url: "https://wiby.me/",
    },
];

/// Which keyless engines one search asks: the one parameter every search path takes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum EngineSet {
    /// Bing, Brave and Mojeek ([`ENGINES`]): the default of every command and API. Each
    /// request keeps the transport's own timeout, as it always has.
    #[default]
    Default,
    /// All thirteen keyless engines ([`EXTENDED_ENGINES`]), asked only on an explicit
    /// `--all`. The whole search shares one 110-second [`Deadline`], and each request is
    /// capped at 6 seconds or what is left of it, whichever is less.
    All,
}

impl EngineSet {
    /// The engines this set asks, in the order their outcomes are reported.
    #[must_use]
    pub const fn engines(self) -> &'static [EngineSpec] {
        match self {
            Self::Default => &ENGINES,
            Self::All => &EXTENDED_ENGINES,
        }
    }

    /// The budget one search over this set shares, started now. The default set has
    /// none, so its requests are timed exactly as before the larger set existed.
    fn start_deadline(self, clock: &dyn Clock) -> Option<Deadline<'_>> {
        match self {
            Self::Default => None,
            Self::All => Some(Deadline::start(
                clock,
                Duration::from_secs(EXTENDED_BUDGET_SECS),
            )),
        }
    }
}

/// The search-page URL that asks `engine` for `query`: the one builder behind live
/// search and the source registry's engine pivots. The query is RFC 3986 encoded, so a
/// space is `%20` and a literal `+` stays `%2B`.
#[must_use]
pub fn search_url(engine: EngineSpec, query: &str) -> String {
    let separator = if engine.base_url.contains('?') {
        '&'
    } else {
        '?'
    };
    format!(
        "{}{separator}{}={}",
        engine.base_url,
        search_parameter(engine.name),
        percent_encode_unreserved(query)
    )
}

/// The query parameter of an engine's public search form.
fn search_parameter(engine: &str) -> &'static str {
    match engine {
        "yahoo" => "p",
        "yandex" => "text",
        _ => "q",
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SearchHit {
    pub engine: String,
    pub url: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SearchReport {
    pub hits: Vec<SearchHit>,
    pub outcomes: Vec<SourceExecutionOutcome>,
}

impl SearchReport {
    /// The text of the report: a line per engine outcome, a line per hit, then the hit count. A hit's
    /// address is whatever the engine's page held, so it is written through
    /// [`escape_controls`](crate::textnorm::escape_controls), as the other reports are.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::new();
        for outcome in &self.outcomes {
            let kind = outcome.kind.as_str();
            let found = outcome
                .found
                .map_or_else(|| "none".to_owned(), |count| count.to_string());
            let _ = writeln!(
                out,
                "engine={}\toutcome={kind}\tfound={found}",
                escape_controls(&outcome.module)
            );
        }
        for hit in &self.hits {
            let _ = writeln!(
                out,
                "{}\t{}",
                escape_controls(&hit.engine),
                escape_controls(&hit.url)
            );
        }
        let _ = writeln!(out, "hits={}", self.hits.len());
        out
    }
}

/// Ask every engine in `engines` for `query`, each independently.
///
/// # Errors
/// Returns only network-boundary errors that prevent a request from being sent.
/// Provider-specific transport failures and block pages remain typed outcomes.
pub fn search<T: Transport + ?Sized>(
    transport: &T,
    query: &str,
    now_unix: u64,
    engines: EngineSet,
) -> Result<SearchReport, Error> {
    search_with_provenance(transport, query, now_unix, engines).map(|(report, _)| report)
}

/// A complete, typed search with both the legacy URL-deduplicated report and the
/// original per-engine URL sightings. Repeated index sightings are discoverability,
/// never independently corroborating observations of the target page's claims.
///
/// # Errors
/// Uses the same bounded input validation and fetch boundary as `search`.
pub fn search_with_provenance<T: Transport + ?Sized>(
    transport: &T,
    query: &str,
    now_unix: u64,
    engines: EngineSet,
) -> Result<(SearchReport, Vec<SearchHit>), Error> {
    let query = checked_query(query, "query")?;
    let deadline = engines.start_deadline(&SystemClock);
    let round = Round {
        engines: engines.engines(),
        deadline: deadline.as_ref(),
        skip: None,
    };
    search_with_observations(transport, &query, now_unix, round)
}

/// Validate before allocating provider URLs or sending any network request.
fn checked_query(input: &str, label: &str) -> Result<String, Error> {
    if input.len() > MAX_SEARCH_QUERY_BYTES || input.chars().any(char::is_control) {
        return Err(Error::Invalid(format!(
            "{label} is too long or contains control characters"
        )));
    }
    // Normalising never lengthens the query, so the budget checked above still holds.
    let normalized = canonical_whitespace(input);
    if normalized.is_empty() {
        return Err(Error::Invalid(format!("{label} must not be empty")));
    }
    Ok(normalized)
}

/// What one round of a search asks: its engines, the search's shared budget when it has
/// one, and the engines it leaves out because they refused the baseline round.
#[derive(Clone, Copy)]
struct Round<'a> {
    engines: &'static [EngineSpec],
    deadline: Option<&'a Deadline<'a>>,
    skip: Option<&'a BTreeSet<String>>,
}

/// Keep every engine's URL observation before compatibility-preserving deduplication.
/// An engine discovery is a lead, not independent corroboration of the page's claims.
/// An engine the round leaves out keeps a typed row saying why; it is never dropped.
fn search_with_observations<T: Transport + ?Sized>(
    transport: &T,
    query: &str,
    now_unix: u64,
    round: Round<'_>,
) -> Result<(SearchReport, Vec<SearchHit>), Error> {
    let mut hits = Vec::new();
    let mut outcomes = Vec::new();
    for &engine in round.engines {
        let result = if round
            .skip
            .is_some_and(|blocked| blocked.contains(engine.name))
        {
            not_queried(engine, now_unix, BLOCKED_IN_BASELINE)
        } else {
            search_engine(transport, engine, query, now_unix, round.deadline)?
        };
        hits.extend(result.hits);
        outcomes.push(result.outcome);
    }
    let observations = hits.clone();
    dedupe_hits(&mut hits);
    Ok((SearchReport { hits, outcomes }, observations))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AdaptiveHit {
    pub url: String,
    pub discovered_by_engines: Vec<String>,
    pub found_in_queries: Vec<String>,
    pub appearances: usize,
    pub evidence_status: &'static str,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AdaptiveRound {
    pub query: String,
    pub strategy: &'static str,
    pub observed_url_count: usize,
    pub novel_url_count: usize,
    pub outcomes: Vec<SourceExecutionOutcome>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AdaptiveSearchReport {
    pub input: String,
    pub rounds: Vec<AdaptiveRound>,
    pub hits: Vec<AdaptiveHit>,
    pub stop_reason: &'static str,
    pub limitations: Vec<&'static str>,
}

#[derive(Default)]
struct HitObservation {
    engines: BTreeSet<String>,
    queries: BTreeSet<String>,
    appearances: usize,
}

fn append_round<T: Transport + ?Sized>(
    transport: &T,
    query: &str,
    strategy: &'static str,
    now_unix: u64,
    round: Round<'_>,
    reports: &mut Vec<AdaptiveRound>,
    seen: &mut BTreeMap<String, HitObservation>,
) -> Result<usize, Error> {
    let (report, observations) = search_with_observations(transport, query, now_unix, round)?;
    let mut novel = 0;
    for hit in &observations {
        let entry = seen.entry(hit.url.clone()).or_insert_with(|| {
            novel += 1;
            HitObservation::default()
        });
        entry.engines.insert(hit.engine.clone());
        entry.queries.insert(query.to_owned());
        entry.appearances += 1;
    }
    reports.push(AdaptiveRound {
        query: query.to_owned(),
        strategy,
        observed_url_count: observations.len(),
        novel_url_count: novel,
        outcomes: report.outcomes,
    });
    Ok(novel)
}

fn has_viable_provider(round: &AdaptiveRound) -> bool {
    round.outcomes.iter().any(|o| {
        matches!(
            o.kind,
            SourceOutcomeKind::Success
                | SourceOutcomeKind::ValidZero
                | SourceOutcomeKind::ZeroYieldAnomaly
        )
    })
}

/// An opt-in, deterministic, outcome-adaptive multi-query search.
/// Each of at most three rounds asks every engine in `engines` once. An engine that
/// refused the baseline round is not asked again in this run; its later rows say so.
///
/// URL overlap between engines is discoverability metadata, NEVER proof that
/// two independent primary documents agree. Query variants produce leads only.
///
/// # Errors
/// Rejects empty, oversized or control-character-bearing queries. Transport
/// boundary setup errors propagate; individual engine errors remain outcomes.
pub fn adaptive_search<T: Transport + ?Sized>(
    transport: &T,
    input: &str,
    now_unix: u64,
    engines: EngineSet,
) -> Result<AdaptiveSearchReport, Error> {
    let deadline = engines.start_deadline(&SystemClock);
    adaptive_search_within(
        transport,
        input,
        now_unix,
        engines.engines(),
        deadline.as_ref(),
    )
}

/// Finalise discovery provenance separately from bounded network scheduling.
/// URLs remain leads even when seen by multiple indexes or query variants.
fn finalize_adaptive_report(
    input: String,
    rounds: Vec<AdaptiveRound>,
    discovery_index: BTreeMap<String, HitObservation>,
    stop_reason: &'static str,
) -> AdaptiveSearchReport {
    let hits = discovery_index
        .into_iter()
        .map(|(url, observation)| AdaptiveHit {
            url,
            discovered_by_engines: observation.engines.into_iter().collect(),
            found_in_queries: observation.queries.into_iter().collect(),
            appearances: observation.appearances,
            evidence_status: "search_discovery_only_not_independent_fact_verification",
        })
        .collect();
    AdaptiveSearchReport {
        input,
        rounds,
        hits,
        stop_reason,
        limitations: vec![
            "search_results_are_leads_not_evidence_of_page_claims",
            "engine_overlap_does_not_establish_independent_primary_sources",
            "search_index_and_html_parser_coverage_are_incomplete",
            "no_live_page_authenticity_or_claim_verification",
            "no_cross_run_learning_or_persistent_adaptation",
        ],
    }
}

/// The engines that refused the baseline round. A quoted or broader query variant does
/// not undo a block page, a rate limit or an authentication wall, so the later rounds of
/// this one search do not ask them again; nothing is remembered across searches.
fn blocked_provider_names(round: &AdaptiveRound) -> BTreeSet<String> {
    round
        .outcomes
        .iter()
        .filter(|outcome| {
            matches!(
                outcome.kind,
                SourceOutcomeKind::BotWaf
                    | SourceOutcomeKind::AuthRequired
                    | SourceOutcomeKind::AuthRejected
                    | SourceOutcomeKind::EntitlementDenied
                    | SourceOutcomeKind::QuotaExhausted
                    | SourceOutcomeKind::RateLimited
                    | SourceOutcomeKind::ConfirmedDead
                    | SourceOutcomeKind::RefusedBeforeSending
            )
        })
        .map(|outcome| outcome.module.clone())
        .collect()
}

/// [`adaptive_search`] over `engines`, every round inside `deadline` when there is one.
fn adaptive_search_within<T: Transport + ?Sized>(
    transport: &T,
    input: &str,
    now_unix: u64,
    engines: &'static [EngineSpec],
    deadline: Option<&Deadline<'_>>,
) -> Result<AdaptiveSearchReport, Error> {
    let normalized_query = checked_query(input, "adaptive query")?;
    let baseline = Round {
        engines,
        deadline,
        skip: None,
    };
    let mut rounds = Vec::new();
    let mut discovery_index = BTreeMap::new();
    let baseline_gain = append_round(
        transport,
        &normalized_query,
        "baseline",
        now_unix,
        baseline,
        &mut rounds,
        &mut discovery_index,
    )?;
    let blocked = blocked_provider_names(&rounds[0]);
    let later = Round {
        skip: Some(&blocked),
        ..baseline
    };

    let stop_reason = if has_viable_provider(&rounds[0]) {
        let mut variant_exceeds_budget = false;
        let second = if normalized_query.starts_with('"')
            && normalized_query.ends_with('"')
            && normalized_query.len() > 2
        {
            let bare = normalized_query.trim_matches('"').trim();
            (bare != normalized_query).then(|| (bare.to_owned(), "unquoted_recall"))
        } else if normalized_query.split_whitespace().count() > 1 {
            let quoted = format!("\"{normalized_query}\"");
            if quoted.len() > MAX_SEARCH_QUERY_BYTES {
                variant_exceeds_budget = true;
                None
            } else {
                Some((quoted, "exact_phrase"))
            }
        } else {
            None
        };
        if let Some((refined, strategy)) = second {
            let refinement_gain = append_round(
                transport,
                &refined,
                strategy,
                now_unix,
                later,
                &mut rounds,
                &mut discovery_index,
            )?;
            let tokens: Vec<&str> = normalized_query.split_whitespace().collect();
            if !has_viable_provider(&rounds[1]) {
                "refinement_sources_unavailable"
            } else if refinement_gain == 0 && baseline_gain > 0 {
                "diminishing_marginal_discovery"
            } else if tokens.len() >= 3 && !normalized_query.contains('"') {
                let broader = tokens[..tokens.len() - 1].join(" ");
                let _ = append_round(
                    transport,
                    &broader,
                    "broader_low_confidence_recall",
                    now_unix,
                    later,
                    &mut rounds,
                    &mut discovery_index,
                )?;
                "bounded_three_round_budget"
            } else {
                "no_safe_additional_query_variant"
            }
        } else if variant_exceeds_budget {
            "query_variant_budget_exhausted"
        } else {
            "no_safe_additional_query_variant"
        }
    } else {
        "all_engines_unavailable_or_unparseable"
    };
    Ok(finalize_adaptive_report(
        normalized_query,
        rounds,
        discovery_index,
        stop_reason,
    ))
}

struct EngineReport {
    hits: Vec<SearchHit>,
    outcome: SourceExecutionOutcome,
}

/// An engine this search did not ask, and why: a typed row, never a silent zero.
fn not_queried(engine: EngineSpec, now_unix: u64, why: &str) -> EngineReport {
    EngineReport {
        hits: Vec::new(),
        outcome: outcome(
            engine.name,
            SourceOutcomeKind::Inconclusive,
            now_unix,
            None,
            None,
            why,
        ),
    }
}

/// Ask one engine. Inside a shared `deadline` an engine the budget was spent before is not
/// asked, each attempt is capped at [`EXTENDED_REQUEST_SECS`] or what is left of the
/// budget, whichever is less, and a retry is sent only when its pause fits in the budget.
fn search_engine<T: Transport + ?Sized>(
    transport: &T,
    engine: EngineSpec,
    query: &str,
    now_unix: u64,
    deadline: Option<&Deadline<'_>>,
) -> Result<EngineReport, Error> {
    let url = search_url(engine, query);
    if let Some(cached) = cached_response(&url, now_unix) {
        return Ok(parse_engine_response(engine, &cached, now_unix));
    }
    if deadline.is_some_and(Deadline::expired) {
        return Ok(not_queried(engine, now_unix, BUDGET_SPENT));
    }

    let request = Request::get(&url)
        .header("accept", "text/html,application/xhtml+xml")
        .header("user-agent", crate::http::DEFAULT_USER_AGENT);
    let mut attempt = 0u32;

    loop {
        let mut sent = request.clone();
        if let Some(deadline) = deadline {
            sent = sent.with_timeout(
                deadline
                    .remaining()
                    .min(Duration::from_secs(EXTENDED_REQUEST_SECS)),
            );
        }
        // The shared boundary paces per host: it suppresses while the circuit is
        // open and records the outcome's health. A suppressed fetch comes back as a
        // no-response `Inconclusive`, which is not retryable and falls through below.
        let fetched = fetch(
            transport,
            sent,
            None,
            &FetchOptions::default().paced(),
            engine.name,
            now_unix,
        )?;

        if retryable_fetch(fetched.outcome.kind)
            && RETRY_POLICY.should_retry(attempt)
            && pause_before_retry(deadline, RETRY_POLICY.delay(attempt))
        {
            attempt = attempt.saturating_add(1);
            continue;
        }

        let Some(response) = fetched.response else {
            return Ok(EngineReport {
                hits: Vec::new(),
                outcome: fetched.outcome,
            });
        };

        // HTTP 200 is not a successful search. Parse first: a zero-yield page
        // may be a transient interstitial or provider markup drift, and caching
        // it would hide new results on repeat searches for the full TTL.
        let report = parse_engine_response(engine, &response, now_unix);
        if response_is_cacheable(&response, &report) {
            RESPONSE_CACHE.put(
                url.clone(),
                CachedResponse {
                    response,
                    stored_at_unix: now_unix,
                },
            );
        }
        return Ok(report);
    }
}

/// Pause before a retry. Without a shared budget the pause is always taken; inside one
/// it is taken only when time is left after it to send the retry.
fn pause_before_retry(deadline: Option<&Deadline<'_>>, pause: Duration) -> bool {
    if let Some(deadline) = deadline {
        deadline.sleep_within(pause)
    } else {
        thread::sleep(pause);
        true
    }
}

fn cached_response(url: &str, now_unix: u64) -> Option<Response> {
    let cached = RESPONSE_CACHE.get(url)?;
    // Never reuse a future-dated response after a clock rollback.
    now_unix
        .checked_sub(cached.stored_at_unix)
        .is_some_and(|age| age <= CACHE_TTL_SECS)
        .then_some(cached.response)
}

fn response_is_cacheable(response: &Response, report: &EngineReport) -> bool {
    // Only a semantically successful search is reusable. HTTP success with
    // no external hits is explicitly a ZeroYieldAnomaly, not negative evidence.
    // A page over the size cap is used once and not kept, which bounds the cache.
    if response.truncated
        || response.body.len() > MAX_CACHEABLE_BODY_BYTES
        || !(200..300).contains(&response.status)
        || report.outcome.kind != SourceOutcomeKind::Success
        || report.hits.is_empty()
    {
        return false;
    }
    let cache_control = response
        .header_value("cache-control")
        .unwrap_or_default()
        .to_ascii_lowercase();
    !cache_control.split(',').map(str::trim).any(|directive| {
        matches!(directive, "no-store" | "no-cache")
            || directive.split_once('=').is_some_and(|(key, value)| {
                key.trim() == "max-age"
                    && value
                        .trim()
                        .trim_matches('"')
                        .bytes()
                        .all(|byte| byte == b'0')
                    && !value.trim().trim_matches('"').is_empty()
            })
    })
}

fn retryable_fetch(kind: SourceOutcomeKind) -> bool {
    matches!(
        kind,
        SourceOutcomeKind::DnsFailure
            | SourceOutcomeKind::ConnectFailure
            | SourceOutcomeKind::TtfbTimeout
            | SourceOutcomeKind::BodyTimeout
            | SourceOutcomeKind::Upstream5xx
    )
}

fn parse_engine_response(engine: EngineSpec, response: &Response, now_unix: u64) -> EngineReport {
    if response.truncated {
        return EngineReport {
            hits: Vec::new(),
            outcome: outcome(
                engine.name,
                SourceOutcomeKind::ParserDrift,
                now_unix,
                Some(response.status),
                None,
                "truncated search response",
            ),
        };
    }

    let body = response.text();
    let classified = classify_fetch(response.status, &body);
    if classified != SourceOutcomeKind::Inconclusive {
        return EngineReport {
            hits: Vec::new(),
            outcome: outcome(
                engine.name,
                classified,
                now_unix,
                Some(response.status),
                None,
                "search provider did not return a parseable result page",
            ),
        };
    }

    let hits = parse_hits(&body, engine.name);
    let outcome = if hits.is_empty() {
        outcome(
            engine.name,
            SourceOutcomeKind::ZeroYieldAnomaly,
            now_unix,
            Some(response.status),
            Some(0),
            "HTTP response parsed but yielded no external result URLs",
        )
    } else {
        SourceExecutionOutcome::success(engine.name, now_unix, hits.len())
            .with_http_status(response.status)
    };
    EngineReport { hits, outcome }
}

fn outcome(
    module: &str,
    kind: SourceOutcomeKind,
    now_unix: u64,
    status: Option<u16>,
    found: Option<usize>,
    detail: &str,
) -> SourceExecutionOutcome {
    SourceExecutionOutcome::observed(module, now_unix, kind, status, found, detail)
}

#[must_use]
pub fn parse_hits(html: &str, engine: &str) -> Vec<SearchHit> {
    // Set membership deduplicates while the vector preserves provider ranking.
    let mut seen = BTreeSet::new();
    let mut hits = Vec::new();
    for href in href_values(html) {
        let Some(url) = extract_result_url(href, engine) else {
            continue;
        };
        if is_engine_or_navigation_url(&url, engine) {
            continue;
        }
        if seen.insert(url.clone()) {
            hits.push(SearchHit {
                engine: engine.into(),
                url,
            });
            if hits.len() >= MAX_RESULTS_PER_ENGINE {
                break;
            }
        }
    }
    hits
}

/// The target of a Bing click redirect (`https://www.bing.com/ck/a?…&u=a1<base64url>`), or
/// `None` for any other address or an undecodable `u`. Only Bing's own host is unwrapped.
fn bing_click_target(href: &str) -> Option<String> {
    let rest = href
        .strip_prefix("https://www.bing.com/ck/a?")
        .or_else(|| href.strip_prefix("https://bing.com/ck/a?"))?;
    let encoded = rest
        .split('&')
        .find_map(|pair| pair.strip_prefix("u=a1"))?
        .split('#')
        .next()?;
    let standard: String = encoded
        .chars()
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            other => other,
        })
        .collect();
    let bytes = crate::base64::decode_standard(&standard)?;
    String::from_utf8(bytes).ok()
}

/// The result an anchor's `href` points at. Known result-link wrappers are unwrapped
/// offline, never followed: the `uddg` redirect on a `duckduckgo` page, `/url` on a
/// `google` page and `RU=` on a `yahoo` page, and Bing's click redirect on any page. A
/// wrapper whose target is malformed percent-encoding or not an http(s) URL yields `None`,
/// so an engine redirect never stands in for the document it points at.
fn extract_result_url(href: &str, engine: &str) -> Option<String> {
    let decoded = decode_html_entities(href);
    let value = if engine == "duckduckgo"
        && (decoded.starts_with("//duckduckgo.com/l/?")
            || decoded.starts_with("/l/?")
            || decoded.starts_with("https://duckduckgo.com/l/?"))
    {
        percent_decode_strict(wrapped_parameter(&decoded, &["uddg"])?)?
    } else if engine == "google"
        && (decoded.starts_with("/url?") || decoded.starts_with("https://www.google.com/url?"))
    {
        percent_decode_strict(wrapped_parameter(&decoded, &["q", "url"])?)?
    } else if engine == "yahoo"
        && decoded.starts_with("https://r.search.yahoo.com/")
        && decoded.contains("/RU=")
    {
        let target = decoded.split_once("/RU=")?.1.split('/').next()?;
        percent_decode_strict(target)?
    } else {
        bing_click_target(&decoded).unwrap_or(decoded)
    };
    canonical_url(&value)
}

/// The still-encoded value of the first of `keys` in a wrapper URL's query string.
fn wrapped_parameter<'a>(url: &'a str, keys: &[&str]) -> Option<&'a str> {
    url.split_once('?')?
        .1
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(key, _)| keys.contains(key))
        .map(|(_, value)| value)
}

fn href_values(html: &str) -> Vec<&str> {
    // Search results are anchor targets, not arbitrary href-looking bytes in
    // stylesheets, metadata, comments, JavaScript, or hidden HTML templates.
    let bytes = html.as_bytes();
    let mut hits = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'<' {
            index += 1;
            continue;
        }
        if bytes[index..].starts_with(b"<!--") {
            let start = index + 4;
            let Some(skip) = bytes[start..].windows(3).position(|part| part == b"-->") else {
                break;
            };
            index = start + skip + 3;
            continue;
        }
        let Some(end) = tag_end(bytes, index + 1) else {
            break;
        };
        let tag = &bytes[index + 1..end];
        let mut name_start = 0;
        while name_start < tag.len() && tag[name_start].is_ascii_whitespace() {
            name_start += 1;
        }
        let closing = tag.get(name_start) == Some(&b'/');
        if closing {
            name_start += 1;
        }
        let mut name_end = name_start;
        while name_end < tag.len() && tag[name_end].is_ascii_alphabetic() {
            name_end += 1;
        }
        let name = &tag[name_start..name_end];
        if !closing {
            let closer: Option<&[u8]> = if name.eq_ignore_ascii_case(b"script") {
                Some(b"</script")
            } else if name.eq_ignore_ascii_case(b"style") {
                Some(b"</style")
            } else if name.eq_ignore_ascii_case(b"template") {
                Some(b"</template")
            } else if name.eq_ignore_ascii_case(b"textarea") {
                Some(b"</textarea")
            } else {
                None
            };
            if let Some(closer) = closer {
                let Some(skip) = find_ascii_ci_bytes(&bytes[end + 1..], closer) else {
                    break;
                };
                index = end + 1 + skip;
                continue;
            }
            if name.eq_ignore_ascii_case(b"a") {
                if let Some(href) = anchor_href(html, index + 1 + name_end, end) {
                    hits.push(href);
                }
            }
        }
        index = end + 1;
    }
    hits
}

// Find the closing '>' of a tag, not the '>' inside an attribute value.
fn tag_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut quote = None;
    for (index, byte) in bytes.iter().enumerate().skip(start) {
        if let Some(delimiter) = quote {
            if *byte == delimiter {
                quote = None;
            }
        } else if matches!(*byte, b'\'' | b'"') {
            quote = Some(*byte);
        } else if *byte == b'>' {
            return Some(index);
        }
    }
    None
}

// HTML attributes have no fixed order, and valid href values may be quoted or
// unquoted. Only an exact attribute name on an actual <a> tag is a candidate.
fn anchor_href(html: &str, mut index: usize, end: usize) -> Option<&str> {
    let bytes = html.as_bytes();
    while index < end {
        while index < end && (bytes[index].is_ascii_whitespace() || bytes[index] == b'/') {
            index += 1;
        }
        let name_start = index;
        while index < end
            && !bytes[index].is_ascii_whitespace()
            && !matches!(bytes[index], b'=' | b'/')
        {
            index += 1;
        }
        if name_start == index {
            index += 1;
            continue;
        }
        let name = &bytes[name_start..index];
        let mut equals = index;
        while equals < end && bytes[equals].is_ascii_whitespace() {
            equals += 1;
        }
        if equals == end || bytes[equals] != b'=' {
            index = equals;
            continue;
        }
        index = equals + 1;
        while index < end && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if index == end {
            break;
        }
        let (value_start, value_end) = if matches!(bytes[index], b'\'' | b'"') {
            let delimiter = bytes[index];
            index += 1;
            let start = index;
            while index < end && bytes[index] != delimiter {
                index += 1;
            }
            let finish = index;
            index = (index + 1).min(end);
            (start, finish)
        } else {
            let start = index;
            while index < end && !bytes[index].is_ascii_whitespace() {
                index += 1;
            }
            (start, index)
        };
        if name.eq_ignore_ascii_case(b"href") {
            return html.get(value_start..value_end);
        }
    }
    None
}

/// A link that is engine chrome, not a result. The default engines' hosts are chrome on
/// every page, as they always were. Any other engine's hosts are chrome only on that
/// engine's own page: a Bing result on `finance.yahoo.com` is a result.
fn is_engine_or_navigation_url(url: &str, engine: &str) -> bool {
    let Some(host) = host_of(url) else {
        return true;
    };
    const ENGINE_HOSTS: &[&str] = &[
        "bing.com",
        "brave.com",
        "mojeek.com",
        "microsoft.com",
        "msn.com",
    ];
    ENGINE_HOSTS.iter().chain(own_hosts(engine)).any(|known| {
        host == *known
            || host
                .strip_suffix(known)
                .is_some_and(|prefix| prefix.ends_with('.'))
    })
}

/// The domains of an engine beyond the default three, whose links on its own result
/// page are its navigation, settings and redirect chrome.
fn own_hosts(engine: &str) -> &'static [&'static str] {
    match engine {
        "duckduckgo" => &["duckduckgo.com"],
        "google" => &["google.com"],
        // Yahoo's result page links its own feedback forum on a third-party host.
        "yahoo" => &["yahoo.com", "yahoo.uservoice.com"],
        "ecosia" => &["ecosia.org"],
        "startpage" => &["startpage.com"],
        "yandex" => &["yandex.com"],
        "yep" => &["yep.com"],
        "lilo" => &["lilo.org"],
        "you" => &["you.com"],
        "wiby" => &["wiby.me"],
        _ => &[],
    }
}

fn host_of(url: &str) -> Option<String> {
    let (_, rest) = url.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority.rsplit('@').next()?;
    let host = host
        .split(':')
        .next()?
        .trim_matches('.')
        .to_ascii_lowercase();
    (!host.is_empty()).then_some(host)
}

fn dedupe_hits(hits: &mut Vec<SearchHit>) {
    let mut seen = BTreeSet::new();
    hits.retain(|hit| seen.insert(hit.url.clone()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;

    use crate::deadline::FakeClock;
    use crate::http::{Response, TransportFailure};

    #[test]
    fn a_report_prints_an_address_from_the_page_as_text_on_one_line() {
        let report = SearchReport {
            hits: vec![
                SearchHit {
                    engine: "duckduckgo".into(),
                    url: "https://a.example/x\u{1b}[2J\nbing\thttps://b.example/\u{2028}".into(),
                },
                SearchHit {
                    engine: "mojeek".into(),
                    url: "https://c.example/ordinary?q=1&r=2".into(),
                },
            ],
            outcomes: vec![SourceExecutionOutcome::success("duckduckgo", 1, 1)],
        };
        let text = report.render();
        assert_eq!(
            text,
            "engine=duckduckgo\toutcome=success\tfound=1\n\
             duckduckgo\thttps://a.example/x\\u{1b}[2J\\nbing\\thttps://b.example/\\u{2028}\n\
             mojeek\thttps://c.example/ordinary?q=1&r=2\n\
             hits=2\n"
        );
    }

    #[test]
    fn source_observation_view_keeps_index_overlap_without_changing_legacy_results() {
        let html = "<html><a href='https://github.com/example-public'>public</a></html>";
        let fake = Fake::new(vec![
            Ok(response(200, html)),
            Ok(response(200, html)),
            Ok(response(200, html)),
        ]);
        let (deduped, sightings) = search_with_provenance(
            &fake,
            "source-overlap-facet-example",
            171,
            EngineSet::Default,
        )
        .unwrap();
        assert_eq!(deduped.hits.len(), 1);
        assert_eq!(sightings.len(), 3);
        assert_eq!(
            sightings
                .iter()
                .map(|row| row.engine.as_str())
                .collect::<Vec<_>>(),
            ["bing", "brave", "mojeek"]
        );
        assert_eq!(deduped.outcomes.len(), 3);
        assert!(
            deduped
                .outcomes
                .iter()
                .all(|row| row.kind == SourceOutcomeKind::Success)
        );
    }

    struct Fake {
        responses: RefCell<VecDeque<Result<Response, TransportFailure>>>,
    }

    impl Fake {
        fn new(responses: Vec<Result<Response, TransportFailure>>) -> Self {
            Self {
                responses: RefCell::new(responses.into()),
            }
        }
    }

    impl Transport for Fake {
        fn send(&self, _request: &Request) -> Result<Response, TransportFailure> {
            self.responses
                .borrow_mut()
                .pop_front()
                .expect("unexpected request")
        }
    }

    fn response(status: u16, body: &str) -> Response {
        response_with_headers(status, &[("content-type", "text/html")], body)
    }

    fn response_with_headers(status: u16, headers: &[(&str, &str)], body: &str) -> Response {
        Response {
            status,
            headers: headers
                .iter()
                .map(|(name, value)| ((*name).into(), (*value).into()))
                .collect(),
            body: body.as_bytes().to_vec(),
            truncated: false,
        }
    }

    fn transport_failure(kind: SourceOutcomeKind) -> TransportFailure {
        TransportFailure {
            kind,
            detail: "transient test failure".into(),
            blocked: false,
        }
    }

    /// Bing wraps every organic result in a `bing.com/ck/a` click redirect whose `u` parameter is
    /// `a1` plus the target in unpadded URL-safe Base64; the target is the hit, the wrapper is not.
    #[test]
    fn parser_unwraps_bing_click_redirects_to_their_target() {
        let wrap = |target: &str| format!("a1{}", crate::base64::url_unpadded(target.as_bytes()));
        let hit = wrap("https://example.org/spiders?a=1&b=2");
        let html = format!(
            r#"
            <a href="https://www.bing.com/ck/a?!&amp;&amp;p=ab&amp;u={hit}&amp;ntb=1">A</a>
            <a href="https://www.bing.com/ck/a?u={}">relative</a>
            <a href="https://www.bing.com/ck/a?u={}">engine</a>
            <a href="https://www.bing.com/ck/a?u=a1!!notbase64">bad</a>
            <a href="https://evil.example/ck/a?u={hit}">spoof</a>
        "#,
            wrap("/images/search?q=x"),
            wrap("http://go.microsoft.com/fwlink"),
        );
        let hits = parse_hits(&html, "bing");
        let urls: Vec<&str> = hits.iter().map(|hit| hit.url.as_str()).collect();
        assert_eq!(
            urls,
            [
                "https://example.org/spiders?a=1&b=2".to_owned(),
                format!("https://evil.example/ck/a?u={hit}"),
            ]
        );
    }

    #[test]
    fn parser_keeps_external_urls_and_drops_engine_chrome() {
        let html = r#"
            <a href="https://www.bing.com/search?q=x">next</a>
            <a href="https://example.org/a?x=1&amp;y=2">A</a>
            <a HREF='https://sub.example.net/profile'>B</a>
        "#;
        let hits = parse_hits(html, "bing");
        assert_eq!(hits.len(), 2);
        assert!(
            hits.iter()
                .any(|hit| hit.url == "https://example.org/a?x=1&y=2")
        );
        assert!(
            hits.iter()
                .any(|hit| hit.url == "https://sub.example.net/profile")
        );
    }

    #[test]
    fn parser_never_promotes_page_resources_or_script_literals_to_results() {
        let html = r#"
            <link rel="stylesheet" href="https://cdn.example.net/site.css">
            <meta data-href="https://meta.example.org/fake">
            <script>const template = '<a href="https://script.example.org/fake">';</script>
            <style>/* <a href="https://style.example.org/fake"> */</style>
            <template><a href="https://template.example.org/fake">Hidden</a></template>
            <!-- <a href="https://comment.example.org/fake">Comment</a> -->
            <a data-href="https://data.example.org/fake" class="result" href="https://real.example.org/a">Real</a>
        "#;
        let hits = parse_hits(html, "bing");
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!(hits[0].url, "https://real.example.org/a");
    }

    #[test]
    fn parser_supports_unquoted_href_and_embedded_greater_than_in_attributes() {
        let html = concat!(
            "<A data-note='greater > sign' HREF=https://example.org/unquoted>First</A>",
            "<a HREF = 'https://example.net/other?x=1&amp;y=2'>Second</a>",
            "<a title='contains href=\"https://fake.example/\"' href=\"https://example.com/real\">Third</a>",
        );
        let hits = parse_hits(html, "mojeek");
        let urls: Vec<_> = hits.iter().map(|hit| hit.url.as_str()).collect();
        assert_eq!(
            urls,
            [
                "https://example.org/unquoted",
                "https://example.net/other?x=1&y=2",
                "https://example.com/real",
            ]
        );
    }

    /// An href's character references are decoded once, as HTML reads them: `&#233;` is `é`, not
    /// the start of a fragment, and `&amp;#38;` is the text `&#38;`, whose `#` does start one.
    #[test]
    fn parser_decodes_each_character_reference_in_an_href_once() {
        let html = concat!(
            "<a href=\"https://example.org/caf&#233;?q=1&amp;r=2\">accented</a>",
            "<a href=\"https://example.net/p?a=1&amp;#38;b=2\">escaped</a>",
        );
        let hits = parse_hits(html, "bing");
        let urls: Vec<_> = hits.iter().map(|hit| hit.url.as_str()).collect();
        assert_eq!(
            urls,
            [
                "https://example.org/caf\u{e9}?q=1&r=2",
                "https://example.net/p?a=1",
            ]
        );
    }

    #[test]
    fn parser_preserves_first_seen_provider_ranking_and_deduplicates() {
        let html = concat!(
            "<a href=\"https://z.example/item\">first</a>",
            "<a href=\"https://a.example/item\">second</a>",
            "<a href=\"https://z.example/item\">duplicate</a>",
            "<a href=\"https://m.example/item\">third</a>",
        );
        let hits = parse_hits(html, "bing");
        let urls: Vec<_> = hits.iter().map(|hit| hit.url.as_str()).collect();
        assert_eq!(
            urls,
            [
                "https://z.example/item",
                "https://a.example/item",
                "https://m.example/item",
            ]
        );
    }

    #[test]
    fn parser_caps_the_first_distinct_results_without_reordering() {
        let mut html = String::new();
        for index in (0..MAX_RESULTS_PER_ENGINE + 2).rev() {
            std::fmt::Write::write_fmt(
                &mut html,
                format_args!("<a href=\"https://example.org/{index:02}\">hit</a>"),
            )
            .expect("writing to String is infallible");
        }
        let hits = parse_hits(&html, "bing");
        assert_eq!(hits.len(), MAX_RESULTS_PER_ENGINE);
        assert_eq!(
            hits[0].url,
            format!("https://example.org/{:02}", MAX_RESULTS_PER_ENGINE + 1)
        );
        assert_eq!(
            hits[MAX_RESULTS_PER_ENGINE - 1].url,
            "https://example.org/02"
        );
    }

    #[test]
    fn parser_rejects_data_href_and_attribute_substring_false_positives() {
        let html = concat!(
            "<a data-href=\"https://wrong.example/path\" href=\"https://real.example/path\">real</a>",
            "<a nothref=\"https://also-wrong.example/path\">not a link</a>",
            "<a HREF = 'https://second.example/path'>second</a>",
        );
        let hits = parse_hits(html, "bing");
        let urls: Vec<_> = hits.iter().map(|hit| hit.url.as_str()).collect();
        assert_eq!(
            urls,
            ["https://real.example/path", "https://second.example/path"]
        );
    }

    #[test]
    fn multi_engine_search_isolates_zero_yield_and_keeps_other_hits() {
        let fake = Fake::new(vec![
            Ok(response(200, r#"<a href="https://example.org/a">A</a>"#)),
            Ok(response(200, "<html><body>no links</body></html>")),
            Ok(response(200, r#"<a href="https://example.net/b">B</a>"#)),
        ]);
        let report = search(&fake, "alice citizen", 1, EngineSet::Default).unwrap();
        assert_eq!(report.hits.len(), 2);
        assert_eq!(report.outcomes[0].kind, SourceOutcomeKind::Success);
        assert_eq!(report.outcomes[1].kind, SourceOutcomeKind::ZeroYieldAnomaly);
        assert_eq!(report.outcomes[2].kind, SourceOutcomeKind::Success);
    }

    #[test]
    fn empty_http_success_does_not_hide_later_search_results() {
        let engine = EngineSpec {
            name: "cache_zero_yield_test",
            base_url: "https://cache-zero-yield-web-query.invalid/search",
        };
        let fake = Fake::new(vec![
            Ok(response(200, "<html><body>Temporarily empty</body></html>")),
            Ok(response(
                200,
                r#"<a href="https://example.org/new-result">new</a>"#,
            )),
        ]);
        let first = search_engine(&fake, engine, "rare-needle-unique", 300, None).unwrap();
        assert_eq!(first.outcome.kind, SourceOutcomeKind::ZeroYieldAnomaly);
        assert!(first.hits.is_empty());

        // Within the TTL: if the first page were cached, this call would
        // incorrectly return zero hits and leave the second fixture unused.
        let second = search_engine(&fake, engine, "rare-needle-unique", 301, None).unwrap();
        assert_eq!(second.outcome.kind, SourceOutcomeKind::Success);
        assert_eq!(second.hits[0].url, "https://example.org/new-result");
    }

    #[test]
    fn engine_navigation_only_is_not_a_cacheable_search_result() {
        let engine = EngineSpec {
            name: "cache_navigation_only_test",
            base_url: "https://cache-navigation-web-query.invalid/search",
        };
        let fake = Fake::new(vec![
            Ok(response(
                200,
                r#"<a href="https://www.bing.com/search?q=next">Next</a>"#,
            )),
            Ok(response(
                200,
                r#"<a href="https://example.net/real">real</a>"#,
            )),
        ]);
        let first = search_engine(&fake, engine, "navigation-only-unique", 400, None).unwrap();
        assert_eq!(first.outcome.kind, SourceOutcomeKind::ZeroYieldAnomaly);
        let second = search_engine(&fake, engine, "navigation-only-unique", 401, None).unwrap();
        assert_eq!(second.hits[0].url, "https://example.net/real");
    }

    #[test]
    fn duplicate_url_across_engines_is_returned_once() {
        let body = r#"<a href="https://example.org/a">A</a>"#;
        let fake = Fake::new(vec![
            Ok(response(200, body)),
            Ok(response(200, body)),
            Ok(response(200, body)),
        ]);
        let report = search(&fake, "alice duplicate-url-dedupe", 1, EngineSet::Default).unwrap();
        assert_eq!(report.hits.len(), 1);
    }

    #[test]
    fn adaptive_search_preserves_engine_overlap_as_discovery_not_corroboration() {
        let shared = r#"<a href="https://example.org/shared">shared</a>"#;
        let first = r#"<a href="https://example.net/first">first</a>"#;
        let second = r#"<a href="https://example.org/second">second</a>"#;
        let fake = Fake::new(vec![
            Ok(response(200, shared)),
            Ok(response(200, shared)),
            Ok(response(200, first)),
            Ok(response(200, second)),
            Ok(response(200, shared)),
            Ok(response(200, second)),
        ]);
        let report = adaptive_search(
            &fake,
            "unique-adaptive-trial alpha",
            123,
            EngineSet::Default,
        )
        .unwrap();
        assert_eq!(report.rounds.len(), 2);
        assert_eq!(report.rounds[0].novel_url_count, 2);
        assert_eq!(report.rounds[1].novel_url_count, 1);
        assert_eq!(report.hits.len(), 3);
        assert_eq!(report.stop_reason, "no_safe_additional_query_variant");
        let shared = report
            .hits
            .iter()
            .find(|hit| hit.url == "https://example.org/shared")
            .unwrap();
        assert_eq!(shared.discovered_by_engines, vec!["bing", "brave"]);
        assert_eq!(shared.appearances, 3);
        assert_eq!(
            shared.evidence_status,
            "search_discovery_only_not_independent_fact_verification"
        );
    }

    #[test]
    fn adaptive_search_only_broadens_after_zero_yield_and_discloses_it() {
        let empty = response(200, "<html>no external anchors</html>");
        let fake = Fake::new(vec![
            Ok(empty.clone()),
            Ok(empty.clone()),
            Ok(empty.clone()),
            Ok(empty.clone()),
            Ok(empty.clone()),
            Ok(empty.clone()),
            Ok(response(
                200,
                r#"<a href="https://example.org/recovered">found</a>"#,
            )),
            Ok(empty.clone()),
            Ok(empty),
        ]);
        let report =
            adaptive_search(&fake, "needle rare threeword", 456, EngineSet::Default).unwrap();
        assert_eq!(report.rounds.len(), 3);
        assert_eq!(report.rounds[2].strategy, "broader_low_confidence_recall");
        assert_eq!(report.rounds[2].query, "needle rare");
        assert_eq!(report.rounds[2].novel_url_count, 1);
        assert_eq!(report.hits.len(), 1);
        assert_eq!(report.stop_reason, "bounded_three_round_budget");
        assert!(
            report.rounds[0]
                .outcomes
                .iter()
                .all(|outcome| outcome.kind == SourceOutcomeKind::ZeroYieldAnomaly)
        );
    }

    #[test]
    fn plain_search_rejects_oversized_and_control_queries_before_any_request() {
        let fake = Fake::new(vec![]);
        for query in ["", "   ", "line\nfeed", "nul\0byte", "carriage\rreturn"] {
            assert!(
                search(&fake, query, 100, EngineSet::Default).is_err(),
                "accepted {query:?}"
            );
        }
        assert!(
            search(
                &fake,
                &"a".repeat(MAX_SEARCH_QUERY_BYTES + 1),
                100,
                EngineSet::Default
            )
            .is_err()
        );
        assert!(
            search(
                &fake,
                &"🙂".repeat(MAX_SEARCH_QUERY_BYTES / 4 + 1),
                100,
                EngineSet::Default
            )
            .is_err()
        );
        assert_eq!(
            checked_query(&"a".repeat(MAX_SEARCH_QUERY_BYTES), "query")
                .unwrap()
                .len(),
            MAX_SEARCH_QUERY_BYTES
        );
    }

    #[test]
    fn adaptive_search_skips_quoted_variant_over_budget_and_keeps_baseline_hits() {
        let fake = Fake::new(vec![
            Ok(response(
                200,
                r#"<a href="https://unique-variant-limit.example/hit">x</a>"#,
            )),
            Ok(response(200, "<html>no links</html>")),
            Ok(response(200, "<html>no links</html>")),
        ]);
        let query = format!("{} b", "a".repeat(MAX_SEARCH_QUERY_BYTES - 2));
        assert_eq!(query.len(), MAX_SEARCH_QUERY_BYTES);
        let report = adaptive_search(&fake, &query, 42, EngineSet::Default).unwrap();
        assert_eq!(report.rounds.len(), 1);
        assert_eq!(report.stop_reason, "query_variant_budget_exhausted");
        assert_eq!(report.hits.len(), 1);
        assert_eq!(
            report.hits[0].url,
            "https://unique-variant-limit.example/hit"
        );
    }

    #[test]
    fn adaptive_search_refuses_unavailable_sources_and_invalid_queries() {
        let fake = Fake::new(vec![
            Ok(response(403, "<html>Cloudflare Just a moment</html>")),
            Ok(response(403, "<html>Cloudflare Just a moment</html>")),
            Ok(response(403, "<html>Cloudflare Just a moment</html>")),
        ]);
        let report = adaptive_search(
            &fake,
            "unique-provider-block alpha",
            789,
            EngineSet::Default,
        )
        .unwrap();
        assert_eq!(report.rounds.len(), 1);
        assert!(report.hits.is_empty());
        assert_eq!(report.stop_reason, "all_engines_unavailable_or_unparseable");

        assert!(adaptive_search(&Fake::new(vec![]), "   ", 790, EngineSet::Default).is_err());
        assert!(
            adaptive_search(&Fake::new(vec![]), "bad\nquery", 790, EngineSet::Default).is_err()
        );
        assert!(
            adaptive_search(
                &Fake::new(vec![]),
                &"a".repeat(513),
                790,
                EngineSet::Default
            )
            .is_err()
        );
    }

    #[test]
    fn cache_hit_reuses_identical_parsed_result_without_second_send() {
        let engine = EngineSpec {
            name: "cache_test",
            base_url: "https://cache-web-query.invalid/search",
        };
        let fake = Fake::new(vec![Ok(response(
            200,
            r#"<a href="https://example.org/cached">cached</a>"#,
        ))]);

        let first = search_engine(&fake, engine, "cache-key-unique", 100, None).unwrap();
        let second = search_engine(&fake, engine, "cache-key-unique", 101, None).unwrap();

        assert_eq!(first.hits, second.hits);
        assert_eq!(first.outcome.kind, second.outcome.kind);
        assert_eq!(first.hits[0].url, "https://example.org/cached");
    }

    #[test]
    fn stale_cache_entry_is_replaced_after_ttl() {
        let engine = EngineSpec {
            name: "cache_ttl_test",
            base_url: "https://cache-ttl-web-query.invalid/search",
        };
        let fake = Fake::new(vec![
            Ok(response(
                200,
                r#"<a href="https://example.org/first">first</a>"#,
            )),
            Ok(response(
                200,
                r#"<a href="https://example.org/second">second</a>"#,
            )),
        ]);

        let first = search_engine(&fake, engine, "ttl-key-unique", 100, None).unwrap();
        let second = search_engine(
            &fake,
            engine,
            "ttl-key-unique",
            100 + CACHE_TTL_SECS + 1,
            None,
        )
        .unwrap();

        assert_eq!(first.hits[0].url, "https://example.org/first");
        assert_eq!(second.hits[0].url, "https://example.org/second");
    }

    #[test]
    fn no_store_response_is_never_reused() {
        let engine = EngineSpec {
            name: "no_store_test",
            base_url: "https://no-store-web-query.invalid/search",
        };
        let fake = Fake::new(vec![
            Ok(response_with_headers(
                200,
                &[("cache-control", "no-store")],
                r#"<a href="https://example.org/first">first</a>"#,
            )),
            Ok(response_with_headers(
                200,
                &[("cache-control", "no-store")],
                r#"<a href="https://example.org/second">second</a>"#,
            )),
        ]);

        let first = search_engine(&fake, engine, "no-store-key-unique", 200, None).unwrap();
        let second = search_engine(&fake, engine, "no-store-key-unique", 201, None).unwrap();

        assert_eq!(first.hits[0].url, "https://example.org/first");
        assert_eq!(second.hits[0].url, "https://example.org/second");
    }

    #[test]
    fn no_cache_directive_prevents_reusing_a_search_page_without_revalidation() {
        let engine = EngineSpec {
            name: "no_cache_directive_test",
            base_url: "https://no-cache-web-query.invalid/search",
        };
        let fake = Fake::new(vec![
            Ok(response_with_headers(
                200,
                &[("cache-control", "no-cache")],
                r#"<a href="https://example.org/first">first</a>"#,
            )),
            Ok(response(
                200,
                r#"<a href="https://example.org/second">second</a>"#,
            )),
        ]);

        let first = search_engine(&fake, engine, "no-cache-unique-query", 500, None).unwrap();
        let second = search_engine(&fake, engine, "no-cache-unique-query", 501, None).unwrap();
        assert_eq!(first.hits[0].url, "https://example.org/first");
        assert_eq!(second.hits[0].url, "https://example.org/second");

        let response = response_with_headers(
            200,
            &[("cache-control", "max-age=0")],
            r#"<a href="https://example.org/third">third</a>"#,
        );
        let report = parse_engine_response(engine, &response, 502);
        assert!(!response_is_cacheable(&response, &report));
        for directive in [
            "max-age = 0",
            "public, max-age= 0",
            "MAX-AGE =0",
            "max-age=000",
            "max-age=\"0\"",
        ] {
            let response = response_with_headers(
                200,
                &[("cache-control", directive)],
                r#"<a href="https://example.org/third">third</a>"#,
            );
            let report = parse_engine_response(engine, &response, 502);
            assert!(!response_is_cacheable(&response, &report), "{directive}");
        }
    }

    #[test]
    fn oversized_search_pages_are_not_retained_in_android_cache() {
        let engine = EngineSpec {
            name: "cache_size_test",
            base_url: "https://cache-size-web-query.invalid/search",
        };
        let large = format!(
            "<a href=\"https://example.org/big\">Big</a>{}",
            " ".repeat(MAX_CACHEABLE_BODY_BYTES),
        );
        let fake = Fake::new(vec![
            Ok(response(200, &large)),
            Ok(response(
                200,
                r#"<a href="https://example.org/fresh">Fresh</a>"#,
            )),
        ]);
        let first = search_engine(&fake, engine, "unique-cache-size", 400, None).unwrap();
        let second = search_engine(&fake, engine, "unique-cache-size", 401, None).unwrap();
        assert_eq!(first.hits[0].url, "https://example.org/big");
        assert_eq!(second.hits[0].url, "https://example.org/fresh");
    }

    #[test]
    fn a_future_dated_cache_entry_is_not_reused_after_clock_rollback() {
        let engine = EngineSpec {
            name: "cache_clock_rollback_test",
            base_url: "https://clock-rollback-web-query.invalid/search",
        };
        let fake = Fake::new(vec![
            Ok(response(
                200,
                r#"<a href="https://example.org/before">before</a>"#,
            )),
            Ok(response(
                200,
                r#"<a href="https://example.org/after">after</a>"#,
            )),
        ]);

        let first = search_engine(&fake, engine, "clock-rollback-unique-query", 900, None).unwrap();
        let second =
            search_engine(&fake, engine, "clock-rollback-unique-query", 899, None).unwrap();
        assert_eq!(first.hits[0].url, "https://example.org/before");
        assert_eq!(second.hits[0].url, "https://example.org/after");
    }

    #[test]
    fn transient_transport_failure_retries_once_then_recovers() {
        let engine = EngineSpec {
            name: "retry_test",
            base_url: "https://retry-web-query.invalid/search",
        };
        let fake = Fake::new(vec![
            Err(transport_failure(SourceOutcomeKind::ConnectFailure)),
            Ok(response(
                200,
                r#"<a href="https://example.org/recovered">recovered</a>"#,
            )),
        ]);

        let report = search_engine(&fake, engine, "retry-key-unique", 300, None).unwrap();

        assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
        assert_eq!(report.hits[0].url, "https://example.org/recovered");
    }

    #[test]
    fn open_source_pacing_circuit_suppresses_request() {
        let engine = EngineSpec {
            name: "circuit_test",
            base_url: "https://circuit-web-query.invalid/search",
        };
        crate::circuit::record_rate_limited("circuit-web-query.invalid", 400, 60);
        let fake = Fake::new(Vec::new());

        let report = search_engine(&fake, engine, "circuit-key-unique", 401, None).unwrap();

        assert_eq!(report.outcome.kind, SourceOutcomeKind::Inconclusive);
        assert!(
            report
                .outcome
                .detail
                .as_deref()
                .is_some_and(|detail| detail.contains("circuit is open"))
        );
        assert!(report.hits.is_empty());
    }

    #[test]
    fn challenge_page_remains_a_typed_provider_outcome() {
        let challenge = "<html><title>Just a moment</title>Cloudflare</html>";
        let fake = Fake::new(vec![
            Ok(response(403, challenge)),
            Ok(response(200, r#"<a href="https://example.org/a">A</a>"#)),
            Ok(response(200, r#"<a href="https://example.net/b">B</a>"#)),
        ]);
        let report = search(&fake, "alice challenge-page", 1, EngineSet::Default).unwrap();
        assert_eq!(report.outcomes[0].kind, SourceOutcomeKind::BotWaf);
        assert_eq!(report.hits.len(), 2);
    }

    #[test]
    fn search_routes_keep_rfc3986_space_and_literal_plus_distinct() {
        let engine = EXTENDED_ENGINES
            .iter()
            .find(|engine| engine.name == "yahoo")
            .copied()
            .expect("yahoo engine");
        assert_eq!(
            search_url(engine, "Ada + Lovelace"),
            "https://search.yahoo.com/search?p=Ada%20%2B%20Lovelace"
        );
        assert_eq!(
            search_url(ENGINES[0], "Ada + Lovelace"),
            "https://www.bing.com/search?q=Ada%20%2B%20Lovelace"
        );
    }

    /// A transport that records every request it is sent and answers each through `reply`.
    struct Recorder<F: Fn(&Request) -> Response> {
        sent: RefCell<Vec<Request>>,
        reply: F,
    }

    impl<F: Fn(&Request) -> Response> Transport for Recorder<F> {
        fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
            self.sent.borrow_mut().push(request.clone());
            Ok((self.reply)(request))
        }
    }

    fn recorder<F: Fn(&Request) -> Response>(reply: F) -> Recorder<F> {
        Recorder {
            sent: RefCell::new(Vec::new()),
            reply,
        }
    }

    #[test]
    fn adaptive_skips_blocked_providers_after_baseline_without_hiding_outcomes() {
        let fake = recorder(|request| {
            if request.url.starts_with("https://www.mojeek.com/search") {
                response(403, "Cloudflare Just a moment")
            } else {
                response(
                    200,
                    r#"<a href="https://example.org/adaptive-blocked-fixture">Hit</a>"#,
                )
            }
        });
        let report = adaptive_search(
            &fake,
            "unique-blocked-provider check",
            4321,
            EngineSet::Default,
        )
        .unwrap();
        assert_eq!(report.rounds.len(), 2);
        assert_eq!(report.rounds[0].outcomes.len(), ENGINES.len());
        assert_eq!(report.rounds[1].outcomes.len(), ENGINES.len());
        // Every engine in the baseline, then every engine but Mojeek.
        assert_eq!(fake.sent.borrow().len(), 2 * ENGINES.len() - 1);
        let refused = report.rounds[0]
            .outcomes
            .iter()
            .find(|outcome| outcome.module == "mojeek")
            .expect("mojeek baseline row");
        assert_eq!(refused.kind, SourceOutcomeKind::BotWaf);
        let suppressed = report.rounds[1]
            .outcomes
            .iter()
            .find(|outcome| outcome.module == "mojeek")
            .expect("mojeek must retain an outcome row");
        assert_eq!(suppressed.kind, SourceOutcomeKind::Inconclusive);
        assert_eq!(suppressed.detail.as_deref(), Some(BLOCKED_IN_BASELINE));
        assert!(!report.hits.is_empty());
    }

    #[test]
    fn exhaustive_registry_is_keyless_unique_and_has_thirteen_providers() {
        assert_eq!(EXTENDED_ENGINES.len(), 13);
        let mut names = BTreeSet::new();
        for engine in EXTENDED_ENGINES {
            assert!(
                names.insert(engine.name),
                "duplicate engine {}",
                engine.name
            );
            assert!(engine.base_url.starts_with("https://"));
            assert!(!engine.base_url.contains(['?', '#']));
        }
        for engine in ENGINES {
            assert!(names.contains(engine.name));
        }
        assert_eq!(search_parameter("yahoo"), "p");
        assert_eq!(search_parameter("yandex"), "text");
    }

    /// Three engines unless a caller opts in, and only the opt-in set shares a budget.
    #[test]
    fn the_default_set_is_the_original_three_without_a_shared_budget() {
        assert_eq!(EngineSet::default(), EngineSet::Default);
        assert_eq!(EngineSet::Default.engines(), ENGINES);
        assert_eq!(EngineSet::All.engines(), EXTENDED_ENGINES);
        assert!(EngineSet::Default.start_deadline(&SystemClock).is_none());
        let deadline = EngineSet::All
            .start_deadline(&SystemClock)
            .expect("all engines share one budget");
        assert_eq!(deadline.budget(), Duration::from_secs(EXTENDED_BUDGET_SECS));

        // The default search asks each default engine once, at the transport's own timeout.
        let fake =
            recorder(|_| response(200, r#"<a href="https://example.org/default-set">hit</a>"#));
        let report = search(&fake, "unique-default-set-query", 2100, EngineSet::Default).unwrap();
        let sent = fake.sent.borrow();
        assert_eq!(sent.len(), ENGINES.len());
        assert!(sent.iter().all(|request| request.timeout.is_none()));
        let engines: Vec<&str> = report
            .outcomes
            .iter()
            .map(|outcome| outcome.module.as_str())
            .collect();
        assert_eq!(engines, ["bing", "brave", "mojeek"]);
    }

    #[test]
    fn wrapped_search_results_decode_once_without_confusing_engine_navigation() {
        let html = r#"
            <a href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.org%2Fnews%3Fx%3D1%26y%3D2">A</a>
            <a href="/l/?uddg=javascript%3Aalert%281%29">not a URL</a>
            <a href="https://duckduckgo.com/?q=another">navigation</a>
        "#;
        let hits = parse_hits(html, "duckduckgo");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].url, "https://example.org/news?x=1&y=2");
        assert_eq!(
            parse_hits(
                r#"<a href="/url?q=https%3A%2F%2Fexample.net%2Farticle&amp;sa=U">x</a>"#,
                "google",
            )[0]
            .url,
            "https://example.net/article"
        );
        assert_eq!(parse_hits(
            r#"<a href="https://r.search.yahoo.com/_ylt=z/RU=https%3A%2F%2Fexample.com%2Fa/RK=1">x</a>"#,
            "yahoo",
        )[0].url, "https://example.com/a");
    }

    /// The wrapper unwrapping ends in the Bing click-redirect rule, on every engine's page:
    /// an `href` no other wrapper matched goes through `bing_click_target` before it is
    /// canonicalised, or the wrapper would be dropped as Bing chrome and the result lost.
    #[test]
    fn a_bing_click_redirect_is_unwrapped_after_the_other_wrappers_are_tried() {
        let target = "https://example.org/merged?a=1&b=2";
        let href = format!(
            "https://www.bing.com/ck/a?!&amp;&amp;p=ab&amp;u=a1{}&amp;ntb=1",
            crate::base64::url_unpadded(target.as_bytes())
        );
        for engine in ["bing", "duckduckgo", "google", "yahoo"] {
            assert_eq!(
                extract_result_url(&href, engine).as_deref(),
                Some(target),
                "{engine}"
            );
            let hits = parse_hits(&format!(r#"<a href="{href}">result</a>"#), engine);
            let urls: Vec<&str> = hits.iter().map(|hit| hit.url.as_str()).collect();
            assert_eq!(urls, [target], "{engine}");
        }
    }

    /// Another engine's domain is a result; only that engine's own page treats it as chrome,
    /// and the default engines' hosts stay chrome on every page.
    #[test]
    fn another_engines_domain_is_a_result_and_only_its_own_page_drops_it() {
        let html = concat!(
            "<a href=\"https://finance.yahoo.com/quote/ACME\">quote</a>",
            "<a href=\"https://support.google.com/answer/1\">help</a>",
            "<a href=\"https://www.bing.com/search?q=next\">chrome</a>",
        );
        let urls = |engine: &str| -> Vec<String> {
            parse_hits(html, engine)
                .into_iter()
                .map(|hit| hit.url)
                .collect()
        };
        assert_eq!(
            urls("bing"),
            [
                "https://finance.yahoo.com/quote/ACME",
                "https://support.google.com/answer/1",
            ]
        );
        assert_eq!(urls("yahoo"), ["https://support.google.com/answer/1"]);
        assert_eq!(urls("google"), ["https://finance.yahoo.com/quote/ACME"]);
    }

    /// Yahoo's live result page (checked 2026-11-05) links its own feedback forum on a
    /// third-party host; on Yahoo's page that link is chrome, on any other engine's a result.
    #[test]
    fn yahoos_feedback_forum_is_chrome_only_on_yahoos_page() {
        let html = concat!(
            "<a href=\"https://yahoo.uservoice.com/forums/193847-search\">feedback</a>",
            "<a href=\"https://en.wikipedia.org/wiki/Ada_Lovelace\">result</a>",
        );
        let urls = |engine: &str| -> Vec<String> {
            parse_hits(html, engine)
                .into_iter()
                .map(|hit| hit.url)
                .collect()
        };
        assert_eq!(
            urls("yahoo"),
            ["https://en.wikipedia.org/wiki/Ada_Lovelace"]
        );
        assert_eq!(urls("bing").len(), 2);
    }

    /// Engines whose result page a plain fetch sees only as the site's own chrome are not
    /// asked: their social, app-store and footer links would be reported as results.
    #[test]
    fn engines_whose_results_need_javascript_are_not_registered() {
        for absent in ["qwant", "swisscows", "marginalia"] {
            assert!(
                EXTENDED_ENGINES.iter().all(|engine| engine.name != absent),
                "{absent}"
            );
        }
    }

    #[test]
    fn expanded_search_uses_correct_parameters_and_isolates_failures() {
        let fake =
            recorder(|_| response(200, r#"<a href="https://example.org/article">Article</a>"#));
        let report = search(&fake, "test all engines", 2000, EngineSet::All).unwrap();
        assert_eq!(report.outcomes.len(), EXTENDED_ENGINES.len());
        assert_eq!(report.hits.len(), 1);
        let sent = fake.sent.borrow();
        assert_eq!(sent.len(), EXTENDED_ENGINES.len());
        let urls: Vec<&str> = sent.iter().map(|request| request.url.as_str()).collect();
        assert!(
            urls.iter()
                .any(|url| url.starts_with("https://search.yahoo.com/search?p="))
        );
        assert!(
            urls.iter()
                .any(|url| url.starts_with("https://yandex.com/search/?text="))
        );
        // Every opt-in request is capped by the shared budget, never above the request limit.
        assert!(sent.iter().all(|request| {
            request
                .timeout
                .is_some_and(|cap| cap <= Duration::from_secs(EXTENDED_REQUEST_SECS))
        }));
    }

    #[test]
    fn expired_shared_budget_skips_all_engines_with_typed_outcomes() {
        let clock = FakeClock::new();
        let deadline = Deadline::start(&clock, Duration::ZERO);
        let fake = Fake::new(vec![]);
        let round = Round {
            engines: &EXTENDED_ENGINES,
            deadline: Some(&deadline),
            skip: None,
        };
        let (report, observations) =
            search_with_observations(&fake, "unique-expired-budget-query", 100, round).unwrap();
        assert!(observations.is_empty());
        assert!(report.hits.is_empty());
        assert_eq!(report.outcomes.len(), EXTENDED_ENGINES.len());
        assert!(report.outcomes.iter().all(|outcome| {
            outcome.kind == SourceOutcomeKind::Inconclusive
                && outcome.detail.as_deref() == Some(BUDGET_SPENT)
        }));
    }

    /// One budget for the whole opt-in search: each request gets the request limit or what is
    /// left of the budget, whichever is less, and an engine the budget is spent before is not
    /// asked but keeps a typed row.
    #[test]
    fn the_shared_deadline_caps_each_request_and_skips_engines_after_it() {
        let clock = FakeClock::new();
        let deadline = Deadline::start(&clock, Duration::from_secs(EXTENDED_BUDGET_SECS));
        let fake = recorder(|_| {
            clock.advance(Duration::from_secs(27));
            response(
                200,
                r#"<a href="https://example.org/shared-deadline">hit</a>"#,
            )
        });
        let round = Round {
            engines: &EXTENDED_ENGINES,
            deadline: Some(&deadline),
            skip: None,
        };
        let (report, _) =
            search_with_observations(&fake, "unique-shared-deadline-query", 7000, round).unwrap();
        // Sent at 0, 27, 54, 81 and 108 seconds; the sixth engine would start at 135.
        let sent = fake.sent.borrow();
        assert_eq!(sent.len(), 5);
        for (request, limit) in sent.iter().zip([6, 6, 6, 6, 2]) {
            let limit = Duration::from_secs(limit);
            let cap = request.timeout.expect("every opt-in request is capped");
            assert!(
                limit
                    .checked_sub(cap)
                    .is_some_and(|slack| slack < Duration::from_secs(1)),
                "{cap:?} for a {limit:?} cap"
            );
        }
        assert_eq!(report.outcomes.len(), EXTENDED_ENGINES.len());
        assert!(
            report.outcomes[..5]
                .iter()
                .all(|outcome| outcome.kind == SourceOutcomeKind::Success)
        );
        assert!(report.outcomes[5..].iter().all(|outcome| {
            outcome.kind == SourceOutcomeKind::Inconclusive
                && outcome.detail.as_deref() == Some(BUDGET_SPENT)
        }));
    }

    /// The budget spans every adaptive round: once it is spent, a later round sends nothing
    /// and says why for each engine instead of starting a fresh budget.
    #[test]
    fn one_deadline_spans_every_adaptive_round() {
        let clock = FakeClock::new();
        let deadline = Deadline::start(&clock, Duration::from_secs(EXTENDED_BUDGET_SECS));
        let fake = recorder(|_| {
            clock.advance(Duration::from_secs(10));
            response(
                200,
                r#"<a href="https://example.org/adaptive-deadline">hit</a>"#,
            )
        });
        let report = adaptive_search_within(
            &fake,
            "unique-adaptive-deadline check",
            8000,
            &EXTENDED_ENGINES,
            Some(&deadline),
        )
        .unwrap();
        // Eleven requests start inside 110 seconds at ten seconds each; none after.
        assert_eq!(fake.sent.borrow().len(), 11);
        assert_eq!(report.rounds.len(), 2);
        let spent = |round: &AdaptiveRound| {
            round
                .outcomes
                .iter()
                .filter(|outcome| outcome.detail.as_deref() == Some(BUDGET_SPENT))
                .count()
        };
        assert_eq!(spent(&report.rounds[0]), 5);
        assert_eq!(spent(&report.rounds[1]), EXTENDED_ENGINES.len());
        assert_eq!(report.stop_reason, "refinement_sources_unavailable");
    }

    /// Inside the shared budget a retry is sent only when its pause leaves time to send it,
    /// and the pause is taken on the deadline's clock. An engine whose retry did not fit
    /// reports the failure it saw, not a request it never made.
    #[test]
    fn a_retry_pause_that_would_outlast_the_budget_is_not_taken() {
        let engine = EngineSpec {
            name: "retry_budget_test",
            base_url: "https://retry-budget-web-query.invalid/search",
        };
        let clock = FakeClock::new();
        // Less than the shortest retry pause (75 ms) is left.
        let tight = Deadline::start(&clock, Duration::from_millis(50));
        let fake = Fake::new(vec![Err(transport_failure(
            SourceOutcomeKind::ConnectFailure,
        ))]);
        let report =
            search_engine(&fake, engine, "retry-budget-unique", 300, Some(&tight)).unwrap();
        assert_eq!(report.outcome.kind, SourceOutcomeKind::ConnectFailure);
        assert_eq!(clock.elapsed(), Duration::ZERO);

        let roomy = Deadline::start(&clock, Duration::from_secs(EXTENDED_BUDGET_SECS));
        let fake = Fake::new(vec![
            Err(transport_failure(SourceOutcomeKind::ConnectFailure)),
            Ok(response(
                200,
                r#"<a href="https://example.org/after-pause">recovered</a>"#,
            )),
        ]);
        let report = search_engine(
            &fake,
            engine,
            "retry-budget-roomy-unique",
            301,
            Some(&roomy),
        )
        .unwrap();
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
        assert!(clock.elapsed() >= Duration::from_millis(75));
    }

    #[test]
    fn query_budget_and_canonicalization_are_enforced() {
        let valid = "A".repeat(MAX_SEARCH_QUERY_BYTES);
        assert_eq!(
            checked_query(&valid, "query").unwrap(),
            valid.to_ascii_lowercase()
        );
        let invalid = "A".repeat(MAX_SEARCH_QUERY_BYTES + 1);
        assert!(checked_query(&invalid, "query").is_err());
        assert_eq!(
            checked_query("  ADA   LOVELACE  ", "query").unwrap(),
            "ada lovelace"
        );
        assert!(checked_query("   ", "query").is_err());
        assert!(checked_query("ada\n", "query").is_err());
    }

    #[test]
    fn query_is_canonical_before_search_setup() {
        assert_eq!(canonical_whitespace("  Ada   Lovelace "), "ada lovelace");
    }
}
