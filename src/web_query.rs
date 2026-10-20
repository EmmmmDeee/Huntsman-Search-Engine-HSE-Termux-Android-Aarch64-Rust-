//! Minimal keyless web meta-search front-end.
//!
//! Restores a bounded subset of the legacy multi-engine scraper through the
//! shared fetch boundary. Each engine runs independently; one blocked or broken
//! provider never erases results from another.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::thread;

use serde::Serialize;

use crate::canonical::{canonical_url, canonical_whitespace};
use crate::circuit::{BackoffPolicy, ResponseCache};
use crate::error::Error;
use crate::fetch::{FetchOptions, fetch};
use crate::http::{Request, Response, Transport, append_query_param};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind, classify_fetch};
use crate::textnorm::escape_controls;

const MAX_RESULTS_PER_ENGINE: usize = 20;
const MAX_ADAPTIVE_QUERY_BYTES: usize = 512;
const CACHE_TTL_SECS: u64 = 300;
const CACHE_CAPACITY: usize = 256;
const RETRY_POLICY: BackoffPolicy = BackoffPolicy::new(2, 100, 500, true);

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
            let kind = serde_json::to_value(outcome.kind)
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned))
                .unwrap_or_else(|| "unknown".into());
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

/// Query the rebuilt keyless engine subset.
///
/// # Errors
/// Returns only network-boundary errors that prevent a request from being sent.
/// Provider-specific transport failures and block pages remain typed outcomes.
pub fn search<T: Transport + ?Sized>(
    transport: &T,
    query: &str,
    now_unix: u64,
) -> Result<SearchReport, Error> {
    let query = canonical_whitespace(query);
    if query.is_empty() {
        return Err(Error::Invalid("query must not be empty".into()));
    }

    let (report, _) = search_with_observations(transport, &query, now_unix)?;
    Ok(report)
}

/// Keep every engine's URL observation before compatibility-preserving deduplication.
/// An engine discovery is a lead, not independent corroboration of the page's claims.
fn search_with_observations<T: Transport + ?Sized>(
    transport: &T,
    query: &str,
    now_unix: u64,
) -> Result<(SearchReport, Vec<SearchHit>), Error> {
    let mut hits = Vec::new();
    let mut outcomes = Vec::new();
    for engine in ENGINES {
        let result = search_engine(transport, engine, &query, now_unix)?;
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
    reports: &mut Vec<AdaptiveRound>,
    seen: &mut BTreeMap<String, HitObservation>,
) -> Result<usize, Error> {
    let (report, observations) = search_with_observations(transport, query, now_unix)?;
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
/// Each of at most three rounds asks at most three guarded search engines.
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
) -> Result<AdaptiveSearchReport, Error> {
    if input.len() > MAX_ADAPTIVE_QUERY_BYTES
        || input.chars().any(char::is_control)
    {
        return Err(Error::Invalid("adaptive query is too long or contains control characters".into()));
    }
    let seed = canonical_whitespace(input);
    if seed.is_empty() {
        return Err(Error::Invalid("adaptive query must not be empty".into()));
    }
    let mut rounds = Vec::new();
    let mut seen = BTreeMap::new();
    let initial_novel = append_round(
        transport, &seed, "baseline", now_unix, &mut rounds, &mut seen,
    )?;

    let stop_reason = if !has_viable_provider(&rounds[0]) {
        "all_engines_unavailable_or_unparseable"
    } else {
        let second = if seed.starts_with('"') && seed.ends_with('"') && seed.len() > 2 {
            let bare = seed.trim_matches('"').trim();
            (bare != seed).then(|| (bare.to_owned(), "unquoted_recall"))
        } else if seed.split_whitespace().count() > 1 {
            Some((format!("\"{seed}\""), "exact_phrase"))
        } else {
            None
        };
        if let Some((refined, strategy)) = second {
            let novelty = append_round(
                transport, &refined, strategy, now_unix, &mut rounds, &mut seen,
            )?;
            let tokens: Vec<&str> = seed.split_whitespace().collect();
            if !has_viable_provider(&rounds[1]) {
                "refinement_sources_unavailable"
            } else if novelty == 0 && initial_novel > 0 {
                "diminishing_marginal_discovery"
            } else if tokens.len() >= 3 && !seed.contains('"') {
                let broader = tokens[..tokens.len() - 1].join(" ");
                let _ = append_round(
                    transport,
                    &broader,
                    "broader_low_confidence_recall",
                    now_unix,
                    &mut rounds,
                    &mut seen,
                )?;
                "bounded_three_round_budget"
            } else {
                "no_safe_additional_query_variant"
            }
        } else {
            "no_safe_additional_query_variant"
        }
    };
    let hits = seen
        .into_iter()
        .map(|(url, observation)| AdaptiveHit {
            url,
            discovered_by_engines: observation.engines.into_iter().collect(),
            found_in_queries: observation.queries.into_iter().collect(),
            appearances: observation.appearances,
            evidence_status: "search_discovery_only_not_independent_fact_verification",
        })
        .collect();
    Ok(AdaptiveSearchReport {
        input: seed,
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
    })
}

struct EngineReport {
    hits: Vec<SearchHit>,
    outcome: SourceExecutionOutcome,
}

fn search_engine<T: Transport + ?Sized>(
    transport: &T,
    engine: EngineSpec,
    query: &str,
    now_unix: u64,
) -> Result<EngineReport, Error> {
    let url = append_query_param(engine.base_url, "q", query);
    if let Some(cached) = cached_response(&url, now_unix) {
        return Ok(parse_engine_response(engine, &cached, now_unix));
    }

    let request = Request::get(&url)
        .header("accept", "text/html,application/xhtml+xml")
        .header("user-agent", crate::http::DEFAULT_USER_AGENT);
    let mut attempt = 0u32;

    loop {
        // The shared boundary paces per host: it suppresses while the circuit is
        // open and records the outcome's health. A suppressed fetch comes back as a
        // no-response `Inconclusive`, which is not retryable and falls through below.
        let fetched = fetch(
            transport,
            request.clone(),
            None,
            &FetchOptions::default().paced(),
            engine.name,
            now_unix,
        )?;

        if retryable_fetch(fetched.outcome.kind) && RETRY_POLICY.should_retry(attempt) {
            thread::sleep(RETRY_POLICY.delay(attempt));
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
    if response.truncated
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
    !cache_control
        .split(',')
        .map(str::trim)
        .any(|directive| matches!(directive, "no-store" | "no-cache" | "max-age=0"))
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
        let decoded = decode_minimal_html_entities(href);
        let Some(url) = canonical_url(&decoded) else {
            continue;
        };
        if is_engine_or_navigation_url(&url) {
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
                let Some(skip) = find_ascii_case_insensitive(&bytes[end + 1..], closer) else {
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

fn find_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|window| {
        window
            .iter()
            .zip(needle.iter())
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
    })
}

fn decode_minimal_html_entities(raw: &str) -> String {
    raw.replace("&amp;", "&")
        .replace("&#38;", "&")
        .replace("&#x26;", "&")
}

fn is_engine_or_navigation_url(url: &str) -> bool {
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
    ENGINE_HOSTS.iter().any(|known| {
        host == *known
            || host
                .strip_suffix(known)
                .is_some_and(|prefix| prefix.ends_with('.'))
    })
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
        let report = search(&fake, "alice citizen", 1).unwrap();
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
        let first = search_engine(&fake, engine, "rare-needle-unique", 300).unwrap();
        assert_eq!(first.outcome.kind, SourceOutcomeKind::ZeroYieldAnomaly);
        assert!(first.hits.is_empty());

        // Within the TTL: if the first page were cached, this call would
        // incorrectly return zero hits and leave the second fixture unused.
        let second = search_engine(&fake, engine, "rare-needle-unique", 301).unwrap();
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
        let first = search_engine(&fake, engine, "navigation-only-unique", 400).unwrap();
        assert_eq!(first.outcome.kind, SourceOutcomeKind::ZeroYieldAnomaly);
        let second = search_engine(&fake, engine, "navigation-only-unique", 401).unwrap();
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
        let report = search(&fake, "alice duplicate-url-dedupe", 1).unwrap();
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
        let report = adaptive_search(&fake, "unique-adaptive-trial alpha", 123).unwrap();
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
            Ok(empty.clone()), Ok(empty.clone()), Ok(empty.clone()),
            Ok(empty.clone()), Ok(empty.clone()), Ok(empty.clone()),
            Ok(response(200, r#"<a href="https://example.org/recovered">found</a>"#)),
            Ok(empty.clone()), Ok(empty),
        ]);
        let report = adaptive_search(&fake, "needle rare threeword", 456).unwrap();
        assert_eq!(report.rounds.len(), 3);
        assert_eq!(report.rounds[2].strategy, "broader_low_confidence_recall");
        assert_eq!(report.rounds[2].query, "needle rare");
        assert_eq!(report.rounds[2].novel_url_count, 1);
        assert_eq!(report.hits.len(), 1);
        assert_eq!(report.stop_reason, "bounded_three_round_budget");
        assert!(report.rounds[0]
            .outcomes
            .iter()
            .all(|outcome| outcome.kind == SourceOutcomeKind::ZeroYieldAnomaly));
    }

    #[test]
    fn adaptive_search_refuses_unavailable_sources_and_invalid_queries() {
        let fake = Fake::new(vec![
            Ok(response(403, "<html>Cloudflare Just a moment</html>")),
            Ok(response(403, "<html>Cloudflare Just a moment</html>")),
            Ok(response(403, "<html>Cloudflare Just a moment</html>")),
        ]);
        let report = adaptive_search(&fake, "unique-provider-block alpha", 789).unwrap();
        assert_eq!(report.rounds.len(), 1);
        assert!(report.hits.is_empty());
        assert_eq!(report.stop_reason, "all_engines_unavailable_or_unparseable");

        assert!(adaptive_search(&Fake::new(vec![]), "   ", 790).is_err());
        assert!(adaptive_search(&Fake::new(vec![]), "bad\\nquery", 790).is_err());
        assert!(adaptive_search(&Fake::new(vec![]), &"a".repeat(513), 790).is_err());
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

        let first = search_engine(&fake, engine, "cache-key-unique", 100).unwrap();
        let second = search_engine(&fake, engine, "cache-key-unique", 101).unwrap();

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

        let first = search_engine(&fake, engine, "ttl-key-unique", 100).unwrap();
        let second =
            search_engine(&fake, engine, "ttl-key-unique", 100 + CACHE_TTL_SECS + 1).unwrap();

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

        let first = search_engine(&fake, engine, "no-store-key-unique", 200).unwrap();
        let second = search_engine(&fake, engine, "no-store-key-unique", 201).unwrap();

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

        let first = search_engine(&fake, engine, "no-cache-unique-query", 500).unwrap();
        let second = search_engine(&fake, engine, "no-cache-unique-query", 501).unwrap();
        assert_eq!(first.hits[0].url, "https://example.org/first");
        assert_eq!(second.hits[0].url, "https://example.org/second");

        let response = response_with_headers(
            200,
            &[("cache-control", "max-age=0")],
            r#"<a href="https://example.org/third">third</a>"#,
        );
        let report = parse_engine_response(engine, &response, 502);
        assert!(!response_is_cacheable(&response, &report));
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

        let first = search_engine(&fake, engine, "clock-rollback-unique-query", 900).unwrap();
        let second = search_engine(&fake, engine, "clock-rollback-unique-query", 899).unwrap();
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

        let report = search_engine(&fake, engine, "retry-key-unique", 300).unwrap();

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

        let report = search_engine(&fake, engine, "circuit-key-unique", 401).unwrap();

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
        let report = search(&fake, "alice challenge-page", 1).unwrap();
        assert_eq!(report.outcomes[0].kind, SourceOutcomeKind::BotWaf);
        assert_eq!(report.hits.len(), 2);
    }
    #[test]
    fn query_is_canonical_before_search_setup() {
        assert_eq!(canonical_whitespace("  Ada   Lovelace "), "ada lovelace");
    }
}
