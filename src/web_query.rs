//! Minimal keyless web meta-search front-end.
//!
//! Restores a bounded subset of the legacy multi-engine scraper through the
//! shared fetch boundary. Each engine runs independently; one blocked or broken
//! provider never erases results from another.

use std::collections::BTreeSet;
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

    let mut hits = Vec::new();
    let mut outcomes = Vec::new();
    for engine in ENGINES {
        let result = search_engine(transport, engine, &query, now_unix)?;
        hits.extend(result.hits);
        outcomes.push(result.outcome);
    }
    dedupe_hits(&mut hits);
    Ok(SearchReport { hits, outcomes })
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

        if response_is_cacheable(&response) {
            RESPONSE_CACHE.put(
                url.clone(),
                CachedResponse {
                    response: response.clone(),
                    stored_at_unix: now_unix,
                },
            );
        }
        return Ok(parse_engine_response(engine, &response, now_unix));
    }
}

fn cached_response(url: &str, now_unix: u64) -> Option<Response> {
    let cached = RESPONSE_CACHE.get(url)?;
    // A clock rollback must not treat a future-dated entry as freshly observed.
    now_unix
        .checked_sub(cached.stored_at_unix)
        .is_some_and(|age| age <= CACHE_TTL_SECS)
        .then_some(cached.response)
}

fn response_is_cacheable(response: &Response) -> bool {
    if response.truncated || !(200..300).contains(&response.status) {
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
        && classify_fetch(response.status, &response.text()) == SourceOutcomeKind::Inconclusive
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
    // Preserve the provider's first-seen order: lexicographically sorting URLs
    // destroys result ranking and can promote a less relevant link above the first hit.
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
    let bytes = html.as_bytes();
    let mut out = Vec::new();
    let mut index = 0;
    while index + 5 < bytes.len() {
        let Some(rel) = find_ascii_case_insensitive(&bytes[index..], b"href") else {
            break;
        };
        let candidate = index + rel;
        // Only a standalone href attribute is a navigational link. A substring
        // in data-href, onclick, or another attribute is not a search result.
        if candidate > 0
            && !bytes[candidate - 1].is_ascii_whitespace()
            && bytes[candidate - 1] != b'<'
        {
            index = candidate + 4;
            continue;
        }
        index = candidate + 4;
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if bytes.get(index) != Some(&b'=') {
            continue;
        }
        index += 1;
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        let Some(&quote) = bytes.get(index) else {
            break;
        };
        if !matches!(quote, b'\'' | b'"') {
            continue;
        }
        index += 1;
        let start = index;
        while index < bytes.len() && bytes[index] != quote {
            index += 1;
        }
        if let Some(value) = html.get(start..index) {
            out.push(value);
        }
        index = index.saturating_add(1);
    }
    out
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

        assert!(!response_is_cacheable(&response_with_headers(
            200,
            &[("cache-control", "max-age=0")],
            r#"<a href="https://example.org/third">third</a>"#,
        )));
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
