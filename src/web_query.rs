//! Minimal keyless web meta-search front-end.
//!
//! Restores a bounded subset of the legacy multi-engine scraper through the
//! shared fetch boundary. Each engine runs independently; one blocked or broken
//! provider never erases results from another.

use std::collections::BTreeSet;

use serde::Serialize;

use crate::canonical::canonical_url;
use crate::error::Error;
use crate::fetch::{FetchOptions, fetch};
use crate::http::{Request, Transport, append_query_param};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind, classify_fetch};

const MAX_RESULTS_PER_ENGINE: usize = 20;

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
    let query = query.trim();
    if query.is_empty() {
        return Err(Error::Invalid("query must not be empty".into()));
    }

    let mut hits = Vec::new();
    let mut outcomes = Vec::new();
    for engine in ENGINES {
        let result = search_engine(transport, engine, query, now_unix)?;
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
    let fetched = fetch(
        transport,
        Request::get(url)
            .header("accept", "text/html,application/xhtml+xml")
            .header("user-agent", crate::http::DEFAULT_USER_AGENT),
        None,
        &FetchOptions::default(),
        engine.name,
        now_unix,
    )?;

    let Some(response) = fetched.response else {
        return Ok(EngineReport {
            hits: Vec::new(),
            outcome: fetched.outcome,
        });
    };

    if response.truncated {
        return Ok(EngineReport {
            hits: Vec::new(),
            outcome: outcome(
                engine.name,
                SourceOutcomeKind::ParserDrift,
                now_unix,
                Some(response.status),
                None,
                "truncated search response",
            ),
        });
    }

    let body = response.text();
    let classified = classify_fetch(response.status, &body);
    if classified != SourceOutcomeKind::Inconclusive {
        return Ok(EngineReport {
            hits: Vec::new(),
            outcome: outcome(
                engine.name,
                classified,
                now_unix,
                Some(response.status),
                None,
                "search provider did not return a parseable result page",
            ),
        });
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
    Ok(EngineReport { hits, outcome })
}

fn outcome(
    module: &str,
    kind: SourceOutcomeKind,
    now_unix: u64,
    status: Option<u16>,
    found: Option<usize>,
    detail: &str,
) -> SourceExecutionOutcome {
    SourceExecutionOutcome {
        module: module.into(),
        kind,
        observed_at_unix: now_unix,
        http_status: status,
        found,
        retry_after_secs: None,
        detail: Some(detail.into()),
    }
}

#[must_use]
pub fn parse_hits(html: &str, engine: &str) -> Vec<SearchHit> {
    let mut urls = BTreeSet::new();
    for href in href_values(html) {
        let decoded = decode_minimal_html_entities(href);
        let Some(url) = canonical_url(&decoded) else {
            continue;
        };
        if is_engine_or_navigation_url(&url) {
            continue;
        }
        urls.insert(url);
        if urls.len() >= MAX_RESULTS_PER_ENGINE {
            break;
        }
    }
    urls.into_iter()
        .map(|url| SearchHit {
            engine: engine.into(),
            url,
        })
        .collect()
}

fn href_values(html: &str) -> Vec<&str> {
    let bytes = html.as_bytes();
    let mut out = Vec::new();
    let mut index = 0;
    while index + 5 < bytes.len() {
        let Some(rel) = find_ascii_case_insensitive(&bytes[index..], b"href") else {
            break;
        };
        index += rel + 4;
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

    fn response(status: u16, body: &str) -> Result<Response, TransportFailure> {
        Ok(Response {
            status,
            headers: vec![("content-type".into(), "text/html".into())],
            body: body.as_bytes().to_vec(),
            truncated: false,
        })
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
    fn multi_engine_search_isolates_zero_yield_and_keeps_other_hits() {
        let fake = Fake::new(vec![
            response(200, r#"<a href="https://example.org/a">A</a>"#),
            response(200, "<html><body>no links</body></html>"),
            response(200, r#"<a href="https://example.net/b">B</a>"#),
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
            response(200, body),
            response(200, body),
            response(200, body),
        ]);
        let report = search(&fake, "alice", 1).unwrap();
        assert_eq!(report.hits.len(), 1);
    }

    #[test]
    fn challenge_page_remains_a_typed_provider_outcome() {
        let challenge = "<html><title>Just a moment</title>Cloudflare</html>";
        let fake = Fake::new(vec![
            response(403, challenge),
            response(200, r#"<a href="https://example.org/a">A</a>"#),
            response(200, r#"<a href="https://example.net/b">B</a>"#),
        ]);
        let report = search(&fake, "alice", 1).unwrap();
        assert_eq!(report.outcomes[0].kind, SourceOutcomeKind::BotWaf);
        assert_eq!(report.hits.len(), 2);
    }
}
