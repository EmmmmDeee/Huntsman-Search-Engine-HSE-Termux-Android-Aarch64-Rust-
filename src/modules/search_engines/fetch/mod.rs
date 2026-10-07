use std::{
    collections::HashMap,
    sync::{Arc, LazyLock, Mutex},
    time::Instant,
};

use super::helpers::*;
use super::{EngineSpec, MAX_RESULTS_PER_ENGINE, SearchResult};
use crate::util::html::is_challenge_page;
use crate::util::key_harvest::identify_api_key;

/// Per-request fetch ceiling (ms): the most any single SERP request may take.
pub(in crate::modules::search_engines) const MAX_FETCH_MS: u64 = 8_000;

/// Floor below which there's no point starting a request — a sub-1.5 s SERP fetch
/// almost always fails, and starting one risks overrunning the module deadline.
pub(super) const MIN_FETCH_MS: u64 = 1_500;

/// A parsed zero is not automatically a valid zero. Search providers also
/// return marketing shells, consent pages and drifted markup as ordinary HTML.
/// Only an explicit provider statement of no matches earns `Empty`; every
/// other non-blocked zero is kept distinct as `Inconclusive`.
const EXPLICIT_ZERO_MARKERS: &[&str] = &[
    "no results found",
    "no results for",
    "no search results",
    "did not match any",
    "didn't match any",
    "we could not find any results",
    "we couldn't find any results",
];

/// Outcome of a complete engine request after parsing and the bounded alt-UA
/// retry. Keep transport failure, blocking, validated zero, inconclusive zero, and real
/// results distinct all the way into the scheduler. A generic HTML 200 with no
/// extracted rows is not proof of a healthy zero-result query.
#[derive(Clone)]
pub(super) enum SearchFetchResult {
    Results(Vec<SearchResult>),
    /// Provider explicitly confirmed that the query matched nothing.
    Empty,
    /// A substantial non-challenge response produced no parseable results and
    /// did not explicitly confirm a zero. The cause is unknown: parser/semantic
    /// drift, a soft block, or a genuine unmarked zero remain competing states.
    /// It is unusable for this request, but never healthy-zero evidence.
    Inconclusive,
    Blocked,
    Unreachable,
}

impl SearchFetchResult {
    pub(super) fn into_results(self) -> Option<Vec<SearchResult>> {
        match self {
            Self::Results(results) => Some(results),
            Self::Empty | Self::Inconclusive | Self::Blocked | Self::Unreachable => None,
        }
    }

    fn result_count(&self) -> usize {
        match self {
            Self::Results(results) => results.len(),
            Self::Empty | Self::Inconclusive | Self::Blocked | Self::Unreachable => 0,
        }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct FetchKey {
    scan_id: String,
    engine: &'static str,
    url: String,
    query: String,
    post_body: Option<String>,
}

type SharedFetch = Arc<tokio::sync::OnceCell<SearchFetchResult>>;

/// Scan-scoped singleflight registry. Multiple graph branches can ask the same
/// engine the same question concurrently; one request does the I/O and every
/// waiter receives the same parsed outcome. Entries are removed at the next
/// reset for that scan, so a long-lived `hse serve` process does not accumulate
/// old investigations.
static FETCH_SINGLEFLIGHT: LazyLock<Mutex<HashMap<FetchKey, SharedFetch>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub(super) fn reset_scan_singleflight(scan_id: &str) {
    let mut map = FETCH_SINGLEFLIGHT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    map.retain(|key, _| key.scan_id != scan_id);
}

/// The curl timeout for a request issued NOW under `deadline`: the budget that
/// remains, capped at [`MAX_FETCH_MS`]; `None` when too little remains
/// ([`MIN_FETCH_MS`]) to bother.
///
/// This is what keeps an in-flight request from overrunning the engine's hard kill
/// — the gap the per-loop deadline check alone left: a request STARTED just under
/// the deadline still ran its full FIXED 8 s timeout past it, and the kill then
/// dropped the future and every gathered result. Clamping the timeout to the
/// remaining budget guarantees the request finishes inside the deadline.
fn fetch_timeout_ms(deadline: Instant) -> Option<u64> {
    let remaining = deadline
        .saturating_duration_since(Instant::now())
        .as_millis() as u64;
    (remaining >= MIN_FETCH_MS).then(|| remaining.min(MAX_FETCH_MS))
}

fn explicit_zero_result_page(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    EXPLICIT_ZERO_MARKERS
        .iter()
        .any(|marker| lower.contains(marker))
}

fn classify_search_body(body: &str, engine: &'static str, query: &str) -> SearchFetchResult {
    scan_body_for_keys(body);
    let results = parse_results(body, engine, query);
    if !results.is_empty() {
        SearchFetchResult::Results(results)
    } else if explicit_zero_result_page(body) {
        SearchFetchResult::Empty
    } else {
        SearchFetchResult::Inconclusive
    }
}

fn outcome_label(result: &SearchFetchResult, retry: bool) -> &'static str {
    match (result, retry) {
        (SearchFetchResult::Results(_), false) => "ok",
        (SearchFetchResult::Results(_), true) => "ok_retry",
        (SearchFetchResult::Empty, false) => "empty",
        (SearchFetchResult::Empty, true) => "empty_retry",
        (SearchFetchResult::Inconclusive, false) => "inconclusive",
        (SearchFetchResult::Inconclusive, true) => "inconclusive_retry",
        (SearchFetchResult::Blocked, _) => "blocked",
        (SearchFetchResult::Unreachable, _) => "unreachable",
    }
}

async fn fetch_and_parse_uncached(
    url: &str,
    engine: &EngineSpec,
    query: &str,
    post_body: Option<&str>,
    deadline: Instant,
) -> SearchFetchResult {
    let started = Instant::now();
    let Some(timeout_ms) = fetch_timeout_ms(deadline) else {
        return SearchFetchResult::Unreachable;
    };
    let timeout_ms = engine
        .max_fetch_ms
        .map_or(timeout_ms, |cap| timeout_ms.min(cap));

    let first = match try_fetch(url, engine.ua, post_body, timeout_ms).await {
        FetchOutcome::Body(body) => classify_search_body(&body, engine.name, query),
        FetchOutcome::Unreachable => SearchFetchResult::Unreachable,
        FetchOutcome::Blocked => SearchFetchResult::Blocked,
    };
    let first_label = outcome_label(&first, false);

    // Preserve the first attempt's failure class when a bounded alternate-UA
    // retry also fails. A successful retry replaces that failure with its own
    // classified outcome: Results, validated Empty, or Inconclusive.
    let (result, outcome) = if !matches!(&first, SearchFetchResult::Results(_))
        && !matches!(&first, SearchFetchResult::Unreachable)
        && engine.ua != engine.ua_alt
        && let Some(retry_ms) = fetch_timeout_ms(deadline)
    {
        match try_fetch(url, engine.ua_alt, post_body, retry_ms).await {
            FetchOutcome::Body(body) => {
                let retry_result = classify_search_body(&body, engine.name, query);
                let retry_label = outcome_label(&retry_result, true);
                (retry_result, retry_label)
            }
            FetchOutcome::Blocked | FetchOutcome::Unreachable => (first, first_label),
        }
    } else {
        (first, first_label)
    };

    tracing::debug!(
        target: "huntsman::search",
        engine = engine.name,
        query,
        outcome,
        results = result.result_count(),
        latency_ms = started.elapsed().as_millis() as u64,
        "search request"
    );
    result
}

/// Fetch one engine request with scan-wide singleflight deduplication.
///
/// The exact engine+URL+query+POST-body tuple is the cache identity. Pagination therefore
/// stays distinct because each page has a different URL, while duplicate work
/// spawned by concurrent graph branches joins the same in-flight cell.
pub(super) async fn fetch_and_parse_classified(
    url: &str,
    engine: &EngineSpec,
    query: &str,
    post_body: Option<&str>,
    deadline: Instant,
) -> SearchFetchResult {
    // Do not create/cache a synthetic failure when there is not enough budget to
    // start a request. Another caller with a longer remaining deadline must still
    // be allowed to perform the I/O.
    if fetch_timeout_ms(deadline).is_none() {
        return SearchFetchResult::Unreachable;
    }

    let scan_id = crate::util::budget::current_scan();
    if scan_id.is_empty() {
        return fetch_and_parse_uncached(url, engine, query, post_body, deadline).await;
    }

    let key = FetchKey {
        scan_id,
        engine: engine.name,
        url: url.to_string(),
        query: query.to_string(),
        post_body: post_body.map(str::to_string),
    };
    let cell = {
        let mut map = FETCH_SINGLEFLIGHT
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Arc::clone(
            map.entry(key.clone())
                .or_insert_with(|| Arc::new(tokio::sync::OnceCell::new())),
        )
    };

    if let Some(cached) = cell.get() {
        tracing::debug!(
            target: "huntsman::search",
            engine = engine.name,
            query,
            results = cached.result_count(),
            "search request reused from scan singleflight"
        );
        return cached.clone();
    }

    let resolved = cell
        .get_or_init(|| fetch_and_parse_uncached(url, engine, query, post_body, deadline))
        .await
        .clone();

    // Coalesce concurrent failures, but do not memoize them for the whole scan:
    // a later sequential attempt may legitimately recover after a transient
    // network failure or anti-bot response. Successful empty/results are stable
    // enough to reuse for this scan.
    if matches!(
        &resolved,
        SearchFetchResult::Inconclusive | SearchFetchResult::Blocked | SearchFetchResult::Unreachable
    ) {
        let mut map = FETCH_SINGLEFLIGHT
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if map
            .get(&key)
            .is_some_and(|registered| Arc::ptr_eq(registered, &cell))
        {
            map.remove(&key);
        }
    }

    resolved
}

/// Compatibility wrapper for pivot/recycler call sites that only need rows.
pub(super) async fn fetch_and_parse(
    url: &str,
    engine: &EngineSpec,
    query: &str,
    post_body: Option<&str>,
    deadline: Instant,
) -> Option<Vec<SearchResult>> {
    fetch_and_parse_classified(url, engine, query, post_body, deadline)
        .await
        .into_results()
}

/// One engine fetch (page 0 only) as a FIXED, owned-param signature future — the
/// building block the secondary-pivot and recycler passes batch with
/// `buffer_unordered`. Free function (not an inline async closure) so the buffered
/// stream sees one concrete future type without tripping a higher-ranked-lifetime
/// bound. Self-clamps to `deadline` via [`fetch_and_parse`].
pub(super) async fn fetch_one_classified(
    engine: &'static EngineSpec,
    url: String,
    query: String,
    deadline: std::time::Instant,
) -> SearchFetchResult {
    fetch_and_parse_classified(&url, engine, &query, None, deadline).await
}

pub(super) async fn fetch_one(
    engine: &'static EngineSpec,
    url: String,
    query: String,
    deadline: std::time::Instant,
) -> Option<Vec<SearchResult>> {
    fetch_one_classified(engine, url, query, deadline)
        .await
        .into_results()
}

pub(super) async fn try_fetch(
    url: &str,
    ua: &str,
    post_body: Option<&str>,
    timeout_ms: u64,
) -> FetchOutcome {
    // `fetch_with_ua`/`fetch_post_with_ua` already route through `curl_exec`,
    // which tries the validated, health-ranked `crate::util::egress` proxy pool
    // (fed by HUNTSMAN_SEARCH_PROXY, correctly parsed as the comma-separated
    // list it's documented to be) with its own per-request failover BEFORE ever
    // considering a direct connection. There is deliberately no second ad hoc
    // proxy retry here: an earlier version reused this same `timeout_ms` for a
    // second full curl call (doubling one request's worst-case wall time past
    // the deadline this function exists to respect — see `fetch_timeout_ms`'s
    // doc comment) and handed the raw, possibly multi-entry env value straight
    // to curl's single-proxy `-x` flag. The pool already does this correctly.
    let body = if let Some(data) = post_body {
        crate::util::curl::fetch_post_with_ua(url, data, timeout_ms, ua).await
    } else {
        crate::util::curl::fetch_with_ua(url, timeout_ms, ua).await
    };

    let body = match body {
        Some(b) => b,
        None => return FetchOutcome::Unreachable,
    };
    // Detect a recognised anti-bot / block page BEFORE the short-body guard.
    // Some engines (Mojeek) answer with a small `403 … sending automated
    // queries` page well under 500 bytes; checking length first mislabels that
    // genuine *block* as `Unreachable` ("down"), telling the operator the
    // engine is network-dead when it's actually serving an anti-bot wall.
    // A short body matching NO block signature still falls through to
    // `Unreachable` below, so genuinely truncated/empty responses are unchanged.
    // Validated by a live 8-run sweep: mojeek returned HTTP 403 (332 bytes) in
    // 8/8 runs — reclassified down→blocked here.
    if is_challenge_page(&body) {
        return FetchOutcome::Blocked;
    }
    if body.len() < 500 {
        return FetchOutcome::Unreachable;
    }
    FetchOutcome::Body(body)
}

pub(super) fn parse_results(html: &str, engine: &'static str, query: &str) -> Vec<SearchResult> {
    let mut results = Vec::new();
    let mut seen_urls: HashSet<String> = HashSet::new();

    // Primary: extract from href= attributes (works for Yahoo/DDG/Brave)
    for href in HrefIter::new(html) {
        if results.len() >= MAX_RESULTS_PER_ENGINE {
            break;
        }
        let url = match resolve_href(href) {
            Some(u) if !u.is_empty() => u,
            _ => continue,
        };
        add_result(
            &url,
            html,
            href,
            engine,
            query,
            &mut seen_urls,
            &mut results,
        );
    }

    // Secondary: extract from <cite> tags (Bing puts display URLs here)
    for cite_url in CiteIter::new(html) {
        if results.len() >= MAX_RESULTS_PER_ENGINE {
            break;
        }
        let url = if cite_url.starts_with("http") {
            cite_url.to_string()
        } else {
            format!("https://{cite_url}")
        };
        add_result(
            &url,
            html,
            cite_url,
            engine,
            query,
            &mut seen_urls,
            &mut results,
        );
    }

    // Tertiary: extract from Google /url?q= redirect links
    for google_url in GoogleUrlIter::new(html) {
        if results.len() >= MAX_RESULTS_PER_ENGINE {
            break;
        }
        add_result(
            google_url,
            html,
            google_url,
            engine,
            query,
            &mut seen_urls,
            &mut results,
        );
    }

    results
}

/// Count *external* candidate result links in a page — `href`s that resolve to a
/// real host which is neither the engine's own chrome ([`is_engine_domain`]) nor
/// a tracking/redirect URL. This is the honest signal for liveness diagnosis: a
/// genuine results page carries many such links, whereas a nav/interstitial/soft-
/// block page carries mostly the engine's own links (which a naive `href="http"`
/// count would wrongly inflate, falsely blaming the parser). When this count is
/// high yet [`parse_results`] yields nothing, the parser really is at fault.
pub(super) fn external_link_count(html: &str, engine: &str) -> usize {
    let mut seen: HashSet<String> = HashSet::new();
    for href in HrefIter::new(html) {
        let Some(url) = resolve_href(href).filter(|u| !u.is_empty()) else {
            continue;
        };
        let host = extract_host(&url);
        if host.is_empty() || is_engine_domain(&host) || is_tracking_url(&url) {
            continue;
        }
        // Don't count the same external host twice — a results page links many
        // distinct hosts; chrome repeats a few.
        let _ = engine; // engine kept for signature symmetry / future per-engine rules
        seen.insert(host);
    }
    seen.len()
}

pub(super) fn add_result(
    url: &str,
    html: &str,
    anchor: &str,
    engine: &'static str,
    query: &str,
    seen: &mut HashSet<String>,
    results: &mut Vec<SearchResult>,
) {
    // Decode percent-encoded redirect targets (e.g. Google `/url?q=https%3A%2F%2F…`)
    // but leave an already-clean absolute URL untouched. Running a literal
    // `https://host/path?a=b&c=d` through `form_urlencoded` splits it on '&'/'='
    // and keeps only the first key — truncating the query string to `…/path?a`,
    // losing data and breaking "complete URLs". An encoded target has its scheme
    // percent-encoded (no literal `http(s)://`), so the prefix check distinguishes
    // the two cleanly; the encoded form has no literal '&'/'=' so the decode is
    // lossless there.
    let decoded;
    let url = if crate::util::url_util::is_absolute_http_url(url) {
        url
    } else {
        decoded = url::form_urlencoded::parse(url.as_bytes())
            .next()
            .map_or_else(|| url.to_string(), |(k, _)| k.into_owned());
        if decoded.starts_with("http") {
            &decoded
        } else {
            return;
        }
    };

    let host = extract_host(url);
    if host.is_empty() || is_engine_domain(&host) {
        return;
    }
    if is_tracking_url(url) {
        return;
    }
    // Deduplicate by domain+path (strip query/fragment for dedup only)
    let dedup_key = canonicalize_url(url);
    if !seen.insert(dedup_key) {
        return;
    }
    let title = {
        let t = extract_anchor_text(html, anchor, 200);
        if t.len() >= 4 {
            t
        } else {
            extract_surrounding_text(html, anchor, 200)
        }
    };
    let snippet = extract_snippet_near(html, anchor, 800);
    results.push(SearchResult {
        url: url.to_string(),
        title,
        snippet,
        engine,
        query: query.to_string(),
    });
}

/// Extracts URLs from `<cite>` tags (Bing's result format).
pub(super) struct CiteIter<'a> {
    remaining: &'a str,
}

impl<'a> CiteIter<'a> {
    pub(super) fn new(html: &'a str) -> Self {
        Self { remaining: html }
    }
}

impl<'a> Iterator for CiteIter<'a> {
    type Item = &'a str;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let start = self.remaining.find("<cite")?;
            self.remaining = &self.remaining[start..];
            let gt = self.remaining.find('>')?;
            self.remaining = &self.remaining[gt + 1..];
            let end = self.remaining.find("</cite>")?;
            let content = &self.remaining[..end];
            self.remaining = &self.remaining[end + 7..];
            // Bing cite format: "https://example.com › path › ..."
            // Extract the domain part before the first " ›"
            let clean = content.split(" ›").next().unwrap_or(content).trim();
            if clean.contains('.') && clean.len() > 4 && !clean.contains('<') {
                return Some(clean);
            }
        }
    }
}

/// Extracts URLs from Google's `/url?q=<encoded>&sa=` redirect pattern.
pub(super) struct GoogleUrlIter<'a> {
    remaining: &'a str,
}

impl<'a> GoogleUrlIter<'a> {
    pub(super) fn new(html: &'a str) -> Self {
        Self { remaining: html }
    }
}

impl<'a> Iterator for GoogleUrlIter<'a> {
    type Item = &'a str;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let idx = self.remaining.find("/url?q=")?;
            self.remaining = &self.remaining[idx + 7..];
            let end = self
                .remaining
                .find('&')
                .or_else(|| self.remaining.find('"'))?;
            let encoded = &self.remaining[..end];
            self.remaining = &self.remaining[end..];
            if encoded.starts_with("http") && !encoded.contains("google.") {
                return Some(encoded);
            }
        }
    }
}

fn scan_body_for_keys(body: &str) {
    let pool = crate::util::key_pool::global_pool();
    for word in body.split(|c: char| {
        c.is_whitespace() || c == '"' || c == '\'' || c == '`' || c == '>' || c == '<'
    }) {
        let trimmed = word.trim();
        if trimmed.len() >= 16
            && trimmed.len() <= 200
            && let Some((service, key_val)) = identify_api_key(trimmed)
        {
            let mut entry = crate::util::key_pool::KeyEntry::new(key_val);
            entry.status = crate::util::key_pool::KeyStatus::Untested;
            entry.notes = Some("Search engine result page".into());
            pool.add(service, entry);
        }
    }
}

// ---------------------------------------------------------------------------
// Tests — the SERP HTML extraction iterators were previously uncovered. These
// lock in their observed behaviour as a regression guard: engines change their
// result markup over time, and a silent break here drops results.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
