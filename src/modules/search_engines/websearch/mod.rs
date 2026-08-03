//! General-purpose web search: run a RAW free-text query across the same
//! keyless multi-engine scraper the OSINT dork passes use, and return ranked
//! web results (title, URL, snippet) instead of extracted OSINT entities.
//!
//! This is the plain-search path. It deliberately BYPASSES two OSINT-specific
//! stages the [`super::SearchEngines`] module runs:
//!
//!   * `queries::build_queries` — which wraps a target in `site:` / `intext:` /
//!     `filetype:` dorks. Here the query string is handed to each engine's
//!     `build_url` verbatim, so `hse query "buy panadeine forte online"`
//!     searches exactly that, the way a person typing it into a search box
//!     would.
//!   * `build::build_entities` — which turns SERP rows into OSINT entities.
//!     Here the rows ARE the answer: deduplicated by canonical URL and ranked
//!     by how many independent engines surfaced each one, then by the top-most
//!     position it reached.
//!
//! Everything else is reused, so every request inherits the SSRF-pinned curl
//! fetch, block/CAPTCHA detection, alt-UA retry, and the per-request timeout —
//! general search is no more aggressive on a Termux link than a normal scan.

use super::engines::ENGINES;
use super::fetch::fetch_one;
use super::helpers::{canonicalize_url, dedup_results, url_engine_counts};
use super::{SearchResult, engine_enabled, session_dead};
use futures::StreamExt;
use std::cmp::Reverse;
use std::collections::HashMap;
use std::time::Instant;

/// Bounded fan-out width across engines. Mirrors the OSINT pass's own
/// `ENGINE_CONCURRENCY` so a general query is no burstier than a scan.
const ENGINE_CONCURRENCY: usize = 6;

/// One deduplicated web result, owned so callers *outside* the
/// `search_engines` module tree (the `hse query` renderer) can read the
/// fields — the internal [`SearchResult`]'s fields are module-private.
#[derive(Debug, Clone)]
pub(crate) struct WebResult {
    /// Absolute, redirect-decoded result URL.
    pub url: String,
    /// Result title (anchor / surrounding text); may be empty.
    pub title: String,
    /// Snippet text near the result; may be empty.
    pub snippet: String,
    /// Number of DISTINCT engines that returned this (canonical) URL — the
    /// primary cross-engine corroboration signal used to rank results.
    pub engine_count: u32,
}

/// Run `query` as a plain web search across every enabled, live engine and
/// return results ranked by cross-engine corroboration, then by the top-most
/// position the URL reached in any engine, then by canonical URL (for a stable
/// order). Each request self-clamps to `deadline`; an engine that is blocked,
/// unreachable, or slower than the deadline simply contributes nothing.
///
/// Returns an empty vec when the query is blank or no engine produced a result.
pub(crate) async fn web_search(query: &str, deadline: Instant) -> Vec<WebResult> {
    let query = query.trim();
    if query.is_empty() {
        return Vec::new();
    }

    // One page-0 fetch per enabled, non-dead engine, driven by the RAW query —
    // no dork transformation. `fetch_one` applies each engine's own `build_url`
    // and inherits the SSRF pin, block detection, and per-request timeout.
    let jobs: Vec<_> = ENGINES
        .iter()
        .filter(|e| engine_enabled(e.name) && !session_dead(e.name))
        .map(|e| fetch_one(e, (e.build_url)(query), query.to_string(), deadline))
        .collect();

    let per_engine: Vec<Option<Vec<SearchResult>>> = futures::stream::iter(jobs)
        .buffer_unordered(ENGINE_CONCURRENCY)
        .collect()
        .await;

    // Flatten into one list while recording the best (top-most) position each
    // canonical URL reached on ANY engine's result page. Position is a weaker
    // relevance signal than corroboration, so it only breaks ties below.
    let mut best_pos: HashMap<String, usize> = HashMap::new();
    let mut all: Vec<SearchResult> = Vec::new();
    for list in per_engine.into_iter().flatten() {
        for (pos, r) in list.into_iter().enumerate() {
            best_pos
                .entry(canonicalize_url(&r.url))
                .and_modify(|p| *p = (*p).min(pos))
                .or_insert(pos);
            all.push(r);
        }
    }

    rank_results(all, &best_pos)
}

/// Deduplicate raw SERP rows by canonical URL and rank them: most independently
/// corroborated first, then best cross-engine position, then canonical URL for
/// determinism. Pure over its inputs, so the ranking is unit-testable without
/// touching the network.
fn rank_results(all: Vec<SearchResult>, best_pos: &HashMap<String, usize>) -> Vec<WebResult> {
    // Corroboration count must be taken BEFORE dedup collapses each URL to one
    // row — afterwards every URL would credit a single engine and always rank 1.
    let counts = url_engine_counts(&all);
    let deduped = dedup_results(all);

    let mut out: Vec<WebResult> = deduped
        .into_iter()
        .map(|r| {
            let engine_count = counts.get(&canonicalize_url(&r.url)).copied().unwrap_or(1);
            WebResult {
                url: r.url,
                title: r.title,
                snippet: r.snippet,
                engine_count,
            }
        })
        .collect();
    out.sort_by_cached_key(|r| {
        let key = canonicalize_url(&r.url);
        let pos = best_pos.get(&key).copied().unwrap_or(usize::MAX);
        (Reverse(r.engine_count), pos, r.url.clone())
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a raw SERP row. `SearchResult`'s fields are module-private, but
    /// this test lives inside the `search_engines` tree, so it can construct one.
    fn sr(engine: &'static str, url: &str, title: &str) -> SearchResult {
        SearchResult {
            url: url.to_string(),
            title: title.to_string(),
            snippet: String::new(),
            engine,
            query: "q".to_string(),
        }
    }

    #[test]
    fn ranks_by_cross_engine_corroboration() {
        // `/a` returned by two distinct engines, `/b` by one → `/a` ranks first
        // and reports engine_count 2; the duplicate `/a` row is collapsed.
        let ranked = rank_results(
            vec![
                sr("bing", "https://ex.com/a", "A"),
                sr("yahoo", "https://ex.com/a", "A"),
                sr("google", "https://ex.com/b", "B"),
            ],
            &HashMap::new(),
        );
        assert_eq!(ranked.len(), 2, "the duplicate /a row must dedup away");
        assert_eq!(ranked[0].url, "https://ex.com/a");
        assert_eq!(ranked[0].engine_count, 2);
        assert_eq!(ranked[1].url, "https://ex.com/b");
        assert_eq!(ranked[1].engine_count, 1);
    }

    #[test]
    fn same_engine_twice_counts_once() {
        // The SAME engine returning a URL twice (e.g. across pages) is not
        // corroboration — it must count as one.
        let ranked = rank_results(
            vec![
                sr("bing", "https://ex.com/a", "A"),
                sr("bing", "https://ex.com/a", "A"),
            ],
            &HashMap::new(),
        );
        assert_eq!(ranked.len(), 1);
        assert_eq!(ranked[0].engine_count, 1);
    }

    #[test]
    fn equal_corroboration_ranks_top_position_first() {
        // Both URLs appear on exactly one engine (count 1), but `/top` was the
        // engine's #1 result and `/low` its #10 → `/top` ranks first, even
        // though `l` < `t` alphabetically. Position beats the URL tie-break.
        let mut pos = HashMap::new();
        pos.insert("https://ex.com/top".to_string(), 0usize);
        pos.insert("https://ex.com/low".to_string(), 9usize);
        let ranked = rank_results(
            vec![
                sr("bing", "https://ex.com/low", "L"),
                sr("yahoo", "https://ex.com/top", "T"),
            ],
            &pos,
        );
        assert_eq!(ranked[0].url, "https://ex.com/top");
        assert_eq!(ranked[1].url, "https://ex.com/low");
    }

    #[test]
    fn ties_break_by_url_for_determinism() {
        // Equal corroboration AND equal position → canonical-URL ascending, so
        // output is stable regardless of the racy order engines complete in.
        let ranked = rank_results(
            vec![
                sr("bing", "https://ex.com/z", "Z"),
                sr("yahoo", "https://ex.com/a", "A"),
            ],
            &HashMap::new(),
        );
        assert_eq!(ranked[0].url, "https://ex.com/a");
        assert_eq!(ranked[1].url, "https://ex.com/z");
    }
}
