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

use super::engines::{ENGINES, EngineSpec, reliable_engines};
use super::helpers::{canonicalize_url, dedup_results, url_engine_counts};
use super::{
    ENGINE_CONCURRENCY, SearchResult, engine_enabled, fetch_engine, order_engines_for_primary,
    proven_engine_names, record_empty, record_hit, session_dead,
};
use futures::StreamExt;
use std::collections::{BTreeSet, HashMap};
use std::time::Instant;

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

    // Order the live engines exactly as the OSINT primary pass does: proven-live
    // and reliable-core engines fill the bounded concurrency slots first. In raw
    // `ENGINES` declaration order the reliable engines sit late, never make the
    // first batch, and are the first cut when the deadline fires — the very
    // pathology `order_engines_for_primary` exists to prevent.
    let reliable: BTreeSet<&'static str> = reliable_engines().iter().map(|e| e.name).collect();
    let proven = proven_engine_names();
    let live: Vec<&'static EngineSpec> = ENGINES
        .iter()
        .filter(|e| engine_enabled(e.name) && !session_dead(e.name))
        .collect();

    // `fetch_engine` (not `fetch_one`) is the parent's full per-engine unit: it
    // fetches page 0 AND that engine's own pagination, and it honours `build_post`
    // so the POST-only engines (DuckDuckGo, Startpage) actually contribute. Each
    // request self-clamps to `deadline` and inherits the SSRF pin, block detection
    // and alt-UA retry. `qi = 0` marks this as the first (only) query, which is
    // what enables pagination and session-liveness accounting.
    let futs: Vec<_> = order_engines_for_primary(live, &proven, &reliable)
        .into_iter()
        .map(|engine| {
            let url = (engine.build_url)(query);
            let post_body = engine.build_post.map(|f| f(query));
            fetch_engine(engine, url, post_body, query.to_string(), 0, deadline)
        })
        .collect();

    let mut batch: Vec<(&'static str, Option<Vec<SearchResult>>)> = futures::stream::iter(futs)
        .buffer_unordered(ENGINE_CONCURRENCY)
        .collect()
        .await;
    // Completion order is racy; sort by engine name so the ranking input — and
    // therefore the printed output — never depends on which engine answered first.
    batch.sort_by(|a, b| a.0.cmp(b.0));

    // Feed the shared session-liveness map rather than only reading it: a general
    // query now contributes the same up/down evidence a scan does, so a blocked
    // engine is skipped for both and a recovered one is un-silenced for both.
    let mut per_engine: Vec<Vec<SearchResult>> = Vec::new();
    for (name, res) in batch {
        match res {
            Some(results) => {
                record_hit(name);
                per_engine.push(results);
            }
            None => record_empty(name),
        }
    }

    rank_results(per_engine)
}

/// Deduplicate SERP rows by canonical URL and rank them: most independently
/// corroborated first, then best cross-engine position, then canonical URL for
/// determinism.
///
/// Takes the per-engine lists rather than one flat vec because a result's
/// POSITION is only meaningful within its own engine's page — flattening first
/// would lose it. Deriving the position table here (instead of having the caller
/// build a parallel map) means the two can no longer disagree.
///
/// Pure over its input, so the ranking is unit-tested without touching the
/// network.
fn rank_results(per_engine: Vec<Vec<SearchResult>>) -> Vec<WebResult> {
    // Best (top-most) position each canonical URL reached on ANY engine. A weaker
    // relevance signal than corroboration, so it only breaks ties below.
    let mut best_pos: HashMap<String, usize> = HashMap::new();
    let mut all: Vec<SearchResult> = Vec::new();
    for list in per_engine {
        for (pos, r) in list.into_iter().enumerate() {
            let slot = best_pos.entry(canonicalize_url(&r.url)).or_insert(pos);
            *slot = (*slot).min(pos);
            all.push(r);
        }
    }

    // Corroboration count must be taken BEFORE dedup collapses each URL to one
    // row — afterwards every URL would credit a single engine and always rank 1.
    let counts = url_engine_counts(&all);

    // Canonicalize once per surviving row and carry the key through scoring and
    // sorting: it is the map key for both lookups AND the final tie-break, so
    // recomputing it per lookup (and again per comparison) would allocate the
    // same string several times over.
    let mut scored: Vec<(u32, usize, String, WebResult)> = dedup_results(all)
        .into_iter()
        .map(|r| {
            let key = canonicalize_url(&r.url);
            let engine_count = counts.get(&key).copied().unwrap_or(1);
            let pos = best_pos.get(&key).copied().unwrap_or(usize::MAX);
            (
                engine_count,
                pos,
                key,
                WebResult {
                    url: r.url,
                    title: r.title,
                    snippet: r.snippet,
                    engine_count,
                },
            )
        })
        .collect();

    scored.sort_by(|a, b| {
        b.0.cmp(&a.0) // corroboration: descending
            .then_with(|| a.1.cmp(&b.1)) // best position: ascending
            .then_with(|| a.2.cmp(&b.2)) // canonical URL: ascending, deterministic
    });
    scored.into_iter().map(|(_, _, _, r)| r).collect()
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
        let ranked = rank_results(vec![
            vec![sr("bing", "https://ex.com/a", "A")],
            vec![sr("yahoo", "https://ex.com/a", "A")],
            vec![sr("google", "https://ex.com/b", "B")],
        ]);
        assert_eq!(ranked.len(), 2, "the duplicate /a row must dedup away");
        assert_eq!(ranked[0].url, "https://ex.com/a");
        assert_eq!(ranked[0].engine_count, 2);
        assert_eq!(ranked[1].url, "https://ex.com/b");
        assert_eq!(ranked[1].engine_count, 1);
    }

    #[test]
    fn same_engine_twice_counts_once() {
        // The SAME engine returning a URL twice (e.g. across its own paginated
        // pages) is not corroboration — it must count as one.
        let ranked = rank_results(vec![vec![
            sr("bing", "https://ex.com/a", "A"),
            sr("bing", "https://ex.com/a", "A"),
        ]]);
        assert_eq!(ranked.len(), 1);
        assert_eq!(ranked[0].engine_count, 1);
    }

    #[test]
    fn equal_corroboration_ranks_top_position_first() {
        // Both URLs appear on exactly one engine (count 1), but `/top` was its
        // engine's FIRST result and `/low` sat tenth → `/top` ranks first even
        // though `l` < `t` alphabetically. Position beats the URL tie-break.
        let mut low_engine: Vec<SearchResult> = (0..9)
            .map(|i| sr("bing", &format!("https://ex.com/f{i}"), "F"))
            .collect();
        low_engine.push(sr("bing", "https://ex.com/low", "L"));
        let ranked = rank_results(vec![
            low_engine,
            vec![sr("yahoo", "https://ex.com/top", "T")],
        ]);
        let top = ranked.iter().position(|r| r.url == "https://ex.com/top");
        let low = ranked.iter().position(|r| r.url == "https://ex.com/low");
        assert!(
            top < low,
            "a #1 result must outrank a #10 result at equal corroboration: {ranked:?}"
        );
    }

    #[test]
    fn ties_break_by_url_for_determinism() {
        // Equal corroboration AND equal position (both first on their engine) →
        // canonical-URL ascending, so output is stable regardless of the racy
        // order engines complete in.
        let ranked = rank_results(vec![
            vec![sr("bing", "https://ex.com/z", "Z")],
            vec![sr("yahoo", "https://ex.com/a", "A")],
        ]);
        assert_eq!(ranked[0].url, "https://ex.com/a");
        assert_eq!(ranked[1].url, "https://ex.com/z");
    }
}
