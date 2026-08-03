//! `hse query "<text>"` — general web search.
//!
//! Runs a plain, everyday free-text query across HSE's keyless multi-engine
//! scraper and prints ranked web results. Unlike `hse search`, which classifies
//! a seed into an OSINT target kind and wraps it in `site:`/`intext:` dorks,
//! `query` searches the text verbatim and returns the raw web results,
//! deduplicated across engines and ranked by how many independent engines
//! surfaced each URL.

use crate::core::error::{Error, Result};
use crate::modules::search_engines::websearch::{WebResult, web_search};
use std::time::{Duration, Instant};

use super::truncate;

/// Default overall wall-clock ceiling, in seconds. Each engine request
/// self-clamps to this deadline (and to its own per-request cap), so a blocked
/// or slow engine can never push the command past it. 17 engines at concurrency
/// 6 typically finish in a few seconds; this is only the safety wall.
const DEFAULT_TIMEOUT_SECS: u64 = 20;

/// Column width the result title is truncated to before the URL is printed on
/// its own line.
const TITLE_WIDTH: usize = 96;

pub(super) async fn cmd_query(
    query: String,
    limit: usize,
    timeout: Option<u64>,
    output: String,
) -> Result<()> {
    let q = query.trim();
    if q.is_empty() {
        return Err(Error::InvalidTarget(
            "query text is empty — pass something to search, \
             e.g. `hse query \"buy panadeine forte online\"`"
                .to_string(),
        ));
    }

    let secs = timeout.unwrap_or(DEFAULT_TIMEOUT_SECS).clamp(3, 60);
    let deadline = Instant::now() + Duration::from_secs(secs);

    let mut results = web_search(q, deadline).await;
    if limit > 0 && results.len() > limit {
        results.truncate(limit);
    }

    match output.as_str() {
        "json" => print_json(q, &results),
        "table" => {
            print_table(q, &results);
            Ok(())
        }
        other => Err(Error::Other(format!(
            "unknown --output format {other:?} (expected `table` or `json`)"
        ))),
    }
}

fn print_json(query: &str, results: &[WebResult]) -> Result<()> {
    let items: Vec<_> = results
        .iter()
        .enumerate()
        .map(|(i, r)| {
            serde_json::json!({
                "rank": i + 1,
                "engines": r.engine_count,
                "title": r.title,
                "url": r.url,
                "snippet": r.snippet,
            })
        })
        .collect();
    let body = serde_json::to_string_pretty(&serde_json::json!({
        "query": query,
        "count": results.len(),
        "results": items,
    }))
    .map_err(|e| Error::Other(format!("json: {e}")))?;
    println!("{body}");
    Ok(())
}

fn print_table(query: &str, results: &[WebResult]) {
    if results.is_empty() {
        println!(
            "No results for {query:?} — every engine was blocked, unreachable, \
             or returned nothing within the time budget."
        );
        return;
    }

    println!(
        "Web search: {query:?} — {} result(s), ranked by cross-engine corroboration",
        results.len()
    );
    println!();
    for (i, r) in results.iter().enumerate() {
        let title = if r.title.trim().is_empty() {
            "(no title)"
        } else {
            r.title.trim()
        };
        // `[N×]` = N independent engines returned this URL.
        println!(
            "{:>3}. [{}×] {}",
            i + 1,
            r.engine_count,
            truncate(title, TITLE_WIDTH)
        );
        println!("       {}", r.url);
    }
}
