//! `hse query "<text>"` — general web search, rendered as a table or JSON.
//!
//! Both sources ([`web_search`] for clearnet, [`crate::util::ahmia::search`] for
//! `--dark`) reduce to the same [`Report`], so there is exactly one renderer and
//! one place to change when the output changes. The user-facing description of
//! what the command does lives on the clap `Query` variant in `cli::command`;
//! the ranking rationale lives in the `websearch` module.

use crate::core::error::{Error, Result};
use crate::modules::search_engines::websearch::web_search;
use std::time::{Duration, Instant};

use super::truncate;

/// Default overall wall-clock ceiling, in seconds. Bounds the whole command:
/// on the clearnet path every engine request self-clamps to it, and on `--dark`
/// it caps the single Ahmia request. Only a safety wall — 17 engines at
/// concurrency 6 typically finish in a few seconds.
const DEFAULT_TIMEOUT_SECS: u64 = 20;

/// Column width the result title/snippet is truncated to before the URL is
/// printed on its own line.
const TITLE_WIDTH: usize = 96;

/// One rendered result row, borrowed from whichever source produced it so
/// rendering allocates nothing per row.
struct Row<'a> {
    url: &'a str,
    title: &'a str,
    snippet: &'a str,
    /// The query-matching phrase to print in quotes under the result (web search
    /// only; empty for the `--dark` path, which prints full snippets instead).
    key_phrase: &'a str,
    /// Cross-engine corroboration count. `None` for sources where the notion
    /// does not apply (Ahmia returns one index, not N independent engines) —
    /// which also suppresses the `[N×]` badge and the JSON `engines` key.
    ///
    /// Carries the engine NAMES, not just a count: "2×" says a result was
    /// corroborated but not by whom, so two independent indexes look identical
    /// to two mirrors of one upstream. The badge renders as `[bing+startpage]`.
    engines: Option<&'a [&'static str]>,
}

/// Everything the renderer needs, independent of which source produced it.
struct Report<'a> {
    query: &'a str,
    /// Attribution for the JSON `source` key; `None` for the multi-engine path.
    source: Option<&'a str>,
    heading: String,
    /// Fixed line printed under the heading (the `--dark` scope disclaimer).
    note: Option<&'a str>,
    empty: String,
    show_snippets: bool,
    rows: Vec<Row<'a>>,
}

pub(super) async fn cmd_query(
    query: String,
    limit: usize,
    dark: bool,
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

    // Resolve the output format BEFORE dispatching any request. Validating it
    // after the fetch (as this once did) meant a typo like `--output tabel` paid
    // for the full 17-engine fan-out — seconds of mobile data on a Termux link —
    // only to fail at the print step with nothing to show for it.
    let json = match output.as_str() {
        "json" => true,
        "table" => false,
        other => {
            return Err(Error::Other(format!(
                "unknown --output format {other:?} (expected `table` or `json`)"
            )));
        }
    };

    let secs = timeout.unwrap_or(DEFAULT_TIMEOUT_SECS).clamp(3, 60);

    if dark {
        let mut hits = crate::util::ahmia::search(q, secs * 1_000).await;
        cap(&mut hits, limit);
        return render(&dark_report(q, &hits), json);
    }

    let (mut results, coverage) = web_search(q, Instant::now() + Duration::from_secs(secs)).await;
    cap(&mut results, limit);
    render(&web_report(q, &results, &coverage), json)
}

/// Keep at most `limit` rows; `0` means unlimited. (`Vec::truncate` is already a
/// no-op when the vec is shorter, so no length check is needed.)
fn cap<T>(rows: &mut Vec<T>, limit: usize) {
    if limit > 0 {
        rows.truncate(limit);
    }
}

fn web_report<'a>(
    q: &'a str,
    results: &'a [crate::modules::search_engines::websearch::WebResult],
    coverage: &crate::modules::search_engines::websearch::SearchCoverage,
) -> Report<'a> {
    Report {
        query: q,
        source: None,
        // The coverage caveat rides on EVERY web search, not just the empty
        // one: a thin result set needs it as much as none at all, because
        // "2 results" from 2 of 17 engines and "2 results" from 17 of 17 are
        // completely different findings and used to print identically. It goes
        // on `heading`/`empty` (already owned) rather than `note`, which is a
        // borrowed literal for the `--dark` disclaimer.
        heading: match coverage.caveat() {
            Some(c) => format!(
                "Web search: {q:?} — {} result(s), ranked by cross-engine corroboration\n{c}",
                results.len()
            ),
            None => format!(
                "Web search: {q:?} — {} result(s) from all {} engines, ranked by \
                 cross-engine corroboration",
                results.len(),
                coverage.queried
            ),
        },
        note: None,
        empty: match coverage.caveat() {
            Some(c) => format!("No results for {q:?} — {c}"),
            None => format!("No results for {q:?} — every engine answered, none had a match."),
        },
        show_snippets: false,
        rows: results
            .iter()
            .map(|r| Row {
                url: &r.url,
                title: &r.title,
                snippet: &r.snippet,
                key_phrase: &r.key_phrase,
                engines: Some(&r.engines),
            })
            .collect(),
    }
}

/// `--dark`: dark-web exposure via Ahmia's clearnet-served onion index.
///
/// Reports hidden-service pages that MENTION the term. Nothing here fetches an
/// onion address — the finding is the mention, and following it up is a
/// deliberate human decision made outside HSE.
fn dark_report<'a>(q: &'a str, hits: &'a [crate::util::ahmia::AhmiaResult]) -> Report<'a> {
    Report {
        query: q,
        source: Some("ahmia.fi"),
        heading: format!(
            "Dark-web exposure: {q:?} — {} onion page(s) mentioning this term (source: ahmia.fi)",
            hits.len()
        ),
        note: Some("Addresses are reported as evidence of exposure; HSE does not fetch them."),
        empty: format!(
            "No dark-web mentions of {q:?} in Ahmia's index \
             (or Ahmia was unreachable within the time budget)."
        ),
        show_snippets: true,
        rows: hits
            .iter()
            .map(|h| Row {
                url: &h.onion_url,
                title: &h.title,
                snippet: &h.snippet,
                key_phrase: "",
                engines: None,
            })
            .collect(),
    }
}

fn render(rep: &Report<'_>, json: bool) -> Result<()> {
    if json {
        let items: Vec<_> = rep
            .rows
            .iter()
            .enumerate()
            .map(|(i, r)| {
                let mut o = serde_json::json!({
                    "rank": i + 1,
                    "title": r.title,
                    "url": r.url,
                    "snippet": r.snippet,
                });
                if !r.key_phrase.is_empty() {
                    o["key_phrase"] = serde_json::json!(r.key_phrase);
                }
                if let Some(names) = r.engines {
                    o["engines"] = serde_json::json!(names);
                    o["engine_count"] = serde_json::json!(names.len());
                }
                o
            })
            .collect();
        let mut body = serde_json::json!({
            "query": rep.query,
            "count": rep.rows.len(),
            "results": items,
        });
        if let Some(src) = rep.source {
            body["source"] = serde_json::json!(src);
        }
        let text =
            serde_json::to_string_pretty(&body).map_err(|e| Error::Other(format!("json: {e}")))?;
        println!("{text}");
        return Ok(());
    }

    if rep.rows.is_empty() {
        println!("{}", rep.empty);
        return Ok(());
    }
    println!("{}", rep.heading);
    if let Some(note) = rep.note {
        println!("{note}");
    }
    println!();
    for (i, r) in rep.rows.iter().enumerate() {
        let title = if r.title.trim().is_empty() {
            "(no title)"
        } else {
            r.title.trim()
        };
        match r.engines {
            // Name the engines rather than counting them: `[bing+startpage]`
            // is citable provenance, `[2×]` is not.
            Some(names) if !names.is_empty() => println!(
                "{:>3}. [{}] {}",
                i + 1,
                names.join("+"),
                truncate(title, TITLE_WIDTH)
            ),
            _ => println!("{:>3}. {}", i + 1, truncate(title, TITLE_WIDTH)),
        }
        println!("       {}", r.url);
        if !r.key_phrase.trim().is_empty() {
            // The query-matching phrase, quoted, so the reader sees WHY this result
            // matched without printing the whole snippet.
            println!("       “{}”", truncate(r.key_phrase.trim(), TITLE_WIDTH));
        }
        if rep.show_snippets && !r.snippet.trim().is_empty() {
            println!("       {}", truncate(r.snippet.trim(), TITLE_WIDTH));
        }
    }
    Ok(())
}
