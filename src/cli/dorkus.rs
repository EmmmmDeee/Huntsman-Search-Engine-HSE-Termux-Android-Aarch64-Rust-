//! `hse dorkus` — DoRkUS, the meta search engine.
//!
//! A single meta-search surface over the two search back-ends HSE already runs
//! and verifies: the clearnet multi-engine fan-out
//! ([`crate::modules::search_engines::websearch`], ~17 engines with
//! cross-engine corroboration) and the dark-web exposure index
//! ([`crate::util::ahmia`], Ahmia's clearnet-served view of Tor hidden
//! services). `hse query` reaches each of those one at a time (`--dark` picks
//! the onion index *instead of* the clearnet engines); DoRkUS runs **both at
//! once**, concurrently within one time budget, and presents one aggregated,
//! source-attributed report.
//!
//! It is a composition layer, not a new provider: it introduces no new endpoint
//! or API contract, and inherits every guarantee of the layers it calls — the
//! clearnet fan-out's soft-block/consent-wall handling and cross-engine
//! corroboration count, and Ahmia's defensive scope (it reports WHERE a target
//! is mentioned and never fetches an onion service). The query string is passed
//! through verbatim, so search-operator "dorks" (`site:`, `intitle:`,
//! `inurl:`, quoted phrases) work exactly as the underlying engines support
//! them.

use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::core::error::{Error, Result};
use crate::modules::search_engines::websearch::{WebResult, web_search};
use crate::util::ahmia::{AhmiaResult, search as ahmia_search};

use super::truncate;

/// Default overall time budget when `--timeout` is not given. Matches
/// `hse query`'s default so the two surfaces feel the same.
const DEFAULT_TIMEOUT_SECS: u64 = 25;

/// Column width for a printed title/URL line — the same budget `hse query`'s
/// renderer uses, so DoRkUS output lines up with it.
const TITLE_WIDTH: usize = 96;

/// Which back-ends a DoRkUS run queries. Default is [`Both`](Scope::Both) — the
/// whole point of the command; the single-surface variants exist so an operator
/// can scope a run down without falling back to `hse query`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Scope {
    /// Clearnet multi-engine search and dark-web exposure, concurrently.
    Both,
    /// Clearnet multi-engine search only.
    ClearnetOnly,
    /// Dark-web (Ahmia) exposure only.
    DarkOnly,
}

impl Scope {
    fn from_flags(clearnet_only: bool, dark_only: bool) -> Result<Self> {
        match (clearnet_only, dark_only) {
            (true, true) => Err(Error::Other(
                "--clearnet-only and --dark-only are mutually exclusive".into(),
            )),
            (true, false) => Ok(Self::ClearnetOnly),
            (false, true) => Ok(Self::DarkOnly),
            (false, false) => Ok(Self::Both),
        }
    }

    fn wants_clearnet(self) -> bool {
        matches!(self, Self::Both | Self::ClearnetOnly)
    }

    fn wants_dark(self) -> bool {
        matches!(self, Self::Both | Self::DarkOnly)
    }
}

pub(super) async fn cmd_dorkus(
    query: String,
    limit: usize,
    timeout: Option<u64>,
    output: String,
    clearnet_only: bool,
    dark_only: bool,
) -> Result<()> {
    let q = query.trim();
    if q.is_empty() {
        return Err(Error::InvalidTarget(
            "dorkus query is empty — pass something to search, e.g. \
             `hse dorkus \"acme.example\"` or a dork like \
             `hse dorkus 'site:pastebin.com acme'`"
                .to_string(),
        ));
    }

    // Resolve the output format BEFORE any network work, exactly as `hse query`
    // does — a typo like `--output tabel` must fail immediately, not after a
    // full multi-engine + dark-web fan-out has spent the time budget.
    let json = match output.as_str() {
        "json" => true,
        "table" => false,
        other => {
            return Err(Error::Other(format!(
                "unknown --output format {other:?} (expected `table` or `json`)"
            )));
        }
    };

    let scope = Scope::from_flags(clearnet_only, dark_only)?;
    let secs = timeout.unwrap_or(DEFAULT_TIMEOUT_SECS).clamp(3, 60);

    // Run both back-ends CONCURRENTLY so the wall-clock cost of the meta-search
    // is the slower of the two, not their sum — the whole budget covers the
    // whole command. Each back-end still self-bounds to `secs`.
    let deadline = Instant::now() + Duration::from_secs(secs);
    let clearnet_fut = async {
        if scope.wants_clearnet() {
            web_search(q, deadline).await
        } else {
            Vec::new()
        }
    };
    let dark_fut = async {
        if scope.wants_dark() {
            ahmia_search(q, secs * 1_000).await
        } else {
            Vec::new()
        }
    };
    let (mut web, mut dark) = tokio::join!(clearnet_fut, dark_fut);
    cap(&mut web, limit);
    cap(&mut dark, limit);

    if json {
        let text = serde_json::to_string_pretty(&dorkus_json(q, scope, &web, &dark))
            .map_err(|e| Error::Other(format!("json: {e}")))?;
        println!("{text}");
    } else {
        print!("{}", dorkus_table(q, scope, &web, &dark));
    }
    Ok(())
}

/// Keep at most `limit` rows; `0` means unlimited. (`Vec::truncate` is a no-op
/// when the vec is already shorter.)
fn cap<T>(rows: &mut Vec<T>, limit: usize) {
    if limit > 0 {
        rows.truncate(limit);
    }
}

/// Build the DoRkUS JSON report. **Pure** (no I/O) so the aggregated shape is
/// unit-tested directly. Always carries both `clearnet` and `dark_web` arrays
/// (empty when a surface was not queried or found nothing) plus the `scope`, so
/// a consumer can tell "queried and empty" from "not queried".
fn dorkus_json(query: &str, scope: Scope, web: &[WebResult], dark: &[AhmiaResult]) -> Value {
    let clearnet: Vec<Value> = web
        .iter()
        .enumerate()
        .map(|(i, r)| {
            json!({
                "rank": i + 1,
                "title": r.title,
                "url": r.url,
                "snippet": r.snippet,
                "engines": r.engine_count,
            })
        })
        .collect();
    let dark_web: Vec<Value> = dark
        .iter()
        .enumerate()
        .map(|(i, h)| {
            json!({
                "rank": i + 1,
                "title": h.title,
                "onion_url": h.onion_url,
                "snippet": h.snippet,
            })
        })
        .collect();
    json!({
        "query": query,
        "scope": match scope {
            Scope::Both => "both",
            Scope::ClearnetOnly => "clearnet",
            Scope::DarkOnly => "dark",
        },
        "clearnet_count": clearnet.len(),
        "dark_web_count": dark_web.len(),
        "clearnet": clearnet,
        "dark_web": dark_web,
    })
}

/// Render the DoRkUS table report. **Pure** (returns the text; the caller
/// prints it) so the layout is unit-tested without capturing stdout. Each
/// queried surface gets its own labelled section; a queried-but-empty surface
/// says so, distinct from one that was not queried at all.
fn dorkus_table(query: &str, scope: Scope, web: &[WebResult], dark: &[AhmiaResult]) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(out, "DoRkUS meta-search: {query:?}");
    let _ = writeln!(out);

    if scope.wants_clearnet() {
        let _ = writeln!(
            out,
            "── Clearnet ({} result(s), ranked by cross-engine corroboration) ──",
            web.len()
        );
        if web.is_empty() {
            let _ = writeln!(
                out,
                "   nothing — every engine was blocked, unreachable, or returned nothing in budget"
            );
        }
        for (i, r) in web.iter().enumerate() {
            let title = non_empty(r.title.trim(), "(no title)");
            let _ = writeln!(
                out,
                "{:>3}. [{}×] {}",
                i + 1,
                r.engine_count,
                truncate(title, TITLE_WIDTH)
            );
            let _ = writeln!(out, "       {}", r.url);
            if !r.key_phrase.trim().is_empty() {
                let _ = writeln!(
                    out,
                    "       \u{201c}{}\u{201d}",
                    truncate(r.key_phrase.trim(), TITLE_WIDTH)
                );
            }
        }
        let _ = writeln!(out);
    }

    if scope.wants_dark() {
        let _ = writeln!(
            out,
            "── Dark-web exposure via Ahmia ({} onion mention(s); HSE never fetches an onion service) ──",
            dark.len()
        );
        if dark.is_empty() {
            let _ = writeln!(
                out,
                "   nothing indexed mentioning the query (or Ahmia was unreachable in budget)"
            );
        }
        for (i, h) in dark.iter().enumerate() {
            let title = non_empty(h.title.trim(), "(untitled onion page)");
            let _ = writeln!(out, "{:>3}. {}", i + 1, truncate(title, TITLE_WIDTH));
            let _ = writeln!(out, "       {}", h.onion_url);
            if !h.snippet.trim().is_empty() {
                let _ = writeln!(out, "       {}", truncate(h.snippet.trim(), TITLE_WIDTH));
            }
        }
        let _ = writeln!(out);
    }
    out
}

fn non_empty<'a>(s: &'a str, fallback: &'a str) -> &'a str {
    if s.is_empty() { fallback } else { s }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn web(url: &str, title: &str, engines: u32) -> WebResult {
        WebResult {
            url: url.to_string(),
            title: title.to_string(),
            snippet: "snip".to_string(),
            engine_count: engines,
            key_phrase: "phrase".to_string(),
        }
    }

    fn dark(onion: &str, title: &str) -> AhmiaResult {
        AhmiaResult {
            onion_url: onion.to_string(),
            title: title.to_string(),
            snippet: "leak".to_string(),
        }
    }

    #[test]
    fn scope_flags_map_and_conflict() {
        assert_eq!(Scope::from_flags(false, false).unwrap(), Scope::Both);
        assert_eq!(Scope::from_flags(true, false).unwrap(), Scope::ClearnetOnly);
        assert_eq!(Scope::from_flags(false, true).unwrap(), Scope::DarkOnly);
        assert!(Scope::from_flags(true, true).is_err());
    }

    #[test]
    fn json_carries_both_surfaces_with_counts_and_scope() {
        let web = vec![web("https://example.com/a", "A", 3)];
        let dark = vec![dark("http://abcd234567.onion/x", "leak index")];
        let v = dorkus_json("acme", Scope::Both, &web, &dark);
        assert_eq!(v["query"], "acme");
        assert_eq!(v["scope"], "both");
        assert_eq!(v["clearnet_count"], 1);
        assert_eq!(v["dark_web_count"], 1);
        assert_eq!(v["clearnet"][0]["url"], "https://example.com/a");
        assert_eq!(v["clearnet"][0]["engines"], 3);
        // The dark surface uses `onion_url`, not `url` — a distinct, never-fetched
        // exposure location.
        assert_eq!(v["dark_web"][0]["onion_url"], "http://abcd234567.onion/x");
        assert!(v["dark_web"][0].get("url").is_none());
    }

    #[test]
    fn json_distinguishes_not_queried_from_empty() {
        // clearnet-only: the dark array is present but empty (not queried), and
        // the scope records why.
        let web = vec![web("https://example.com/a", "A", 1)];
        let v = dorkus_json("acme", Scope::ClearnetOnly, &web, &[]);
        assert_eq!(v["scope"], "clearnet");
        assert_eq!(v["dark_web_count"], 0);
        assert!(v["dark_web"].as_array().unwrap().is_empty());
    }

    #[test]
    fn table_labels_each_queried_surface() {
        let web = vec![web("https://example.com/a", "Acme leak", 2)];
        let dark = vec![dark("http://abcd234567.onion/x", "dump")];
        let t = dorkus_table("acme", Scope::Both, &web, &dark);
        assert!(t.contains("DoRkUS meta-search: \"acme\""));
        assert!(t.contains("── Clearnet"));
        assert!(t.contains("[2×] Acme leak"));
        assert!(t.contains("https://example.com/a"));
        assert!(t.contains("── Dark-web exposure via Ahmia"));
        assert!(t.contains("http://abcd234567.onion/x"));
        assert!(t.contains("never fetches an onion service"));
    }

    #[test]
    fn table_queried_but_empty_surface_says_so() {
        // Dark-only with no hits must state the empty result under its own
        // heading, and must NOT print a clearnet section at all (not queried).
        let t = dorkus_table("acme", Scope::DarkOnly, &[], &[]);
        assert!(!t.contains("── Clearnet"), "clearnet was not queried");
        assert!(t.contains("── Dark-web exposure via Ahmia"));
        assert!(t.contains("nothing indexed"));
    }
}
