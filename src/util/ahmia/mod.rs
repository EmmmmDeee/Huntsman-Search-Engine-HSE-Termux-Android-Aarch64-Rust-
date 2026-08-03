//! Ahmia (`ahmia.fi`) — dark-web **exposure** search over clearnet.
//!
//! Ahmia indexes Tor hidden services and serves that index over ordinary HTTPS,
//! so HSE can answer "is this authorized target's data, brand, or domain being
//! mentioned on the dark web?" without a Tor daemon, a SOCKS proxy, or any
//! onion routing. That is the same asset-exposure question the existing
//! `intelx` / `hudsonrock` / `leakix` sources answer for breaches and stealer
//! logs, extended to onion-indexed content.
//!
//! ## Defensive scope (deliberate, load-bearing)
//!
//! This module reports **where a target is mentioned**. It is an exposure
//! sensor, not a directory service:
//!
//!   * It takes a search term (the asset you are assessing) and returns the
//!     onion pages that mention it. The subject of every query is the
//!     protected asset — never a marketplace to be located.
//!   * It performs **no** onion fetching. Results carry the `.onion` address
//!     Ahmia reported, and nothing here resolves, probes, health-checks, or
//!     verifies that a hidden service is reachable. Discovering *that a leak
//!     page exists* is the finding; visiting it is not this tool's job.
//!   * Ahmia itself filters abuse material from its index, so this rides on an
//!     upstream that already excludes the worst categories.
//!
//! See `SECURITY.md`: HSE is defensive-only. A "which markets are up right
//! now" capability is out of scope and is not implemented here.

use crate::util::html::{decode_entities, strip_html};
use crate::util::http::{urldecode, urlencode};

/// Ahmia's clearnet search endpoint.
const AHMIA_SEARCH_URL: &str = "https://ahmia.fi/search/?q=";

/// Upper bound on results returned from one query, mirroring the search-engine
/// scraper's own per-engine cap so a huge page can't balloon a scan's memory.
const MAX_RESULTS: usize = 30;

/// A single Ahmia hit: an onion page that mentions the searched term.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AhmiaResult {
    /// The `.onion` URL Ahmia reported. Recorded as evidence of exposure —
    /// nothing in HSE fetches it.
    pub onion_url: String,
    /// Page title as indexed, HTML-stripped and entity-decoded.
    pub title: String,
    /// Snippet/description text, HTML-stripped and entity-decoded.
    pub snippet: String,
}

/// Build the clearnet search URL for `query`.
pub fn search_url(query: &str) -> String {
    format!("{AHMIA_SEARCH_URL}{}", urlencode(query))
}

/// Search Ahmia for `query` over clearnet and return the indexed onion pages
/// that mention it.
///
/// `timeout_ms` bounds the single HTTPS request. Returns an empty vec when the
/// query is blank, the request fails, or nothing matched — an absent or
/// unreachable Ahmia is a quiet no-op, never a scan failure.
pub async fn search(query: &str, timeout_ms: u64) -> Vec<AhmiaResult> {
    let query = query.trim();
    if query.is_empty() {
        return Vec::new();
    }
    // Routed through the shared curl helper, so this inherits the SSRF pin,
    // protocol/redirect hardening, and max-filesize guard applied to every
    // outbound fetch.
    let ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 \
              (KHTML, like Gecko) Chrome/125.0 Safari/537.36";
    match crate::util::curl::fetch_with_ua(&search_url(query), timeout_ms, ua).await {
        Some(html) => parse_results(&html),
        None => Vec::new(),
    }
}

/// Parse an Ahmia results page into [`AhmiaResult`]s.
///
/// Pure over its input so the extraction is unit-tested against a captured
/// fixture rather than the live network. Ahmia renders each hit as
/// `<li class="result">` containing an `<h4><a href="…">title</a></h4>` and a
/// `<p>` description; the `href` is either a direct onion URL or Ahmia's
/// `/search/redirect?redirect_url=<encoded>` wrapper, which is decoded here so
/// the stored value is always the underlying onion address.
///
/// Unparseable or non-onion entries are skipped rather than guessed at.
pub fn parse_results(html: &str) -> Vec<AhmiaResult> {
    let mut out: Vec<AhmiaResult> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    for block in html.split("<li").skip(1) {
        if out.len() >= MAX_RESULTS {
            break;
        }
        // Only consider result list items; Ahmia's nav/footer also uses <li>.
        let Some(href) = extract_attr(block, "href=\"") else {
            continue;
        };
        let Some(onion_url) = normalize_onion_href(&href) else {
            continue;
        };
        if !seen.insert(onion_url.clone()) {
            continue;
        }
        let title = extract_tag_text(block, "<h4").unwrap_or_default();
        let snippet = extract_tag_text(block, "<p").unwrap_or_default();
        out.push(AhmiaResult {
            onion_url,
            title,
            snippet,
        });
    }
    out
}

/// Pull the first value of `attr` (given including `="`) out of `block`.
fn extract_attr(block: &str, attr: &str) -> Option<String> {
    let start = block.find(attr)? + attr.len();
    let rest = &block[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// Extract the visible text of the first `tag` element in `block`, stripped of
/// markup and entity-decoded. `tag` is the opening delimiter, e.g. `"<h4"`.
fn extract_tag_text(block: &str, tag: &str) -> Option<String> {
    let start = block.find(tag)?;
    let after_open = block[start..].find('>')? + start + 1;
    // Close on the matching end tag when present, else run to the block end.
    let close = format!("</{}", tag.trim_start_matches('<'));
    let end = block[after_open..]
        .find(&close)
        .map_or(block.len(), |e| after_open + e);
    let text = decode_entities(&strip_html(&block[after_open..end]));
    let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if text.is_empty() { None } else { Some(text) }
}

/// Resolve an Ahmia result `href` to a bare onion URL, unwrapping Ahmia's
/// `redirect_url=` indirection. Returns `None` for anything that is not an
/// onion address (Ahmia's own nav links, about pages, clearnet mirrors), so
/// non-results never enter the output.
fn normalize_onion_href(href: &str) -> Option<String> {
    let raw = if let Some(idx) = href.find("redirect_url=") {
        urldecode(&href[idx + "redirect_url=".len()..])
    } else {
        href.to_string()
    };
    let raw = raw.trim().to_string();
    // Strip any scheme, then keep just the host portion.
    let host = raw
        .rsplit("://")
        .next()?
        .split('/')
        .next()?
        .split('?')
        .next()?;
    if host.ends_with(".onion") && !host.is_empty() {
        Some(raw)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
