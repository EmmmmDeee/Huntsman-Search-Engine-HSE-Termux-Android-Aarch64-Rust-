//! Keyless Wikimedia (Wikipedia) user-contributions lookup.
//!
//! One lookup is one GET to the `MediaWiki` `usercontribs` list API on English Wikipedia for a single
//! account name. `MediaWiki` attributes every edit to the account that made it, so this source maps a
//! handle to the public pages it has recently edited: each edit becomes a URL to that exact revision,
//! tagged as a Wikipedia page edit, with the editor, page title, revision id, timestamp and edit
//! summary kept as evidence, and the account's contributions page is kept as an anchor. Only the
//! public edit metadata the API returns is read; nothing is inferred beyond it, and the recent window
//! is bounded so a prolific account cannot flood the report.

use serde::Deserialize;

use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid, push_entity};
use crate::error::Error;
use crate::fetch::{FetchOptions, fetch};
use crate::http::{Request, Response, Transport, append_query_param};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind, classify_fetch};
use crate::tags;

/// The source/module name this leg reports its findings under.
pub const SRC: &str = "wikipedia";

const API: &str = "https://en.wikipedia.org/w/api.php";
const PAGE: &str = "https://en.wikipedia.org/w/index.php";

/// Most contributions one lookup reads. A prolific account has hundreds of thousands of edits; the
/// recent window is the useful, bounded sample and the API's non-bot ceiling is far higher.
const MAX_EDITS: usize = 50;

/// An edit is a public, account-attributed revision record, reported with high but not absolute
/// confidence: a handle is not proof of a real-world identity.
const EDIT_CONF: f64 = 0.8;

/// The contributions page anchors the edits to the account; it is a derived URL, a notch lower.
const ANCHOR_CONF: f64 = 0.75;

/// `MediaWiki` account names are at most 255 bytes; an empty or over-long selector names no account,
/// so the lookup is inconclusive without a request.
const MAX_LEN: usize = 255;

#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcome: SourceExecutionOutcome,
}

#[derive(Debug, Deserialize)]
struct ApiResponse {
    /// Present (any shape) when `MediaWiki` rejects the query, for example `baduser_ucuser`.
    #[serde(default)]
    error: Option<serde_json::Value>,
    #[serde(default)]
    query: Option<QueryBlock>,
}

#[derive(Debug, Default, Deserialize)]
struct QueryBlock {
    #[serde(default)]
    usercontribs: Vec<Contrib>,
}

#[derive(Debug, Deserialize)]
struct Contrib {
    #[serde(default)]
    title: String,
    #[serde(default)]
    timestamp: String,
    #[serde(default)]
    comment: String,
    #[serde(default)]
    revid: i64,
    #[serde(default)]
    user: String,
}

/// Query one account's recent public Wikipedia contributions.
///
/// # Errors
/// Returns a network-boundary error when the guarded fetch refuses a URL.
pub fn lookup<T: Transport + ?Sized>(
    transport: &T,
    username: &str,
    scan_id: &str,
    now_unix: u64,
) -> Result<Report, Error> {
    let selector = username.trim();
    if selector.is_empty() || selector.len() > MAX_LEN {
        return Ok(miss(SourceExecutionOutcome::inconclusive(
            SRC,
            now_unix,
            "selector cannot name a Wikipedia account",
        )));
    }

    let url = append_query_param(API, "action", "query");
    let url = append_query_param(&url, "list", "usercontribs");
    let url = append_query_param(&url, "ucuser", selector);
    let url = append_query_param(&url, "uclimit", &MAX_EDITS.to_string());
    let url = append_query_param(&url, "ucprop", "title|timestamp|comment|ids");
    let url = append_query_param(&url, "format", "json");
    let url = append_query_param(&url, "formatversion", "2");

    let fetched = fetch(
        transport,
        Request::get(url)
            .header("accept", "application/json")
            .header("user-agent", crate::http::DEFAULT_USER_AGENT),
        None,
        &FetchOptions::no_redirects().paced(),
        SRC,
        now_unix,
    )?;

    let Some(response) = fetched.response else {
        return Ok(miss(fetched.outcome));
    };
    Ok(interpret(&response, selector, scan_id, now_unix))
}

/// A report that found nothing, carrying only its outcome. **Pure.**
fn miss(outcome: SourceExecutionOutcome) -> Report {
    Report {
        entities: Vec::new(),
        outcome,
    }
}

/// Turn one fetched `usercontribs` response into a report. **Pure.**
fn interpret(response: &Response, selector: &str, scan_id: &str, now_unix: u64) -> Report {
    if response.truncated {
        return miss(SourceExecutionOutcome::failed(
            SRC,
            now_unix,
            SourceOutcomeKind::ParserDrift,
            Some(response.status),
            "truncated Wikipedia response",
        ));
    }

    let body = response.text();
    let classified = classify_fetch(response.status, &body);
    if classified != SourceOutcomeKind::Inconclusive {
        return miss(SourceExecutionOutcome::failed(
            SRC,
            now_unix,
            classified,
            Some(response.status),
            "Wikipedia response was not a contributions document",
        ));
    }

    let parsed: ApiResponse = match serde_json::from_slice(&response.body) {
        Ok(parsed) => parsed,
        Err(error) => {
            return miss(SourceExecutionOutcome::failed(
                SRC,
                now_unix,
                SourceOutcomeKind::ParserDrift,
                Some(response.status),
                format!("Wikipedia JSON: {error}"),
            ));
        }
    };

    // An API error (for example `baduser_ucuser` on a name `MediaWiki` rejects) and an empty
    // contributions list are both clean negatives: the account names no public edits.
    if parsed.error.is_some() {
        return miss(
            SourceExecutionOutcome::valid_zero(SRC, now_unix).with_http_status(response.status),
        );
    }
    let contribs = parsed.query.unwrap_or_default().usercontribs;

    let mut entities = build_entities(selector, &contribs, scan_id);
    if entities.is_empty() {
        return miss(
            SourceExecutionOutcome::valid_zero(SRC, now_unix).with_http_status(response.status),
        );
    }
    merge_by_uid(&mut entities);
    Report {
        outcome: SourceExecutionOutcome::success(SRC, now_unix, entities.len())
            .with_http_status(response.status),
        entities,
    }
}

/// Build the edit URLs and the account anchor from the contributions. **Pure.**
fn build_entities(selector: &str, contribs: &[Contrib], scan_id: &str) -> Vec<Entity> {
    // The cased account name as `MediaWiki` returns it, falling back to the queried selector.
    let editor = contribs
        .iter()
        .map(|c| c.user.trim())
        .find(|user| !user.is_empty())
        .unwrap_or(selector);

    let mut entities = Vec::new();
    let mut kept = 0usize;
    for contrib in contribs {
        if kept >= MAX_EDITS {
            break;
        }
        let title = contrib.title.trim();
        // A log action and a deleted revision carry no revision id; only a real page edit does.
        if contrib.revid <= 0 || title.is_empty() {
            continue;
        }
        let mut evidence = Evidence::new(
            EvidenceProvenance::for_scan(SRC, scan_id),
            format!("Wikipedia edit by {editor} to \"{title}\""),
        )
        .with_attr("dataset", "Wikimedia user contributions")
        .with_attr("editor", editor)
        .with_attr("page_title", title)
        .with_attr("revision_id", contrib.revid.to_string());
        let timestamp = contrib.timestamp.trim();
        if !timestamp.is_empty() {
            evidence = evidence.with_attr("timestamp", timestamp);
        }
        let comment = contrib.comment.trim();
        if !comment.is_empty() {
            evidence = evidence.with_attr("edit_comment", comment);
        }
        let url = append_query_param(PAGE, "oldid", &contrib.revid.to_string());
        push_entity(
            &mut entities,
            EntityKind::Url,
            &url,
            EDIT_CONF,
            scan_id,
            evidence,
            &[SRC, tags::WIKIPEDIA_EDIT],
        );
        kept += 1;
    }

    if !entities.is_empty() {
        let anchor = append_query_param(
            &append_query_param(PAGE, "title", "Special:Contributions"),
            "target",
            editor,
        );
        push_entity(
            &mut entities,
            EntityKind::Url,
            &anchor,
            ANCHOR_CONF,
            scan_id,
            Evidence::new(
                EvidenceProvenance::for_scan(SRC, scan_id),
                format!("Wikipedia contributions page of {editor}"),
            )
            .with_attr("dataset", "Wikimedia user contributions")
            .with_attr("editor", editor),
            &[SRC],
        );
    }
    entities
}

#[cfg(test)]
mod tests;
