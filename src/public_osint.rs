//! Independent public OSINT: GDELT global news, official FBI notices, and
//! Huntsman's existing Bing/Brave/Mojeek discovery. No proprietary backend.
//! Findings are leads, not identity or culpability assertions.

use std::collections::BTreeSet;
use std::time::Duration;

use serde::Serialize;
use serde_json::Value;

use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid, push_entity};
use crate::fetch::{FetchOptions, fetch};
use crate::http::{Request, Transport, append_query_param};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};

pub const MAX_PUBLIC_QUERY_BYTES: usize = 160;
const MAX_ROWS: usize = 20;
const NEWS: &str = "gdelt_doc";
const NOTICES: &str = "fbi_wanted";
const GDELT_URL: &str = "https://api.gdeltproject.org/api/v2/doc/doc";
const FBI_URL: &str = "https://api.fbi.gov/wanted/v1/list";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    News,
    Notices,
    Web,
    All,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub query: String,
    pub entities: Vec<Entity>,
    pub outcomes: Vec<SourceExecutionOutcome>,
    pub limitations: Vec<&'static str>,
}

fn checked_query(raw: &str) -> Result<String, &'static str> {
    if raw.len() > MAX_PUBLIC_QUERY_BYTES {
        return Err("query must be between 1 and 160 UTF-8 bytes");
    }
    // Check raw input before trimming; otherwise a newline or tab at the
    // boundary evades the public-source query control-character gate.
    if raw
        .chars()
        .any(|c| c.is_control() || matches!(c, '"' | '\\'))
    {
        return Err("query cannot contain controls, quotes or backslashes");
    }
    let query = raw.trim();
    if query.is_empty() {
        return Err("query must be between 1 and 160 UTF-8 bytes");
    }
    Ok(query.to_owned())
}

fn name(source: Source) -> &'static str {
    match source {
        Source::News => NEWS,
        Source::Notices => NOTICES,
        Source::Web | Source::All => "public_osint",
    }
}

fn endpoint(source: Source, query: &str) -> String {
    match source {
        Source::News => {
            let mut url = append_query_param(GDELT_URL, "query", &format!("\"{query}\""));
            for (k, v) in [
                ("mode", "artlist"),
                ("format", "json"),
                ("maxrecords", "20"),
                ("timespan", "3months"),
                ("sort", "datedesc"),
            ] {
                url = append_query_param(&url, k, v);
            }
            url
        }
        Source::Notices => {
            let url = append_query_param(FBI_URL, "title", query);
            append_query_param(&url, "pageSize", "20")
        }
        Source::Web | Source::All => unreachable!(),
    }
}

fn normalize_news_time(raw: &str) -> Option<String> {
    let b = raw.as_bytes();
    if b.len() != 16
        || b[8] != b'T'
        || b[15] != b'Z'
        || !b[..8].iter().chain(b[9..15].iter()).all(u8::is_ascii_digit)
    {
        return None;
    }
    let formatted = format!(
        "{}-{}-{}T{}:{}:{}Z",
        &raw[..4],
        &raw[4..6],
        &raw[6..8],
        &raw[9..11],
        &raw[11..13],
        &raw[13..15]
    );
    crate::timefmt::parse_timestamp_and_iso(&formatted).map(|(_, iso)| iso)
}

// Converts one source record into Huntsman's existing evidence contract.
fn push_sourced_entity(
    entities: &mut Vec<Entity>,
    source: Source,
    row: &Value,
    url: &str,
    title: &str,
    scan_id: &str,
) {
    let mut evidence = Evidence::new(
        EvidenceProvenance::for_scan(name(source), scan_id),
        if source == Source::News {
            "Indexed news article; underlying claims unverified"
        } else {
            "Official notice exists; status and reward are subject to change"
        },
    )
    .with_attr("source_url", url)
    .with_attr("title", title);

    match source {
        Source::News => {
            for (upstream, field) in [
                ("domain", "domain"),
                ("language", "language"),
                ("sourcecountry", "source_country"),
            ] {
                if let Some(s) = row.get(upstream).and_then(Value::as_str) {
                    evidence = evidence.with_attr(field, s);
                }
            }
            if let Some(time) = row
                .get("seendate")
                .and_then(Value::as_str)
                .and_then(normalize_news_time)
            {
                evidence = evidence.with_attr("first_seen", time);
            }
            push_entity(
                entities,
                EntityKind::Url,
                url,
                0.35,
                scan_id,
                evidence,
                &["news_lead", "unverified"],
            );
        }
        Source::Notices => {
            for key in ["reward_text", "publication", "status", "uid"] {
                if let Some(s) = row
                    .get(key)
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                {
                    evidence = evidence.with_attr(key, s);
                }
            }
            if let Some(date) = row.get("modified").and_then(Value::as_str) {
                evidence = evidence.with_attr("last_updated", date);
            }
            push_entity(
                entities,
                EntityKind::Document,
                url,
                0.8,
                scan_id,
                evidence,
                &["official_notice", "status_unverified"],
            );
        }
        Source::Web | Source::All => unreachable!(),
    }
}

fn parse(
    source: Source,
    body: &Value,
    scan_id: &str,
) -> Result<(Vec<Entity>, usize), &'static str> {
    let key = match source {
        Source::News => "articles",
        Source::Notices => "items",
        Source::Web | Source::All => return Err("unsupported parse mode"),
    };
    let rows = body
        .get(key)
        .and_then(Value::as_array)
        .ok_or("missing result array")?;
    let mut entities = Vec::new();
    let mut seen = BTreeSet::new();
    let mut skipped = rows.len().saturating_sub(MAX_ROWS);
    // A nonempty upstream result set with no validated rows is not a verified zero.
    // Preserve the count of omitted records for outcome classification.

    for row in rows.iter().take(MAX_ROWS) {
        let Some(url) = row.get("url").and_then(Value::as_str) else {
            skipped += 1;
            continue;
        };
        if url.chars().any(char::is_control)
            || !url.starts_with("https://")
            || url.len() > 2048
            || (source == Source::Notices
                && !(url.starts_with("https://www.fbi.gov/wanted/")
                    || url.starts_with("https://fbi.gov/wanted/")))
            || !seen.insert(url.to_owned())
        {
            skipped += 1;
            continue;
        }
        let Some(title) = row
            .get("title")
            .and_then(Value::as_str)
            .filter(|s| !s.trim().is_empty() && !s.chars().any(char::is_control))
        else {
            skipped += 1;
            continue;
        };
        push_sourced_entity(&mut entities, source, row, url, title, scan_id);
    }
    merge_by_uid(&mut entities);
    Ok((entities, skipped))
}

/// GDELT's documented pacing notice, sent as a 429 body without a `retry-after` header.
const GDELT_PACING_NOTICE: &[u8] = b"Please limit requests to one every 5 seconds";
const GDELT_PACING_SECS: u64 = 5;
/// The longest pause one bounded GDELT retry will sleep through.
const GDELT_MAX_RETRY_PAUSE_SECS: u64 = 10;

/// The pause before one retry of a rate-limited GDELT answer: its `retry-after`, or the
/// pacing its notice documents, and only when that is short. `None` means do not retry.
fn gdelt_retry_pause(source: Source, fetched: &crate::fetch::Fetched) -> Option<u64> {
    if source != Source::News || fetched.outcome.kind != SourceOutcomeKind::RateLimited {
        return None;
    }
    let response = fetched.response.as_ref()?;
    let pause = fetched.outcome.retry_after_secs.or_else(|| {
        response
            .body
            .starts_with(GDELT_PACING_NOTICE)
            .then_some(GDELT_PACING_SECS)
    })?;
    (pause <= GDELT_MAX_RETRY_PAUSE_SECS).then_some(pause)
}

fn collect<T: Transport + ?Sized>(
    transport: &T,
    source: Source,
    query: &str,
    scan_id: &str,
    now: u64,
    clock: &dyn crate::deadline::Clock,
) -> (Vec<Entity>, SourceExecutionOutcome) {
    let label = name(source);
    let attempt = |at: u64| {
        let request = Request::get(endpoint(source, query)).with_timeout(Duration::from_secs(16));
        fetch(
            transport,
            request,
            None,
            &FetchOptions::no_redirects().paced(),
            label,
            at,
        )
    };
    let mut fetched = attempt(now);
    if let Ok(first) = &fetched {
        if let Some(pause) = gdelt_retry_pause(source, first) {
            if let Some(host) = crate::circuit::host_of(GDELT_URL) {
                crate::circuit::record_rate_limited(&host, now, pause);
            }
            clock.sleep(Duration::from_secs(pause));
            fetched = attempt(now + pause);
            if let Ok(second) = &mut fetched {
                if second.outcome.kind == SourceOutcomeKind::RateLimited
                    && second.outcome.retry_after_secs.is_none()
                {
                    second.outcome.retry_after_secs = Some(pause);
                }
            }
        }
    }
    let Ok(fetched) = fetched else {
        return (
            Vec::new(),
            SourceExecutionOutcome::refused_before_sending(
                label,
                now,
                "guarded network transport refused the request",
            ),
        );
    };
    let Some(response) = fetched.response else {
        return (Vec::new(), fetched.outcome);
    };
    if response.truncated {
        return (
            Vec::new(),
            SourceExecutionOutcome::failed(
                label,
                now,
                SourceOutcomeKind::ParserDrift,
                Some(response.status),
                "response exceeded the configured byte limit",
            ),
        );
    }
    if response.status != 200 {
        return (Vec::new(), fetched.outcome);
    }
    let Ok(document) = serde_json::from_slice::<Value>(&response.body) else {
        return (
            Vec::new(),
            SourceExecutionOutcome::failed(
                label,
                now,
                SourceOutcomeKind::ParserDrift,
                Some(200),
                "response is not JSON",
            ),
        );
    };
    if document.get("ok").and_then(Value::as_bool) == Some(false) {
        return (
            Vec::new(),
            SourceExecutionOutcome::failed(
                label,
                now,
                SourceOutcomeKind::SemanticDrift,
                Some(200),
                "upstream reported failure",
            ),
        );
    }
    classify_document(source, &document, scan_id, now)
}

// Preserves source-level failures and refuses to convert schema drift into zero findings.
fn classify_document(
    source: Source,
    document: &Value,
    scan_id: &str,
    now: u64,
) -> (Vec<Entity>, SourceExecutionOutcome) {
    let label = name(source);
    match parse(source, document, scan_id) {
        Ok((entities, skipped)) if !entities.is_empty() => {
            let mut outcome =
                SourceExecutionOutcome::success(label, now, entities.len()).with_http_status(200);
            if skipped > 0 {
                outcome = outcome.with_detail(format!(
                    "{skipped} invalid, duplicate, or over-limit records omitted"
                ));
            }
            (entities, outcome)
        }
        Ok((_, skipped)) => {
            let total = document.get("total").and_then(Value::as_u64).unwrap_or(0);
            if skipped == 0 && total == 0 {
                (
                    Vec::new(),
                    SourceExecutionOutcome::valid_zero(label, now).with_http_status(200),
                )
            } else {
                (
                    Vec::new(),
                    SourceExecutionOutcome::failed(
                        label,
                        now,
                        SourceOutcomeKind::SchemaDrift,
                        Some(200),
                        "result rows could not be validated",
                    ),
                )
            }
        }
        Err(why) => (
            Vec::new(),
            SourceExecutionOutcome::failed(
                label,
                now,
                SourceOutcomeKind::SchemaDrift,
                Some(200),
                why,
            ),
        ),
    }
}

fn web_search<T: Transport + ?Sized>(
    transport: &T,
    query: &str,
    scan_id: &str,
    now: u64,
) -> (Vec<Entity>, Vec<SourceExecutionOutcome>) {
    let Ok(found) = crate::web_query::search(transport, query, now) else {
        return (
            Vec::new(),
            vec![SourceExecutionOutcome::refused_before_sending(
                "web_query",
                now,
                "search request was refused",
            )],
        );
    };
    let mut entities = Vec::new();
    for hit in found.hits.into_iter().take(40) {
        if !hit.url.starts_with("https://")
            || hit.url.len() > 2048
            || hit.url.chars().any(char::is_control)
        {
            continue;
        }
        let evidence = Evidence::new(
            EvidenceProvenance::for_scan(format!("web_{}", hit.engine), scan_id),
            "Indexed URL; page contents are not verified",
        )
        .with_attr("source_url", &hit.url)
        .with_attr("engine", &hit.engine);
        push_entity(
            &mut entities,
            EntityKind::Url,
            &hit.url,
            0.25,
            scan_id,
            evidence,
            &["web_lead", "unverified"],
        );
    }
    merge_by_uid(&mut entities);
    (entities, found.outcomes)
}

/// Search official notices, recent news, existing keyless web engines, or all.
/// A failure in one source never erases the other source's findings.
///
/// # Errors
/// Returns an error only for invalid user input, before any network activity.
pub fn search<T: Transport + ?Sized>(
    transport: &T,
    source: Source,
    raw_query: &str,
    scan_id: &str,
    now: u64,
) -> Result<Report, &'static str> {
    search_with_clock(
        transport,
        source,
        raw_query,
        scan_id,
        now,
        &crate::deadline::SystemClock,
    )
}

/// [`search`] with the clock a bounded rate-limit pause sleeps on, injectable for tests.
fn search_with_clock<T: Transport + ?Sized>(
    transport: &T,
    source: Source,
    raw_query: &str,
    scan_id: &str,
    now: u64,
    clock: &dyn crate::deadline::Clock,
) -> Result<Report, &'static str> {
    let query = checked_query(raw_query)?;
    let mut entities = Vec::new();
    let mut outcomes = Vec::new();
    for provider in match source {
        Source::News => &[Source::News][..],
        Source::Notices => &[Source::Notices][..],
        Source::Web => &[][..],
        Source::All => &[Source::News, Source::Notices][..],
    } {
        let (mut found, outcome) = collect(transport, *provider, &query, scan_id, now, clock);
        entities.append(&mut found);
        outcomes.push(outcome);
    }
    if matches!(source, Source::Web | Source::All) {
        let (mut found, web_outcomes) = web_search(transport, &query, scan_id, now);
        entities.append(&mut found);
        outcomes.extend(web_outcomes);
    }
    merge_by_uid(&mut entities);
    Ok(Report {
        query,
        entities,
        outcomes,
        limitations: vec![
            "News and search results are leads, not independently verified event reports.",
            "Official notices can be amended or withdrawn; consult the issuing agency.",
            "Search-result agreement does not prove real-world identity or culpability.",
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::Response;
    use crate::test_support::{OneResponse, ScriptedTransport};

    fn reply(status: u16, body: &str) -> Response {
        Response {
            status,
            headers: vec![("content-type".into(), "application/json".into())],
            body: body.as_bytes().to_vec(),
            truncated: false,
        }
    }

    const PACING: &str =
        "Please limit requests to one every 5 seconds or contact the project for larger queries.";

    fn paced_reply(status: u16, body: &str, headers: &[(&str, &str)]) -> Response {
        Response {
            status,
            headers: headers
                .iter()
                .map(|(k, v)| ((*k).into(), (*v).into()))
                .collect(),
            body: body.as_bytes().to_vec(),
            truncated: false,
        }
    }

    /// GDELT answers a burst with a 429 and no `retry-after`, its body naming the pause it
    /// enforces: one request every 5 seconds. One retry after that pause is the documented use.
    #[test]
    fn gdelt_pacing_429_is_retried_once_after_its_documented_pause() {
        let clock = crate::deadline::FakeClock::new();
        let transport = ScriptedTransport::new(vec![
            Ok(paced_reply(429, PACING, &[])),
            Ok(reply(200, r#"{"articles":[]}"#)),
        ]);
        let report =
            search_with_clock(&transport, Source::News, "story", "s", 1_000, &clock).unwrap();
        assert_eq!(report.outcomes[0].kind, SourceOutcomeKind::ValidZero);
        assert_eq!(transport.seen.borrow().len(), 2);
        assert_eq!(clock.elapsed(), Duration::from_secs(5));
    }

    #[test]
    fn a_second_gdelt_429_stops_with_the_pause_it_asked_for() {
        let clock = crate::deadline::FakeClock::new();
        let transport = ScriptedTransport::new(vec![
            Ok(paced_reply(429, PACING, &[])),
            Ok(paced_reply(429, PACING, &[])),
            Ok(reply(200, r#"{"articles":[]}"#)),
        ]);
        let report =
            search_with_clock(&transport, Source::News, "story", "s", 2_000, &clock).unwrap();
        assert_eq!(report.outcomes[0].kind, SourceOutcomeKind::RateLimited);
        assert_eq!(report.outcomes[0].retry_after_secs, Some(5));
        assert_eq!(transport.seen.borrow().len(), 2, "one bounded retry only");
    }

    #[test]
    fn a_429_without_a_known_or_short_pause_is_not_retried() {
        // Distinct clocks: the first case's 429 opens this thread's breaker for 60 s.
        for (headers, body, carried, now) in [
            (&[][..], "slow down", None, 3_000),
            (&[("retry-after", "120")][..], "", Some(120), 4_000),
        ] {
            let clock = crate::deadline::FakeClock::new();
            let transport = ScriptedTransport::new(vec![
                Ok(paced_reply(429, body, headers)),
                Ok(reply(200, r#"{"articles":[]}"#)),
            ]);
            let report =
                search_with_clock(&transport, Source::News, "story", "s", now, &clock).unwrap();
            assert_eq!(report.outcomes[0].kind, SourceOutcomeKind::RateLimited);
            assert_eq!(report.outcomes[0].retry_after_secs, carried);
            assert_eq!(transport.seen.borrow().len(), 1);
            assert_eq!(clock.elapsed(), Duration::ZERO);
        }
    }

    #[test]
    fn rejects_invalid_queries_before_network() {
        let silent = crate::test_support::Silent;
        assert!(search(&silent, Source::All, "", "s", 1).is_err());
        assert!(search(&silent, Source::All, "a\"b", "s", 1).is_err());
        for bad in ["\ntext", "text\r", "\ttext", "te\0xt"] {
            assert!(search(&silent, Source::All, bad, "s", 1).is_err(), "{bad:?}");
        }
        assert!(search(&silent, Source::All, &"x".repeat(161), "s", 1).is_err());
    }

    #[test]
    fn parses_news_time_and_source_provenance() {
        let fake = OneResponse::json(
            200,
            r#"{"articles":[{"title":"Headline","url":"https://example.org/a","seendate":"20261026T123000Z"}]}"#,
        );
        let report = search(&fake, Source::News, "story", "s", 1).unwrap();
        assert_eq!(report.outcomes[0].kind, SourceOutcomeKind::Success);
        assert_eq!(report.entities[0].evidence[0].provenance.source, NEWS);
        assert!(
            report.entities[0].evidence[0]
                .attributes
                .contains_key("first_seen")
        );
    }

    #[test]
    fn refuses_to_conflate_missing_array_with_zero() {
        let fake = OneResponse::json(200, r#"{"error":"blocked"}"#);
        let report = search(&fake, Source::News, "story", "s", 1).unwrap();
        assert_eq!(report.outcomes[0].kind, SourceOutcomeKind::SchemaDrift);
    }

    #[test]
    fn accepts_true_empty_result() {
        let fake = OneResponse::json(200, r#"{"articles":[]}"#);
        let report = search(&fake, Source::News, "story", "s", 1).unwrap();
        assert_eq!(report.outcomes[0].kind, SourceOutcomeKind::ValidZero);
    }

    #[test]
    fn rejects_control_characters_in_upstream_urls() {
        let fake = OneResponse::json(
            200,
            r#"{"articles":[{"title":"Headline","url":"https://example.org/a\nInjected"}]}"#,
        );
        let report = search(&fake, Source::News, "test", "s", 1).unwrap();
        assert!(report.entities.is_empty());
        assert_eq!(report.outcomes[0].kind, SourceOutcomeKind::SchemaDrift);
    }

    #[test]
    fn rejects_control_characters_in_upstream_titles() {
        let fake = OneResponse::json(
            200,
            r#"{"articles":[{"title":"Headline\nInjected","url":"https://example.org/a"}]}"#,
        );
        let report = search(&fake, Source::News, "test", "s", 1).unwrap();
        assert!(report.entities.is_empty());
        assert_eq!(report.outcomes[0].kind, SourceOutcomeKind::SchemaDrift);
    }

    #[test]
    fn rejects_blank_upstream_titles() {
        let fake = OneResponse::json(
            200,
            r#"{"articles":[{"title":"   ","url":"https://example.org/a"}]}"#,
        );
        let report = search(&fake, Source::News, "test", "s", 1).unwrap();
        assert!(report.entities.is_empty());
        assert_eq!(report.outcomes[0].kind, SourceOutcomeKind::SchemaDrift);
    }

    #[test]
    fn reported_nonzero_total_is_not_a_verified_empty_result() {
        for source in [Source::News, Source::Notices] {
            let fake = OneResponse::json(
                200,
                if source == Source::News {
                    r#"{"articles":[],"total":7}"#
                } else {
                    r#"{"items":[],"total":7}"#
                },
            );
            let report = search(&fake, source, "test", "s", 1).unwrap();
            assert!(report.entities.is_empty());
            assert_eq!(report.outcomes[0].kind, SourceOutcomeKind::SchemaDrift);
        }
    }

    #[test]
    fn rejects_non_fbi_notice_origin() {
        let fake = OneResponse::json(
            200,
            r#"{"items":[{"title":"Notice","url":"https://fake-fbi.example/wanted/x"}]}"#,
        );
        let report = search(&fake, Source::Notices, "notice", "s", 1).unwrap();
        assert!(report.entities.is_empty());
        assert_eq!(report.outcomes[0].kind, SourceOutcomeKind::SchemaDrift);
    }

    #[test]
    fn preserves_partial_results_and_source_failures() {
        let transport = ScriptedTransport::new(vec![
            Ok(reply(
                200,
                r#"{"articles":[{"title":"Headline","url":"https://example.org/a"}]}"#,
            )),
            Ok(reply(503, "failure")),
            Ok(reply(403, "blocked")),
            Ok(reply(403, "blocked")),
            Ok(reply(403, "blocked")),
        ]);
        let report = search(&transport, Source::All, "story", "s", 1).unwrap();
        assert!(!report.entities.is_empty());
        assert_eq!(report.outcomes[0].kind, SourceOutcomeKind::Success);
        assert!(!report.outcomes[1].kind.is_accepted());
    }

    #[test]
    fn official_reward_is_claim_not_guarantee() {
        let fake = OneResponse::json(
            200,
            r#"{"items":[{"title":"Official notice","url":"https://www.fbi.gov/wanted/seeking-info/test","reward_text":"Up to $10,000"}]}"#,
        );
        let report = search(&fake, Source::Notices, "test", "s", 1).unwrap();
        assert_eq!(report.entities[0].kind, EntityKind::Document);
        assert_eq!(
            report.entities[0].evidence[0]
                .attributes
                .get("reward_text")
                .map(String::as_str),
            Some("Up to $10,000")
        );
    }
}
