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
/// The FBI wanted-notices leg, a module of its own in a people scan.
pub const NOTICES: &str = "fbi_wanted";
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

fn checked_query(raw: &str, source: Source) -> Result<String, &'static str> {
    if raw.len() > MAX_PUBLIC_QUERY_BYTES {
        return Err("query must be between 1 and 160 UTF-8 bytes");
    }
    // Check raw input before trimming; otherwise a newline or tab at the
    // boundary evades the public-source query control-character gate.
    if raw
        .chars()
        .any(|c| c.is_control() || c == '\\' || (c == '"' && source != Source::Web))
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

fn parse(source: Source, body: &Value, query: &str, scan_id: &str) -> Result<Parsed, &'static str> {
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
    let mut other_people = 0;
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
        // The FBI's search is full text: it answers "Mohammed bin Rashid Al Maktoum" with every
        // notice that shares a word. A notice is kept only when its title or one of its aliases
        // names every word of the query; any other is a different person.
        if source == Source::Notices && !notice_names_query(row, title, query) {
            other_people += 1;
            continue;
        }
        push_sourced_entity(&mut entities, source, row, url, title, scan_id);
    }
    merge_by_uid(&mut entities);
    Ok(Parsed {
        entities,
        skipped,
        other_people,
    })
}

/// What one answer's rows held: the kept entities, the rows that could not be validated (or were
/// duplicates or over the limit), and the valid notices that name someone other than the query.
struct Parsed {
    entities: Vec<Entity>,
    skipped: usize,
    other_people: usize,
}

/// Whether a notice names every word of `query`, in its title or in one of its `aliases`.
fn notice_names_query(row: &Value, title: &str, query: &str) -> bool {
    let wanted = crate::textnorm::name_tokens(query);
    if wanted.is_empty() {
        return false;
    }
    let names_all = |name: &str| {
        let have = crate::textnorm::name_tokens(name);
        wanted.iter().all(|word| have.contains(word))
    };
    names_all(title)
        || row
            .get("aliases")
            .and_then(Value::as_array)
            .is_some_and(|aliases| aliases.iter().filter_map(Value::as_str).any(names_all))
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
    classify_document(source, &document, query, scan_id, now)
}

// Preserves source-level failures and refuses to convert schema drift into zero findings.
fn classify_document(
    source: Source,
    document: &Value,
    query: &str,
    scan_id: &str,
    now: u64,
) -> (Vec<Entity>, SourceExecutionOutcome) {
    let label = name(source);
    match parse(source, document, query, scan_id) {
        Ok(Parsed {
            entities, skipped, ..
        }) if !entities.is_empty() => {
            let mut outcome =
                SourceExecutionOutcome::success(label, now, entities.len()).with_http_status(200);
            if skipped > 0 {
                outcome = outcome.with_detail(format!(
                    "{skipped} invalid, duplicate, or over-limit records omitted"
                ));
            }
            (entities, outcome)
        }
        Ok(Parsed {
            skipped,
            other_people,
            ..
        }) => {
            let total = document.get("total").and_then(Value::as_u64).unwrap_or(0);
            if skipped == 0 && (total == 0 || other_people > 0) {
                let mut zero = SourceExecutionOutcome::valid_zero(label, now).with_http_status(200);
                if other_people > 0 {
                    zero = zero.with_detail(format!(
                        "{other_people} notices the search returned name other people"
                    ));
                }
                (Vec::new(), zero)
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
    let Ok(found) =
        crate::web_query::search(transport, query, now, crate::web_query::EngineSet::Default)
    else {
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

/// The safe public Telegram surface indicated by an *indexed URL*, not by
/// reading Telegram itself. It cannot establish who owns a profile or post.
#[derive(Debug, Clone, PartialEq, Eq)]
struct IndexedTelegramUrl {
    /// A stable URL for URL-level de-duplication, not proof that a page exists.
    canonical: String,
    surface: &'static str,
}

/// Canonicalise only unambiguous *public URL shapes*. No web fetch or identity
/// resolution occurs here. Rejecting a URL never proves the target is absent.
/// The hot path borrows path segments and allocates only after validation.
fn telegram_index_surface(url: &str) -> Option<IndexedTelegramUrl> {
    if url.len() > 2048
        || !url.starts_with("https://")
        || url
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace() || b == b'\\')
    {
        return None;
    }
    let rest = url.strip_prefix("https://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let suffix = rest.strip_prefix(authority)?;
    let path = suffix.split(['?', '#']).next()?;

    if matches!(
        authority,
        "tgstat.com" | "www.tgstat.com" | "telemetr.io" | "www.telemetr.io"
    ) {
        // A catalogue landing page, general search form, or leaderboard is
        // not a specific record and must not inflate the discovery count.
        if path.len() > 300 || !path.starts_with('/') || path.contains('%') {
            return None;
        }
        let mut segments = path.strip_prefix('/')?.split('/');
        let first = segments.next()?;
        let second = segments.next()?;
        if first.is_empty()
            || second.is_empty()
            || matches!(first, "." | "..")
            || matches!(second, "." | "..")
            || segments.any(|part| part.is_empty() || matches!(part, "." | ".."))
        {
            return None;
        }
        if first.eq_ignore_ascii_case("search")
            || first.eq_ignore_ascii_case("ratings")
            || first.eq_ignore_ascii_case("catalog")
            || second.eq_ignore_ascii_case("search")
            || second.eq_ignore_ascii_case("catalog")
        {
            return None;
        }
        let host = if authority.contains("tgstat.com") {
            "tgstat.com"
        } else {
            "telemetr.io"
        };
        return Some(IndexedTelegramUrl {
            canonical: format!("https://{host}{path}"),
            surface: "third_party_directory",
        });
    }

    if !matches!(authority, "t.me" | "telegram.me" | "telegram.dog") {
        return None;
    }
    let mut segments = path.strip_prefix('/')?.split('/');
    let first = segments.next()?;
    let preview = first == "s";
    let handle = if preview { segments.next()? } else { first };
    let message = segments.next();
    if segments.next().is_some() {
        return None;
    }

    // 5..32 ASCII chars and a leading Latin letter are Telegram's public
    // username grammar. These are handles, not names of people.
    const RESERVED: &[&str] = &[
        "c", "joinchat", "share", "addstickers", "proxy", "socks",
        "iv", "login", "boost", "setlanguage", "bg", "invoice",
    ];
    if !(5..=32).contains(&handle.len())
        || !handle.as_bytes()[0].is_ascii_alphabetic()
        || !handle.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        || RESERVED.iter().any(|r| handle.eq_ignore_ascii_case(r))
    {
        return None;
    }

    let handle = handle.to_ascii_lowercase();
    if let Some(raw_id) = message {
        // Post zero, blank/negative, extremely long or overflowing numeric
        // tokens are not usable message IDs.
        if raw_id.is_empty()
            || raw_id.len() > 19
            || !raw_id.bytes().all(|b| b.is_ascii_digit())
        {
            return None;
        }
        let id = raw_id.parse::<u64>().ok().filter(|id| *id > 0)?;
        return Some(IndexedTelegramUrl {
            canonical: format!("https://t.me/{handle}/{id}"),
            surface: "indexed_post_url",
        });
    }
    Some(IndexedTelegramUrl {
        canonical: if preview {
            format!("https://t.me/s/{handle}")
        } else {
            format!("https://t.me/{handle}")
        },
        surface: if preview {
            "indexed_public_preview"
        } else {
            "indexed_handle_url"
        },
    })
}

/// Keyless Telegram-focused *index* discovery, not a Telegram API session.
/// All network traffic uses Huntsman's guarded web engines. A hit becomes an
/// unverified URL entity only after it passes exact host and path checks.
/// Search-index agreement remains one discovery family, never identity proof.
///
/// # Errors
/// Invalid selectors fail before any request; provider failures retain typed
/// outcome rows and never turn into claims that a person is absent.
pub fn telegram_index_search<T: Transport + ?Sized>(
    transport: &T,
    raw_query: &str,
    scan_id: &str,
    now: u64,
) -> Result<Report, &'static str> {
    let query = checked_query(raw_query, Source::Web)?;
    if query.len() > 120 {
        return Err("Telegram index query exceeds the 120-byte bounded selector");
    }
    const COHORTS: [(&str, &str); 4] = [
        ("telegram_preview", "site:t.me/s"),
        ("telegram", "site:t.me"),
        ("tgstat", "site:tgstat.com"),
        ("telemetr", "site:telemetr.io"),
    ];
    let mut entities = Vec::new();
    let mut outcomes = Vec::new();
    for (cohort, prefix) in COHORTS {
        let search = format!("{prefix} {query}");
        let found = crate::web_query::search_with_provenance(
            transport,
            &search,
            now,
            crate::web_query::EngineSet::Default,
        );
        let Ok((report, observations)) = found else {
            outcomes.push(SourceExecutionOutcome::inconclusive(
                format!("telegram_index_{cohort}"),
                now,
                "web-query boundary could not execute this cohort",
            ));
            continue;
        };
        for mut outcome in report.outcomes {
            outcome.module = format!("telegram_index_{cohort}_{}", outcome.module);
            outcomes.push(outcome);
        }
        // The index did not prove page content, account ownership, family
        // relationships or whether the query occurs on the target page.
        for hit in observations.into_iter().take(75) {
            if let Some(parsed) = telegram_index_surface(&hit.url) {
                let evidence = Evidence::new(
                    EvidenceProvenance::for_scan("telegram_web_index", scan_id),
                    "Public-index URL lead; Telegram page and identity not verified",
                )
                .with_attr("source_url", &hit.url)
                .with_attr("discovered_by", &hit.engine)
                .with_attr("query", &search)
                .with_attr("surface", parsed.surface)
                .with_attr("canonical_index_url", &parsed.canonical)
                .with_attr("evidence_role", "indexed_url_only");
                push_entity(
                    &mut entities,
                    EntityKind::Url,
                    &parsed.canonical,
                    0.20,
                    scan_id,
                    evidence,
                    &["telegram_index_lead", "unverified"],
                );
            }
        }
    }
    merge_by_uid(&mut entities);
    Ok(Report {
        query,
        entities,
        outcomes,
        limitations: vec![
            "Search engines index only a subset of Telegram; no results do not prove absence.",
            "Indexed links are not proof of a post's text or a handle's human owner.",
            "Third-party directories are not independent Telegram primary evidence.",
        ],
    })
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
    let query = checked_query(raw_query, source)?;
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
            assert!(
                search(&silent, Source::All, bad, "s", 1).is_err(),
                "{bad:?}"
            );
        }
        assert!(search(&silent, Source::All, &"x".repeat(161), "s", 1).is_err());
    }

    /// Exact-phrase web searches are safe for the existing guarded web-query layer.
    /// GDELT and notice query grammars must continue refusing quote characters.
    #[test]
    fn exact_phrase_web_lookup_preserves_quotes_only_for_web() {
        let quoted = r#"site:t.me/s "Kylie Truong""#;
        assert_eq!(checked_query(quoted, Source::Web), Ok(quoted.to_owned()));
        for source in [Source::News, Source::Notices, Source::All] {
            assert!(checked_query(quoted, source).is_err());
        }
        for invalid in ["a\nb", "a\\b"] {
            assert!(checked_query(invalid, Source::Web).is_err());
        }
    }

    #[test]
    fn telegram_index_rejects_spoofed_private_and_noncanonical_links() {
        for raw in [
            "https://t.me@evil.example/truong",
            "https://t.me.evil.example/truong",
            "https://t.me:443/truong",
            "http://t.me/truong",
            "https://t.me/+PrivateInvite",
            "https://t.me/joinchat/SomeInvite",
            "https://t.me/c/100000/123",
            "https://t.me/share/url",
            "https://t.me/s/",
            "https://t.me/truong/abc",
            "https://t.me/truong/123/456",
            "https://evil.example/?site=t.me/truong",
            "https://tgstat.com.evil.example/channel/1",
            "https://telemetr.io",
        ] {
            assert_eq!(telegram_index_surface(raw), None, "{raw}");
        }
    }

    #[test]
    fn telegram_index_distinguishes_public_link_surfaces_without_owner_attribution() {
        for (raw, expected) in [
            ("https://t.me/TRUONG", "indexed_handle_url"),
            ("https://t.me/s/CheemsCMNews", "indexed_public_preview"),
            ("https://t.me/CheemsCMNews/132", "indexed_post_url"),
            ("https://t.me/s/CheemsCMNews/132", "indexed_post_url"),
            ("https://tgstat.com/channel/123", "third_party_directory"),
            ("https://telemetr.io/en/channels/123", "third_party_directory"),
            ("https://telegram.dog/cheemscmnews", "indexed_handle_url"),
        ] {
            assert_eq!(telegram_index_surface(raw).map(|parsed| parsed.surface), Some(expected), "{raw}");
        }
    }

    #[test]
    fn telegram_index_canonicalises_aliases_and_preview_post_urls() {
        let urls = [
            "https://t.me/CheemsCMNews/00132?single",
            "https://t.me/s/cheemscmnews/132#x",
            "https://telegram.me/CHEEMSCMNEWS/132",
            "https://telegram.dog/cheemscmnews/132",
        ];
        for url in urls {
            let parsed = telegram_index_surface(url).expect(url);
            assert_eq!(parsed.canonical, "https://t.me/cheemscmnews/132");
            assert_eq!(parsed.surface, "indexed_post_url");
        }
        let handle = telegram_index_surface("https://telegram.me/TRUONG?start=1").unwrap();
        assert_eq!(handle.canonical, "https://t.me/truong");
        assert_eq!(handle.surface, "indexed_handle_url");
    }

    #[test]
    fn telegram_index_never_turns_generic_directory_pages_into_entity_leads() {
        for url in [
            "https://tgstat.com/channels/search",
            "https://tgstat.com/ratings/posts",
            "https://tgstat.com/search",
            "https://telemetr.io/en/catalog",
            "https://telemetr.io/en/catalog/global",
            "https://tgstat.com/channel/../../admin",
            "https://t.me/TRUONG/0",
            "https://t.me/TRUONG/18446744073709551616",
            "https://t.me/TRUONG/",
        ] {
            assert_eq!(telegram_index_surface(url), None, "{url}");
        }
    }

    #[test]
    fn telegram_index_rejects_invalid_query_before_fetch() {
        let silent = crate::test_support::Silent;
        for query in ["", "bad\nname", "bad\\name"] {
            assert!(telegram_index_search(&silent, query, "s", 1).is_err());
        }
        assert!(telegram_index_search(&silent, &"x".repeat(121), "s", 1).is_err());
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

    /// The FBI's full-text search answers a name with every notice sharing one of its words. Only
    /// a notice whose title or an alias names every word of the query is kept: a head of state is
    /// never shown beside another man's wanted notice because they share a first name.
    #[test]
    fn a_notice_is_kept_only_when_it_names_the_query() {
        let fake = OneResponse::json(
            200,
            r#"{"items":[
              {"title":"MOHAMMED REZA SABAHI","url":"https://www.fbi.gov/wanted/cyber/a"},
              {"title":"AHLAM AHMAD AL-TAMIMI","url":"https://www.fbi.gov/wanted/b"},
              {"title":"JOHN DOE","aliases":["Mohammed bin Rashid Al Maktoum"],"url":"https://www.fbi.gov/wanted/c"}
            ]}"#,
        );
        let report = search(
            &fake,
            Source::Notices,
            "Mohammed bin Rashid Al Maktoum",
            "s",
            1,
        )
        .unwrap();
        assert_eq!(report.entities.len(), 1, "{:?}", report.entities);
        assert_eq!(report.entities[0].value, "https://www.fbi.gov/wanted/c");
    }

    #[test]
    fn official_reward_is_claim_not_guarantee() {
        let fake = OneResponse::json(
            200,
            r#"{"items":[{"title":"Official notice","url":"https://www.fbi.gov/wanted/seeking-info/test","reward_text":"Up to $10,000"}]}"#,
        );
        let report = search(&fake, Source::Notices, "Official notice", "s", 1).unwrap();
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
