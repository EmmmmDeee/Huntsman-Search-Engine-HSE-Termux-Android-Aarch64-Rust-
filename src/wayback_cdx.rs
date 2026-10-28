//! Keyless historical URL discovery through the Internet Archive Wayback CDX index, and the
//! contact details the archived pages themselves published.
//!
//! One bounded, read-only GET to the public CDX index yields actual indexed captures, not
//! search links or proof that a historic page's contents are true. Every accepted URL
//! carries its CDX timestamp, digest and replay link as unverified source evidence.
//! Then at most [`MAX_CONTENT_PAGES`] of those captures (contact, about and team pages first,
//! then the site root, newest first) are read from the archive's raw replay
//! (`/web/TIMESTAMP` + `id_/URL`, the bytes as captured), and the e-mail addresses and phone
//! numbers on them become historical leads, each naming the capture it came from. A
//! returned URL is *never fetched* from its own site: it cannot redirect the scanner or
//! reach a local/private host. The only network origin contacted is web.archive.org.

use crate::canonical::{canonical_domain, canonical_url};
use crate::classifier;
use crate::domains::host_only;
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid, push_entity};
use crate::error::Error;
use crate::fetch::{FetchOptions, Fetched, answer, decode_json, fetch, whole_response};
use crate::html_text::{Markup, Piece, attribute, html_to_text};
use crate::http::{Request, Response, Transport, append_query_param};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};

pub const SOURCE: &str = "wayback_cdx";
const API: &str = "https://web.archive.org/cdx/search/cdx";
const ARCHIVE: &str = "https://web.archive.org/web";
const MAX_CAPTURES: usize = 32;
const MAX_JSON_BYTES: usize = 128 * 1024;
const MAX_URL_BYTES: usize = 2048;
const FIELDS: [&str; 4] = ["timestamp", "original", "statuscode", "digest"];
/// The most archived pages read for their content in one lookup.
pub const MAX_CONTENT_PAGES: usize = 3;
/// The largest archived page read, in bytes; a larger one is not read.
const MAX_PAGE_BYTES: usize = 1024 * 1024;
/// The most text taken from one archived page, in characters.
const MAX_PAGE_CHARS: usize = 200_000;
/// The most contact details kept from one archived page.
const MAX_CONTACTS_PER_PAGE: usize = 32;
/// The ceiling on a contact's confidence: a page's past claim, not a current fact.
const CONTENT_CONFIDENCE_CAP: f64 = 0.6;
/// Path words of the pages that publish contact details, read before any other page.
const CONTACT_WORDS: &[&str] = &[
    "contact",
    "about",
    "team",
    "staff",
    "people",
    "impressum",
    "imprint",
    "support",
];

#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcome: SourceExecutionOutcome,
}

/// Retrieve a bounded sample of historically indexed web pages on this domain.
/// No credentials, crawling of returned pages, or account access.
///
/// # Errors
/// An egress-policy refusal is returned as a network error to the existing domain
/// caller, which records a typed "not sent" source outcome.
pub fn lookup<T: Transport + ?Sized>(
    transport: &T,
    domain: &str,
    scan_id: &str,
    now_unix: u64,
) -> Result<Report, Error> {
    let Some(domain) = canonical_domain(domain) else {
        return Ok(miss(SourceExecutionOutcome::inconclusive(
            SOURCE,
            now_unix,
            "invalid domain selector",
        )));
    };
    let mut url = append_query_param(API, "url", &domain);
    url = append_query_param(&url, "matchType", "domain");
    url = append_query_param(&url, "output", "json");
    url = append_query_param(&url, "fl", "timestamp,original,statuscode,digest");
    url = append_query_param(&url, "filter", "statuscode:200");
    url = append_query_param(&url, "collapse", "urlkey");
    url = append_query_param(&url, "limit", &MAX_CAPTURES.to_string());

    let fetched = fetch(
        transport,
        Request::get(url)
            .header("accept", "application/json")
            .header("user-agent", crate::http::DEFAULT_USER_AGENT),
        None,
        &FetchOptions::no_redirects().paced(),
        SOURCE,
        now_unix,
    )?;
    let mut report = interpret(&fetched, &domain, scan_id, now_unix).unwrap_or_else(miss);
    if report.outcome.kind == SourceOutcomeKind::Success {
        read_contents(transport, &mut report, scan_id, now_unix);
    }
    Ok(report)
}

/// One capture to read: its 14-digit timestamp and its canonical original URL.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Capture {
    timestamp: String,
    url: String,
}

/// The captures to read for content: contact-like pages first, then the site root, then the
/// rest, each group newest first, at most [`MAX_CONTENT_PAGES`].
fn content_captures(entities: &[Entity]) -> Vec<Capture> {
    let mut captures: Vec<(u8, Capture)> = Vec::new();
    for entity in entities
        .iter()
        .filter(|entity| entity.kind == EntityKind::Url)
    {
        for evidence in &entity.evidence {
            let (Some(timestamp), Some(url)) = (
                evidence.attr_values("capture_timestamp_utc").next(),
                evidence.attr_values("original_url").next(),
            ) else {
                continue;
            };
            let path = url
                .split_once("://")
                .and_then(|(_, rest)| rest.split_once('/'))
                .map_or("", |(_, path)| path)
                .to_ascii_lowercase();
            let rank = if CONTACT_WORDS.iter().any(|word| path.contains(word)) {
                0
            } else if path.is_empty() {
                1
            } else {
                2
            };
            let capture = Capture {
                timestamp: timestamp.to_owned(),
                url: url.to_owned(),
            };
            if !captures.iter().any(|(_, seen)| seen.url == capture.url) {
                captures.push((rank, capture));
            }
        }
    }
    captures.sort_by(|(a_rank, a), (b_rank, b)| {
        a_rank
            .cmp(b_rank)
            .then_with(|| b.timestamp.cmp(&a.timestamp))
            .then_with(|| a.url.cmp(&b.url))
    });
    captures
        .into_iter()
        .take(MAX_CONTENT_PAGES)
        .map(|(_, capture)| capture)
        .collect()
}

/// Read the chosen captures and add the contact details they published to `report`, saying in
/// its outcome's detail how many pages were read and why any was not.
fn read_contents<T: Transport + ?Sized>(
    transport: &T,
    report: &mut Report,
    scan_id: &str,
    now_unix: u64,
) {
    let captures = content_captures(&report.entities);
    if captures.is_empty() {
        return;
    }
    let mut read = 0usize;
    let mut found = Vec::new();
    let mut unread = Vec::new();
    for capture in &captures {
        match read_capture(transport, capture, scan_id, now_unix) {
            Ok(entities) => {
                read += 1;
                found.extend(entities);
            }
            Err(reason) => unread.push(reason),
        }
    }
    let contacts = found.len();
    report.entities.extend(found);
    merge_by_uid(&mut report.entities);
    report.outcome.found = Some(report.entities.len());
    let mut detail = format!(
        "archived content: {read} of {} page(s) read, {contacts} contact detail(s) found",
        captures.len()
    );
    if !unread.is_empty() {
        detail.push_str("; not read: ");
        detail.push_str(&unread.join(", "));
    }
    report.outcome.detail = Some(match report.outcome.detail.take() {
        Some(existing) => format!("{existing}; {detail}"),
        None => detail,
    });
}

/// The e-mail addresses and phone numbers one archived page published, or why it was not read.
fn read_capture<T: Transport + ?Sized>(
    transport: &T,
    capture: &Capture,
    scan_id: &str,
    now_unix: u64,
) -> Result<Vec<Entity>, String> {
    let replay = format!("{ARCHIVE}/{}id_/{}", capture.timestamp, capture.url);
    let fetched = fetch(
        transport,
        Request::get(replay)
            .header("accept", "text/html,text/plain;q=0.9")
            .header("user-agent", crate::http::DEFAULT_USER_AGENT),
        None,
        &FetchOptions::no_redirects().paced(),
        SOURCE,
        now_unix,
    )
    .map_err(|_| "egress refused".to_owned())?;
    let response = whole_response(&fetched, "Wayback capture")
        .map_err(|outcome| outcome.kind.as_str().to_owned())?;
    answer(&fetched, "Wayback capture").map_err(|outcome| outcome.kind.as_str().to_owned())?;
    if response.status != 200 {
        return Err(format!("HTTP {}", response.status));
    }
    let content_type = response.header_value("content-type").unwrap_or_default();
    if !(content_type.contains("html") || content_type.starts_with("text/plain")) {
        return Err("not a web page".to_owned());
    }
    if response.body.len() > MAX_PAGE_BYTES {
        return Err("page over 1 MiB".to_owned());
    }
    Ok(page_contacts(
        &String::from_utf8_lossy(&response.body),
        capture,
        scan_id,
    ))
}

/// The e-mail addresses and phone numbers `html` publishes in its text and in its `mailto:` and
/// `tel:` links, each a historical lead naming `capture`. **Pure.**
fn page_contacts(html: &str, capture: &Capture, scan_id: &str) -> Vec<Entity> {
    let mut text = html_to_text(html, MAX_PAGE_CHARS).unwrap_or_default();
    for piece in Markup::new(html) {
        let Piece::Tag {
            name,
            end: false,
            attrs,
        } = piece
        else {
            continue;
        };
        if !name.eq_ignore_ascii_case("a") {
            continue;
        }
        let Some(href) = attribute(attrs, "href") else {
            continue;
        };
        let href = crate::textnorm::decode_html_entities(href.trim());
        let target = href
            .strip_prefix("mailto:")
            .or_else(|| href.strip_prefix("tel:"))
            .map(|rest| {
                rest.split(['?', '#'])
                    .next()
                    .unwrap_or_default()
                    .replace("%40", "@")
                    .replace("%20", " ")
            });
        if let Some(target) = target {
            text.push(' ');
            text.push_str(&target);
        }
    }
    let snapshot = format!("{ARCHIVE}/{}/{}", capture.timestamp, capture.url);
    let mut entities = Vec::new();
    for found in classifier::extract(&text)
        .into_iter()
        .filter(|found| {
            found.is_actionable() && matches!(found.kind, EntityKind::Email | EntityKind::Phone)
        })
        .take(MAX_CONTACTS_PER_PAGE)
    {
        let evidence = Evidence::new(
            EvidenceProvenance::for_scan(SOURCE, scan_id),
            format!(
                "published on {} as archived by the Internet Archive at {} UTC (historical; not proof it is current)",
                capture.url, capture.timestamp
            ),
        )
        .with_attr("dataset", "Internet Archive Wayback capture content")
        .with_attr("capture_timestamp_utc", &capture.timestamp)
        .with_attr("original_url", &capture.url)
        .with_attr("archive_snapshot_url", &snapshot)
        .with_attr("signal", found.signal);
        push_entity(
            &mut entities,
            found.kind,
            &found.value,
            found.confidence.min(CONTENT_CONFIDENCE_CAP),
            scan_id,
            evidence,
            &[SOURCE, "historical_content"],
        );
    }
    entities
}

fn miss(outcome: SourceExecutionOutcome) -> Report {
    Report {
        entities: Vec::new(),
        outcome,
    }
}

fn interpret(
    fetched: &Fetched,
    domain: &str,
    scan_id: &str,
    now_unix: u64,
) -> Result<Report, SourceExecutionOutcome> {
    let response = whole_response(fetched, "Wayback CDX")?;
    answer(fetched, "Wayback CDX")?;
    parse_response(response, domain, scan_id, now_unix)
}

/// Pure CDX contract validation: malformed/foreign rows are not corroboration.
fn parse_response(
    response: &Response,
    domain: &str,
    scan_id: &str,
    now_unix: u64,
) -> Result<Report, SourceExecutionOutcome> {
    if response.body.len() > MAX_JSON_BYTES {
        return Err(failed(
            SourceOutcomeKind::ParserDrift,
            now_unix,
            response.status,
            "Wayback CDX response exceeds the per-source JSON limit",
        ));
    }
    let rows: Vec<Vec<String>> = decode_json(response, SOURCE, now_unix, "Wayback CDX")?;
    if !rows
        .first()
        .is_some_and(|header| header.iter().map(String::as_str).eq(FIELDS))
        || rows.len() > MAX_CAPTURES + 1
    {
        return Err(failed(
            SourceOutcomeKind::SchemaDrift,
            now_unix,
            response.status,
            "Wayback CDX header, columns or row bound changed",
        ));
    }
    if rows.len() == 1 {
        return Ok(miss(
            SourceExecutionOutcome::valid_zero(SOURCE, now_unix).with_http_status(response.status),
        ));
    }

    // All rows are validated before admitting any evidence. This is intentionally
    // fail-closed for provider drift; one bad capture cannot taint a saved report.
    let mut entities = Vec::new();
    let mut skipped_query_urls = 0usize;
    for row in rows.iter().skip(1) {
        if parse_capture(
            row,
            domain,
            scan_id,
            now_unix,
            response.status,
            &mut entities,
        )? {
            skipped_query_urls += 1;
        }
    }
    if entities.is_empty() {
        return Err(failed(
            SourceOutcomeKind::Inconclusive,
            now_unix,
            response.status,
            "Wayback CDX returned captures but none had safe evidence URLs",
        ));
    }
    merge_by_uid(&mut entities);
    let mut outcome = SourceExecutionOutcome::success(SOURCE, now_unix, entities.len())
        .with_http_status(response.status);
    if skipped_query_urls != 0 {
        outcome = outcome.with_detail(format!(
            "{skipped_query_urls} URLs with query, fragment or user-info were excluded"
        ));
    }
    Ok(Report { entities, outcome })
}

/// Validate and record one CDX capture, returning true only for a deliberately
/// excluded sensitive URL. No evidence is admitted for an invalid CDX capture.
fn parse_capture(
    row: &[String],
    domain: &str,
    scan_id: &str,
    now_unix: u64,
    status: u16,
    entities: &mut Vec<Entity>,
) -> Result<bool, SourceExecutionOutcome> {
    if row.len() != FIELDS.len() || !valid_timestamp(&row[0]) || row[2] != "200" {
        return Err(failed(
            SourceOutcomeKind::SchemaDrift,
            now_unix,
            status,
            "Wayback CDX capture row violates the documented contract",
        ));
    }
    let original = row[1].as_str();
    if original.len() > MAX_URL_BYTES {
        return Err(failed(
            SourceOutcomeKind::SemanticDrift,
            now_unix,
            status,
            "Wayback CDX capture URL exceeds local evidence limits",
        ));
    }
    let Some(canonical) = canonical_url(original) else {
        return Err(failed(
            SourceOutcomeKind::SemanticDrift,
            now_unix,
            status,
            "Wayback CDX returned an invalid HTTP(S) URL",
        ));
    };
    let host = host_only(&canonical)
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if host != domain
        && !host
            .strip_suffix(domain)
            .is_some_and(|prefix| prefix.ends_with('.'))
    {
        return Err(failed(
            SourceOutcomeKind::SemanticDrift,
            now_unix,
            status,
            "Wayback CDX returned a URL outside the requested domain",
        ));
    }
    // Do not persist historical session tokens, emails or other query values
    // that may have been accidentally exposed in archived URL parameters.
    if original
        .bytes()
        .any(|byte| matches!(byte, b'?' | b'#' | b'@'))
    {
        return Ok(true);
    }
    let timestamp = &row[0];
    let mut evidence = Evidence::new(
        EvidenceProvenance::for_scan(SOURCE, scan_id),
        "URL observed in the Internet Archive CDX index (historical, unverified)",
    )
    .with_attr("dataset", "Internet Archive Wayback CDX")
    .with_attr("capture_timestamp_utc", timestamp)
    .with_attr("original_url", &canonical)
    .with_attr("capture_http_status", "200")
    .with_attr(
        "archive_snapshot_url",
        format!("{ARCHIVE}/{timestamp}/{canonical}"),
    );
    if !row[3].is_empty() {
        evidence = evidence.with_attr("cdx_digest", &row[3]);
    }
    push_entity(
        entities,
        EntityKind::Url,
        &canonical,
        0.65,
        scan_id,
        evidence.clone(),
        &[SOURCE, "historical_capture"],
    );
    // Historical subdomains are leads, not currently resolving infrastructure.
    if host != domain {
        push_entity(
            entities,
            EntityKind::Domain,
            &host,
            0.55,
            scan_id,
            evidence,
            &[SOURCE, "historical_subdomain"],
        );
    }
    Ok(false)
}

fn failed(
    kind: SourceOutcomeKind,
    now_unix: u64,
    status: u16,
    detail: &str,
) -> SourceExecutionOutcome {
    SourceExecutionOutcome::failed(SOURCE, now_unix, kind, Some(status), detail)
}

fn valid_timestamp(raw: &str) -> bool {
    if raw.len() != 14 || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    let parse = |start: usize, end: usize| raw[start..end].parse::<u32>().ok();
    let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) = (
        parse(0, 4),
        parse(4, 6),
        parse(6, 8),
        parse(8, 10),
        parse(10, 12),
        parse(12, 14),
    ) else {
        return false;
    };
    if year == 0 || hour > 23 || minute > 59 || second > 59 {
        return false;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1..=days).contains(&day)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{Response, TransportFailure};

    const NOW: u64 = 1_800_000_000;

    fn response(body: &str) -> Response {
        Response {
            status: 200,
            headers: Vec::new(),
            body: body.as_bytes().to_vec(),
            truncated: false,
        }
    }

    #[test]
    fn accepts_indexed_urls_and_historical_subdomain_pivots() {
        let body = r#"[["timestamp","original","statuscode","digest"],["20200102030405","https://example.org/about","200","ABC"],["20221231235959","http://old.example.org/","200","DEF"]]"#;
        let report =
            parse_response(&response(body), "example.org", "scan", NOW).expect("CDX contract");
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
        assert_eq!(report.entities.len(), 3);
        assert!(
            report
                .entities
                .iter()
                .any(|e| e.kind == EntityKind::Domain && e.value == "old.example.org")
        );
        assert!(report.entities.iter().any(|e| e.evidence.iter().any(|ev| {
            ev.attr_values("capture_timestamp_utc")
                .any(|a| a == "20200102030405")
        })));
    }

    #[test]
    fn domain_boundary_accepts_only_actual_subdomains() {
        let body = r#"[["timestamp","original","statuscode","digest"],["20200102030405","https://deep.old.example.org/a","200","ABC"]]"#;
        let report =
            parse_response(&response(body), "example.org", "scan", NOW).expect("nested subdomain");
        assert!(
            report
                .entities
                .iter()
                .any(|e| e.value == "deep.old.example.org")
        );
        let bad = r#"[["timestamp","original","statuscode","digest"],["20200102030405","https://fakeexample.org/a","200","ABC"]]"#;
        assert!(parse_response(&response(bad), "example.org", "scan", NOW).is_err());
    }

    #[test]
    fn timestamp_rejects_impossible_calendar_dates_and_times() {
        for invalid in [
            "00000101000000",
            "20261301000000",
            "20260001000000",
            "20260431000000",
            "20230229000000",
            "19000229000000",
            "20240230000000",
            "20240101240000",
            "20240101236000",
            "20240101235960",
            "2024010123595x",
        ] {
            assert!(!valid_timestamp(invalid), "{invalid}");
        }
        for valid in ["20000229000000", "20240229235959", "20241231235959"] {
            assert!(valid_timestamp(valid), "{valid}");
        }
    }

    #[test]
    fn valid_empty_index_is_not_a_claim_that_site_never_existed() {
        let body = r#"[["timestamp","original","statuscode","digest"]]"#;
        let report = parse_response(&response(body), "example.org", "scan", NOW).expect("zero");
        assert_eq!(report.outcome.kind, SourceOutcomeKind::ValidZero);
        assert!(report.entities.is_empty());
    }

    #[test]
    fn rejects_foreign_hosts_bad_dates_and_schema_drift() {
        for body in [
            r#"[["timestamp","original","statuscode","digest"],["20200102030405","https://notexample.org/","200","ABC"]]"#,
            r#"[["timestamp","original","statuscode","digest"],["20200102","https://example.org/","200","ABC"]]"#,
            r#"[["timestamp","original","statuscode","digest"],["20200102030405","https://example.org/","302","ABC"]]"#,
            r#"[["original","timestamp","statuscode","digest"],["https://example.org/","20200102030405","200","ABC"]]"#,
            r#"{"error":"rate limit"}"#,
        ] {
            assert!(
                parse_response(&response(body), "example.org", "scan", NOW).is_err(),
                "{body}"
            );
        }
    }

    #[test]
    fn excludes_sensitive_query_urls_without_losing_other_captures() {
        let body = r#"[["timestamp","original","statuscode","digest"],["20200102030405","https://example.org/?token=secret","200","ABC"],["20200102030406","https://example.org/page","200","DEF"]]"#;
        let report =
            parse_response(&response(body), "example.org", "scan", NOW).expect("safe subset");
        assert_eq!(report.entities.len(), 1);
        assert!(!format!("{report:?}").contains("secret"));
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
    }

    struct NetworkStub;
    impl Transport for NetworkStub {
        fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
            assert!(!request.url.contains("token"));
            assert!(request.header_value("authorization").is_none());
            // The index, then the capture it named, both from the archive and nowhere else.
            if request.url.starts_with(API) {
                assert!(request.url.contains("matchType=domain"));
                return Ok(response(
                    r#"[["timestamp","original","statuscode","digest"],["20200102030405","https://example.org/a","200","ABC"]]"#,
                ));
            }
            assert_eq!(
                request.url,
                "https://web.archive.org/web/20200102030405id_/https://example.org/a"
            );
            Ok(page(200, "text/html", "<p>no contact here</p>"))
        }
    }

    #[test]
    fn live_adapter_uses_exact_archival_origin_without_credentials() {
        let report = lookup(&NetworkStub, "example.org", "scan", NOW).expect("transport");
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
        assert!(
            report
                .entities
                .iter()
                .any(|e| e.value == "https://example.org/a")
        );
    }

    fn page(status: u16, content_type: &str, body: &str) -> Response {
        Response {
            status,
            headers: vec![("content-type".to_owned(), content_type.to_owned())],
            body: body.as_bytes().to_vec(),
            truncated: false,
        }
    }

    const CDX_THREE: &str = r#"[["timestamp","original","statuscode","digest"],["20220101000000","https://example.org/blog/post","200","A"],["20190505050505","https://example.org/contact-us","200","B"],["20210303030303","https://example.org/","200","C"]]"#;

    /// The contact page is read first, then the root, then the rest, each from the archive's raw
    /// replay; the contacts it published become historical leads naming the capture, and a page
    /// the archive refused or that is not a web page is named, never read as an absence.
    #[test]
    fn archived_pages_yield_historical_contact_leads_naming_their_capture() {
        let contact = r#"<html><head><script>var spam="evil@attacker.test";</script><style>.a{}</style></head><body>
<p>Write to <a href="mailto:info%40example.org?subject=hello">us</a> or call +61 491 570 006.</p>
<img src="logo@2x.png"><!-- old@example.org --></body></html>"#;
        let transport = crate::test_support::ScriptedTransport::new(vec![
            Ok(response(CDX_THREE)),
            Ok(page(200, "text/html; charset=utf-8", contact)),
            Ok(page(404, "text/html", "gone")),
            Ok(page(200, "image/png", "PNG")),
        ]);
        let report = lookup(&transport, "example.org", "scan", NOW).unwrap();
        let urls: Vec<String> = transport
            .seen
            .borrow()
            .iter()
            .map(|r| r.url.clone())
            .collect();
        assert_eq!(urls.len(), 4, "{urls:?}");
        assert!(urls[0].starts_with(API));
        assert_eq!(
            &urls[1..],
            [
                "https://web.archive.org/web/20190505050505id_/https://example.org/contact-us",
                "https://web.archive.org/web/20210303030303id_/https://example.org",
                "https://web.archive.org/web/20220101000000id_/https://example.org/blog/post",
            ]
        );
        let lead = |kind: EntityKind, value: &str| {
            report
                .entities
                .iter()
                .find(|e| e.kind == kind && e.value == value)
                .unwrap_or_else(|| panic!("{value}: {:?}", report.entities))
        };
        let email = lead(EntityKind::Email, "info@example.org");
        assert!(email.has_tag("historical_content"));
        assert!(email.confidence <= CONTENT_CONFIDENCE_CAP);
        let evidence = &email.evidence[0];
        assert_eq!(
            evidence.attr_values("capture_timestamp_utc").next(),
            Some("20190505050505")
        );
        assert_eq!(
            evidence.attr_values("archive_snapshot_url").next(),
            Some("https://web.archive.org/web/20190505050505/https://example.org/contact-us")
        );
        assert!(evidence.summary.contains("not proof it is current"));
        assert!(
            report
                .entities
                .iter()
                .any(|e| e.kind == EntityKind::Phone && e.has_tag("historical_content")),
            "{:?}",
            report.entities
        );
        // Script text, comments and an image name are not published contacts.
        for absent in ["evil@attacker.test", "old@example.org", "logo@2x.png"] {
            assert!(
                !report.entities.iter().any(|e| e.value.contains(absent)),
                "{absent}"
            );
        }
        let detail = report.outcome.detail.as_deref().unwrap_or_default();
        assert!(
            detail.contains("archived content: 1 of 3 page(s) read")
                && detail.contains("not a web page"),
            "{detail}"
        );
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
    }

    #[test]
    fn no_content_is_fetched_when_the_index_answer_is_not_a_success() {
        let transport = crate::test_support::ScriptedTransport::new(vec![Ok(response(
            r#"[["timestamp","original","statuscode","digest"]]"#,
        ))]);
        let report = lookup(&transport, "example.org", "scan", NOW).unwrap();
        assert_eq!(report.outcome.kind, SourceOutcomeKind::ValidZero);
        assert_eq!(transport.seen.borrow().len(), 1);
    }

    #[test]
    fn at_most_three_captures_are_read_contact_pages_first_and_newest_first() {
        let body = r#"[["timestamp","original","statuscode","digest"],["20200101000000","https://example.org/a","200","A"],["20240101000000","https://example.org/b","200","B"],["20180101000000","https://example.org/about","200","C"],["20230101000000","https://example.org/team","200","D"],["20220101000000","https://example.org/","200","E"]]"#;
        // The site root canonicalises to `https://example.org`.
        let report = parse_response(&response(body), "example.org", "scan", NOW).unwrap();
        let chosen: Vec<String> = content_captures(&report.entities)
            .into_iter()
            .map(|capture| capture.url)
            .collect();
        assert_eq!(
            chosen,
            [
                "https://example.org/team",
                "https://example.org/about",
                "https://example.org"
            ]
        );
    }
}
