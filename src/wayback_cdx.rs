//! Keyless historical URL discovery through the Internet Archive Wayback CDX index, and the
//! contact details the archived pages themselves published.
//!
//! One bounded, read-only GET to the public CDX index yields actual indexed captures, not
//! search links or proof that a historic page's contents are true. Every accepted URL
//! carries its CDX timestamp, digest and replay link as unverified source evidence.
//! Then at most [`archived_page::MAX_PAGES`] of those captures (contact, about and team pages first,
//! then the site root, newest first) that the index did not record as something other than a web
//! page are read from the archive's raw replay (`/web/TIMESTAMP` + `id_/URL`, the bytes as
//! captured), and the e-mail addresses and phone numbers on them become historical leads, each
//! naming the capture it came from. A
//! returned URL is *never fetched* from its own site: it cannot redirect the scanner or
//! reach a local/private host. The only network origin contacted is web.archive.org.

use std::fmt::Write as _;

use crate::archived_page::{self, Admission, Archive, Capture};
use crate::canonical::canonical_domain;
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid, push_entity};
use crate::error::Error;
use crate::fetch::{FetchOptions, Fetched, answer, decode_json, fetch, whole_response};
use crate::http::{Request, Response, Transport, append_query_param};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};

pub const SOURCE: &str = "wayback_cdx";
const API: &str = "https://web.archive.org/cdx/search/cdx";
const ARCHIVE: &str = "https://web.archive.org/web";
const MAX_CAPTURES: usize = 32;
const MAX_JSON_BYTES: usize = 128 * 1024;
const FIELDS: [&str; 5] = ["timestamp", "original", "statuscode", "digest", "mimetype"];
pub use crate::archived_page::Report;

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
    url = append_query_param(&url, "fl", &FIELDS.join(","));
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

/// The captures to read for content, chosen by [`archived_page::choose`] from the URLs found
/// that the index did not record as something other than a web page, and how many it did: a PDF,
/// an archive or an image whose path names a contact page is a historical URL lead, never one of
/// the pages read. A capture the index recorded no type for ([`type_unrecorded`]) can be read, and
/// the replay's own type decides.
fn content_captures(entities: &[Entity]) -> (Vec<Capture>, usize) {
    let mut not_pages = 0usize;
    let captures: Vec<Capture> = entities
        .iter()
        .filter(|entity| entity.kind == EntityKind::Url)
        .flat_map(|entity| &entity.evidence)
        .filter(|evidence| {
            let page = evidence
                .attr_values("capture_mimetype")
                .next()
                .is_none_or(|mimetype| {
                    type_unrecorded(mimetype) || archived_page::is_web_page_type(mimetype)
                });
            not_pages += usize::from(!page);
            page
        })
        .filter_map(|evidence| {
            Some(Capture {
                timestamp: evidence
                    .attr_values("capture_timestamp_utc")
                    .next()?
                    .to_owned(),
                url: evidence.attr_values("original_url").next()?.to_owned(),
            })
        })
        .collect();
    (archived_page::choose(captures), not_pages)
}

/// Whether the index recorded no type of its own for a capture: `-` or `unk`, or a revisit
/// record's `warc/revisit`, which stands for an earlier capture of the same bytes. **Pure.**
fn type_unrecorded(mimetype: &str) -> bool {
    ["-", "unk", "warc/revisit"]
        .iter()
        .any(|unrecorded| mimetype.trim().eq_ignore_ascii_case(unrecorded))
}

/// Read the chosen captures and add the contact details they published to `report`, saying in
/// its outcome's detail how many pages were read, why any was not, and how many captures the
/// index recorded as no web page.
fn read_contents<T: Transport + ?Sized>(
    transport: &T,
    report: &mut Report,
    scan_id: &str,
    now_unix: u64,
) {
    let (captures, not_pages) = content_captures(&report.entities);
    if captures.is_empty() && not_pages == 0 {
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
    if not_pages > 0 {
        let _ = write!(
            detail,
            "; {not_pages} capture(s) the index recorded as no web page, not read"
        );
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
    archived_page::web_page(
        response.header_value("content-type").unwrap_or_default(),
        response.body.len(),
    )?;
    Ok(archived_page::contacts(
        &String::from_utf8_lossy(&response.body),
        capture,
        &Archive {
            source: SOURCE,
            dataset: "Internet Archive Wayback capture content",
            holder: "the Internet Archive",
            snapshot_url: format!("{ARCHIVE}/{}/{}", capture.timestamp, capture.url),
        },
        scan_id,
    ))
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
    if row.len() != FIELDS.len() || !archived_page::valid_timestamp(&row[0]) || row[2] != "200" {
        return Err(failed(
            SourceOutcomeKind::SchemaDrift,
            now_unix,
            status,
            "Wayback CDX capture row violates the documented contract",
        ));
    }
    let (canonical, host) = match archived_page::admit(&row[1], domain) {
        Ok(Admission::Admit { url, host }) => (url, host),
        // Historical session tokens, e-mail addresses and other query values an archived URL
        // exposed are not persisted.
        Ok(Admission::Sensitive) => return Ok(true),
        Err(reason) => {
            return Err(failed(
                SourceOutcomeKind::SemanticDrift,
                now_unix,
                status,
                &format!("Wayback CDX returned {reason}"),
            ));
        }
    };
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
    if !row[4].is_empty() {
        evidence = evidence.with_attr("capture_mimetype", &row[4]);
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
        let body = r#"[["timestamp","original","statuscode","digest","mimetype"],["20200102030405","https://example.org/about","200","ABC","text/html"],["20221231235959","http://old.example.org/","200","DEF","text/html"]]"#;
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
        let body = r#"[["timestamp","original","statuscode","digest","mimetype"],["20200102030405","https://deep.old.example.org/a","200","ABC","text/html"]]"#;
        let report =
            parse_response(&response(body), "example.org", "scan", NOW).expect("nested subdomain");
        assert!(
            report
                .entities
                .iter()
                .any(|e| e.value == "deep.old.example.org")
        );
        let bad = r#"[["timestamp","original","statuscode","digest","mimetype"],["20200102030405","https://fakeexample.org/a","200","ABC","text/html"]]"#;
        assert!(parse_response(&response(bad), "example.org", "scan", NOW).is_err());
    }

    #[test]
    fn valid_empty_index_is_not_a_claim_that_site_never_existed() {
        let body = r#"[["timestamp","original","statuscode","digest","mimetype"]]"#;
        let report = parse_response(&response(body), "example.org", "scan", NOW).expect("zero");
        assert_eq!(report.outcome.kind, SourceOutcomeKind::ValidZero);
        assert!(report.entities.is_empty());
    }

    #[test]
    fn rejects_foreign_hosts_bad_dates_and_schema_drift() {
        for body in [
            r#"[["timestamp","original","statuscode","digest","mimetype"],["20200102030405","https://notexample.org/","200","ABC","text/html"]]"#,
            r#"[["timestamp","original","statuscode","digest","mimetype"],["20200102","https://example.org/","200","ABC","text/html"]]"#,
            r#"[["timestamp","original","statuscode","digest","mimetype"],["20200102030405","https://example.org/","302","ABC","text/html"]]"#,
            r#"[["original","timestamp","statuscode","digest","mimetype"],["https://example.org/","20200102030405","200","ABC","text/html"]]"#,
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
        let body = r#"[["timestamp","original","statuscode","digest","mimetype"],["20200102030405","https://example.org/?token=secret","200","ABC","text/html"],["20200102030406","https://example.org/page","200","DEF","text/html"]]"#;
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
                    r#"[["timestamp","original","statuscode","digest","mimetype"],["20200102030405","https://example.org/a","200","ABC","text/html"]]"#,
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

    const CDX_THREE: &str = r#"[["timestamp","original","statuscode","digest","mimetype"],["20220101000000","https://example.org/blog/post","200","A","text/html"],["20190505050505","https://example.org/contact-us","200","B","text/html"],["20210303030303","https://example.org/","200","C","text/html"]]"#;

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
        assert!(email.confidence <= archived_page::CONFIDENCE_CAP);
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

    /// A capture the index recorded as a PDF, an archive or an image is a historical URL lead, never
    /// one of the pages read, so the contact page further down the list still is.
    #[test]
    fn only_captures_the_index_recorded_as_web_pages_are_read() {
        let cdx = r#"[["timestamp","original","statuscode","digest","mimetype"],["20230101000000","https://example.org/about/annual-report-2023.pdf","200","A","application/pdf"],["20220101000000","https://example.org/support/driver.zip","200","B","application/zip"],["20210101000000","https://example.org/team/group.jpg","200","C","image/jpeg"],["20090101000000","https://example.org/contact","200","D","text/html"]]"#;
        let contact = r#"<html><body><a href="mailto:info%40example.org">us</a></body></html>"#;
        let transport = crate::test_support::ScriptedTransport::new(vec![
            Ok(response(cdx)),
            Ok(page(200, "text/html", contact)),
        ]);
        let report = lookup(&transport, "example.org", "scan", NOW).unwrap();
        let urls: Vec<String> = transport
            .seen
            .borrow()
            .iter()
            .map(|r| r.url.clone())
            .collect();
        assert_eq!(
            &urls[1..],
            ["https://web.archive.org/web/20090101000000id_/https://example.org/contact"]
        );
        assert!(
            report
                .entities
                .iter()
                .any(|e| e.kind == EntityKind::Email && e.value == "info@example.org"),
            "{:?}",
            report.entities
        );
        for (lead, mimetype) in [
            (
                "https://example.org/about/annual-report-2023.pdf",
                "application/pdf",
            ),
            ("https://example.org/support/driver.zip", "application/zip"),
            ("https://example.org/team/group.jpg", "image/jpeg"),
        ] {
            let entity = report
                .entities
                .iter()
                .find(|e| e.kind == EntityKind::Url && e.value == lead)
                .unwrap_or_else(|| panic!("{lead}: {:?}", report.entities));
            assert_eq!(
                entity.evidence[0].attr_values("capture_mimetype").next(),
                Some(mimetype)
            );
        }
        let detail = report.outcome.detail.as_deref().unwrap_or_default();
        assert!(
            detail.contains("archived content: 1 of 1 page(s) read"),
            "{detail}"
        );
        assert!(
            detail.ends_with("; 3 capture(s) the index recorded as no web page, not read"),
            "{detail}"
        );
    }

    /// An index answer with no web page reads none and says so, never leaving the archived
    /// content unaccounted for; a capture the index recorded no type for is read, and its
    /// replay's own type decides.
    #[test]
    fn captures_the_index_typed_as_no_page_are_counted_and_untyped_ones_read() {
        let cdx = r#"[["timestamp","original","statuscode","digest","mimetype"],["20230101000000","https://example.org/about/report.pdf","200","A","application/pdf"],["20220101000000","https://example.org/logo.png","200","B","image/png"]]"#;
        let transport = crate::test_support::ScriptedTransport::new(vec![Ok(response(cdx))]);
        let report = lookup(&transport, "example.org", "scan", NOW).unwrap();
        assert_eq!(transport.seen.borrow().len(), 1);
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
        assert_eq!(
            report.outcome.detail.as_deref(),
            Some(
                "archived content: 0 of 0 page(s) read, 0 contact detail(s) found; \
                 2 capture(s) the index recorded as no web page, not read"
            )
        );

        let cdx = r#"[["timestamp","original","statuscode","digest","mimetype"],["20230101000000","https://example.org/contact","200","A","warc/revisit"],["20220101000000","https://example.org/about","200","B","unk"],["20210101000000","https://example.org/team","200","C",""]]"#;
        let contact = r#"<html><body><a href="mailto:info%40example.org">us</a></body></html>"#;
        let transport = crate::test_support::ScriptedTransport::new(vec![
            Ok(response(cdx)),
            Ok(page(200, "text/html", contact)),
            Ok(page(200, "text/html", contact)),
            Ok(page(200, "text/html", contact)),
        ]);
        let report = lookup(&transport, "example.org", "scan", NOW).unwrap();
        assert_eq!(transport.seen.borrow().len(), 4);
        let detail = report.outcome.detail.as_deref().unwrap_or_default();
        assert!(
            detail.contains("archived content: 3 of 3 page(s) read"),
            "{detail}"
        );
        assert!(!detail.contains("recorded as no web page"), "{detail}");
        for unrecorded in ["-", "UNK", "warc/revisit"] {
            assert!(type_unrecorded(unrecorded), "{unrecorded}");
        }
        assert!(!type_unrecorded("application/pdf"));
    }

    #[test]
    fn no_content_is_fetched_when_the_index_answer_is_not_a_success() {
        let transport = crate::test_support::ScriptedTransport::new(vec![Ok(response(
            r#"[["timestamp","original","statuscode","digest","mimetype"]]"#,
        ))]);
        let report = lookup(&transport, "example.org", "scan", NOW).unwrap();
        assert_eq!(report.outcome.kind, SourceOutcomeKind::ValidZero);
        assert_eq!(transport.seen.borrow().len(), 1);
    }

    #[test]
    fn at_most_three_captures_are_read_contact_pages_first_and_newest_first() {
        let body = r#"[["timestamp","original","statuscode","digest","mimetype"],["20200101000000","https://example.org/a","200","A","text/html"],["20240101000000","https://example.org/b","200","B","text/html"],["20180101000000","https://example.org/about","200","C","text/html"],["20230101000000","https://example.org/team","200","D","text/html"],["20220101000000","https://example.org/","200","E","text/html"]]"#;
        // The site root canonicalises to `https://example.org`.
        let report = parse_response(&response(body), "example.org", "scan", NOW).unwrap();
        let chosen: Vec<String> = content_captures(&report.entities)
            .0
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
