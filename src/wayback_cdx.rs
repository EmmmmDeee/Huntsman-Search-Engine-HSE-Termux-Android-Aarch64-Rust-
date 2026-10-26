//! Keyless historical URL discovery through the Internet Archive Wayback CDX index.
//!
//! One bounded, read-only GET to the public CDX index yields actual indexed captures, not
//! search links or proof that a historic page's contents are true. Every accepted URL
//! carries its CDX timestamp, digest and replay link as unverified source evidence.
//! CDX URLs are *never fetched*: a returned URL cannot redirect the scanner or reach a
//! local/private host. The only network origin contacted is web.archive.org.

use crate::canonical::{canonical_domain, canonical_url};
use crate::domains::host_only;
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
const MAX_URL_BYTES: usize = 2048;
const FIELDS: [&str; 4] = ["timestamp", "original", "statuscode", "digest"];

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
    Ok(interpret(&fetched, &domain, scan_id, now_unix).unwrap_or_else(miss))
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
        if row.len() != FIELDS.len() || !valid_timestamp(&row[0]) || row[2] != "200" {
            return Err(failed(
                SourceOutcomeKind::SchemaDrift,
                now_unix,
                response.status,
                "Wayback CDX capture row violates the documented contract",
            ));
        }
        let original = row[1].as_str();
        if original.len() > MAX_URL_BYTES {
            return Err(failed(
                SourceOutcomeKind::SemanticDrift,
                now_unix,
                response.status,
                "Wayback CDX capture URL exceeds local evidence limits",
            ));
        }
        let Some(canonical) = canonical_url(original) else {
            return Err(failed(
                SourceOutcomeKind::SemanticDrift,
                now_unix,
                response.status,
                "Wayback CDX returned an invalid HTTP(S) URL",
            ));
        };
        let host = host_only(&canonical)
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if host != domain && !host.strip_suffix(domain).is_some_and(|prefix| prefix.ends_with('.')) {
            return Err(failed(
                SourceOutcomeKind::SemanticDrift,
                now_unix,
                response.status,
                "Wayback CDX returned a URL outside the requested domain",
            ));
        }
        // Do not persist historical session tokens, emails or other query values
        // that may have been accidentally exposed in archived URL parameters.
        if original
            .bytes()
            .any(|byte| matches!(byte, b'?' | b'#' | b'@'))
        {
            skipped_query_urls += 1;
            continue;
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
            &mut entities,
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
                &mut entities,
                EntityKind::Domain,
                &host,
                0.55,
                scan_id,
                evidence,
                &[SOURCE, "historical_subdomain"],
            );
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

fn failed(
    kind: SourceOutcomeKind,
    now_unix: u64,
    status: u16,
    detail: &str,
) -> SourceExecutionOutcome {
    SourceExecutionOutcome::failed(SOURCE, now_unix, kind, Some(status), detail)
}

fn valid_timestamp(raw: &str) -> bool {
    raw.len() == 14 && raw.bytes().all(|byte| byte.is_ascii_digit())
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
        let report = parse_response(&response(body), "example.org", "scan", NOW).expect("nested subdomain");
        assert!(report.entities.iter().any(|e| e.value == "deep.old.example.org"));
        let bad = r#"[["timestamp","original","statuscode","digest"],["20200102030405","https://fakeexample.org/a","200","ABC"]]"#;
        assert!(parse_response(&response(bad), "example.org", "scan", NOW).is_err());
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
            assert!(request.url.starts_with(API));
            assert!(request.url.contains("matchType=domain"));
            assert!(!request.url.contains("token"));
            Ok(response(
                r#"[["timestamp","original","statuscode","digest"],["20200102030405","https://example.org/a","200","ABC"]]"#,
            ))
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
}
