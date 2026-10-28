//! Keyless historical URL discovery through the Common Crawl index of the newest crawl, and the
//! contact details the crawled pages themselves published.
//!
//! Three bounded, read-only steps, all to Common Crawl's own origins:
//! 1. the collection list (`index.commoncrawl.org/collinfo.json`) names the newest crawl;
//! 2. that crawl's CDX index lists at most [`MAX_CAPTURES`] HTML captures of the domain and its
//!    subdomains, each with the WARC file, offset and length holding it;
//! 3. at most [`archived_page::MAX_PAGES`] of those records (contact, about and team pages
//!    first) are read by HTTP range from `data.commoncrawl.org`, inflated, checked against their
//!    gzip CRC and their WARC target URI, and their e-mail addresses and phone numbers become
//!    historical leads through [`archived_page::contacts`], the reader the Wayback source uses.
//!
//! A captured URL is *never fetched* from its own site. What a crawl saw is what a page said on
//! the crawl date, not a claim that it is still true; an empty index is not proof that a site
//! never existed.

use crate::archived_page::{self, Admission, Archive, Capture};
use crate::canonical::{canonical_domain, canonical_url};
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid, push_entity};
use crate::error::Error;
use crate::fetch::{FetchOptions, Fetched, answer, decode_json, fetch, whole_response};
use crate::http::{Request, Response, Transport, append_query_param};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};
use serde_json::Value;

pub const SOURCE: &str = "common_crawl";
const COLLECTIONS: &str = "https://index.commoncrawl.org/collinfo.json";
const INDEX: &str = "https://index.commoncrawl.org";
const DATA: &str = "https://data.commoncrawl.org";
/// Index captures listed per lookup.
pub const MAX_CAPTURES: usize = 32;
/// Largest collection list or index answer read.
const MAX_INDEX_BYTES: usize = 256 * 1024;
/// Largest compressed WARC record read by range; a larger one is named, never read in part.
const MAX_RECORD_BYTES: u64 = 1024 * 1024;
/// Largest inflated WARC record: headers plus the page body bound.
const MAX_INFLATED_BYTES: usize = archived_page::MAX_PAGE_BYTES + 64 * 1024;
const FIELDS: &str = "url,timestamp,status,mime,filename,offset,length,digest";
const DATASET: &str = "Common Crawl CDX index";

pub use crate::archived_page::Report;

/// Retrieve a bounded sample of the domain's pages captured by the newest Common Crawl, and the
/// contacts the most telling of them published.
///
/// # Errors
/// An egress-policy refusal of the collection list or index, for the caller to record as a typed
/// "not sent" outcome.
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
    let fetched = get(
        transport,
        COLLECTIONS.to_owned(),
        "application/json",
        now_unix,
    )?;
    let crawl = match newest_crawl(&fetched, now_unix) {
        Ok(crawl) => crawl,
        Err(outcome) => return Ok(miss(outcome)),
    };
    let mut url = append_query_param(&format!("{INDEX}/{crawl}-index"), "url", &domain);
    url = append_query_param(&url, "matchType", "domain");
    url = append_query_param(&url, "output", "json");
    url = append_query_param(&url, "fl", FIELDS);
    url = append_query_param(&url, "filter", "=status:200");
    url = append_query_param(&url, "filter", "mime:html");
    url = append_query_param(&url, "limit", &MAX_CAPTURES.to_string());
    let fetched = get(transport, url, "application/json", now_unix)?;
    let mut report = match index_answer(&fetched, &domain, &crawl, scan_id, now_unix) {
        Ok(report) => report,
        Err(outcome) => miss(outcome),
    };
    if report.outcome.kind == SourceOutcomeKind::Success {
        read_contents(transport, &mut report, &crawl, scan_id, now_unix);
    }
    Ok(report)
}

fn get<T: Transport + ?Sized>(
    transport: &T,
    url: String,
    accept: &str,
    now_unix: u64,
) -> Result<Fetched, Error> {
    fetch(
        transport,
        Request::get(url)
            .header("accept", accept)
            .header("user-agent", crate::http::DEFAULT_USER_AGENT),
        None,
        &FetchOptions::no_redirects().paced(),
        SOURCE,
        now_unix,
    )
}

fn miss(outcome: SourceExecutionOutcome) -> Report {
    Report {
        entities: Vec::new(),
        outcome,
    }
}

fn failed(
    kind: SourceOutcomeKind,
    now_unix: u64,
    status: u16,
    detail: &str,
) -> SourceExecutionOutcome {
    SourceExecutionOutcome::failed(SOURCE, now_unix, kind, Some(status), detail)
}

/// Whether `id` is a main crawl's name, `CC-MAIN-YYYY-WW`. **Pure.**
fn crawl_id(id: &str) -> bool {
    id.strip_prefix("CC-MAIN-").is_some_and(|rest| {
        let bytes = rest.as_bytes();
        bytes.len() == 7
            && bytes[4] == b'-'
            && bytes
                .iter()
                .enumerate()
                .all(|(at, byte)| at == 4 || byte.is_ascii_digit())
    })
}

/// The newest main crawl the collection list names: the greatest valid id, whatever the list's
/// order. **Pure** over the fetched answer.
fn newest_crawl(fetched: &Fetched, now_unix: u64) -> Result<String, SourceExecutionOutcome> {
    let response = whole_response(fetched, "Common Crawl collection list")?;
    answer(fetched, "Common Crawl collection list")?;
    if response.body.len() > MAX_INDEX_BYTES {
        return Err(failed(
            SourceOutcomeKind::ParserDrift,
            now_unix,
            response.status,
            "Common Crawl collection list exceeds the per-source JSON limit",
        ));
    }
    let collections: Vec<Value> =
        decode_json(response, SOURCE, now_unix, "Common Crawl collection list")?;
    collections
        .iter()
        .filter_map(|collection| collection.get("id")?.as_str())
        .filter(|id| crawl_id(id))
        .max()
        .map(str::to_owned)
        .ok_or_else(|| {
            failed(
                SourceOutcomeKind::SchemaDrift,
                now_unix,
                response.status,
                "Common Crawl collection list names no CC-MAIN crawl",
            )
        })
}

/// The index answer as a report. A `404` whose JSON says no captures were found is the
/// documented empty answer, a valid zero. **Pure** over the fetched answer.
fn index_answer(
    fetched: &Fetched,
    domain: &str,
    crawl: &str,
    scan_id: &str,
    now_unix: u64,
) -> Result<Report, SourceExecutionOutcome> {
    let response = whole_response(fetched, "Common Crawl index")?;
    if response.status == 404 && no_captures(response) {
        return Ok(miss(
            SourceExecutionOutcome::valid_zero(SOURCE, now_unix)
                .with_http_status(404)
                .with_detail(format!("no {crawl} capture of {domain}")),
        ));
    }
    answer(fetched, "Common Crawl index")?;
    parse_index(response, domain, crawl, scan_id, now_unix)
}

/// Whether a `404` body is the CDX server's own "No Captures found" document. **Pure.**
fn no_captures(response: &Response) -> bool {
    serde_json::from_slice::<Value>(&response.body).is_ok_and(|document| {
        ["message", "error"].iter().any(|key| {
            document
                .get(key)
                .and_then(Value::as_str)
                .is_some_and(|text| text.starts_with("No Captures found"))
        })
    })
}

/// One index line's WARC location.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Record {
    filename: String,
    offset: u64,
    length: u64,
}

/// A field the index gives as a decimal string (or a number). **Pure.**
fn integer(line: &Value, key: &str) -> Option<u64> {
    match line.get(key)? {
        Value::String(text) if !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) => {
            text.parse().ok()
        }
        Value::Number(number) => number.as_u64(),
        _ => None,
    }
}

/// Whether `filename` is a WARC file of `crawl`'s own data tree: no traversal, no other crawl, no
/// other kind of file. **Pure.**
fn warc_filename(filename: &str, crawl: &str) -> bool {
    filename
        .strip_prefix("crawl-data/")
        .and_then(|rest| rest.strip_prefix(crawl))
        .is_some_and(|rest| rest.starts_with('/'))
        && filename.ends_with(".warc.gz")
        && !filename.contains("..")
        && !filename.contains("//")
        && filename
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'-' | b'_'))
}

/// One validated index line.
struct IndexLine {
    url: String,
    host: String,
    timestamp: String,
    filename: String,
    offset: u64,
    length: u64,
    digest: String,
}

/// One index line checked against the documented contract: `None` for a URL withheld because
/// it carries a query, fragment or user-info, or the drift kind and detail. **Pure.**
fn index_line(
    line: &str,
    domain: &str,
    crawl: &str,
) -> Result<Option<IndexLine>, (SourceOutcomeKind, String)> {
    let Ok(line) = serde_json::from_str::<Value>(line) else {
        return Err((
            SourceOutcomeKind::ParserDrift,
            "Common Crawl index line is not JSON".to_owned(),
        ));
    };
    let field = |key: &str| line.get(key).and_then(Value::as_str).unwrap_or_default();
    let (Some(offset), Some(length)) = (integer(&line, "offset"), integer(&line, "length")) else {
        return Err((
            SourceOutcomeKind::SchemaDrift,
            "Common Crawl index line lacks a WARC offset or length".to_owned(),
        ));
    };
    if !archived_page::valid_timestamp(field("timestamp"))
        || field("status") != "200"
        || !warc_filename(field("filename"), crawl)
        || length == 0
    {
        return Err((
            SourceOutcomeKind::SchemaDrift,
            "Common Crawl index line violates the documented contract".to_owned(),
        ));
    }
    match archived_page::admit(field("url"), domain) {
        Ok(Admission::Admit { url, host }) => Ok(Some(IndexLine {
            url,
            host,
            timestamp: field("timestamp").to_owned(),
            filename: field("filename").to_owned(),
            offset,
            length,
            digest: field("digest").to_owned(),
        })),
        Ok(Admission::Sensitive) => Ok(None),
        Err(reason) => Err((
            SourceOutcomeKind::SemanticDrift,
            format!("Common Crawl index returned {reason}"),
        )),
    }
}

/// Pure index contract validation: every line is checked before any is admitted, so provider
/// drift cannot leave part of a bad answer in a saved report.
fn parse_index(
    response: &Response,
    domain: &str,
    crawl: &str,
    scan_id: &str,
    now_unix: u64,
) -> Result<Report, SourceExecutionOutcome> {
    let drift = |kind, detail: &str| failed(kind, now_unix, response.status, detail);
    if response.body.len() > MAX_INDEX_BYTES {
        return Err(drift(
            SourceOutcomeKind::ParserDrift,
            "Common Crawl index answer exceeds the per-source JSON limit",
        ));
    }
    let text = String::from_utf8_lossy(&response.body);
    let lines: Vec<&str> = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    if lines.len() > MAX_CAPTURES {
        return Err(drift(
            SourceOutcomeKind::SchemaDrift,
            "Common Crawl index ignored the capture limit",
        ));
    }
    if lines.is_empty() {
        return Ok(miss(
            SourceExecutionOutcome::valid_zero(SOURCE, now_unix).with_http_status(response.status),
        ));
    }
    let mut entities = Vec::new();
    let mut withheld = 0usize;
    for line in lines {
        let capture = match index_line(line, domain, crawl) {
            Ok(Some(capture)) => capture,
            Ok(None) => {
                withheld += 1;
                continue;
            }
            Err((kind, detail)) => return Err(drift(kind, &detail)),
        };
        let IndexLine {
            url,
            host,
            timestamp,
            filename,
            offset,
            length,
            digest,
        } = capture;
        let mut evidence = Evidence::new(
            EvidenceProvenance::for_scan(SOURCE, scan_id),
            format!("URL captured by Common Crawl {crawl} (historical, unverified)"),
        )
        .with_attr("dataset", DATASET)
        .with_attr("crawl", crawl)
        .with_attr("capture_timestamp_utc", timestamp)
        .with_attr("original_url", &url)
        .with_attr("capture_http_status", "200")
        .with_attr("warc_filename", filename)
        .with_attr("warc_offset", offset.to_string())
        .with_attr("warc_length", length.to_string());
        if !digest.is_empty() {
            evidence = evidence.with_attr("cdx_digest", digest);
        }
        push_entity(
            &mut entities,
            EntityKind::Url,
            &url,
            0.65,
            scan_id,
            evidence.clone(),
            &[SOURCE, "historical_capture"],
        );
        // A historical subdomain is a lead, not currently resolving infrastructure.
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
        return Err(drift(
            SourceOutcomeKind::Inconclusive,
            "Common Crawl returned captures but none had a safe evidence URL",
        ));
    }
    merge_by_uid(&mut entities);
    let mut outcome = SourceExecutionOutcome::success(SOURCE, now_unix, entities.len())
        .with_http_status(response.status)
        .with_detail(format!("crawl {crawl}"));
    if withheld != 0 {
        outcome = outcome.with_detail(format!(
            "crawl {crawl}; {withheld} URLs with query, fragment or user-info were excluded"
        ));
    }
    Ok(Report { entities, outcome })
}

/// The captures to read and where each record lies, chosen by [`archived_page::choose`].
fn content_records(entities: &[Entity]) -> Vec<(Capture, Record)> {
    let mut located: Vec<(Capture, Record)> = Vec::new();
    for evidence in entities
        .iter()
        .filter(|entity| entity.kind == EntityKind::Url)
        .flat_map(|entity| &entity.evidence)
    {
        let attr = |key: &str| evidence.attr_values(key).next();
        let (Some(timestamp), Some(url), Some(filename), Some(offset), Some(length)) = (
            attr("capture_timestamp_utc"),
            attr("original_url"),
            attr("warc_filename"),
            attr("warc_offset").and_then(|v| v.parse().ok()),
            attr("warc_length").and_then(|v| v.parse().ok()),
        ) else {
            continue;
        };
        located.push((
            Capture {
                timestamp: timestamp.to_owned(),
                url: url.to_owned(),
            },
            Record {
                filename: filename.to_owned(),
                offset,
                length,
            },
        ));
    }
    archived_page::choose(located.iter().map(|(capture, _)| capture.clone()))
        .into_iter()
        .filter_map(|capture| {
            located
                .iter()
                .find(|(seen, _)| *seen == capture)
                .map(|(_, record)| (capture, record.clone()))
        })
        .collect()
}

/// Read the chosen records and add the contacts they published to `report`, saying in its
/// outcome's detail how many pages were read and why any was not.
fn read_contents<T: Transport + ?Sized>(
    transport: &T,
    report: &mut Report,
    crawl: &str,
    scan_id: &str,
    now_unix: u64,
) {
    let records = content_records(&report.entities);
    if records.is_empty() {
        return;
    }
    let mut read = 0usize;
    let mut found = Vec::new();
    let mut unread = Vec::new();
    for (capture, record) in &records {
        match read_record(transport, capture, record, crawl, scan_id, now_unix) {
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
        "crawled content: {read} of {} page(s) read, {contacts} contact detail(s) found",
        records.len()
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

/// The contacts one crawled page published, or why it was not read.
fn read_record<T: Transport + ?Sized>(
    transport: &T,
    capture: &Capture,
    record: &Record,
    crawl: &str,
    scan_id: &str,
    now_unix: u64,
) -> Result<Vec<Entity>, String> {
    if record.length > MAX_RECORD_BYTES {
        return Err("record over 1 MiB".to_owned());
    }
    let last = record
        .offset
        .checked_add(record.length - 1)
        .ok_or_else(|| "record offset out of range".to_owned())?;
    let fetched = fetch(
        transport,
        Request::get(format!("{DATA}/{}", record.filename))
            .header("range", format!("bytes={}-{last}", record.offset))
            .header("user-agent", crate::http::DEFAULT_USER_AGENT),
        None,
        &FetchOptions::no_redirects().paced(),
        SOURCE,
        now_unix,
    )
    .map_err(|_| "egress refused".to_owned())?;
    let response = whole_response(&fetched, "Common Crawl record")
        .map_err(|outcome| outcome.kind.as_str().to_owned())?;
    answer(&fetched, "Common Crawl record").map_err(|outcome| outcome.kind.as_str().to_owned())?;
    if response.status != 206 || u64::try_from(response.body.len()).ok() != Some(record.length) {
        return Err(format!("HTTP {} not the requested range", response.status));
    }
    let warc = gunzip_member(&response.body, MAX_INFLATED_BYTES)?;
    let page = warc_response(&warc)?;
    if page.target.as_deref().and_then(canonical_url).as_deref() != Some(capture.url.as_str()) {
        return Err("record names another URL".to_owned());
    }
    archived_page::web_page(&page.content_type, page.body.len())?;
    Ok(archived_page::contacts(
        &String::from_utf8_lossy(page.body),
        capture,
        &Archive {
            source: SOURCE,
            dataset: "Common Crawl WARC record content",
            holder: "Common Crawl",
            snapshot_url: format!(
                "{DATA}/{} (bytes {}-{last}, {crawl})",
                record.filename, record.offset
            ),
        },
        scan_id,
    ))
}

/// One gzip member (RFC 1952) inflated to at most `limit` bytes and checked against its CRC-32
/// and length. **Pure.**
///
/// # Errors
/// Why the bytes are not one intact member within the limit.
fn gunzip_member(bytes: &[u8], limit: usize) -> Result<Vec<u8>, String> {
    const FHCRC: u8 = 2;
    const FEXTRA: u8 = 4;
    const FNAME: u8 = 8;
    const FCOMMENT: u8 = 16;
    let malformed = || "record is not a gzip member".to_owned();
    if bytes.len() < 18 || bytes[..3] != [0x1f, 0x8b, 8] || bytes[3] & 0xE0 != 0 {
        return Err(malformed());
    }
    let flags = bytes[3];
    let trailer = bytes.len() - 8;
    let mut at = 10usize;
    if flags & FEXTRA != 0 {
        let extra = bytes.get(at..at + 2).ok_or_else(malformed)?;
        at += 2 + usize::from(u16::from_le_bytes([extra[0], extra[1]]));
    }
    for flag in [FNAME, FCOMMENT] {
        if flags & flag != 0 {
            let end = bytes
                .get(at..trailer)
                .and_then(|rest| rest.iter().position(|&byte| byte == 0))
                .ok_or_else(malformed)?;
            at += end + 1;
        }
    }
    if flags & FHCRC != 0 {
        at += 2;
    }
    let deflate = bytes.get(at..trailer).ok_or_else(malformed)?;
    let inflated = miniz_oxide::inflate::decompress_to_vec_with_limit(deflate, limit)
        .map_err(|_| "record is corrupt or over the inflated limit".to_owned())?;
    let word = |from: usize| {
        u32::from_le_bytes([
            bytes[from],
            bytes[from + 1],
            bytes[from + 2],
            bytes[from + 3],
        ])
    };
    if crc32fast::hash(&inflated) != word(trailer)
        || u32::try_from(inflated.len()).ok() != Some(word(trailer + 4))
    {
        return Err("record fails its gzip checksum".to_owned());
    }
    Ok(inflated)
}

/// The page a WARC `response` record holds: its target URI, the captured response's content
/// type and body.
#[derive(Debug)]
struct WarcPage<'a> {
    target: Option<String>,
    content_type: String,
    body: &'a [u8],
}

/// A header block's fields, the first being the start line under an empty name.
type HeaderFields = Vec<(String, String)>;

/// The header block before the first blank line, as lowercase-named fields, and what follows.
/// **Pure.**
fn header_block(bytes: &[u8]) -> Option<(HeaderFields, &[u8])> {
    let end = bytes.windows(4).position(|window| window == b"\r\n\r\n")?;
    let head = std::str::from_utf8(&bytes[..end]).ok()?;
    let mut lines = head.split("\r\n");
    let first = lines.next()?.to_owned();
    let mut fields = vec![(String::new(), first)];
    for line in lines {
        let (name, value) = line.split_once(':')?;
        fields.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
    }
    Some((fields, &bytes[end + 4..]))
}

/// The captured page of a WARC/1.x `response` record whose HTTP status was 200. **Pure.**
///
/// # Errors
/// Why the record is not such a page.
fn warc_response(record: &[u8]) -> Result<WarcPage<'_>, String> {
    let malformed = || "record is not a WARC response".to_owned();
    let (warc, rest) = header_block(record).ok_or_else(malformed)?;
    let field = |fields: &[(String, String)], name: &str| {
        fields
            .iter()
            .skip(1)
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
    };
    if !warc[0].1.starts_with("WARC/1.") || field(&warc, "warc-type").as_deref() != Some("response")
    {
        return Err(malformed());
    }
    let length: usize = field(&warc, "content-length")
        .and_then(|value| value.parse().ok())
        .ok_or_else(malformed)?;
    let block = rest.get(..length).ok_or_else(malformed)?;
    let (http, body) = header_block(block).ok_or_else(malformed)?;
    let status = http[0].1.split_whitespace().nth(1).unwrap_or_default();
    if !http[0].1.starts_with("HTTP/") || status != "200" {
        return Err(format!("captured HTTP {status}"));
    }
    Ok(WarcPage {
        target: field(&warc, "warc-target-uri"),
        content_type: field(&http, "content-type").unwrap_or_default(),
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::ScriptedTransport;

    const NOW: u64 = 1_800_000_000;
    const CRAWL: &str = "CC-MAIN-2026-40";
    const FILE: &str =
        "crawl-data/CC-MAIN-2026-40/segments/1759648664410.92/warc/CC-MAIN-20261001-00549.warc.gz";

    fn response(status: u16, body: &[u8]) -> Response {
        Response {
            status,
            headers: Vec::new(),
            body: body.to_vec(),
            truncated: false,
        }
    }

    fn collinfo() -> Response {
        response(
            200,
            br#"[{"id":"CC-MAIN-2026-36","name":"Sept 2026"},{"id":"CC-MAIN-2026-40","name":"Oct 2026"},{"id":"CC-NEWS-2026-10"}]"#,
        )
    }

    fn line(url: &str, timestamp: &str, offset: u64, length: usize) -> String {
        format!(
            r#"{{"url": "{url}", "timestamp": "{timestamp}", "status": "200", "mime": "text/html", "filename": "{FILE}", "offset": "{offset}", "length": "{length}", "digest": "D4IRZZ6NS7QW37BB"}}"#
        )
    }

    /// A gzip member as a crawler writes it: no optional header fields.
    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut out = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255];
        out.extend(miniz_oxide::deflate::compress_to_vec(data, 6));
        out.extend(crc32fast::hash(data).to_le_bytes());
        out.extend(u32::try_from(data.len()).unwrap().to_le_bytes());
        out
    }

    fn warc(target: &str, status: &str, content_type: &str, body: &str) -> Vec<u8> {
        let http = format!(
            "HTTP/1.1 {status} \r\ncontent-type: {content_type}\r\nX-Crawler-content-encoding: gzip\r\n\r\n{body}"
        );
        let record = format!(
            "WARC/1.0\r\nWARC-Type: response\r\nWARC-Date: 2026-10-01T00:00:00Z\r\nContent-Length: {}\r\nContent-Type: application/http; msgtype=response\r\nWARC-Target-URI: {target}\r\n\r\n{http}\r\n\r\n",
            http.len()
        );
        gzip(record.as_bytes())
    }

    #[test]
    fn the_newest_main_crawl_is_chosen_whatever_the_list_order() {
        let fetched = fetched(collinfo());
        assert_eq!(newest_crawl(&fetched, NOW).unwrap(), CRAWL);
        let none = fetched_of(response(
            200,
            br#"[{"id":"CC-NEWS-2026-10"},{"id":"CC-MAIN-26-40"}]"#,
        ));
        assert_eq!(
            newest_crawl(&none, NOW).unwrap_err().kind,
            SourceOutcomeKind::SchemaDrift
        );
    }

    fn fetched(response: Response) -> Fetched {
        fetched_of(response)
    }

    fn fetched_of(response: Response) -> Fetched {
        let transport = ScriptedTransport::new(vec![Ok(response)]);
        get(&transport, COLLECTIONS.to_owned(), "application/json", NOW).unwrap()
    }

    #[test]
    fn only_the_crawls_own_warc_files_are_read() {
        assert!(warc_filename(FILE, CRAWL));
        for bad in [
            "crawl-data/CC-MAIN-2026-36/segments/1/warc/a.warc.gz",
            "crawl-data/CC-MAIN-2026-40/../../etc/passwd.warc.gz",
            "crawl-data/CC-MAIN-2026-40/segments/1/warc/a.warc",
            "crawl-data/CC-MAIN-2026-40//a.warc.gz",
            "crawl-data/CC-MAIN-2026-40/segments/1/warc/a b.warc.gz",
            "https://evil.example/crawl-data/CC-MAIN-2026-40/a.warc.gz",
        ] {
            assert!(!warc_filename(bad, CRAWL), "{bad}");
        }
        assert!(crawl_id("CC-MAIN-2026-40"));
        for bad in [
            "CC-MAIN-2026-4",
            "CC-MAIN-2026_40",
            "CC-NEWS-2026-40",
            "CC-MAIN-20a6-40",
        ] {
            assert!(!crawl_id(bad), "{bad}");
        }
    }

    #[test]
    fn index_lines_become_historical_urls_and_subdomains_and_drift_is_refused() {
        let body = [
            line("https://example.org/about", "20261001000000", 10, 100),
            line("https://old.example.org/", "20261002000000", 20, 100),
            line(
                "https://example.org/?session=secret",
                "20261002000000",
                30,
                100,
            ),
        ]
        .join("\n");
        let report = parse_index(
            &response(200, body.as_bytes()),
            "example.org",
            CRAWL,
            "scan",
            NOW,
        )
        .unwrap();
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
        assert!(!format!("{report:?}").contains("secret"));
        let about = report
            .entities
            .iter()
            .find(|e| e.value == "https://example.org/about")
            .unwrap();
        let evidence = &about.evidence[0];
        assert_eq!(evidence.attr_values("crawl").next(), Some(CRAWL));
        assert_eq!(evidence.attr_values("warc_offset").next(), Some("10"));
        assert!(
            report
                .entities
                .iter()
                .any(|e| e.kind == EntityKind::Domain && e.value == "old.example.org")
        );
        for bad in [
            line("https://fakeexample.org/", "20261001000000", 1, 1),
            line("https://example.org/", "20261341000000", 1, 1),
            line("https://example.org/", "20261001000000", 1, 0),
            line("https://example.org/", "20261001000000", 1, 1)
                .replace(FILE, "crawl-data/CC-MAIN-2026-40/../x.warc.gz"),
            line("https://example.org/", "20261001000000", 1, 1)
                .replace(r#""status": "200""#, r#""status": "302""#),
            line("https://example.org/", "20261001000000", 1, 1)
                .replace(r#""offset": "1""#, r#""offset": "-1""#),
            "not json".to_owned(),
        ] {
            assert!(
                parse_index(
                    &response(200, bad.as_bytes()),
                    "example.org",
                    CRAWL,
                    "scan",
                    NOW
                )
                .is_err(),
                "{bad}"
            );
        }
        let flood =
            vec![line("https://example.org/", "20261001000000", 1, 1); MAX_CAPTURES + 1].join("\n");
        assert!(
            parse_index(
                &response(200, flood.as_bytes()),
                "example.org",
                CRAWL,
                "scan",
                NOW
            )
            .is_err()
        );
    }

    #[test]
    fn the_documented_no_captures_answer_is_a_valid_zero_and_other_404s_are_not() {
        let transport = ScriptedTransport::new(vec![
            Ok(collinfo()),
            Ok(response(
                404,
                br#"{"message": "No Captures found for: example.org"}"#,
            )),
        ]);
        let report = lookup(&transport, "example.org", "scan", NOW).unwrap();
        assert_eq!(report.outcome.kind, SourceOutcomeKind::ValidZero);
        assert!(report.entities.is_empty());
        let transport = ScriptedTransport::new(vec![
            Ok(collinfo()),
            Ok(response(404, b"<html>Not Found</html>")),
        ]);
        let report = lookup(&transport, "example.org", "scan", NOW).unwrap();
        assert_ne!(report.outcome.kind, SourceOutcomeKind::ValidZero);
        assert_ne!(report.outcome.kind, SourceOutcomeKind::Success);
    }

    #[test]
    fn gzip_members_are_inflated_only_when_intact_and_bounded() {
        let data = b"WARC/1.0\r\n\r\nhello";
        assert_eq!(gunzip_member(&gzip(data), 1024).unwrap(), data);
        let mut corrupt = gzip(data);
        let at = corrupt.len() - 8;
        corrupt[at] ^= 1;
        assert!(gunzip_member(&corrupt, 1024).is_err());
        assert!(gunzip_member(&gzip(&[b'a'; 4096]), 1024).is_err());
        assert!(gunzip_member(b"PK\x03\x04 not gzip at all", 1024).is_err());
        // Optional name and comment fields are skipped, not inflated.
        let mut named = gzip(data);
        named[3] = 8 | 16;
        named.splice(10..10, b"rec.warc\0note\0".iter().copied());
        assert_eq!(gunzip_member(&named, 1024).unwrap(), data);
    }

    /// The index lists three pages; the contact page and the root are read by exact byte range
    /// from the crawl's data origin, the third over the page bound is never requested; a record
    /// naming another URL, or a captured non-200, is named and not read.
    #[test]
    fn crawled_records_yield_historical_contact_leads_naming_their_capture() {
        let contact = warc(
            "https://example.org/contact",
            "200",
            "text/html; charset=UTF-8",
            r#"<p>Mail <a href="mailto:desk%40example.org">desk</a> or call +61 491 570 006.</p>"#,
        );
        let root = warc("https://elsewhere.example/", "200", "text/html", "<p>x</p>");
        let index = [
            line(
                "https://example.org/contact",
                "20261003000000",
                500,
                contact.len(),
            ),
            line("https://example.org/", "20261002000000", 900, root.len()),
            line(
                "https://example.org/blog",
                "20261001000000",
                1,
                2 * 1024 * 1024,
            ),
        ]
        .join("\n");
        let transport = ScriptedTransport::new(vec![
            Ok(collinfo()),
            Ok(response(200, index.as_bytes())),
            Ok(response(206, &contact)),
            Ok(response(206, &root)),
        ]);
        let report = lookup(&transport, "example.org", "scan", NOW).unwrap();
        let seen = transport.seen.borrow();
        assert_eq!(
            seen.len(),
            4,
            "{:?}",
            seen.iter().map(|r| &r.url).collect::<Vec<_>>()
        );
        assert_eq!(seen[0].url, COLLECTIONS);
        assert!(
            seen[1]
                .url
                .starts_with("https://index.commoncrawl.org/CC-MAIN-2026-40-index?")
        );
        assert!(seen[1].url.contains("matchType=domain"));
        assert_eq!(seen[2].url, format!("{DATA}/{FILE}"));
        let last = 500 + contact.len() - 1;
        assert_eq!(
            seen[2].header_value("range"),
            Some(format!("bytes=500-{last}").as_str())
        );
        assert!(
            seen.iter()
                .all(|r| r.header_value("authorization").is_none())
        );
        let email = report
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Email && e.value == "desk@example.org")
            .unwrap_or_else(|| panic!("{:?}", report.entities));
        assert!(email.has_tag(SOURCE) && email.has_tag("historical_content"));
        assert!(email.confidence <= archived_page::CONFIDENCE_CAP);
        let evidence = &email.evidence[0];
        assert!(
            evidence
                .summary
                .contains("archived by Common Crawl at 20261003000000")
        );
        assert!(
            report
                .entities
                .iter()
                .any(|e| e.kind == EntityKind::Phone && e.has_tag("historical_content")),
            "{:?}",
            report.entities
        );
        let detail = report.outcome.detail.as_deref().unwrap_or_default();
        assert!(
            detail.contains("crawl CC-MAIN-2026-40")
                && detail.contains("crawled content: 1 of 3 page(s) read")
                && detail.contains("record names another URL")
                && detail.contains("record over 1 MiB"),
            "{detail}"
        );
    }

    #[test]
    fn a_partial_or_non_range_answer_and_a_captured_error_page_are_not_read() {
        let capture = Capture {
            timestamp: "20261001000000".to_owned(),
            url: "https://example.org/contact".to_owned(),
        };
        let body = warc(&capture.url, "404", "text/html", "<p>desk@example.org</p>");
        let record = Record {
            filename: FILE.to_owned(),
            offset: 0,
            length: u64::try_from(body.len()).unwrap(),
        };
        for (status, bytes, reason) in [
            (200, body.clone(), "not the requested range"),
            (
                206,
                body[..body.len() - 1].to_vec(),
                "not the requested range",
            ),
            (206, body.clone(), "captured HTTP 404"),
        ] {
            let transport = ScriptedTransport::new(vec![Ok(response(status, &bytes))]);
            let error = read_record(&transport, &capture, &record, CRAWL, "scan", NOW).unwrap_err();
            assert!(error.contains(reason), "{error}");
        }
    }
}
