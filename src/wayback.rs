//! Guarded Internet Archive Wayback CDX client.
//!
//! The client queries only the CDX endpoint through [`crate::fetch::fetch`]. Returned
//! original URLs are observations; this module never dereferences them.

use std::fmt::Write as _;

use serde_json::Value;

use crate::archive::{ArchiveCapture, ArchiveSource, parse_archive_url};
use crate::canonical::canonical_domain;
use crate::error::Error;
use crate::fetch::{FetchOptions, fetch};
use crate::http::{Request, Transport, append_query_param};
use crate::sha256::sha256;
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};

const MODULE: &str = "wayback";
const DATASET: &str = "internet_archive_wayback";
const CDX_ENDPOINT: &str = "https://web.archive.org/cdx/search/cdx";
const REQUIRED_FIELDS: [&str; 5] = ["timestamp", "original", "mimetype", "statuscode", "digest"];

#[derive(Debug, Clone, Copy)]
pub struct WaybackQuery<'a> {
    pub domain: &'a str,
    pub row_limit: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WaybackResult {
    pub captures: Vec<ArchiveCapture>,
    pub outcome: SourceExecutionOutcome,
    pub response_sha256: Option<String>,
    pub truncated: bool,
}

pub fn wayback_lookup<T: Transport + ?Sized>(
    transport: &T,
    query: &WaybackQuery<'_>,
    now_unix: u64,
) -> Result<WaybackResult, Error> {
    let domain = canonical_domain(query.domain)
        .ok_or_else(|| Error::Invalid("Wayback query requires a valid domain".into()))?;

    if query.row_limit == 0 {
        let mut outcome = SourceExecutionOutcome::success(MODULE, now_unix, 0)
            .with_detail("row_limit=0: explicit no-work result");
        outcome.found = None;
        return Ok(WaybackResult {
            captures: Vec::new(),
            outcome,
            response_sha256: None,
            truncated: true,
        });
    }

    let request = Request::get(build_request_url(&domain, query.row_limit));
    let fetched = fetch(
        transport,
        request,
        None,
        &FetchOptions::no_redirects(),
        MODULE,
        now_unix,
    )?;

    let Some(response) = fetched.response else {
        return Ok(WaybackResult {
            captures: Vec::new(),
            outcome: fetched.outcome,
            response_sha256: None,
            truncated: false,
        });
    };

    let response_sha256 = Some(hex_sha256(&response.body));
    let truncated = response.truncated;

    if fetched.outcome.kind != SourceOutcomeKind::Inconclusive {
        return Ok(WaybackResult {
            captures: Vec::new(),
            outcome: fetched.outcome,
            response_sha256,
            truncated,
        });
    }

    if truncated {
        let mut outcome = SourceExecutionOutcome::success(MODULE, now_unix, 0)
            .with_http_status(response.status)
            .with_detail("truncated CDX response is not evidence of presence or absence");
        outcome.found = None;
        return Ok(WaybackResult {
            captures: Vec::new(),
            outcome,
            response_sha256,
            truncated: true,
        });
    }

    let parsed = parse_cdx(&response.body, query.row_limit);
    let (captures, malformed_rows, bounded) = match parsed {
        Ok(parsed) => parsed,
        Err(detail) => {
            return Ok(WaybackResult {
                captures: Vec::new(),
                outcome: drift_outcome(now_unix, response.status, detail),
                response_sha256,
                truncated: false,
            });
        }
    };

    let outcome = if captures.is_empty() {
        if malformed_rows == 0 {
            SourceExecutionOutcome::valid_zero(MODULE, now_unix)
                .with_http_status(response.status)
                .with_detail("validated CDX envelope contained zero capture rows")
        } else {
            drift_outcome(
                now_unix,
                response.status,
                format!("CDX rows unusable: malformed_rows={malformed_rows}"),
            )
        }
    } else {
        let mut detail = format!("parsed_rows={}", captures.len());
        if malformed_rows > 0 {
            let _ = write!(detail, " malformed_rows={malformed_rows}");
        }
        if bounded {
            detail.push_str(" row_limit_reached");
        }
        SourceExecutionOutcome::success(MODULE, now_unix, captures.len())
            .with_http_status(response.status)
            .with_detail(detail)
    };

    Ok(WaybackResult {
        captures,
        outcome,
        response_sha256,
        truncated: bounded,
    })
}

fn build_request_url(domain: &str, row_limit: usize) -> String {
    let mut url = CDX_ENDPOINT.to_owned();
    url = append_query_param(&url, "url", &format!("*.{domain}/*"));
    url = append_query_param(&url, "output", "json");
    url = append_query_param(&url, "fl", &REQUIRED_FIELDS.join(","));
    url = append_query_param(&url, "limit", &row_limit.to_string());
    append_query_param(&url, "gzip", "false")
}

fn parse_cdx(body: &[u8], row_limit: usize) -> Result<(Vec<ArchiveCapture>, usize, bool), String> {
    let value: Value =
        serde_json::from_slice(body).map_err(|_| "CDX response is not valid JSON".to_owned())?;
    let rows = value
        .as_array()
        .ok_or_else(|| "CDX response is not a JSON row array".to_owned())?;
    let Some(header) = rows.first().and_then(Value::as_array) else {
        return Err("CDX response is missing its field header".into());
    };
    let indices = required_indices(header)?;

    let mut captures = Vec::new();
    let mut malformed_rows = 0usize;
    let mut bounded = false;
    for row in rows.iter().skip(1) {
        if captures.len() >= row_limit {
            bounded = true;
            break;
        }
        let Some(row) = row.as_array() else {
            malformed_rows = malformed_rows.saturating_add(1);
            continue;
        };
        match parse_row(row, &indices) {
            Some(capture) => captures.push(capture),
            None => malformed_rows = malformed_rows.saturating_add(1),
        }
    }
    Ok((captures, malformed_rows, bounded))
}

#[derive(Debug, Clone, Copy)]
struct FieldIndices {
    timestamp: usize,
    original: usize,
    mimetype: usize,
    statuscode: usize,
    digest: usize,
}

fn required_indices(header: &[Value]) -> Result<FieldIndices, String> {
    let find = |name: &str| {
        header
            .iter()
            .position(|value| value.as_str() == Some(name))
            .ok_or_else(|| format!("CDX header missing required field {name}"))
    };
    Ok(FieldIndices {
        timestamp: find("timestamp")?,
        original: find("original")?,
        mimetype: find("mimetype")?,
        statuscode: find("statuscode")?,
        digest: find("digest")?,
    })
}

fn parse_row(row: &[Value], indices: &FieldIndices) -> Option<ArchiveCapture> {
    let timestamp = cell(row, indices.timestamp)?;
    if timestamp.len() != 14 || !timestamp.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let original = cell(row, indices.original)?;
    let key = parse_archive_url(original)?;
    let mime = optional_cell(cell(row, indices.mimetype)?);
    let digest = optional_cell(cell(row, indices.digest)?);
    let status_text = cell(row, indices.statuscode)?;
    let status = if status_text.is_empty() || status_text == "-" {
        None
    } else {
        let status = status_text.parse::<u16>().ok()?;
        if !(100..=599).contains(&status) {
            return None;
        }
        Some(status)
    };
    let source_url = format!("https://web.archive.org/web/{timestamp}/{original}");

    Some(ArchiveCapture {
        source: ArchiveSource::Wayback,
        dataset: DATASET.into(),
        collection: None,
        original_url: original.to_owned(),
        key,
        captured_at: timestamp.to_owned(),
        status,
        mime: mime.map(str::to_owned),
        digest: digest.map(str::to_owned),
        source_url: Some(source_url),
    })
}

fn cell(row: &[Value], index: usize) -> Option<&str> {
    row.get(index)?.as_str()
}

fn optional_cell(value: &str) -> Option<&str> {
    if value.is_empty() || value == "-" {
        None
    } else {
        Some(value)
    }
}

fn drift_outcome(now_unix: u64, status: u16, detail: impl Into<String>) -> SourceExecutionOutcome {
    let mut outcome = SourceExecutionOutcome::success(MODULE, now_unix, 0)
        .with_http_status(status)
        .with_detail(detail);
    outcome.kind = SourceOutcomeKind::ParserDrift;
    outcome.found = None;
    outcome
}

fn hex_sha256(body: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = sha256(body);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}
