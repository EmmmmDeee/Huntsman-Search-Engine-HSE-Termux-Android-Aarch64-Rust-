//! Bounded active web reconnaissance for operator-authorized targets.
//!
//! The probe reuses Huntsman's guarded transport and causal outcome model. It visits
//! a fixed, tiny same-origin surface, extracts passive fingerprints and pivot
//! candidates, and never auto-traverses discovered pivots.

use std::collections::BTreeMap;

use crate::error::Error;
use crate::fetch::{FetchOptions, fetch};
use crate::http::{Request, Response, Transport, origin_of, parse_http_uri, resolve_location};
use crate::source_outcome::SourceOutcomeKind;

const PROBE_PATHS: [&str; 4] = [
    "/",
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
];
const MAX_REDIRECTS_PER_REQUEST: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeOptions {
    pub max_requests: usize,
}

impl Default for ProbeOptions {
    fn default() -> Self {
        Self {
            max_requests: PROBE_PATHS.len(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProbeFingerprint {
    pub title: Option<String>,
    pub server: Option<String>,
    pub powered_by: Option<String>,
    pub hsts: bool,
    pub csp: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeObservation {
    pub requested_url: String,
    pub final_url: String,
    pub status: Option<u16>,
    pub outcome: SourceOutcomeKind,
    pub found: Option<usize>,
    pub bytes: usize,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbePivot {
    pub url: String,
    pub source: String,
    pub same_origin: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeReport {
    pub base_url: String,
    pub requests_made: usize,
    pub observations: Vec<ProbeObservation>,
    pub fingerprint: ProbeFingerprint,
    pub pivots: Vec<ProbePivot>,
}

/// Probe a deliberately small HTTP surface. Discovered pivots are reported only;
/// they are never fetched by this function.
pub fn probe<T: Transport + ?Sized>(
    transport: &T,
    seed_url: &str,
    options: &ProbeOptions,
    now_unix: u64,
) -> Result<ProbeReport, Error> {
    let base_url = base_url(seed_url)?;
    if options.max_requests == 0 {
        return Err(Error::Invalid(
            "active probe max_requests must be positive".into(),
        ));
    }
    let budget = options.max_requests.min(PROBE_PATHS.len());
    let base_origin = origin_of(&base_url);
    let mut observations = Vec::with_capacity(budget);
    let mut fingerprint = ProbeFingerprint::default();
    let mut pivots: BTreeMap<String, String> = BTreeMap::new();

    for path in PROBE_PATHS.iter().take(budget) {
        let requested_url = format!("{base_url}{path}");
        let fetched = fetch(
            transport,
            Request::get(requested_url.clone()),
            None,
            &FetchOptions {
                max_redirects: MAX_REDIRECTS_PER_REQUEST,
            },
            "active_probe",
            now_unix,
        )?;

        if fetched.final_url != requested_url {
            insert_pivot(
                &mut pivots,
                &fetched.final_url,
                "redirect_final",
                &fetched.final_url,
            );
        }

        let (bytes, truncated) = if let Some(response) = fetched.response.as_ref() {
            fingerprint_response(&mut fingerprint, response);
            extract_response_pivots(&mut pivots, &fetched.final_url, path, response);
            (response.body.len(), response.truncated)
        } else {
            (0, false)
        };

        observations.push(ProbeObservation {
            requested_url,
            final_url: fetched.final_url,
            status: fetched.outcome.http_status,
            outcome: fetched.outcome.kind,
            found: fetched.outcome.found,
            bytes,
            truncated,
        });
    }

    let pivots = pivots
        .into_iter()
        .map(|(url, source)| ProbePivot {
            same_origin: origin_of(&url).is_some() && origin_of(&url) == base_origin,
            url,
            source,
        })
        .collect();

    Ok(ProbeReport {
        base_url,
        requests_made: observations.len(),
        observations,
        fingerprint,
        pivots,
    })
}

fn base_url(seed_url: &str) -> Result<String, Error> {
    let uri = parse_http_uri(seed_url)?;
    let scheme = uri
        .scheme_str()
        .ok_or_else(|| Error::Network("active probe URL has no scheme".into()))?;
    let authority = uri
        .authority()
        .ok_or_else(|| Error::Network("active probe URL has no authority".into()))?;
    Ok(format!("{scheme}://{authority}"))
}

fn fingerprint_response(fingerprint: &mut ProbeFingerprint, response: &Response) {
    if fingerprint.server.is_none() {
        fingerprint.server = response.header_value("server").map(str::to_owned);
    }
    if fingerprint.powered_by.is_none() {
        fingerprint.powered_by = response.header_value("x-powered-by").map(str::to_owned);
    }
    fingerprint.hsts |= response.header_value("strict-transport-security").is_some();
    fingerprint.csp |= response.header_value("content-security-policy").is_some();
    if fingerprint.title.is_none() {
        fingerprint.title = extract_title(&response.text());
    }
}

fn extract_response_pivots(
    pivots: &mut BTreeMap<String, String>,
    final_url: &str,
    path: &str,
    response: &Response,
) {
    let text = response.text();
    for raw in extract_attr_values(&text, "href") {
        insert_pivot(pivots, final_url, "html_href", &raw);
    }
    for raw in extract_attr_values(&text, "src") {
        insert_pivot(pivots, final_url, "html_src", &raw);
    }
    if let Some(csp) = response.header_value("content-security-policy") {
        for raw in csp
            .split_ascii_whitespace()
            .filter(|v| v.starts_with("http://") || v.starts_with("https://"))
        {
            insert_pivot(pivots, final_url, "csp", raw.trim_end_matches(';'));
        }
    }
    match path {
        "/robots.txt" => {
            for line in text.lines() {
                if let Some(raw) = prefixed_value(line, "sitemap:") {
                    insert_pivot(pivots, final_url, "robots_sitemap", raw);
                }
            }
        }
        "/sitemap.xml" => {
            for raw in extract_tag_values(&text, "loc") {
                insert_pivot(pivots, final_url, "sitemap_loc", &raw);
            }
        }
        "/.well-known/security.txt" => {
            for line in text.lines() {
                if let Some(raw) = prefixed_value(line, "canonical:") {
                    insert_pivot(pivots, final_url, "security_canonical", raw);
                }
                if let Some(raw) = prefixed_value(line, "contact:") {
                    if raw.starts_with("http://") || raw.starts_with("https://") {
                        insert_pivot(pivots, final_url, "security_contact", raw);
                    }
                }
            }
        }
        _ => {}
    }
}

fn insert_pivot(pivots: &mut BTreeMap<String, String>, base: &str, source: &str, raw: &str) {
    let raw = raw.trim().trim_matches(['\'', '"', '<', '>', '(', ')']);
    if raw.is_empty()
        || raw.starts_with('#')
        || raw.starts_with("mailto:")
        || raw.starts_with("javascript:")
        || raw.starts_with("data:")
    {
        return;
    }
    if let Ok(url) = resolve_location(base, raw) {
        pivots.entry(url).or_insert_with(|| source.to_owned());
    }
}

fn prefixed_value<'a>(line: &'a str, prefix: &str) -> Option<&'a str> {
    let trimmed = line.trim();
    (trimmed.len() >= prefix.len() && trimmed[..prefix.len()].eq_ignore_ascii_case(prefix))
        .then(|| trimmed[prefix.len()..].trim())
}

fn extract_title(text: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    let start = lower.find("<title")?;
    let open = lower[start..].find('>')? + start + 1;
    let close = lower[open..].find("</title>")? + open;
    let title = text[open..close].trim();
    (!title.is_empty()).then(|| title.chars().take(256).collect())
}

fn extract_attr_values(text: &str, attr: &str) -> Vec<String> {
    let lower = text.to_ascii_lowercase();
    let needle = format!("{attr}=");
    let mut out = Vec::new();
    let mut offset = 0usize;
    while let Some(found) = lower[offset..].find(&needle) {
        let start = offset + found + needle.len();
        let bytes = text.as_bytes();
        if start >= bytes.len() {
            break;
        }
        let quote = bytes[start];
        let (value_start, terminator) = if quote == b'\'' || quote == b'"' {
            (start + 1, Some(quote))
        } else {
            (start, None)
        };
        let mut end = value_start;
        while end < bytes.len() {
            let b = bytes[end];
            if terminator.is_some_and(|q| b == q)
                || (terminator.is_none() && (b.is_ascii_whitespace() || b == b'>'))
            {
                break;
            }
            end += 1;
        }
        if end > value_start {
            out.push(text[value_start..end].to_owned());
        }
        offset = end.saturating_add(1);
    }
    out
}

fn extract_tag_values(text: &str, tag: &str) -> Vec<String> {
    let lower = text.to_ascii_lowercase();
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut out = Vec::new();
    let mut offset = 0usize;
    while let Some(found) = lower[offset..].find(&open) {
        let start = offset + found + open.len();
        let Some(rel_end) = lower[start..].find(&close) else {
            break;
        };
        let end = start + rel_end;
        let value = text[start..end].trim();
        if !value.is_empty() {
            out.push(value.to_owned());
        }
        offset = end + close.len();
    }
    out
}
