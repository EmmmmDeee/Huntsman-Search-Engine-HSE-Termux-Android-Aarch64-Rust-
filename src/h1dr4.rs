//! Keyless, read-only H1DR4 public intelligence adapter.
//! Every fetched response is retained byte-for-byte as UTF-8 in the report, with a
//! content digest. Derived records are never independent confirmation of allegations.
//! No H1DR4 credentials, writes, payments, remote MCP or LLM are needed.

use std::collections::BTreeSet;
use std::time::Duration;

use serde::Serialize;
use serde_json::Value;

use crate::fetch::{FetchOptions, fetch};
use crate::http::{Request, Transport, append_query_param, percent_encode_unreserved};
use crate::sha256::{hex32, sha256};
use crate::source_outcome::SourceOutcomeKind;

pub const BASE: &str = "https://h1dr4.dev/api/v1";
pub const MAX_PAGES: u8 = 3;
pub const MAX_LIST_LIMIT: u16 = 20;
pub const MAX_CASE_TIPS: u16 = 200;
const TIMEOUT: Duration = Duration::from_secs(16);

/// No endpoint here can publish, sign, pay, access private cases or modify records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resource {
    Search(String),
    Case(String),
    OfficialRewards,
    OnchainStats,
}

#[derive(Debug, Clone, Copy)]
pub struct Bounds {
    pub pages: u8,
    pub limit: u16,
}
impl Bounds {
    /// # Errors
    /// Rejects over-budget requests before any HTTP request is made.
    pub fn checked(self, resource: &Resource) -> Result<Self, &'static str> {
        let max_limit = if matches!(resource, Resource::Case(_)) {
            MAX_CASE_TIPS
        } else {
            MAX_LIST_LIMIT
        };
        if self.pages == 0 || self.pages > MAX_PAGES || self.limit == 0 || self.limit > max_limit {
            return Err("h1dr4 page or result limit out of bounds");
        }
        if !matches!(resource, Resource::Search(_)) && self.pages != 1 {
            return Err("multi-page access has not been verified for this endpoint");
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Coordinates {
    pub lat: f64,
    pub lon: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct PublicRecord {
    pub kind: &'static str,
    pub source_record_id: String,
    pub title: Option<String>,
    pub upstream_source: Option<String>,
    pub original_source_url: Option<String>,
    pub status: Option<String>,
    pub event_at: Option<String>,
    pub time_precision: Option<String>,
    pub asserted_tip_count: Option<u64>,
    pub geo: Option<Coordinates>,
    pub evidence_status: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct RawPage {
    pub request_url: String,
    pub fetched_at_unix: u64,
    pub http_status: u16,
    pub sha256: String,
    /// Original, unmodified UTF-8 payload including unknown upstream fields.
    pub original_json: String,
    pub normalized_count: usize,
    pub schema_warning: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub provider: &'static str,
    pub resource: &'static str,
    pub requested_identifier: Option<String>,
    pub pages: Vec<RawPage>,
    pub records: Vec<PublicRecord>,
    pub upstream_total_available: Option<u64>,
    pub returned_count: usize,
    pub pagination_stalled: bool,
    pub complete_dataset_verified: bool,
    pub limitations: Vec<&'static str>,
}

fn checked_identifier(s: &str) -> bool {
    (1..=128).contains(&s.len())
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b':' | b'.'))
}

fn checked_query(s: &str) -> bool {
    (1..=160).contains(&s.len()) && s.trim() == s && !s.chars().any(char::is_control)
}

fn url(resource: &Resource, limit: u16, offset: u16) -> String {
    match resource {
        Resource::Search(q) => {
            let u = append_query_param(&format!("{BASE}/investigations"), "q", q);
            let u = append_query_param(&u, "limit", &limit.to_string());
            append_query_param(&u, "offset", &offset.to_string())
        }
        Resource::Case(id) => append_query_param(
            &format!("{BASE}/investigations/{}", percent_encode_unreserved(id)),
            "limit",
            &limit.to_string(),
        ),
        Resource::OfficialRewards => append_query_param(
            &format!("{BASE}/official-rewards"),
            "limit",
            &limit.to_string(),
        ),
        Resource::OnchainStats => format!("{BASE}/onchain-registry/stats"),
    }
}

fn label(resource: &Resource) -> &'static str {
    match resource {
        Resource::Search(_) => "cases",
        Resource::Case(_) => "case_with_tips",
        Resource::OfficialRewards => "official_rewards",
        Resource::OnchainStats => "onchain_stats",
    }
}

fn field<'a>(row: &'a Value, key: &str) -> Option<&'a str> {
    row.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
}
fn record_id(row: &Value) -> Option<String> {
    row.get("id")
        .and_then(|v| match v {
            Value::String(s) => Some(s.clone()),
            Value::Number(n) => Some(n.to_string()),
            _ => None,
        })
        .filter(|s| !s.is_empty())
}
fn geo(row: &Value) -> Option<Coordinates> {
    // Never interpret missing coordinates or a (0,0) placeholder as a real observation.
    // A route/unknown geometry is not a point. Do not infer a place from free text.
    let point = row
        .get("raw")
        .and_then(|v| v.get("geo"))
        .or_else(|| row.get("geo"))?;
    if point
        .get("type")
        .and_then(Value::as_str)
        .is_some_and(|t| t != "point")
    {
        return None;
    }
    let lat = point.get("lat").and_then(Value::as_f64)?;
    let lon = point.get("lon").and_then(Value::as_f64)?;
    (lat.is_finite()
        && lon.is_finite()
        && (-90.0..=90.0).contains(&lat)
        && (-180.0..=180.0).contains(&lon)
        && !(lat == 0.0 && lon == 0.0))
        .then_some(Coordinates { lat, lon })
}

fn normalize(row: &Value, kind: &'static str) -> Option<PublicRecord> {
    let id = record_id(row)?;
    let source_url = field(row, "source_url")
        .or_else(|| field(row, "official_url"))
        .or_else(|| row.get("raw").and_then(|r| field(r, "source_url")));
    let timeline = row.get("raw").and_then(|r| r.get("timeline"));
    Some(PublicRecord {
        kind,
        source_record_id: id,
        title: field(row, "title").map(str::to_owned),
        upstream_source: field(row, "source").map(str::to_owned),
        original_source_url: source_url.map(str::to_owned),
        status: field(row, "status").map(str::to_owned),
        event_at: timeline
            .and_then(|v| field(v, "happened_at"))
            .or_else(|| field(row, "created_at"))
            .or_else(|| field(row, "published_at"))
            .map(str::to_owned),
        time_precision: timeline
            .and_then(|v| field(v, "time_precision"))
            .map(str::to_owned),
        asserted_tip_count: if kind == "case" {
            row.get("tip_count").and_then(Value::as_u64)
        } else {
            None
        },
        geo: geo(row),
        evidence_status: if kind == "official_reward" {
            "official_reference_status_requires_source_recheck"
        } else {
            "third_party_unverified_assertion"
        },
    })
}

fn parse_rows(value: &Value, resource: &Resource) -> Result<Vec<PublicRecord>, &'static str> {
    let mut rows = Vec::new();
    match resource {
        Resource::Search(_) => {
            let cases = value
                .get("cases")
                .and_then(Value::as_array)
                .ok_or("missing cases array")?;
            rows.extend(cases.iter().filter_map(|row| normalize(row, "case")));
        }
        Resource::Case(_) => {
            let case = value.get("case").ok_or("missing case object")?;
            if let Some(rec) = normalize(case, "case") {
                rows.push(rec);
            }
            let tips = value
                .get("tips")
                .and_then(Value::as_array)
                .ok_or("missing tips array")?;
            rows.extend(tips.iter().filter_map(|row| normalize(row, "tip")));
        }
        Resource::OfficialRewards => {
            let rewards = value
                .get("rewards")
                .and_then(Value::as_array)
                .ok_or("missing rewards array")?;
            rows.extend(
                rewards
                    .iter()
                    .filter_map(|row| normalize(row, "official_reward")),
            );
        }
        Resource::OnchainStats => {
            if value.get("metrics").and_then(Value::as_object).is_none() {
                return Err("missing onchain metrics");
            }
        }
    }
    Ok(rows)
}

/// Fetches bounded public pages through Huntsman's guarded shared transport.
/// Every successful HTTP body (even JSON schema drift) is preserved in `pages`.
/// No upstream allegation becomes verified merely because it parsed.
///
/// # Errors
/// Refuses invalid parameters, network failures, non-2xx responses, truncated
/// bodies, or responses that are not valid UTF-8. No writes or credentials.
pub fn retrieve<T: Transport + ?Sized>(
    transport: &T,
    resource: &Resource,
    bounds: Bounds,
    now_unix: u64,
) -> Result<Report, String> {
    let bounds = bounds.checked(resource).map_err(str::to_owned)?;
    match resource {
        Resource::Search(q) if !checked_query(q) => return Err("invalid h1dr4 query".into()),
        Resource::Case(id) if !checked_identifier(id) => return Err("invalid h1dr4 case id".into()),
        _ => {}
    }
    let mut report = Report {
        provider: "h1dr4_public",
        resource: label(resource),
        requested_identifier: match resource {
            Resource::Search(s) | Resource::Case(s) => Some(s.clone()),
            _ => None,
        },
        pages: Vec::new(),
        records: Vec::new(),
        upstream_total_available: None,
        returned_count: 0,
        pagination_stalled: false,
        complete_dataset_verified: false,
        limitations: vec![
            "H1DR4 cases and tips are third-party assertions, not proven facts",
            "Pagination and case-detail tip_count are not authoritative totals",
            "Source freshness differs from HTTP cache freshness; verify official records at origin",
            "Raw pages are immutable evidence; normalized rows are an incomplete derived view",
        ],
    };
    let mut seen = BTreeSet::new();
    for page in 0..bounds.pages {
        let offset = u16::from(page) * bounds.limit;
        let request_url = url(resource, bounds.limit, offset);
        let attempt = || {
            fetch(
                transport,
                Request::get_json(&request_url).with_timeout(TIMEOUT),
                None,
                &FetchOptions::no_redirects().paced(),
                "h1dr4_public",
                now_unix,
            )
        };
        let mut response = attempt().map_err(|e| e.to_string())?;
        // One bounded retry, only for an immediate/short rate-limit response.
        if response.outcome.kind == SourceOutcomeKind::RateLimited
            && response.outcome.retry_after_secs.is_some_and(|s| s <= 2)
        {
            let pause = response.outcome.retry_after_secs.unwrap_or(0);
            if pause > 0 {
                std::thread::sleep(Duration::from_secs(pause));
            }
            response = attempt().map_err(|e| e.to_string())?;
        }
        crate::fetch::answer(&response, "h1dr4")
            .map_err(|e| format!("H1DR4 source outcome: {}", e.kind.as_str()))?;
        let body = crate::fetch::whole_response(&response, "h1dr4")
            .map_err(|e| format!("H1DR4 incomplete response: {}", e.kind.as_str()))?;
        let raw = std::str::from_utf8(&body.body)
            .map_err(|_| "H1DR4 response is not UTF-8")?
            .to_owned();
        let digest = hex32(&sha256(&body.body));
        let value = serde_json::from_slice::<Value>(&body.body);
        let parsed = value.as_ref().ok().map(|v| parse_rows(v, resource));
        let warning = match &parsed {
            Some(Err(s)) => Some((*s).to_owned()),
            None => Some("invalid JSON payload".to_owned()),
            Some(Ok(_)) => None,
        };
        let new_rows = parsed.and_then(Result::ok).unwrap_or_default();
        let mut unique_on_page = 0usize;
        for rec in &new_rows {
            if seen.insert((rec.kind, rec.source_record_id.clone())) {
                report.records.push(rec.clone());
                unique_on_page += 1;
            }
        }
        if let Ok(v) = &value {
            report.upstream_total_available = report
                .upstream_total_available
                .or_else(|| v.get("total_available").and_then(Value::as_u64));
        }
        report.pages.push(RawPage {
            request_url,
            fetched_at_unix: now_unix,
            http_status: body.status,
            sha256: digest,
            original_json: raw,
            normalized_count: new_rows.len(),
            schema_warning: warning,
        });
        // H1DR4 currently ignores offset on case-tip pages; never loop or
        // misleadingly claim a full history when upstream pagination stalls.
        if page > 0 && unique_on_page == 0 && !new_rows.is_empty() {
            report.pagination_stalled = true;
            break;
        }
        if new_rows.len() < usize::from(bounds.limit) || !matches!(resource, Resource::Search(_)) {
            break;
        }
    }
    report.returned_count = report.records.len();
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{Response, TransportFailure};
    use std::cell::{Cell, RefCell};

    struct Fake {
        body: Vec<u8>,
        calls: Cell<u32>,
        urls: RefCell<Vec<String>>,
    }
    impl Transport for Fake {
        fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
            self.calls.set(self.calls.get() + 1);
            self.urls.borrow_mut().push(request.url.clone());
            Ok(Response {
                status: 200,
                headers: vec![],
                body: self.body.clone(),
                truncated: false,
            })
        }
    }
    fn fake(body: &str) -> Fake {
        Fake {
            body: body.as_bytes().to_vec(),
            calls: Cell::new(0),
            urls: RefCell::new(Vec::new()),
        }
    }

    #[test]
    fn preserves_raw_unknown_fields_and_detects_stalled_pagination() {
        let raw = r#"{"cases":[{"id":"dossier-1","title":"Unverified lead","tip_count":140,"unknown":{"keep":[1,2,3]}}]}"#;
        let t = fake(raw);
        let r = retrieve(
            &t,
            &Resource::Search("testing".into()),
            Bounds { pages: 3, limit: 1 },
            100,
        )
        .unwrap();
        assert_eq!(r.pages.len(), 2);
        assert_eq!(r.pages[0].original_json, raw);
        assert_eq!(r.records.len(), 1);
        assert_eq!(r.records[0].asserted_tip_count, Some(140));
        assert!(r.pagination_stalled);
        assert!(!r.complete_dataset_verified);
        assert_eq!(t.calls.get(), 2);
    }
    #[test]
    fn scoped_tip_counts_are_never_reported_as_complete() {
        let raw = r#"{"case":{"id":"dossier-1","tip_count":1},"tips":[{"id":617,"raw":{"timeline":{"time_precision":"date_only","happened_at":"2026-09-01T00:00:00Z"}}}]}"#;
        let t = fake(raw);
        let r = retrieve(
            &t,
            &Resource::Case("dossier-1".into()),
            Bounds { pages: 1, limit: 1 },
            100,
        )
        .unwrap();
        assert_eq!(r.records.len(), 2);
        assert_eq!(r.records[0].asserted_tip_count, Some(1));
        assert_eq!(r.records[1].source_record_id, "617");
        assert_eq!(r.records[1].time_precision.as_deref(), Some("date_only"));
        assert!(!r.complete_dataset_verified);
    }
    #[test]
    fn no_placeholder_geo_and_no_automatic_verification() {
        let r = serde_json::json!({"id":"x","raw":{"geo":{"lat":0.0,"lon":0.0}}});
        let record = normalize(&r, "case").unwrap();
        assert!(record.geo.is_none());
        assert_eq!(record.evidence_status, "third_party_unverified_assertion");
        assert!(
            normalize(
                &serde_json::json!({"id":"x","geo":{"lat":-26.8,"lon":152.9}}),
                "case"
            )
            .unwrap()
            .geo
            .is_some()
        );
    }
    #[test]
    fn rejects_unsafe_identifiers_without_a_request() {
        let t = fake("{}");
        assert!(
            retrieve(
                &t,
                &Resource::Case("../private".into()),
                Bounds { pages: 1, limit: 1 },
                100
            )
            .is_err()
        );
        assert!(
            retrieve(
                &t,
                &Resource::Search("x".into()),
                Bounds { pages: 4, limit: 1 },
                100
            )
            .is_err()
        );
        assert_eq!(t.calls.get(), 0);
    }
    #[test]
    fn malformed_json_keeps_the_original_response() {
        let raw = "<!doctype html>error";
        let t = fake(raw);
        let r = retrieve(
            &t,
            &Resource::Search("test".into()),
            Bounds { pages: 1, limit: 1 },
            100,
        )
        .unwrap();
        assert_eq!(r.pages[0].original_json, raw);
        assert!(r.pages[0].schema_warning.is_some());
        assert!(r.records.is_empty());
    }
}
