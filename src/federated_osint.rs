//! Independent, read-only OSINT federation for indexed X links.
//!
//! No borrowed backend access, shared provider credentials or transaction signing.
//! A search result is a discovery lead, not corroboration of a claim or identity.

use serde::Serialize;
use serde_json::Value;

use crate::error::Error;
use crate::fetch::{Credential, FetchOptions, answer, decode_json, fetch, whole_response};
use crate::http::{Request, Transport, append_query_param, parse_http_uri};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};
use crate::web_query::{self, SearchHit};

pub use crate::environment::X_BEARER_TOKEN_ENV as X_BEARER_SLOT;

pub const X_API_URL: &str = "https://api.x.com/2/tweets/search/recent";
pub const X_API_ORIGIN: &str = "https://api.x.com:443";

/// URLs are discovery leads only. The indexed mode does not access Grok/X's private index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct XDiscoveryReport {
    pub source: &'static str,
    pub evidence_role: &'static str,
    pub observed_at_unix: u64,
    pub hits: Vec<SearchHit>,
    pub outcomes: Vec<SourceExecutionOutcome>,
}

fn checked_query(query: &str) -> Result<&str, Error> {
    let query = query.trim();
    if query.is_empty() || query.len() > 460 || query.chars().any(char::is_control) {
        return Err(Error::invalid(
            "X query must be 1..460 bytes without control characters",
        ));
    }
    Ok(query)
}

/// Public site-index search with no API key, credit consumption, or inference about ownership.
///
/// # Errors
/// Invalid query or prohibited outbound request.
pub fn search_indexed_x<T: Transport + ?Sized>(
    transport: &T,
    query: &str,
    now_unix: u64,
) -> Result<XDiscoveryReport, Error> {
    let query = checked_query(query)?;
    let indexed = web_query::search(transport, &format!("site:x.com {query}"), now_unix)?;
    let mut outcomes = indexed.outcomes;
    let mut hits = Vec::new();
    for hit in indexed.hits {
        if is_public_x_url(&hit.url) && !hits.iter().any(|prior: &SearchHit| prior.url == hit.url) {
            hits.push(hit);
        }
    }
    // Legacy links can still be indexed under twitter.com. Search only when
    // the first pass yielded no X links and at least one index was reachable.
    if hits.is_empty() && outcomes.iter().any(|o| o.kind.is_accepted()) {
        let legacy = web_query::search(transport, &format!("site:twitter.com {query}"), now_unix)?;
        for hit in legacy.hits {
            if is_public_x_url(&hit.url)
                && !hits.iter().any(|prior: &SearchHit| prior.url == hit.url)
            {
                hits.push(hit);
            }
        }
        outcomes.extend(legacy.outcomes);
    }
    Ok(XDiscoveryReport {
        source: "public_web_indexes",
        evidence_role: "unverified_discovery_lead",
        observed_at_unix: now_unix,
        hits,
        outcomes,
    })
}

fn is_public_x_url(url: &str) -> bool {
    let Ok(uri) = parse_http_uri(url) else {
        return false;
    };
    uri.scheme_str() == Some("https")
        && matches!(
            uri.host().map(str::to_ascii_lowercase).as_deref(),
            Some("x.com" | "www.x.com" | "twitter.com" | "www.twitter.com" | "mobile.twitter.com")
        )
}

/// An explicitly operator-authorized official X API search. Uses one bounded recent-search
/// page (at most ten posts); there is no implicit paid API escalation from indexed search.
///
/// # Errors
/// Invalid query or prohibited outbound request.
pub fn search_official_x<T: Transport + ?Sized>(
    transport: &T,
    credential: &Credential,
    query: &str,
    now_unix: u64,
) -> Result<XDiscoveryReport, Error> {
    let query = checked_query(query)?;
    let url = append_query_param(X_API_URL, "query", query);
    let url = append_query_param(&url, "max_results", "10");
    let fetched = fetch(
        transport,
        Request::get(url).header("accept", "application/json"),
        Some(credential),
        &FetchOptions::no_redirects().paced(),
        "x_recent_search",
        now_unix,
    )?;
    let mut report = XDiscoveryReport {
        source: "official_x_recent_search",
        evidence_role: "public_post_link_lead_not_verified_attribution",
        observed_at_unix: now_unix,
        hits: Vec::new(),
        outcomes: Vec::new(),
    };
    let decoded = whole_response(&fetched, "X API").and_then(|response| {
        answer(&fetched, "X API")?;
        decode_json::<Value>(response, "x_recent_search", now_unix, "X API")
    });
    let value = match decoded {
        Ok(value) => value,
        Err(outcome) => {
            report.outcomes.push(outcome);
            return Ok(report);
        }
    };
    let has_errors = value
        .get("errors")
        .and_then(Value::as_array)
        .is_some_and(|e| !e.is_empty());
    let mut invalid_posts = false;
    if let Some(data) = value.get("data").and_then(Value::as_array) {
        for post in data.iter().take(10) {
            if let Some(id) = post.get("id").and_then(Value::as_str).filter(|id| {
                !id.is_empty() && id.len() <= 24 && id.bytes().all(|b| b.is_ascii_digit())
            }) {
                report.hits.push(SearchHit {
                    engine: "official_x_recent_search".to_owned(),
                    url: format!("https://x.com/i/web/status/{id}"),
                });
            } else {
                invalid_posts = true;
            }
        }
    }
    let malformed = invalid_posts
        || value.get("data").is_some_and(|d| !d.is_array())
        || (value
            .get("data")
            .and_then(Value::as_array)
            .is_some_and(|a| !a.is_empty())
            && report.hits.is_empty());
    let result_count = value
        .get("meta")
        .and_then(|v| v.get("result_count"))
        .and_then(Value::as_u64);
    let outcome = if has_errors {
        SourceExecutionOutcome::failed(
            "x_recent_search",
            now_unix,
            SourceOutcomeKind::SemanticDrift,
            Some(200),
            "X API returned errors; any links are partial leads",
        )
    } else if malformed || (report.hits.is_empty() && result_count.is_some_and(|n| n > 0)) {
        SourceExecutionOutcome::failed(
            "x_recent_search",
            now_unix,
            SourceOutcomeKind::SchemaDrift,
            Some(200),
            "X API returned inconsistent or malformed result data",
        )
    } else if report.hits.is_empty() {
        SourceExecutionOutcome::valid_zero("x_recent_search", now_unix).with_http_status(200)
    } else {
        SourceExecutionOutcome::success("x_recent_search", now_unix, report.hits.len())
            .with_http_status(200)
    };
    report.outcomes.push(outcome);
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{Response, TransportFailure};
    use std::sync::Mutex;

    #[derive(Default)]
    struct Fake {
        responses: Mutex<Vec<Response>>,
        requests: Mutex<Vec<Request>>,
    }

    impl Fake {
        fn new(bodies: &[&str]) -> Self {
            Self {
                responses: Mutex::new(
                    bodies
                        .iter()
                        .rev()
                        .map(|body| Response {
                            status: 200,
                            headers: vec![(
                                "content-type".to_owned(),
                                "application/json".to_owned(),
                            )],
                            body: body.as_bytes().to_vec(),
                            truncated: false,
                        })
                        .collect(),
                ),
                requests: Mutex::new(Vec::new()),
            }
        }
    }

    impl Transport for Fake {
        fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
            self.requests
                .lock()
                .expect("requests")
                .push(request.clone());
            Ok(self
                .responses
                .lock()
                .expect("responses")
                .pop()
                .expect("request exceeds fixture"))
        }
    }

    #[test]
    fn official_x_uses_pinned_auth_and_filters_invalid_post_identifiers() {
        use crate::credential_origin::{AuthenticationAuthority, OperatorCredentialRef};
        use crate::fetch::AuthStyle;
        use crate::keys::Secret;
        let fake = Fake::new(&[
            r#"{"data":[{"id":"123456789"},{"id":"123/evil"}],"meta":{"result_count":2}}"#,
        ]);
        let authority = AuthenticationAuthority::operator_approved(OperatorCredentialRef {
            provider_id: "official_x_recent_search".to_owned(),
            credential_slot: X_BEARER_SLOT.to_owned(),
            approved_at_unix: 100,
            approval_provenance: "operator-owned fixture".to_owned(),
        })
        .expect("approved");
        let credential = Credential::new(
            authority,
            Secret::new("owned-fixture-secret-abcdef123456").expect("fixture"),
            AuthStyle::Bearer,
        )
        .expect("credential")
        .only_for_origin(X_API_ORIGIN);
        let report = search_official_x(&fake, &credential, "sample", 100).expect("search");
        assert_eq!(report.hits.len(), 1);
        assert_eq!(report.hits[0].url, "https://x.com/i/web/status/123456789");
        assert_eq!(report.outcomes[0].kind, SourceOutcomeKind::SchemaDrift);
        let requests = fake.requests.lock().expect("requests");
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].header_value("authorization"),
            Some("Bearer owned-fixture-secret-abcdef123456")
        );
        assert!(!format!("{:?}", requests[0]).contains("owned-fixture-secret-abcdef123456"));
        assert!(requests[0].url.starts_with(X_API_URL));
    }

    #[test]
    fn reject_spoofed_social_host_and_invalid_query_without_io() {
        let fake = Fake::default();
        assert!(is_public_x_url("https://x.com/u/status/1"));
        assert!(!is_public_x_url("https://x.com.attacker.example/status/1"));
        assert!(!is_public_x_url("http://x.com/u/status/1"));
        assert!(search_indexed_x(&fake, "a\nb", 100).is_err());
        assert!(fake.requests.lock().expect("requests").is_empty());
    }
}
