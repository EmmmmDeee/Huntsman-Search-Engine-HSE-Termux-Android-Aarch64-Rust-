//! Explicit, bounded Exa web search for discovery leads, never claim corroboration.
//!
//! The search API spends Exa credits. No automatic scan, adaptive round or
//! background fetch calls this source. Only an operator's explicit `query --exa`
//! action may request it with `HUNTSMAN_EXA_KEY` privately configured.

use std::collections::BTreeSet;

use serde_json::{Value, json};

use crate::api_leg::{self, Answer, Api, KeyPlace, KeyUse, LegError};
use crate::canonical::canonical_url;
use crate::http::Transport;
use crate::keys::Keys;

pub const SOURCE: &str = "exa";
pub const URL: &str = "https://api.exa.ai/search";
/// Keep the low-cost Exa Lite request within the first base-priced result batch.
pub const MAX_RESULTS: usize = 5;
pub const EXA_MAX_QUERY_BYTES: usize = 512;

pub const API: Api = Api {
    source: SOURCE,
    provider: "exa.ai",
    origin: "https://api.exa.ai:443",
    key: Some(KeyUse {
        slot: crate::environment::EXA_KEY_ENV,
        place: KeyPlace::Header("x-api-key"),
        required: true,
    }),
};

/// Return public HTTP(S) search URLs only. Search hits are unverified leads.
///
/// # Errors
/// Returns a typed missing-key, transport, provider or invalid-response error.
/// Malformed responses are never treated as a completed search with zero hits.
pub fn search<T: Transport + ?Sized>(
    transport: &T,
    keys: &Keys,
    query: &str,
    now_unix: u64,
) -> Result<Vec<String>, LegError> {
    if query.trim().is_empty()
        || query.len() > EXA_MAX_QUERY_BYTES
        || query.chars().any(char::is_control)
    {
        return Err(LegError::Decode(
            "search query must contain 1-512 bytes without control characters".into(),
        ));
    }
    let body = json!({
        "query": query.trim(),
        "type": "lite",
        "numResults": MAX_RESULTS
    });
    match api_leg::post_json(transport, &API, keys, URL, &body, now_unix)? {
        Answer::Body(bytes) => decode(&bytes),
        Answer::NotFound(_) => Err(LegError::Unexpected(404)),
    }
}

/// Validate the documented Exa search response and canonicalize the returned URLs.
///
/// # Errors
/// Missing results or invalid URLs are schema drift, not verified zero.
pub fn decode(body: &[u8]) -> Result<Vec<String>, LegError> {
    let payload: Value = api_leg::decode(body)?;
    let results = payload
        .get("results")
        .and_then(Value::as_array)
        .ok_or_else(|| LegError::Decode("Exa results array missing".into()))?;
    if results.len() > MAX_RESULTS {
        return Err(LegError::Decode(
            "Exa returned more results than requested".into(),
        ));
    }
    let mut seen = BTreeSet::new();
    let mut hits = Vec::with_capacity(results.len());
    for row in results {
        let url = row
            .get("url")
            .and_then(Value::as_str)
            .and_then(canonical_url)
            .ok_or_else(|| LegError::Decode("Exa result URL missing or invalid".into()))?;
        if seen.insert(url.clone()) {
            hits.push(url);
        }
    }
    Ok(hits)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::http::{Request, Response, TransportFailure};

    struct Fixed {
        status: u16,
        body: &'static str,
        requests: Mutex<Vec<Request>>,
    }

    impl Fixed {
        fn new(status: u16, body: &'static str) -> Self {
            Self {
                status,
                body,
                requests: Mutex::new(Vec::new()),
            }
        }
    }

    impl Transport for Fixed {
        fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
            self.requests
                .lock()
                .expect("requests")
                .push(request.clone());
            Ok(Response {
                status: self.status,
                headers: vec![("content-type".into(), "application/json".into())],
                body: self.body.as_bytes().to_vec(),
                truncated: false,
            })
        }
    }

    fn keys() -> Keys {
        Keys::parse("HUNTSMAN_EXA_KEY=TEST_ONLY_EXA_TOKEN\n").expect("test key")
    }

    #[test]
    fn missing_key_is_not_a_paid_request() {
        let transport = Fixed::new(200, r#"{"results":[]}"#);
        let result = search(&transport, &Keys::default(), "example", 1);
        assert!(matches!(result, Err(LegError::MissingKey(_))));
        assert!(transport.requests.lock().expect("requests").is_empty());
    }

    #[test]
    fn explicit_search_has_correct_headers_and_fixed_credit_budget() {
        let transport = Fixed::new(
            200,
            r#"{"results":[{"url":"https://example.org/a#frag"},{"url":"https://example.org/a"}]}"#,
        );
        let hits = search(&transport, &keys(), "open data", 1).expect("search");
        assert_eq!(hits, ["https://example.org/a"]);
        let requests = transport.requests.lock().expect("requests");
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].url, URL);
        assert_eq!(
            requests[0].header_value("x-api-key"),
            Some("TEST_ONLY_EXA_TOKEN")
        );
        assert!(String::from_utf8_lossy(&requests[0].body).contains("\"numResults\":5"));
        assert!(String::from_utf8_lossy(&requests[0].body).contains("\"type\":\"lite\""));
        assert!(!String::from_utf8_lossy(&requests[0].body).contains("TEST_ONLY_EXA_TOKEN"));
    }

    #[test]
    fn invalid_response_is_never_a_zero() {
        for body in [
            r"{}",
            r#"{"results":{}}"#,
            r#"{"results":[{"url":"file:///etc/passwd"}]}"#,
            r#"{"results":[{}]}"#,
        ] {
            assert!(decode(body.as_bytes()).is_err(), "{body}");
        }
        assert!(decode(br#"{"results":[]}"#).expect("valid zero").is_empty());
    }

    #[test]
    fn invalid_query_or_rejected_key_makes_no_claims() {
        let transport = Fixed::new(401, r#"{"error":"bad token"}"#);
        assert!(search(&transport, &keys(), "\n", 1).is_err());
        assert!(transport.requests.lock().expect("requests").is_empty());
        assert!(matches!(
            search(&transport, &keys(), "example", 1),
            Err(LegError::Unauthorized)
        ));
    }
}
