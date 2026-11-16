//! Explicit, bounded Exa web search for discovery leads, never claim corroboration.
//!
//! The search API spends Exa credits. No automatic scan, adaptive round or
//! background fetch calls this source. Only an operator's explicit `query --exa`
//! action may request it with `HUNTSMAN_EXA_KEY` privately configured.

use crate::api_leg::{Api, LegError};
use crate::http::Transport;
use crate::keys::Keys;
use crate::search_api::SearchApi;

pub use crate::search_api::{MAX_QUERY_BYTES as EXA_MAX_QUERY_BYTES, MAX_RESULTS};

pub const SOURCE: &str = crate::search_api::EXA_SOURCE;
pub const URL: &str = crate::search_api::EXA_URL;
pub const API: Api = crate::search_api::EXA_API;

/// Return up to five public HTTP(S) discovery URLs.
///
/// # Errors
/// See [`SearchApi::search`].
pub fn search<T: Transport + ?Sized>(
    transport: &T,
    keys: &Keys,
    query: &str,
    now_unix: u64,
) -> Result<Vec<String>, LegError> {
    SearchApi::Exa.search(transport, keys, query, now_unix)
}

/// Validate an Exa search result and canonicalize its URLs.
///
/// # Errors
/// Returns a schema error for malformed results.
pub fn decode(body: &[u8]) -> Result<Vec<String>, LegError> {
    SearchApi::Exa.decode(body, None, None)
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
