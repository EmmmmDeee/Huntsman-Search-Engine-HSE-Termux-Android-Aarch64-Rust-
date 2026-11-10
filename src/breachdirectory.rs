//! Opt-in BreachDirectory RapidAPI source-only lookup.
//!
//! This collector intentionally requests `func=sources` and **never** the modes that
//! return passwords, password hashes, or domain-wide account records. A source name
//! is an uncorroborated breach lead, not independently verified account ownership.
//! The API key comes only from the operator-managed Huntsman credential slot,
//! travels through the single guarded fetch path, and is pinned to RapidAPI's origin.
//! A missing or malformed `sources` list is an inconclusive provider response,
//! never proof that no breach exists.

use std::sync::OnceLock;
use std::time::Duration;

use serde_json::Value;

use crate::credential_origin::AuthenticationAuthority;
use crate::fetch::{self, AuthStyle, Credential, FetchOptions};
use crate::http::{Request, Transport, percent_encode_component};
use crate::keys::Keys;
use crate::rate_limit::RateLimiter;
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};

pub const SOURCE: &str = "breachdirectory";
pub const KEY_SLOT: &str = crate::environment::BREACHDIRECTORY_KEY_ENV;
pub const API_URL: &str = "https://breachdirectory.p.rapidapi.com/";
pub const KEY_ORIGIN: &str = "https://breachdirectory.p.rapidapi.com:443";
pub const API_HOST: &str = "breachdirectory.p.rapidapi.com";
pub const MAX_SOURCES: usize = 256;
pub const MAX_SOURCE_BYTES: usize = 256;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

static REQUEST_BUDGET: OnceLock<RateLimiter> = OnceLock::new();

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Search {
    /// Only names returned by `sources`; never credential records.
    pub sources: Vec<String>,
}

/// Build an exact one-selector query with URL-encoded bytes; no raw selector is logged.
#[must_use]
pub fn sources_url(selector: &str) -> String {
    format!(
        "{API_URL}?func=sources&term={}",
        percent_encode_component(selector)
    )
}

/// Parse a documented `sources` array. Empty `[]` is a valid zero; absent,
/// null or malformed arrays are schema errors until live observations establish
/// the provider's negative-response contract. Provider diagnostic text is dropped.
pub fn decode_sources(body: &[u8]) -> Result<Search, SourceOutcomeKind> {
    let data: Value =
        serde_json::from_slice(body).map_err(|_| SourceOutcomeKind::ParserDrift)?;
    let object = data.as_object().ok_or(SourceOutcomeKind::SchemaDrift)?;
    if object.get("success") == Some(&Value::Bool(false))
        || object.get("error").is_some_and(|error| !error.is_null() && error != &Value::Bool(false))
    {
        return Err(SourceOutcomeKind::Inconclusive);
    }
    let array = object
        .get("sources")
        .and_then(Value::as_array)
        .ok_or(SourceOutcomeKind::SchemaDrift)?;
    if array.len() > MAX_SOURCES {
        return Err(SourceOutcomeKind::SchemaDrift);
    }
    let mut sources = Vec::with_capacity(array.len());
    for item in array {
        let name = item.as_str().ok_or(SourceOutcomeKind::SchemaDrift)?;
        if name.trim().is_empty()
            || name.len() > MAX_SOURCE_BYTES
            || name.chars().any(char::is_control)
        {
            return Err(SourceOutcomeKind::SchemaDrift);
        }
        if !sources.iter().any(|prior| prior == name) {
            sources.push(name.to_owned());
        }
    }
    Ok(Search { sources })
}

/// One source-only query, paced across this entire process. The default budget
/// is one request per second because active plan limits are not verified; a
/// future verified provider contract may replace that conservative default.
#[must_use]
pub fn search<T: Transport + ?Sized>(
    transport: &T,
    keys: &Keys,
    selector: &str,
    now_unix: u64,
) -> (Option<Search>, SourceExecutionOutcome) {
    let limiter = REQUEST_BUDGET.get_or_init(|| RateLimiter::new(1, Duration::from_secs(1)));
    search_with_limiter(transport, keys, selector, now_unix, limiter)
}

/// Injectable limiter keeps transport/parser tests deterministic without sleeps.
#[must_use]
pub fn search_with_limiter<T: Transport + ?Sized>(
    transport: &T,
    keys: &Keys,
    selector: &str,
    now_unix: u64,
    limiter: &RateLimiter,
) -> (Option<Search>, SourceExecutionOutcome) {
    let Some(secret) = keys.provider_key(KEY_SLOT) else {
        return (None, SourceExecutionOutcome::not_configured(SOURCE, now_unix));
    };
    let fail = |kind, status, detail| {
        SourceExecutionOutcome::failed(SOURCE, now_unix, kind, status, detail)
    };

    if selector.is_empty() || selector.len() > 254 || selector.chars().any(char::is_control) {
        return (
            None,
            fail(SourceOutcomeKind::Inconclusive, None, "invalid exact selector"),
        );
    }
    let authority = match AuthenticationAuthority::configured_slot(SOURCE, KEY_SLOT, now_unix) {
        Ok(authority) => authority,
        Err(_) => {
            return (
                None,
                SourceExecutionOutcome::refused_before_sending(
                    SOURCE,
                    now_unix,
                    "operator authentication authority unavailable",
                ),
            );
        }
    };
    let credential = match Credential::new(
        authority,
        secret,
        AuthStyle::Header("X-RapidAPI-Key".to_owned()),
    ) {
        Ok(credential) => credential.only_for_origin(KEY_ORIGIN),
        Err(_) => {
            return (
                None,
                SourceExecutionOutcome::refused_before_sending(
                    SOURCE,
                    now_unix,
                    "credential origin binding failed",
                ),
            );
        }
    };
    if limiter.acquire_within(REQUEST_TIMEOUT).is_err() {
        return (
            None,
            fail(SourceOutcomeKind::RateLimited, None, "provider pacing budget unavailable"),
        );
    }
    let request = Request::get(sources_url(selector))
        .header("Accept", "application/json")
        .header("X-RapidAPI-Host", API_HOST)
        .with_timeout(REQUEST_TIMEOUT);
    let fetched = match fetch::fetch(
        transport,
        request,
        Some(&credential),
        &FetchOptions::no_redirects(),
        SOURCE,
        now_unix,
    ) {
        Ok(fetched) => fetched,
        Err(_) => {
            return (
                None,
                SourceExecutionOutcome::refused_before_sending(
                    SOURCE,
                    now_unix,
                    "guarded HTTP refused request",
                ),
            );
        }
    };
    if fetched.outcome.kind == SourceOutcomeKind::RateLimited {
        if let Some(seconds) = fetched.outcome.retry_after_secs {
            limiter.block_for(Duration::from_secs(seconds));
        }
    }
    let response = match fetch::whole_response(&fetched, "BreachDirectory") {
        Ok(response) => response,
        Err(outcome) => return (None, outcome),
    };
    if let Err(outcome) = fetch::answer(&fetched, "BreachDirectory") {
        return (None, outcome);
    }
    let search = match decode_sources(&response.body) {
        Ok(search) => search,
        Err(kind) => {
            return (
                None,
                fail(
                    kind,
                    Some(response.status),
                    "BreachDirectory source response was not an authoritative sources array",
                ),
            );
        }
    };
    let outcome = if search.sources.is_empty() {
        SourceExecutionOutcome::valid_zero(SOURCE, now_unix)
    } else {
        SourceExecutionOutcome::success(SOURCE, now_unix, search.sources.len())
    }
    .with_http_status(response.status);
    (Some(search), outcome)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::http::{Response, TransportFailure};

    struct Fake {
        status: u16,
        body: &'static [u8],
        requests: Mutex<Vec<Request>>,
    }

    impl Fake {
        fn new(status: u16, body: &'static [u8]) -> Self {
            Self {
                status,
                body,
                requests: Mutex::new(Vec::new()),
            }
        }

        fn requests(&self) -> Vec<Request> {
            self.requests.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone()
        }
    }

    impl Transport for Fake {
        fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
            self.requests
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(request.clone());
            Ok(Response {
                status: self.status,
                headers: Vec::new(),
                body: self.body.to_vec(),
                truncated: false,
            })
        }
    }

    fn keys() -> Keys {
        Keys::parse(&format!("{KEY_SLOT}=test-operator-key-not-a-secret"))
            .unwrap_or_else(|error| panic!("{error}"))
    }

    fn run<'a>(net: &Fake, keys: &Keys, selector: &'a str) -> (Option<Search>, SourceExecutionOutcome) {
        search_with_limiter(net, keys, selector, 7, &RateLimiter::per_minute(0))
    }

    #[test]
    fn missing_key_never_sends_and_is_not_zero() {
        let net = Fake::new(200, br#"{"sources":[]}"#);
        let (found, outcome) = run(&net, &Keys::default(), "ada@example.com");
        assert!(found.is_none());
        assert_eq!(outcome.kind, SourceOutcomeKind::NotConfigured);
        assert!(net.requests().is_empty());
    }

    #[test]
    fn exact_sources_request_has_both_headers_and_encoded_selector() {
        let net = Fake::new(200, br#"{"sources":["Example Breach","Archive A"]}"#);
        let (found, outcome) = run(&net, &keys(), "test+tag@example.com");
        assert_eq!(outcome.kind, SourceOutcomeKind::Success);
        assert_eq!(found.unwrap().sources, ["Example Breach", "Archive A"]);
        let requests = net.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].header_value("X-RapidAPI-Host"), Some(API_HOST));
        assert_eq!(requests[0].header_value("X-RapidAPI-Key"), Some("test-operator-key-not-a-secret"));
        assert!(requests[0].url.contains("func=sources&term=test%2Btag%40example.com"));
        assert!(!requests[0].url.contains("func=auto"));
    }

    #[test]
    fn explicit_empty_list_is_zero_but_null_is_not() {
        let zero = Fake::new(200, br#"{"sources":[]}"#);
        assert_eq!(run(&zero, &keys(), "ada@example.com").1.kind, SourceOutcomeKind::ValidZero);
        let unknown = Fake::new(200, br#"{"sources":null}"#);
        assert_eq!(run(&unknown, &keys(), "ada@example.com").1.kind, SourceOutcomeKind::SchemaDrift);
    }

    #[test]
    fn provider_error_and_password_payload_are_never_promoted_to_evidence() {
        let err = Fake::new(200, br#"{"success":false,"sources":[]}"#);
        assert_eq!(run(&err, &keys(), "ada@example.com").1.kind, SourceOutcomeKind::Inconclusive);
        let extra = Fake::new(200, br#"{"sources":["Sample"],"password":"do-not-retain"}"#);
        let (found, outcome) = run(&extra, &keys(), "ada@example.com");
        assert_eq!(outcome.kind, SourceOutcomeKind::Success);
        assert!(!format!("{found:?}").contains("do-not-retain"));
    }

    #[test]
    fn unauthorized_and_rate_limit_never_become_valid_zero() {
        let unauthorized = Fake::new(401, br#"{"message":"invalid key"}"#);
        let (_, denied) = run(&unauthorized, &keys(), "ada@example.com");
        assert!(!denied.kind.is_accepted());
        let limit = Fake::new(429, br#"{"message":"rate limited"}"#);
        let (_, exceeded) = run(&limit, &keys(), "ada@example.com");
        assert_eq!(exceeded.kind, SourceOutcomeKind::RateLimited);
    }

    #[test]
    fn malformed_and_oversized_source_lists_fail_closed() {
        let bad = Fake::new(200, br#"{"sources":[{"password":"secret"}]}"#);
        assert_eq!(run(&bad, &keys(), "ada@example.com").1.kind, SourceOutcomeKind::SchemaDrift);
        let sources = serde_json::json!({"sources": vec!["x"; MAX_SOURCES + 1]});
        assert_eq!(decode_sources(sources.to_string().as_bytes()), Err(SourceOutcomeKind::SchemaDrift));
    }
}
