//! Client behaviour over a fake transport. No test touches the network.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use super::cli;
use super::client::{
    API_KEY_HEADER, DEHASHED_API_BASE, DehashedClient, DehashedError, SearchRequest,
};
use super::query::{Field, Purpose, Selector};
use crate::hibp::rate_limit::RateLimiter;
use crate::http::{Request, Response, Transport, TransportFailure};
use crate::keys::Secret;

const KEY: &str = "test-key-7f3a9c";

#[derive(Default)]
struct Fake {
    responses: Mutex<VecDeque<Response>>,
    requests: Mutex<Vec<Request>>,
    fail: bool,
}

impl Fake {
    fn with(status: u16, body: &str, headers: &[(&str, &str)]) -> Arc<Self> {
        let fake = Self::default();
        fake.responses.lock().unwrap().push_back(Response {
            status,
            headers: headers
                .iter()
                .map(|(k, v)| ((*k).into(), (*v).into()))
                .collect(),
            body: body.as_bytes().to_vec(),
            truncated: false,
        });
        Arc::new(fake)
    }

    fn calls(&self) -> usize {
        self.requests.lock().unwrap().len()
    }
}

impl Transport for Fake {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        self.requests.lock().unwrap().push(request.clone());
        if self.fail {
            return Err(TransportFailure {
                kind: crate::source_outcome::SourceOutcomeKind::TtfbTimeout,
                detail: "a@example.com leaked-detail".into(),
                blocked: false,
            });
        }
        Ok(self
            .responses
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected request"))
    }
}

fn client(fake: &Arc<Fake>) -> DehashedClient {
    DehashedClient::with_limiter(
        fake.clone(),
        Secret::new(KEY).unwrap(),
        RateLimiter::per_minute(0),
    )
}

fn email_request(purpose: Purpose) -> SearchRequest {
    SearchRequest::new(
        Selector::new(Field::Email, "a@example.com").unwrap(),
        purpose,
    )
}

#[test]
fn sends_one_post_to_the_fixed_origin_with_exact_body_and_key_header() {
    let fake = Fake::with(200, r#"{"entries": [], "total": 0}"#, &[]);
    let outcome = client(&fake)
        .search(&email_request(Purpose::OwnAccount))
        .unwrap();
    assert_eq!(outcome.total, Some(0));
    assert_eq!(outcome.query, "email:\"a@example.com\"");

    let requests = fake.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    let sent = &requests[0];
    assert_eq!(sent.method, crate::http::Method::Post);
    assert_eq!(sent.url, format!("{DEHASHED_API_BASE}/search"));
    assert_eq!(sent.header_value(API_KEY_HEADER), Some(KEY));
    let body: serde_json::Value = serde_json::from_slice(&sent.body).unwrap();
    assert_eq!(
        body,
        serde_json::json!({
            "query": "email:\"a@example.com\"",
            "page": 1,
            "size": 10,
            "de_dupe": true,
            "regex": false,
            "wildcard": false
        })
    );
}

#[test]
fn debug_output_of_the_request_redacts_the_key() {
    let fake = Fake::with(200, r#"{"entries": []}"#, &[]);
    client(&fake)
        .search(&email_request(Purpose::OwnAccount))
        .unwrap();
    let rendered = format!("{:?}", fake.requests.lock().unwrap()[0]);
    assert!(!rendered.contains(KEY), "{rendered}");
    assert!(rendered.contains("[redacted]"), "{rendered}");
}

#[test]
fn decodes_entries_into_the_outcome() {
    let body = r#"{"entries": [{"database_name": "Ex", "email": ["a@example.com"], "password": "p"}], "total": 1}"#;
    let fake = Fake::with(200, body, &[]);
    let outcome = client(&fake)
        .search(&email_request(Purpose::IncidentResponse))
        .unwrap();
    assert_eq!(outcome.entries.len(), 1);
    assert_eq!(outcome.entries[0].database_name.as_deref(), Some("Ex"));
    assert_eq!(outcome.purpose, Purpose::IncidentResponse);
}

#[test]
fn status_codes_map_to_named_errors() {
    let cases: [(u16, &str); 4] = [
        (401, "Unauthorized"),
        (403, "Forbidden"),
        (400, "BadRequest"),
        (418, "Unexpected"),
    ];
    for (status, name) in cases {
        let fake = Fake::with(status, "echo a@example.com", &[]);
        let error = client(&fake)
            .search(&email_request(Purpose::OwnAccount))
            .unwrap_err();
        assert!(
            format!("{error:?}").starts_with(name),
            "{status}: {error:?}"
        );
        assert!(!error.to_string().contains("a@example.com"), "{error}");
    }
    let fake = Fake::with(503, "", &[]);
    assert!(matches!(
        client(&fake).search(&email_request(Purpose::OwnAccount)),
        Err(DehashedError::Server(503))
    ));
}

#[test]
fn rate_limit_reports_retry_after_without_retrying() {
    let fake = Fake::with(429, "", &[("retry-after", "42")]);
    let error = client(&fake)
        .search(&email_request(Purpose::OwnAccount))
        .unwrap_err();
    match error {
        DehashedError::RateLimited { retry_after } => {
            assert_eq!(retry_after, Some(std::time::Duration::from_secs(42)));
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(fake.calls(), 1, "a 429 must not be retried automatically");
}

#[test]
fn unexpected_body_shape_is_an_error_and_is_not_echoed() {
    let fake = Fake::with(200, r#"{"results": "a@example.com"}"#, &[]);
    let error = client(&fake)
        .search(&email_request(Purpose::OwnAccount))
        .unwrap_err();
    assert!(matches!(error, DehashedError::Decode(_)), "{error:?}");
    assert!(!error.to_string().contains("a@example.com"), "{error}");
}

#[test]
fn truncated_body_is_refused() {
    let fake = Fake::default();
    fake.responses.lock().unwrap().push_back(Response {
        status: 200,
        headers: vec![],
        body: b"{\"entries\": []}".to_vec(),
        truncated: true,
    });
    let error = client(&Arc::new(fake))
        .search(&email_request(Purpose::OwnAccount))
        .unwrap_err();
    assert!(matches!(error, DehashedError::Decode(_)), "{error:?}");
}

#[test]
fn transport_failure_does_not_leak_the_identifier() {
    let fake = Arc::new(Fake {
        fail: true,
        ..Fake::default()
    });
    let error = client(&fake)
        .search(&email_request(Purpose::OwnAccount))
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "dehashed: transport error: request failed"
    );
}

#[test]
fn invalid_bounds_are_rejected_before_any_request() {
    let fake = Fake::with(200, r#"{"entries": []}"#, &[]);
    let mut request = email_request(Purpose::OwnAccount);
    request.size = 0;
    assert!(matches!(
        client(&fake).search(&request),
        Err(DehashedError::InvalidSize(0))
    ));
    request.size = 10;
    request.page = 1_001;
    assert!(matches!(
        client(&fake).search(&request),
        Err(DehashedError::InvalidPage(1_001))
    ));
    assert_eq!(fake.calls(), 0);
}

#[test]
fn cli_refuses_bad_arguments_before_loading_a_key_or_sending() {
    let fake = Fake::with(200, r#"{"entries": []}"#, &[]);
    let mut out = Vec::new();
    let mut err = Vec::new();
    let key_loaded = std::cell::Cell::new(false);
    let args: Vec<String> = [
        "search",
        "--email",
        "*@example.com",
        "--purpose",
        "own-account",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect();
    let code = cli::run(
        &args,
        || {
            key_loaded.set(true);
            Secret::new(KEY).map_err(|_| DehashedError::MissingKey)
        },
        fake.clone(),
        &mut out,
        &mut err,
    );
    assert_eq!(code, 65);
    assert!(!key_loaded.get());
    assert_eq!(fake.calls(), 0);
}

#[test]
fn cli_without_a_key_exits_66_and_sends_nothing() {
    let fake = Fake::with(200, r#"{"entries": []}"#, &[]);
    let args: Vec<String> = [
        "search",
        "--domain",
        "example.com",
        "--purpose",
        "own-account",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = cli::run(
        &args,
        || Err(DehashedError::MissingKey),
        fake.clone(),
        &mut out,
        &mut err,
    );
    assert_eq!(code, 66);
    assert_eq!(fake.calls(), 0);
}

#[test]
fn cli_success_prints_results_and_purpose() {
    let body = r#"{"entries": [{"email": "a@example.com", "hashed_password": "h"}], "total": 1}"#;
    let fake = Fake::with(200, body, &[]);
    let args: Vec<String> = [
        "search",
        "--email",
        "a@example.com",
        "--purpose",
        "own-account",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = cli::run(
        &args,
        || Ok(Secret::new(KEY).unwrap()),
        fake,
        &mut out,
        &mut err,
    );
    assert_eq!(code, 0, "{}", String::from_utf8_lossy(&err));
    let text = String::from_utf8(out).unwrap();
    assert!(text.contains("purpose=own-account\n"), "{text}");
    assert!(text.contains("has_hashed_password=true\n"), "{text}");
    assert!(!text.contains(KEY));
}
