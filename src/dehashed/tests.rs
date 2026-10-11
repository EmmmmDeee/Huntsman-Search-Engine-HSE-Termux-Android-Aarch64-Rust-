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
pub(super) struct Fake {
    pub(super) responses: Mutex<VecDeque<Response>>,
    pub(super) requests: Mutex<Vec<Request>>,
    pub(super) fail: bool,
}

impl Fake {
    pub(super) fn with(status: u16, body: &str, headers: &[(&str, &str)]) -> Arc<Self> {
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

    pub(super) fn calls(&self) -> usize {
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

pub(super) fn client(fake: &Arc<Fake>) -> DehashedClient {
    DehashedClient::with_limiter(
        fake.clone(),
        Secret::new(KEY).unwrap(),
        RateLimiter::per_minute(0),
    )
}

pub(super) fn email_request(purpose: Purpose) -> SearchRequest {
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

mod collector_tests {
    use super::*;
    use crate::collector::{CollectionLimits, CollectionOutcome, CollectorError};
    use crate::dehashed::collector::{COLLECTOR_ID, collect};
    use crate::entity::{Entity, EntityKind};
    use crate::lineage::Lineage;
    use crate::source_outcome::SourceOutcomeKind;

    const RECORDS: &str = r#"{
        "entries": [
            {"database_name": "ExampleBreach", "email": ["a@example.com", "b@example.com"],
             "username": "ada", "password": "must-not-leak"},
            {"database_name": "ExampleBreach", "email": "a@example.com", "hashed_password": "h"}
        ],
        "total": 2
    }"#;

    fn selector(kind: EntityKind, value: &str) -> Entity {
        Entity::new(kind, value, 1.0, "scan-1")
    }

    fn purpose() -> Purpose {
        Purpose::OwnAccount
    }

    fn limits() -> CollectionLimits {
        CollectionLimits::default()
    }

    #[test]
    fn maps_records_to_entities_pivots_and_evidence() {
        let fake = Fake::with(200, RECORDS, &[]);
        let client = client(&fake);
        let batch = collect(
            &client,
            &selector(EntityKind::Email, "a@example.com"),
            purpose(),
            &limits(),
            1_700_000_000,
        )
        .unwrap();

        assert_eq!(batch.collector_id, COLLECTOR_ID);
        assert_eq!(batch.outcome, CollectionOutcome::Success);
        assert_eq!(batch.receipts.len(), 1);
        assert_eq!(batch.receipts[0].dataset.as_deref(), Some("ExampleBreach"));
        assert_eq!(batch.receipts[0].parsed_rows, 2);
        assert!(batch.receipts[0].response_sha256.is_some());

        // Selector "a@example.com" is deduplicated across records; "b@example.com" and "ada" are pivots.
        let emails: Vec<&str> = batch
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Email)
            .map(|e| e.value.as_str())
            .collect();
        assert_eq!(emails.len(), 2, "{emails:?}");
        assert!(batch.pivots.iter().any(|p| p.value == "b@example.com"));
        assert!(batch.pivots.iter().any(|p| p.value == "ada"));
        assert!(!batch.pivots.iter().any(|p| p.value == "a@example.com"));
    }

    #[test]
    fn evidence_never_carries_password_values() {
        let fake = Fake::with(200, RECORDS, &[]);
        let batch = collect(
            &client(&fake),
            &selector(EntityKind::Email, "a@example.com"),
            purpose(),
            &limits(),
            1,
        )
        .unwrap();
        for entity in &batch.entities {
            for evidence in &entity.evidence {
                let rendered = format!("{evidence:?}");
                assert!(!rendered.contains("must-not-leak"), "{rendered}");
            }
        }
    }

    #[test]
    fn database_name_feeds_lineage_as_one_family() {
        let fake = Fake::with(200, RECORDS, &[]);
        let batch = collect(
            &client(&fake),
            &selector(EntityKind::Email, "a@example.com"),
            purpose(),
            &limits(),
            1,
        )
        .unwrap();
        let evidence = batch
            .entities
            .iter()
            .flat_map(|e| e.evidence.iter())
            .next()
            .expect("at least one evidence record");
        let lineage = Lineage::of(evidence);
        // Lineage canonicalises dataset names to lower case; mirrors of one dataset must collapse to one family.
        assert_eq!(lineage.family(), Some("examplebreach"), "{lineage:?}");
    }

    #[test]
    fn valid_zero_is_a_zero_not_a_failure() {
        let fake = Fake::with(200, r#"{"entries": [], "total": 0}"#, &[]);
        let batch = collect(
            &client(&fake),
            &selector(EntityKind::Domain, "example.com"),
            purpose(),
            &limits(),
            1,
        )
        .unwrap();
        assert_eq!(batch.outcome, CollectionOutcome::ValidZero);
        assert_eq!(batch.receipts[0].outcome.kind, SourceOutcomeKind::ValidZero);
        assert!(batch.entities.is_empty());
    }

    #[test]
    fn more_records_than_returned_is_partial() {
        let fake = Fake::with(
            200,
            r#"{"entries": [{"email": "a@example.com"}], "total": 50}"#,
            &[],
        );
        let batch = collect(
            &client(&fake),
            &selector(EntityKind::Email, "a@example.com"),
            purpose(),
            &limits(),
            1,
        )
        .unwrap();
        assert_eq!(batch.outcome, CollectionOutcome::Partial);
        assert!(batch.receipts[0].truncated);
    }

    #[test]
    fn upstream_failures_are_recorded_not_raised() {
        let cases = [
            (401, SourceOutcomeKind::AuthRejected),
            (403, SourceOutcomeKind::EntitlementDenied),
            (429, SourceOutcomeKind::RateLimited),
            (503, SourceOutcomeKind::Upstream5xx),
        ];
        for (status, expected) in cases {
            let fake = Fake::with(status, "", &[]);
            let batch = collect(
                &client(&fake),
                &selector(EntityKind::Email, "a@example.com"),
                purpose(),
                &limits(),
                1,
            )
            .unwrap_or_else(|e| panic!("{status}: {e:?}"));
            assert_eq!(batch.outcome, CollectionOutcome::Failed, "{status}");
            assert_eq!(batch.receipts[0].outcome.kind, expected, "{status}");
            assert_eq!(batch.receipts[0].outcome.http_status, Some(status));
            assert!(batch.entities.is_empty());
        }
    }

    #[test]
    fn failure_receipt_detail_never_names_the_identifier() {
        let fake = Fake::with(400, "", &[]);
        let batch = collect(
            &client(&fake),
            &selector(EntityKind::Email, "a@example.com"),
            purpose(),
            &limits(),
            1,
        )
        .unwrap();
        let detail = batch.receipts[0].outcome.detail.clone().unwrap_or_default();
        assert!(!detail.contains("a@example.com"), "{detail}");
    }

    #[test]
    fn unsupported_kinds_and_invalid_values_send_nothing() {
        let fake = Fake::with(200, r#"{"entries": []}"#, &[]);
        assert!(matches!(
            collect(
                &client(&fake),
                &selector(EntityKind::Phone, "15551234567"),
                purpose(),
                &limits(),
                1
            ),
            Err(CollectorError::UnsupportedSelector(_))
        ));
        assert!(matches!(
            collect(
                &client(&fake),
                &selector(EntityKind::Email, "*@example.com"),
                purpose(),
                &limits(),
                1
            ),
            Err(CollectorError::InvalidSelector(_))
        ));
        let zero_budget = CollectionLimits {
            max_requests: 0,
            ..CollectionLimits::default()
        };
        assert!(matches!(
            collect(
                &client(&fake),
                &selector(EntityKind::Email, "a@example.com"),
                purpose(),
                &zero_budget,
                1
            ),
            Err(CollectorError::Invariant(_))
        ));
        assert_eq!(fake.calls(), 0);
    }
}

#[test]
fn key_env_var_matches_the_provider_registry() {
    // service_defs sits in a lower layer and cannot import this module, so the
    // env var name is kept in step by this test instead.
    let def = crate::service_defs::find_service("dehashed").expect("dehashed registered");
    assert_eq!(def.env_var, super::client::API_KEY_ENV);
}
