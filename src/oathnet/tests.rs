use std::sync::Mutex;

use super::*;
use crate::http::{Method, TransportFailure};

const KEY: &str = "on-test-key-0123456789abcdef";

fn keys() -> Keys {
    match Keys::parse(&format!("{KEY_SLOT}={KEY}\n")) {
        Ok(keys) => keys,
        Err(error) => panic!("fixture keys parse: {error}"),
    }
}

/// The breach-search guide's response, with a second database, a record that names no database,
/// and the `dbname_info` block of the `OpenAPI` schema.
fn sample() -> Value {
    serde_json::json!({
        "success": true,
        "message": "Breach search completed",
        "data": {
            "items": [
                {"id": "r1", "email": "user@example.com", "email_domain": "example.com",
                 "username": "user123", "password": "hunter2-secret", "country": "US",
                 "dbname": "linkedin_2012", "indexed_at": "2026-04-18T12:00:00Z"},
                {"id": "r2", "email": "user@example.com", "phone_number": "+15555550100",
                 "password_hash": "5f4dcc3b5aa765d61d8327deb882cf99", "dbname": "linkedin_2012",
                 "indexed_at": "2025-01-02T00:00:00Z", "city": "", "extra": {"twitter": "@ada"}},
                {"id": "r3", "email": "user@example.com", "full_name": "Ada Example",
                 "dbname": "acme_forum", "indexed_at": "2024-06-01T00:00:00Z"},
                {"id": "r4", "email": "user@example.com", "username": "ada_alt"}
            ],
            "meta": {"count": 4, "total": 4, "took_ms": 8, "has_more": false, "total_pages": 1},
            "dbname_info": {
                "linkedin_2012": {"Title": "LinkedIn", "Domain": "linkedin.com",
                                  "BreachDate": "2012-05-05", "PwnCount": 164_611_595}
            },
            "next_cursor": null
        },
        "_meta": {"lookups": {"left_today": 9998}}
    })
}

fn decoded(body: &Value) -> Search {
    match decode(body.to_string().as_bytes(), &[KEY]) {
        Ok(search) => search,
        Err(error) => panic!("decode failed: {error}"),
    }
}

#[test]
fn records_become_per_database_exposure_metadata() {
    let search = decoded(&sample());
    assert_eq!(search.records, 4);
    assert_eq!(search.unnamed_records, 1);
    assert_eq!(search.truncation(), None);
    let names: Vec<&str> = search.breaches.iter().map(|b| b.dbname.as_str()).collect();
    assert_eq!(names, ["acme_forum", "linkedin_2012"]);

    let linkedin = &search.breaches[1];
    assert_eq!(linkedin.records, 2);
    assert!(linkedin.password_exposed);
    let fields: Vec<&str> = linkedin.fields.iter().map(String::as_str).collect();
    assert_eq!(
        fields,
        [
            "country",
            "email",
            "password",
            "password_hash",
            "phone_number",
            "twitter",
            "username"
        ],
        "a blank value and the record's own metadata are not exposed fields"
    );
    assert_eq!(linkedin.title.as_deref(), Some("LinkedIn"));
    assert_eq!(linkedin.domain.as_deref(), Some("linkedin.com"));
    assert_eq!(linkedin.breach_date.as_deref(), Some("2012-05-05"));
    assert_eq!(linkedin.pwn_count, Some(164_611_595));
    assert_eq!(
        linkedin.first_indexed.as_deref(),
        Some("2025-01-02T00:00:00Z")
    );
    assert_eq!(
        linkedin.last_indexed.as_deref(),
        Some("2026-04-18T12:00:00Z")
    );

    let forum = &search.breaches[0];
    assert!(!forum.password_exposed);
    assert_eq!(forum.title, None, "no dbname_info entry means no title");

    let usernames: Vec<&str> = search.usernames.iter().map(String::as_str).collect();
    assert_eq!(usernames, ["ada_alt", "user123"]);
}

#[test]
fn no_secret_or_personal_value_survives_decoding() {
    let rendered = format!("{:?}", decoded(&sample()));
    for value in [
        "hunter2-secret",
        "5f4dcc3b5aa765d61d8327deb882cf99",
        "+15555550100",
        "Ada Example",
        "@ada",
        "US",
    ] {
        assert!(!rendered.contains(value), "{value:?} kept: {rendered}");
    }
}

#[test]
fn a_field_name_that_could_carry_a_value_is_dropped() {
    let body = serde_json::json!({"success": true, "data": {"items": [
        {"dbname": "db", "hunter2 secret": "x", "Pass=word": "x", "UserName": "ada",
         "flag": false, "count": 0, "list": [], "nested": {"a": 1}}
    ]}});
    let search = decoded(&body);
    let fields: Vec<&str> = search.breaches[0]
        .fields
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(fields, ["count", "nested", "username"]);
}

#[test]
fn field_names_are_bounded_per_database() {
    let mut item = Map::new();
    item.insert("dbname".into(), Value::from("db"));
    for i in 0..(MAX_FIELDS + 10) {
        item.insert(format!("f{i:03}"), Value::from("x"));
    }
    let body = serde_json::json!({"success": true, "data": {"items": [item]}});
    assert_eq!(decoded(&body).breaches[0].fields.len(), MAX_FIELDS);
}

#[test]
fn more_records_than_read_is_partial() {
    let mut body = sample();
    body["data"]["meta"] = serde_json::json!({"total": 250, "has_more": true});
    let note = decoded(&body).truncation().unwrap_or_default();
    assert!(note.contains("first 4 of 250"), "{note}");

    body["data"]["meta"] = serde_json::json!({"total": 9});
    assert!(
        decoded(&body).truncation().is_some(),
        "total alone shows it"
    );

    body["data"]["meta"] = serde_json::json!({"has_more": true});
    let note = decoded(&body).truncation().unwrap_or_default();
    assert!(note.contains("an unreported number"), "{note}");
}

#[test]
fn an_empty_success_is_a_zero_and_a_failure_envelope_is_not() {
    let empty = decoded(&serde_json::json!({"success": true, "data": {"items": []}}));
    assert_eq!(empty.records, 0);
    assert!(empty.breaches.is_empty());

    let refused = decode(
        format!(r#"{{"success": false, "message": "Invalid API key {KEY}\u0007"}}"#).as_bytes(),
        &[KEY],
    );
    let Err(OathnetError::Provider(words)) = refused else {
        panic!("expected a provider failure, got {refused:?}");
    };
    assert!(!words.contains(KEY), "{words}");
    assert!(!words.contains('\u{7}'), "{words}");
}

#[test]
fn a_body_that_is_not_the_envelope_is_schema_drift_and_quotes_nothing() {
    for body in [
        r#"{"success": true}"#,
        r#"{"success": true, "data": {"items": "user@example.com"}}"#,
        "<html>user@example.com</html>",
    ] {
        let error = match decode(body.as_bytes(), &[KEY]) {
            Err(error) => error,
            Ok(search) => panic!("{body:?} decoded as {search:?}"),
        };
        assert_eq!(
            error.outcome_kind(),
            SourceOutcomeKind::SchemaDrift,
            "{body}"
        );
        assert!(!error.to_string().contains("example.com"), "{error}");
    }
}

/// Answers each request with the next canned response and records what was sent.
struct Recorder {
    responses: Mutex<Vec<Response>>,
    sent: Mutex<Vec<Request>>,
}

impl Recorder {
    fn new(responses: Vec<Response>) -> Self {
        Self {
            responses: Mutex::new(responses),
            sent: Mutex::default(),
        }
    }

    fn sent(&self) -> Vec<Request> {
        self.sent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

impl Transport for Recorder {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        self.sent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(request.clone());
        let mut responses = self
            .responses
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if responses.is_empty() {
            return Ok(status(500, ""));
        }
        Ok(responses.remove(0))
    }
}

fn status(code: u16, body: &str) -> Response {
    Response {
        status: code,
        headers: vec![("content-type".into(), "application/json".into())],
        body: body.as_bytes().to_vec(),
        truncated: false,
    }
}

#[test]
fn the_search_sends_one_get_with_the_key_header_to_the_fixed_origin() {
    let transport = Recorder::new(vec![crate::test_support::json_ok(&sample().to_string())]);
    let search = match search_email(&transport, &keys(), "user+tag@example.com", 7) {
        Ok(search) => search,
        Err(error) => panic!("search failed: {error}"),
    };
    assert_eq!(search.breaches.len(), 2);
    let sent = transport.sent();
    assert_eq!(sent.len(), 1);
    let request = &sent[0];
    assert_eq!(request.method, Method::Get);
    assert_eq!(
        request.url,
        "https://oathnet.org/api/service/v2/breach/search?email%5B%5D=user%2Btag%40example.com&page_size=100"
    );
    assert_eq!(request.header_value("x-api-key"), Some(KEY));
}

#[test]
fn no_key_sends_nothing() {
    let transport = Recorder::new(Vec::new());
    let empty = match Keys::parse("") {
        Ok(keys) => keys,
        Err(error) => panic!("empty keys parse: {error}"),
    };
    assert_eq!(
        search_email(&transport, &empty, "user@example.com", 7),
        Err(OathnetError::MissingKey)
    );
    assert!(transport.sent().is_empty());
}

#[test]
fn statuses_map_to_outcomes_and_never_quote_the_body() {
    let mut limited = status(
        429,
        r#"{"success": false, "message": "Daily quota exceeded"}"#,
    );
    limited.headers.push(("retry-after".into(), "60".into()));
    let cases = [
        (status(400, "{}"), SourceOutcomeKind::Upstream4xx, Some(400)),
        (
            status(401, r#"{"success": false, "message": "Invalid API key."}"#),
            SourceOutcomeKind::AuthRejected,
            Some(401),
        ),
        (
            status(403, "{}"),
            SourceOutcomeKind::EntitlementDenied,
            Some(403),
        ),
        (limited, SourceOutcomeKind::RateLimited, Some(429)),
        (
            status(503, "user@example.com"),
            SourceOutcomeKind::Upstream5xx,
            Some(503),
        ),
        (status(404, "{}"), SourceOutcomeKind::Upstream4xx, Some(404)),
    ];
    for (response, kind, http) in cases {
        let code = response.status;
        let transport = Recorder::new(vec![response]);
        let error = match search_email(&transport, &keys(), "user@example.com", 7) {
            Err(error) => error,
            Ok(search) => panic!("HTTP {code} gave {search:?}"),
        };
        assert_eq!(error.outcome_kind(), kind, "HTTP {code}");
        assert_eq!(error.http_status(), http, "HTTP {code}");
        let text = error.to_string();
        assert!(
            !text.contains("example.com") && !text.contains(KEY),
            "{text}"
        );
        if code == 429 {
            assert_eq!(
                error,
                OathnetError::RateLimited {
                    retry_after: Some(60)
                }
            );
        }
    }
}

#[test]
fn a_redirect_is_not_followed_so_the_key_goes_nowhere_else() {
    let mut moved = status(302, "");
    moved
        .headers
        .push(("location".into(), "https://elsewhere.example/steal".into()));
    let transport = Recorder::new(vec![moved]);
    let result = search_email(&transport, &keys(), "user@example.com", 7);
    assert_eq!(result, Err(OathnetError::Unexpected(302)));
    let sent = transport.sent();
    assert_eq!(sent.len(), 1, "only the first request is sent");
    assert!(sent[0].url.starts_with(API_URL));
}
