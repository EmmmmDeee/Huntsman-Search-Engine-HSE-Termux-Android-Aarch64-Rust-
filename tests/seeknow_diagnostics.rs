use std::cell::RefCell;
use std::collections::VecDeque;

use huntsman_recon::credential_origin::{AuthenticationAuthority, OperatorCredentialRef};
use huntsman_recon::fetch::{AuthStyle, Credential};
use huntsman_recon::http::{Method, Request, Response, Transport, TransportFailure};
use huntsman_recon::keys::Secret;
use huntsman_recon::seeknow::{
    KEY_SLOT, MAX_FIELDS_PER_ROW, MAX_FIELD_CHARS, SEARCH_LIMIT_MAX, SeekNowQueryType,
    SeekNowSearch, credits, search_fast, status,
};
use huntsman_recon::source_outcome::SourceOutcomeKind;

struct ScriptedTransport {
    responses: RefCell<VecDeque<Response>>,
    seen: RefCell<Vec<Request>>,
}

impl ScriptedTransport {
    fn new(responses: Vec<Response>) -> Self {
        Self {
            responses: RefCell::new(responses.into()),
            seen: RefCell::new(Vec::new()),
        }
    }
}

impl Transport for ScriptedTransport {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        self.seen.borrow_mut().push(request.clone());
        Ok(self.responses.borrow_mut().pop_front().expect("scripted response"))
    }
}

fn response(body: String) -> Response {
    Response {
        status: 200,
        headers: Vec::new(),
        body: body.into_bytes(),
        truncated: false,
    }
}

fn credential() -> Credential {
    let authority = AuthenticationAuthority::operator_approved(OperatorCredentialRef {
        provider_id: "seeknow".into(),
        credential_slot: KEY_SLOT.into(),
        approved_at_unix: 1,
        approval_provenance: "integration-test".into(),
    })
    .unwrap();
    Credential::new(
        authority,
        Secret::new("seek-test-secret").unwrap(),
        AuthStyle::Header("X-API-Key".into()),
    )
    .unwrap()
}

#[test]
fn credits_and_status_are_authenticated_zero_redirect_gets() {
    let transport = ScriptedTransport::new(vec![
        response(r#"{"success":true,"credits_remaining":123,"daily_limit":500}"#.into()),
        response(r#"{"success":true,"status":"ok","version":"v1"}"#.into()),
    ]);
    let credential = credential();

    let credits_result = credits(&transport, &credential, 10).unwrap();
    assert_eq!(credits_result.outcome.kind, SourceOutcomeKind::Success);
    assert_eq!(credits_result.remaining, Some(123));
    assert_eq!(credits_result.limit, Some(500));

    let status_result = status(&transport, &credential, 11).unwrap();
    assert_eq!(status_result.outcome.kind, SourceOutcomeKind::Success);
    assert_eq!(status_result.fields.get("status").map(String::as_str), Some("ok"));

    let seen = transport.seen.borrow();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].method, Method::Get);
    assert_eq!(seen[0].url, "https://see-know.ru/api/v1/credits");
    assert_eq!(seen[1].method, Method::Get);
    assert_eq!(seen[1].url, "https://see-know.ru/api/v1/status");
    assert_eq!(seen[0].header_value("x-api-key"), Some("seek-test-secret"));
    assert_eq!(seen[1].header_value("x-api-key"), Some("seek-test-secret"));
}

#[test]
fn upstream_arrays_survive_as_multiple_values_for_lineage() {
    let transport = ScriptedTransport::new(vec![response(
        r#"{"success":true,"data":[{"email":"a@example.com","dbname":["Dataset A","Dataset B"],"source":["mirror-1","mirror-2"],"record_id":"r1"}]}"#.into(),
    )]);
    let result = search_fast(
        &transport,
        &credential(),
        &SeekNowSearch {
            query: "a@example.com".into(),
            query_type: SeekNowQueryType::Email,
            limit: SEARCH_LIMIT_MAX,
        },
        12,
    )
    .unwrap();
    assert_eq!(result.rows.len(), 1);
    assert_eq!(
        result.rows[0].upstream.dbname,
        vec!["Dataset A".to_owned(), "Dataset B".to_owned()]
    );
    assert_eq!(
        result.rows[0].upstream.source,
        vec!["mirror-1".to_owned(), "mirror-2".to_owned()]
    );
    assert_eq!(result.rows[0].upstream.record_id.as_deref(), Some("r1"));
}

#[test]
fn rows_fields_and_strings_are_bounded_with_visible_truncation() {
    let huge = "x".repeat(MAX_FIELD_CHARS + 100);
    let mut row = serde_json::Map::new();
    row.insert("email".into(), serde_json::Value::String("a@example.com".into()));
    row.insert("bio".into(), serde_json::Value::String(huge));
    for i in 0..(MAX_FIELDS_PER_ROW + 20) {
        row.insert(format!("field_{i}"), serde_json::Value::String(format!("v{i}")));
    }
    let rows = (0..(SEARCH_LIMIT_MAX as usize + 5))
        .map(|_| serde_json::Value::Object(row.clone()))
        .collect::<Vec<_>>();
    let body = serde_json::json!({"success": true, "data": rows}).to_string();
    let transport = ScriptedTransport::new(vec![response(body)]);
    let result = search_fast(
        &transport,
        &credential(),
        &SeekNowSearch {
            query: "a@example.com".into(),
            query_type: SeekNowQueryType::Email,
            limit: SEARCH_LIMIT_MAX,
        },
        13,
    )
    .unwrap();

    assert_eq!(result.rows.len(), SEARCH_LIMIT_MAX as usize);
    assert!(result.meta.normalized_rows_truncated);
    assert!(result.rows[0].fields.len() <= MAX_FIELDS_PER_ROW);
    assert!(result.rows[0].truncated_fields.contains("bio"));
    assert!(!result.rows[0].fields.contains_key("bio"));
    assert!(result.rows[0].fields_truncated);
}
