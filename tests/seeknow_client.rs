use std::cell::RefCell;
use std::collections::VecDeque;

use huntsman_recon::credential_origin::{AuthenticationAuthority, OperatorCredentialRef};
use huntsman_recon::fetch::{AuthStyle, Credential};
use huntsman_recon::http::{Method, Request, Response, Transport, TransportFailure};
use huntsman_recon::keys::Secret;
use huntsman_recon::seeknow::{
    KEY_SLOT, SEARCH_LIMIT_MAX, SeekNowQueryType, SeekNowSearch, search_deep, search_fast,
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
        Ok(self
            .responses
            .borrow_mut()
            .pop_front()
            .expect("scripted response"))
    }
}

fn response(body: &str) -> Response {
    response_with(200, body, Vec::new(), false)
}

fn response_with(
    status: u16,
    body: &str,
    headers: Vec<(String, String)>,
    truncated: bool,
) -> Response {
    Response {
        status,
        headers,
        body: body.as_bytes().to_vec(),
        truncated,
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

fn auto_search() -> SeekNowSearch {
    SeekNowSearch {
        query: "alice@example.com".into(),
        query_type: SeekNowQueryType::Auto,
        limit: SEARCH_LIMIT_MAX,
    }
}

#[test]
fn fast_auto_search_omits_type_clamps_limit_and_sends_key_only_at_transport() {
    let transport = ScriptedTransport::new(vec![response(r#"{"success":true,"data":[]}"#)]);
    let search = SeekNowSearch {
        query: "alice@example.com".into(),
        query_type: SeekNowQueryType::Auto,
        limit: SEARCH_LIMIT_MAX + 50,
    };

    let result = search_fast(&transport, &credential(), &search, 7).unwrap();
    assert_eq!(result.outcome.kind, SourceOutcomeKind::ValidZero);

    let seen = transport.seen.borrow();
    assert_eq!(seen.len(), 1);
    let request = &seen[0];
    assert_eq!(request.method, Method::Post);
    assert_eq!(request.url, "https://see-know.ru/api/v1/search");
    assert_eq!(
        request.header_value("content-type"),
        Some("application/json")
    );
    assert_eq!(request.header_value("x-api-key"), Some("seek-test-secret"));
    assert!(!format!("{request:?}").contains("seek-test-secret"));

    let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
    assert_eq!(body["query"], "alice@example.com");
    assert_eq!(body["limit"], SEARCH_LIMIT_MAX);
    assert!(body.get("type").is_none());
}

#[test]
fn deep_typed_search_uses_documented_path_and_type() {
    let transport = ScriptedTransport::new(vec![response(r#"{"success":true,"results":[]}"#)]);
    let search = SeekNowSearch {
        query: "alice".into(),
        query_type: SeekNowQueryType::Username,
        limit: 0,
    };

    let result = search_deep(&transport, &credential(), &search, 8).unwrap();
    assert_eq!(result.outcome.kind, SourceOutcomeKind::ValidZero);

    let seen = transport.seen.borrow();
    let request = &seen[0];
    assert_eq!(request.url, "https://see-know.ru/api/v1/search/deep");
    let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
    assert_eq!(body["type"], "username");
    assert_eq!(body["limit"], 1);
}

#[test]
fn provider_failures_are_classified_from_top_level_envelope_only() {
    let cases = [
        (
            200,
            r#"{"success":false,"error":"invalid_api_key","message":"bad key"}"#,
            SourceOutcomeKind::AuthRejected,
        ),
        (
            403,
            r#"{"success":false,"error":"plan_required","message":"upgrade plan"}"#,
            SourceOutcomeKind::EntitlementDenied,
        ),
        (
            429,
            r#"{"success":false,"error":"quota_exhausted","credits_remaining":0}"#,
            SourceOutcomeKind::QuotaExhausted,
        ),
        (
            429,
            r#"{"success":false,"error":"rate_limited","credits_remaining":42}"#,
            SourceOutcomeKind::RateLimited,
        ),
    ];

    for (status, body, expected) in cases {
        let transport =
            ScriptedTransport::new(vec![response_with(status, body, Vec::new(), false)]);
        let result = search_fast(&transport, &credential(), &auto_search(), 9).unwrap();
        assert_eq!(result.outcome.kind, expected, "{body}");
        assert!(result.rows.is_empty());
    }

    let leaked_text = r#"{
        "success":true,
        "data":[{
            "email":"alice@example.com",
            "dbname":"Example Breach",
            "note":"application logged invalid_api_key during an old incident"
        }]
    }"#;
    let transport = ScriptedTransport::new(vec![response(leaked_text)]);
    let result = search_fast(&transport, &credential(), &auto_search(), 10).unwrap();
    assert_eq!(result.outcome.kind, SourceOutcomeKind::Success);
    assert_eq!(result.rows.len(), 1);
    assert_eq!(
        result.rows[0].fields.get("dbname"),
        Some(&"Example Breach".into())
    );
}

#[test]
fn positive_last_credit_is_kept_and_rate_headers_are_metadata() {
    let transport = ScriptedTransport::new(vec![response_with(
        200,
        r#"{"success":true,"credits_remaining":0,"data":[{"email":"alice@example.com","breach":"B1"}]}"#,
        vec![
            ("X-RateLimit-Limit".into(), "500".into()),
            ("X-RateLimit-Remaining".into(), "0".into()),
            ("X-RateLimit-Reset".into(), "12345".into()),
        ],
        false,
    )]);
    let result = search_fast(&transport, &credential(), &auto_search(), 11).unwrap();
    assert_eq!(result.outcome.kind, SourceOutcomeKind::Success);
    assert_eq!(result.rows.len(), 1);
    assert_eq!(result.meta.rate_limit_limit, Some(500));
    assert_eq!(result.meta.rate_limit_remaining, Some(0));
    assert_eq!(result.meta.rate_limit_reset.as_deref(), Some("12345"));
}

#[test]
fn malformed_truncated_waf_and_upstream_failure_never_become_zero() {
    let cases = [
        (
            response_with(200, "{not-json", Vec::new(), false),
            SourceOutcomeKind::ParserDrift,
        ),
        (
            response_with(200, r#"{"success":true,"message":"ok"}"#, Vec::new(), false),
            SourceOutcomeKind::SchemaDrift,
        ),
        (
            response_with(200, r#"{"success":true,"data":[]}"#, Vec::new(), true),
            SourceOutcomeKind::ParserDrift,
        ),
        (
            response_with(
                403,
                "<html>checking your browser cloudflare</html>",
                Vec::new(),
                false,
            ),
            SourceOutcomeKind::BotWaf,
        ),
        (
            response_with(503, "unavailable", Vec::new(), false),
            SourceOutcomeKind::Upstream5xx,
        ),
    ];

    for (response, expected) in cases {
        let transport = ScriptedTransport::new(vec![response]);
        let result = search_fast(&transport, &credential(), &auto_search(), 12).unwrap();
        assert_eq!(result.outcome.kind, expected);
        assert_ne!(result.outcome.kind, SourceOutcomeKind::ValidZero);
    }
}

#[test]
fn sensitive_result_values_are_discarded_but_upstream_lineage_fields_survive() {
    let secret = "raw-password-value-that-must-never-survive";
    let body = format!(
        r#"{{"success":true,"data":[{{
            "email":"alice@example.com",
            "dbname":"Dataset A",
            "breach":"Breach A",
            "source_db":"Source DB A",
            "database_name":"Database A",
            "dataset":"Corpus A",
            "source":"provider-x",
            "record_id":"row-1",
            "password":"{secret}",
            "access_token":"tok-secret",
            "cookie":"sid=secret"
        }}]}}"#
    );
    let transport = ScriptedTransport::new(vec![response(&body)]);
    let result = search_fast(&transport, &credential(), &auto_search(), 13).unwrap();
    assert_eq!(result.outcome.kind, SourceOutcomeKind::Success);
    let row = &result.rows[0];

    for key in [
        "dbname",
        "breach",
        "source_db",
        "database_name",
        "dataset",
        "source",
        "record_id",
    ] {
        assert!(row.fields.contains_key(key), "missing {key}");
    }
    for key in ["password", "access_token", "cookie"] {
        assert!(!row.fields.contains_key(key));
        assert!(row.sensitive_fields.contains(key));
    }
    let rendered = serde_json::to_string(&result).unwrap();
    assert!(!rendered.contains(secret));
    assert!(!rendered.contains("tok-secret"));
    assert!(!rendered.contains("sid=secret"));
}
