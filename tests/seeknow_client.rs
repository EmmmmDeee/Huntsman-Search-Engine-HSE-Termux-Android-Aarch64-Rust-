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
    Response {
        status: 200,
        headers: Vec::new(),
        body: body.as_bytes().to_vec(),
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
