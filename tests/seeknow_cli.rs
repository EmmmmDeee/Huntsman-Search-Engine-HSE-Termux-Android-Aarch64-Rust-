use std::cell::RefCell;
use std::collections::VecDeque;

use huntsman_recon::http::{Method, Request, Response, Transport, TransportFailure};
use huntsman_recon::keys::Keys;
use huntsman_recon::seeknow_cli::{SeekNowCliRun, run_with_keys};

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

fn response(status: u16, body: &str) -> Response {
    Response {
        status,
        headers: Vec::new(),
        body: body.as_bytes().to_vec(),
        truncated: false,
    }
}

fn configured_keys() -> Keys {
    Keys::parse("HUNTSMAN_SEEKNOW_KEY=dummy-seeknow-key-for-tests\n").unwrap()
}

#[test]
fn missing_or_unknown_arguments_are_usage_and_make_no_request() {
    let transport = ScriptedTransport::new(Vec::new());
    assert_eq!(
        run_with_keys(&transport, &[], &configured_keys(), 1),
        SeekNowCliRun::Usage
    );
    assert_eq!(
        run_with_keys(&transport, &["unknown".into()], &configured_keys(), 1),
        SeekNowCliRun::Usage
    );
    assert_eq!(transport.seen.borrow().len(), 0);
}

#[test]
fn missing_key_is_permission_failure_before_transport() {
    let transport = ScriptedTransport::new(Vec::new());
    let result = run_with_keys(&transport, &["credits".into()], &Keys::default(), 2);
    match result {
        SeekNowCliRun::NoPerm(message) => {
            assert!(message.contains("HUNTSMAN_SEEKNOW_KEY"));
            assert!(!message.contains("dummy-seeknow-key-for-tests"));
        }
        other => panic!("unexpected result: {other:?}"),
    }
    assert_eq!(transport.seen.borrow().len(), 0);
}

#[test]
fn credits_and_status_use_authenticated_diagnostic_endpoints_without_printing_secret() {
    let transport = ScriptedTransport::new(vec![
        response(
            200,
            r#"{"success":true,"credits_remaining":499,"daily_limit":500}"#,
        ),
        response(200, r#"{"success":true,"status":"ok","region":"eu"}"#),
    ]);
    let keys = configured_keys();

    let credits = run_with_keys(&transport, &["credits".into()], &keys, 3);
    let status = run_with_keys(&transport, &["status".into()], &keys, 4);
    for result in [credits, status] {
        match result {
            SeekNowCliRun::Printed(text) => {
                assert!(!text.contains("dummy-seeknow-key-for-tests"));
                assert!(text.contains("outcome=success"), "{text}");
            }
            other => panic!("unexpected result: {other:?}"),
        }
    }

    let seen = transport.seen.borrow();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].method, Method::Get);
    assert!(seen[0].url.ends_with("/credits"));
    assert!(seen[1].url.ends_with("/status"));
    assert_eq!(
        seen[0].header_value("x-api-key"),
        Some("dummy-seeknow-key-for-tests")
    );
}

#[test]
fn search_defaults_to_adaptive_and_deep_is_spent_only_after_valid_zero() {
    let transport = ScriptedTransport::new(vec![
        response(200, r#"{"success":true,"data":[]}"#),
        response(
            200,
            r#"{"success":true,"data":[{"email":"alice@example.com","dbname":"Dataset A"}]}"#,
        ),
    ]);
    let result = run_with_keys(
        &transport,
        &["search".into(), "email".into(), "alice@example.com".into()],
        &configured_keys(),
        5,
    );
    match result {
        SeekNowCliRun::Printed(text) => {
            assert!(text.contains("outcome=success"), "{text}");
            assert!(text.contains("email\talice@example.com"), "{text}");
            assert!(text.contains("dataset a"), "{text}");
        }
        other => panic!("unexpected result: {other:?}"),
    }
    let seen = transport.seen.borrow();
    assert_eq!(seen.len(), 2);
    assert!(seen[0].url.ends_with("/search"));
    assert!(seen[1].url.ends_with("/search/deep"));
}

#[test]
fn explicit_fast_only_and_deep_modes_are_distinct_and_invalid_selector_is_data_error() {
    let fast = ScriptedTransport::new(vec![response(200, r#"{"success":true,"data":[]}"#)]);
    let result = run_with_keys(
        &fast,
        &[
            "search".into(),
            "username".into(),
            "alice".into(),
            "--fast-only".into(),
        ],
        &configured_keys(),
        6,
    );
    assert!(matches!(result, SeekNowCliRun::Printed(_)));
    assert_eq!(fast.seen.borrow().len(), 1);
    assert!(fast.seen.borrow()[0].url.ends_with("/search"));

    let deep = ScriptedTransport::new(vec![response(200, r#"{"success":true,"data":[]}"#)]);
    let result = run_with_keys(
        &deep,
        &[
            "search".into(),
            "person".into(),
            "Alice Example".into(),
            "--deep".into(),
        ],
        &configured_keys(),
        7,
    );
    assert!(matches!(result, SeekNowCliRun::Printed(_)));
    assert_eq!(deep.seen.borrow().len(), 1);
    assert!(deep.seen.borrow()[0].url.ends_with("/search/deep"));

    let invalid = ScriptedTransport::new(Vec::new());
    let result = run_with_keys(
        &invalid,
        &["search".into(), "person".into(), "A".into()],
        &configured_keys(),
        8,
    );
    assert!(matches!(result, SeekNowCliRun::BadData(_)));
    assert_eq!(invalid.seen.borrow().len(), 0);
}
