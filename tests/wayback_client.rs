use std::{cell::RefCell, collections::VecDeque};

use huntsman_recon::{
    http::{Request, Response, Transport, TransportFailure},
    source_outcome::SourceOutcomeKind,
    wayback::{WaybackQuery, wayback_lookup},
};

struct FakeTransport {
    outcomes: RefCell<VecDeque<Result<Response, TransportFailure>>>,
    seen: RefCell<Vec<Request>>,
}

impl FakeTransport {
    fn new(outcomes: Vec<Result<Response, TransportFailure>>) -> Self {
        Self {
            outcomes: RefCell::new(outcomes.into()),
            seen: RefCell::new(Vec::new()),
        }
    }
}

impl Transport for FakeTransport {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        self.seen.borrow_mut().push(request.clone());
        self.outcomes.borrow_mut().pop_front().unwrap_or_else(|| {
            Err(TransportFailure {
                kind: SourceOutcomeKind::ConnectFailure,
                detail: "unexpected request".into(),
                blocked: false,
            })
        })
    }
}

fn response(status: u16, body: &str, truncated: bool) -> Response {
    Response {
        status,
        headers: Vec::new(),
        body: body.as_bytes().to_vec(),
        truncated,
    }
}

fn valid_body() -> &'static str {
    r#"[["urlkey","timestamp","original","mimetype","statuscode","digest"],["com,example)/","20260102030405","https://Example.COM./admin/login?next=%2F","text/html","200","sha1:ABC"],["malformed"],["com,example)/report.pdf","20260203040506","http://example.com:80/report.pdf","application/pdf","301","sha1:DEF"]]"#
}

#[test]
fn wayback_request_is_https_domain_scoped_and_bounded() {
    let transport = FakeTransport::new(vec![Ok(response(200, valid_body(), false))]);
    let result = wayback_lookup(
        &transport,
        &WaybackQuery {
            domain: "Example.COM.",
            row_limit: 2,
        },
        1_700_000_000,
    )
    .expect("lookup");

    let seen = transport.seen.borrow();
    assert_eq!(seen.len(), 1, "returned live URLs must never be fetched");
    let url = &seen[0].url;
    assert!(url.starts_with("https://web.archive.org/cdx/search/cdx?"));
    assert!(url.contains("url=%2A.example.com%2F%2A"), "{url}");
    assert!(url.contains("output=json"), "{url}");
    assert!(
        url.contains("fl=timestamp%2Coriginal%2Cmimetype%2Cstatuscode%2Cdigest"),
        "{url}"
    );
    assert!(url.contains("limit=2"), "{url}");
    assert_eq!(result.captures.len(), 2);
    assert_eq!(result.outcome.kind, SourceOutcomeKind::Success);
    assert_eq!(result.response_sha256.as_deref().map(str::len), Some(64));
}

#[test]
fn wayback_parser_accepts_valid_rows_and_isolates_malformed_rows() {
    let transport = FakeTransport::new(vec![Ok(response(200, valid_body(), false))]);
    let result = wayback_lookup(
        &transport,
        &WaybackQuery {
            domain: "example.com",
            row_limit: 10,
        },
        1_700_000_000,
    )
    .expect("lookup");

    assert_eq!(result.captures.len(), 2);
    let first = &result.captures[0];
    assert_eq!(first.dataset, "internet_archive_wayback");
    assert_eq!(first.collection, None);
    assert_eq!(first.captured_at, "20260102030405");
    assert_eq!(first.status, Some(200));
    assert_eq!(first.mime.as_deref(), Some("text/html"));
    assert_eq!(first.digest.as_deref(), Some("sha1:ABC"));
    assert_eq!(first.key.host, "example.com");
    assert!(
        first
            .source_url
            .as_deref()
            .is_some_and(|url| url.starts_with("https://web.archive.org/web/20260102030405/"))
    );
}

#[test]
fn wayback_empty_valid_response_is_valid_zero() {
    let body = r#"[["urlkey","timestamp","original","mimetype","statuscode","digest"]]"#;
    let transport = FakeTransport::new(vec![Ok(response(200, body, false))]);
    let result = wayback_lookup(
        &transport,
        &WaybackQuery {
            domain: "example.com",
            row_limit: 10,
        },
        1_700_000_000,
    )
    .expect("lookup");

    assert_eq!(result.captures.len(), 0);
    assert_eq!(result.outcome.kind, SourceOutcomeKind::ValidZero);
    assert!(!result.truncated);
}

#[test]
fn wayback_body_truncation_propagates_without_manufacturing_absence() {
    let body = r#"[["urlkey","timestamp","original","mimetype","statuscode","digest"]]"#;
    let transport = FakeTransport::new(vec![Ok(response(200, body, true))]);
    let result = wayback_lookup(
        &transport,
        &WaybackQuery {
            domain: "example.com",
            row_limit: 10,
        },
        1_700_000_000,
    )
    .expect("lookup");

    assert!(result.truncated);
    assert_ne!(result.outcome.kind, SourceOutcomeKind::ValidZero);
}

#[test]
fn wayback_transport_failure_stays_transport_outcome() {
    let transport = FakeTransport::new(vec![Err(TransportFailure {
        kind: SourceOutcomeKind::TtfbTimeout,
        detail: "timeout".into(),
        blocked: false,
    })]);
    let result = wayback_lookup(
        &transport,
        &WaybackQuery {
            domain: "example.com",
            row_limit: 10,
        },
        1_700_000_000,
    )
    .expect("typed transport outcome");

    assert_eq!(result.outcome.kind, SourceOutcomeKind::TtfbTimeout);
    assert_eq!(result.captures.len(), 0);
}

#[test]
fn wayback_non_2xx_never_emits_capture_evidence() {
    let transport = FakeTransport::new(vec![Ok(response(503, valid_body(), false))]);
    let result = wayback_lookup(
        &transport,
        &WaybackQuery {
            domain: "example.com",
            row_limit: 10,
        },
        1_700_000_000,
    )
    .expect("typed HTTP outcome");

    assert_eq!(result.outcome.kind, SourceOutcomeKind::Upstream5xx);
    assert_eq!(result.captures.len(), 0);
}

#[test]
fn wayback_unusable_envelope_is_parser_drift() {
    let transport = FakeTransport::new(vec![Ok(response(200, r#"{"rows":[]}"#, false))]);
    let result = wayback_lookup(
        &transport,
        &WaybackQuery {
            domain: "example.com",
            row_limit: 10,
        },
        1_700_000_000,
    )
    .expect("lookup");

    assert_eq!(result.outcome.kind, SourceOutcomeKind::ParserDrift);
    assert_eq!(result.captures.len(), 0);
}

#[test]
fn wayback_zero_row_limit_is_explicit_no_work_and_sends_nothing() {
    let transport = FakeTransport::new(Vec::new());
    let result = wayback_lookup(
        &transport,
        &WaybackQuery {
            domain: "example.com",
            row_limit: 0,
        },
        1_700_000_000,
    )
    .expect("no-work result");

    assert_eq!(transport.seen.borrow().len(), 0);
    assert_eq!(result.captures.len(), 0);
    assert_eq!(result.outcome.kind, SourceOutcomeKind::Inconclusive);
    assert!(result.truncated);
    assert!(
        result
            .outcome
            .detail
            .as_deref()
            .is_some_and(|detail| detail.contains("row_limit=0"))
    );
}
