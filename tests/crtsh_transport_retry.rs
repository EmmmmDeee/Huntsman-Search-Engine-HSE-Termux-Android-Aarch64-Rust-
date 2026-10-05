use std::cell::RefCell;
use std::collections::VecDeque;

use huntsman_recon::crtsh::{CrtShError, lookup};
use huntsman_recon::http::{Request, Response, Transport, TransportFailure};
use huntsman_recon::recon::ReconTargetKind;
use huntsman_recon::source_outcome::SourceOutcomeKind;

type Reply = Result<Response, TransportFailure>;

struct Script {
    replies: RefCell<VecDeque<Reply>>,
    sent: RefCell<usize>,
}

impl Script {
    fn new(replies: Vec<Reply>) -> Self {
        Self {
            replies: RefCell::new(replies.into()),
            sent: RefCell::new(0),
        }
    }

    fn sent(&self) -> usize {
        *self.sent.borrow()
    }
}

impl Transport for Script {
    fn send(&self, _request: &Request) -> Result<Response, TransportFailure> {
        *self.sent.borrow_mut() += 1;
        self.replies
            .borrow_mut()
            .pop_front()
            .expect("unscripted request")
    }
}

fn failure(kind: SourceOutcomeKind) -> Reply {
    Err(TransportFailure {
        kind,
        detail: "scripted transport failure".into(),
        blocked: false,
    })
}

fn ok_json() -> Reply {
    Ok(Response {
        status: 200,
        headers: Vec::new(),
        body: br#"[{"name_value":"api.example.com"}]"#.to_vec(),
        truncated: false,
    })
}

fn assert_transient_transport_retries(kind: SourceOutcomeKind) {
    let script = Script::new(vec![failure(kind), ok_json()]);
    let report = lookup(
        &script,
        ReconTargetKind::Domain,
        "example.com",
        "transport-retry-test",
    )
    .expect("one transient transport failure should be retried");

    assert_eq!(report.attempts, 2);
    assert_eq!(script.sent(), 2);
    assert!(report.entities.iter().any(|e| e.value == "api.example.com"));
}

#[test]
fn retries_one_ttfb_timeout_then_succeeds() {
    assert_transient_transport_retries(SourceOutcomeKind::TtfbTimeout);
}

#[test]
fn retries_one_body_timeout_then_succeeds() {
    assert_transient_transport_retries(SourceOutcomeKind::BodyTimeout);
}

#[test]
fn retries_one_connect_failure_then_succeeds() {
    assert_transient_transport_retries(SourceOutcomeKind::ConnectFailure);
}

#[test]
fn dns_failure_is_not_retried() {
    let script = Script::new(vec![failure(SourceOutcomeKind::DnsFailure)]);
    let err = lookup(
        &script,
        ReconTargetKind::Domain,
        "example.com",
        "transport-retry-test",
    )
    .expect_err("DNS failures are not transient crt.sh transport flaps");

    assert_eq!(err, CrtShError::NoResponse(SourceOutcomeKind::DnsFailure));
    assert_eq!(script.sent(), 1);
}

#[test]
fn tls_failure_is_not_retried() {
    let script = Script::new(vec![failure(SourceOutcomeKind::TlsFailure)]);
    let err = lookup(
        &script,
        ReconTargetKind::Domain,
        "example.com",
        "transport-retry-test",
    )
    .expect_err("TLS failures are not transient crt.sh transport flaps");

    assert_eq!(err, CrtShError::NoResponse(SourceOutcomeKind::TlsFailure));
    assert_eq!(script.sent(), 1);
}
