use std::cell::{Cell, RefCell};
use std::collections::VecDeque;

use super::*;
use crate::http::{Response, TransportFailure};

type Reply = Result<Response, TransportFailure>;

struct Script {
    replies: RefCell<VecDeque<Reply>>,
    sent: Cell<u32>,
}

impl Script {
    fn new(replies: Vec<Reply>) -> Self {
        Self {
            replies: RefCell::new(replies.into()),
            sent: Cell::new(0),
        }
    }
}

impl Transport for Script {
    fn send(&self, _request: &Request) -> Result<Response, TransportFailure> {
        self.sent.set(self.sent.get() + 1);
        self.replies
            .borrow_mut()
            .pop_front()
            .expect("unscripted request")
    }
}

fn failure(kind: SourceOutcomeKind) -> Reply {
    Err(TransportFailure {
        kind,
        detail: "scripted failure".into(),
        blocked: false,
    })
}

fn success() -> Reply {
    Ok(Response {
        status: 200,
        headers: Vec::new(),
        body: br#"[{"name_value":"api.example.com"}]"#.to_vec(),
        truncated: false,
    })
}

fn run(script: &Script, pauses: &Cell<u32>) -> Result<CrtShReport, CrtShError> {
    lookup_with_pause(
        script,
        ReconTargetKind::Domain,
        "example.com",
        "transport-retry-unit",
        &|duration| {
            assert_eq!(duration, TRANSIENT_PAUSE);
            pauses.set(pauses.get() + 1);
        },
    )
}

#[test]
fn transient_transport_classes_pause_once_retry_once_and_succeed() {
    for kind in [
        SourceOutcomeKind::ConnectFailure,
        SourceOutcomeKind::TtfbTimeout,
        SourceOutcomeKind::BodyTimeout,
    ] {
        let script = Script::new(vec![failure(kind), success()]);
        let pauses = Cell::new(0);
        let report = run(&script, &pauses).unwrap();

        assert_eq!(script.sent.get(), 2, "{kind:?}");
        assert_eq!(pauses.get(), 1, "{kind:?}");
        assert_eq!(report.attempts, 2, "{kind:?}");
        assert!(report.entities.iter().any(|e| e.value == "api.example.com"));
    }
}

#[test]
fn second_transient_transport_failure_is_terminal() {
    let script = Script::new(vec![
        failure(SourceOutcomeKind::TtfbTimeout),
        failure(SourceOutcomeKind::TtfbTimeout),
    ]);
    let pauses = Cell::new(0);

    assert_eq!(
        run(&script, &pauses).unwrap_err(),
        CrtShError::NoResponse(SourceOutcomeKind::TtfbTimeout)
    );
    assert_eq!(script.sent.get(), 2);
    assert_eq!(pauses.get(), 1);
}

#[test]
fn dns_and_tls_failures_remain_non_retryable() {
    for kind in [SourceOutcomeKind::DnsFailure, SourceOutcomeKind::TlsFailure] {
        let script = Script::new(vec![failure(kind)]);
        let pauses = Cell::new(0);

        assert_eq!(run(&script, &pauses).unwrap_err(), CrtShError::NoResponse(kind));
        assert_eq!(script.sent.get(), 1, "{kind:?}");
        assert_eq!(pauses.get(), 0, "{kind:?}");
    }
}

#[test]
fn status_retry_budget_remains_three_attempts() {
    let script = Script::new(vec![
        Ok(Response {
            status: 503,
            headers: Vec::new(),
            body: b"Service Unavailable".to_vec(),
            truncated: false,
        }),
        Ok(Response {
            status: 503,
            headers: Vec::new(),
            body: b"Service Unavailable".to_vec(),
            truncated: false,
        }),
        success(),
    ]);
    let pauses = Cell::new(0);
    let report = run(&script, &pauses).unwrap();

    assert_eq!(script.sent.get(), TRANSIENT_ATTEMPTS);
    assert_eq!(pauses.get(), TRANSIENT_ATTEMPTS - 1);
    assert_eq!(report.attempts, TRANSIENT_ATTEMPTS);
}
