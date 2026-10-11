//! Test doubles shared by the source-client tests. Compiled only for `cargo test`.

use std::cell::RefCell;
use std::collections::VecDeque;

use crate::http::{Request, Response, Transport, TransportFailure};
use crate::source_outcome::SourceOutcomeKind;

/// Replays scripted results in order and records every request. A request past the end of
/// the script fails as a connect failure, so an unexpected call shows up in the test.
pub struct ScriptedTransport {
    pub script: RefCell<VecDeque<Result<Response, TransportFailure>>>,
    pub seen: RefCell<Vec<Request>>,
}

impl ScriptedTransport {
    #[must_use]
    pub fn new(script: Vec<Result<Response, TransportFailure>>) -> Self {
        Self {
            script: RefCell::new(script.into()),
            seen: RefCell::new(Vec::new()),
        }
    }
}

impl Transport for ScriptedTransport {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        self.seen.borrow_mut().push(request.clone());
        self.script.borrow_mut().pop_front().unwrap_or_else(|| {
            Err(TransportFailure {
                kind: SourceOutcomeKind::ConnectFailure,
                detail: "unexpected request".into(),
                blocked: false,
            })
        })
    }
}

/// A 200 response with an HTML body.
#[must_use]
pub fn html_ok(body: &str) -> Response {
    Response {
        status: 200,
        headers: vec![("content-type".into(), "text/html".into())],
        body: body.as_bytes().to_vec(),
        truncated: false,
    }
}

/// A 200 response with a JSON body.
#[must_use]
pub fn json_ok(body: &str) -> Response {
    Response {
        status: 200,
        headers: vec![("content-type".into(), "application/json".into())],
        body: body.as_bytes().to_vec(),
        truncated: false,
    }
}
