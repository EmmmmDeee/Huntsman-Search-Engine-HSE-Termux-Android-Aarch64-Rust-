//! Test doubles shared by the source-client tests. Compiled only for `cargo test`.

use std::cell::RefCell;
use std::collections::VecDeque;

use crate::http::{Request, Response, Transport, TransportFailure};
use crate::source_outcome::SourceOutcomeKind;

/// Replays scripted results in order and records every request. A request past the end of
/// the script fails as a connect failure, so an unexpected call shows up in the test.
/// The control characters in `text` that are not in `allowed`: the ones a terminal could act on.
#[must_use]
pub fn unexpected_controls(text: &str, allowed: &[char]) -> Vec<char> {
    text.chars()
        .filter(|c| c.is_control() && !allowed.contains(c))
        .collect()
}

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

/// Returns one scripted response and fails the test if a second request is made.
pub struct OneResponse {
    pub response: RefCell<Option<Result<Response, TransportFailure>>>,
}

impl OneResponse {
    /// A response with the given status and a JSON body.
    #[must_use]
    pub fn json(status: u16, body: &str) -> Self {
        Self::with_headers(status, &[("content-type", "application/json")], body)
    }

    /// A response with the given status, headers, and body.
    #[must_use]
    pub fn with_headers(status: u16, headers: &[(&str, &str)], body: &str) -> Self {
        Self {
            response: RefCell::new(Some(Ok(Response {
                status,
                headers: headers
                    .iter()
                    .map(|(name, value)| ((*name).into(), (*value).into()))
                    .collect(),
                body: body.as_bytes().to_vec(),
                truncated: false,
            }))),
        }
    }
}

impl Transport for OneResponse {
    fn send(&self, _request: &Request) -> Result<Response, TransportFailure> {
        self.response
            .borrow_mut()
            .take()
            .expect("one request expected")
    }
}

mod tests {
    use super::unexpected_controls;

    #[test]
    fn controls_outside_the_allowed_set_are_reported_in_order() {
        assert_eq!(
            unexpected_controls("a\u{1b}\n\tb\u{7f}", &['\n', '\t']),
            ['\u{1b}', '\u{7f}']
        );
        assert!(unexpected_controls("a\n\t", &['\n', '\t']).is_empty());
        assert_eq!(unexpected_controls("a\tb", &['\n']), ['\t']);
        assert!(unexpected_controls("plain \u{e9}", &[]).is_empty());
    }
}
