//! Doubles the `SeekNow` integration tests share: a transport that replays scripted responses in
//! order and records every request, the response constructors, and an operator-approved test
//! credential. Each of `seeknow_cli.rs`, `seeknow_client.rs`, `seeknow_collector.rs` and
//! `seeknow_diagnostics.rs` carried its own copy of these; they are defined once here. (The
//! library's `test_support` has the same transport, but it is `cfg(test)` and so invisible to
//! integration tests.)

use std::cell::RefCell;
use std::collections::VecDeque;

use huntsman_recon::credential_origin::{AuthenticationAuthority, OperatorCredentialRef};
use huntsman_recon::fetch::{AuthStyle, Credential};
use huntsman_recon::http::{Request, Response, Transport, TransportFailure};
use huntsman_recon::keys::Secret;
use huntsman_recon::seeknow::KEY_SLOT;

/// Replays scripted responses in order and records every request in `seen`. A request past the
/// end of the script is a test bug and panics.
pub struct ScriptedTransport {
    responses: RefCell<VecDeque<Response>>,
    pub seen: RefCell<Vec<Request>>,
}

impl ScriptedTransport {
    pub fn new(responses: Vec<Response>) -> Self {
        Self {
            responses: RefCell::new(responses.into()),
            seen: RefCell::new(Vec::new()),
        }
    }

    pub fn request_count(&self) -> usize {
        self.seen.borrow().len()
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

/// A response with the given status and body, no headers, not truncated.
pub fn response(status: u16, body: &str) -> Response {
    response_with(status, body, Vec::new(), false)
}

/// A response with every field chosen.
pub fn response_with(
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

/// The operator-approved `SeekNow` credential most tests use.
pub fn credential() -> Credential {
    credential_with("integration-test", "seek-test-secret")
}

/// An operator-approved `SeekNow` credential with the given approval provenance and secret value.
pub fn credential_with(provenance: &str, secret: &str) -> Credential {
    let authority = AuthenticationAuthority::operator_approved(OperatorCredentialRef {
        provider_id: "seeknow".into(),
        credential_slot: KEY_SLOT.into(),
        approved_at_unix: 1,
        approval_provenance: provenance.into(),
    })
    .unwrap();
    Credential::new(
        authority,
        Secret::new(secret).unwrap(),
        AuthStyle::Header("X-API-Key".into()),
    )
    .unwrap()
}
