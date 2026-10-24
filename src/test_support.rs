//! Test doubles and fixtures shared across the crate's tests. Compiled only for `cargo test`.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

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

/// Answers by URL prefix, the first matching route winning, and records every URL asked; a URL
/// no route matches gets no response.
pub struct RoutedTransport {
    pub routes: Vec<(&'static str, u16, &'static str)>,
    pub seen: std::sync::Mutex<Vec<String>>,
}

impl RoutedTransport {
    #[must_use]
    pub fn new(routes: &[(&'static str, u16, &'static str)]) -> Self {
        Self {
            routes: routes.to_vec(),
            seen: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Every URL asked, in order.
    #[must_use]
    pub fn urls(&self) -> Vec<String> {
        self.seen
            .lock()
            .map(|seen| seen.clone())
            .unwrap_or_default()
    }
}

impl Transport for RoutedTransport {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        if let Ok(mut seen) = self.seen.lock() {
            seen.push(request.url.clone());
        }
        self.routes
            .iter()
            .find(|(prefix, _, _)| request.url.starts_with(prefix))
            .map(|(_, status, body)| Response {
                status: *status,
                headers: Vec::new(),
                body: body.as_bytes().to_vec(),
                truncated: false,
            })
            .ok_or_else(|| TransportFailure {
                kind: SourceOutcomeKind::ConnectFailure,
                detail: "no route".into(),
                blocked: false,
            })
    }
}

/// Every request the egress policy refuses, as for a host that resolves to 0.0.0.0: each HTTP
/// send and each UDP exchange is blocked, as the real transport's policy can block both, so
/// nothing is sent. The policy never blocks the system resolver, so `resolve` keeps the trait's
/// unblocked failure. Threads may share it, as they share the real transport, so a lookup asks
/// its independent sources at once through it.
#[derive(Debug, Clone, Copy, Default)]
pub struct Refusing;

impl Refusing {
    fn failure() -> TransportFailure {
        TransportFailure {
            kind: SourceOutcomeKind::ConnectFailure,
            detail: "egress-policy: destination (0.0.0.0) is not publicly routable".into(),
            blocked: true,
        }
    }
}

impl Transport for Refusing {
    fn send(&self, _: &Request) -> Result<Response, TransportFailure> {
        Err(Self::failure())
    }

    fn exchange_udp(&self, _: SocketAddr, _: &[u8]) -> Result<Vec<u8>, TransportFailure> {
        Err(Self::failure())
    }

    fn shared(&self) -> Option<&(dyn Transport + Sync)> {
        Some(self)
    }
}

/// No network: every HTTP send gets no response. The kind is `DnsFailure` because crt.sh pauses
/// two seconds before it retries a `ConnectFailure`. The system resolver and UDP keep the trait's
/// unblocked failures. Threads may share it, as they share [`Refusing`].
#[derive(Debug, Clone, Copy, Default)]
pub struct Silent;

impl Transport for Silent {
    fn send(&self, _: &Request) -> Result<Response, TransportFailure> {
        Err(TransportFailure {
            kind: SourceOutcomeKind::DnsFailure,
            detail: "no route to host".into(),
            blocked: false,
        })
    }

    fn shared(&self) -> Option<&(dyn Transport + Sync)> {
        Some(self)
    }
}

/// Every source reached, answering with an error: each HTTP send gets HTTP 500 with an empty body
/// (crt.sh retries only 429, 502 and 503), the system resolver knows no name, and a UDP exchange
/// gets no answer, unblocked. Threads may share it, as they share [`Refusing`].
#[derive(Debug, Clone, Copy, Default)]
pub struct Failing;

impl Transport for Failing {
    fn send(&self, _: &Request) -> Result<Response, TransportFailure> {
        Ok(Response {
            status: 500,
            headers: Vec::new(),
            body: Vec::new(),
            truncated: false,
        })
    }

    fn resolve(&self, _: &str) -> Result<Vec<IpAddr>, TransportFailure> {
        Ok(Vec::new())
    }

    fn exchange_udp(&self, server: SocketAddr, _: &[u8]) -> Result<Vec<u8>, TransportFailure> {
        Err(TransportFailure {
            kind: SourceOutcomeKind::ConnectFailure,
            detail: format!("no UDP answer from {server}"),
            blocked: false,
        })
    }

    fn shared(&self) -> Option<&(dyn Transport + Sync)> {
        Some(self)
    }
}

/// One thing a [`Recording`] transport was asked to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attempt {
    /// An HTTP request, by its URL.
    Http(String),
    /// A name asked of the system resolver.
    SystemResolver(String),
    /// A DNS message sent over UDP, by its server.
    Udp(SocketAddr),
}

/// `inner`, keeping every attempt asked of it in order. Clones share one record, so a lookup's
/// clones of the transport all write to it.
#[derive(Debug, Clone, Default)]
pub struct Recording<T> {
    pub inner: T,
    pub asked: Arc<Mutex<Vec<Attempt>>>,
}

impl<T> Recording<T> {
    #[must_use]
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            asked: Arc::default(),
        }
    }

    /// Every attempt so far, in order.
    #[must_use]
    pub fn attempts(&self) -> Vec<Attempt> {
        self.asked
            .lock()
            .map(|asked| asked.clone())
            .unwrap_or_default()
    }

    fn note(&self, attempt: Attempt) {
        if let Ok(mut asked) = self.asked.lock() {
            asked.push(attempt);
        }
    }
}

impl<T: Transport + Sync> Transport for Recording<T> {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        self.note(Attempt::Http(request.url.clone()));
        self.inner.send(request)
    }

    fn resolve(&self, name: &str) -> Result<Vec<IpAddr>, TransportFailure> {
        self.note(Attempt::SystemResolver(name.to_owned()));
        self.inner.resolve(name)
    }

    fn exchange_udp(
        &self,
        server: SocketAddr,
        message: &[u8],
    ) -> Result<Vec<u8>, TransportFailure> {
        self.note(Attempt::Udp(server));
        self.inner.exchange_udp(server, message)
    }

    fn runs_module(&self, module: &str) -> bool {
        self.inner.runs_module(module)
    }

    fn shared(&self) -> Option<&(dyn Transport + Sync)> {
        self.inner.shared().map(|_| self as &(dyn Transport + Sync))
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

/// A random entity graph of 1 to `max_nodes` nodes from the xorshift sequence in `state`:
/// sparse or dense, built from duplicate, reversed and self-loop relations for `Graph::build` to
/// fold away. A fixed seed gives the same graphs on every run.
#[must_use]
pub fn random_graph(state: &mut u64, max_nodes: usize) -> crate::graph::Graph {
    use crate::entity::{Entity, EntityKind};
    use crate::graph::{EntityRelation, Graph, RelationKind};

    let mut draw = |bound: usize| -> usize {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        usize::try_from(*state % u64::try_from(bound).unwrap_or(1)).unwrap_or(0)
    };
    let nodes = (0..=draw(max_nodes))
        .map(|n| Entity::new(EntityKind::Email, format!("n{n}@example.com"), 0.6, "scan"))
        .collect::<Vec<_>>();
    let density = 1 + draw(6);
    let relations = (0..draw(nodes.len() * density))
        .map(|_| {
            EntityRelation::new(
                nodes[draw(nodes.len())].uid.clone(),
                nodes[draw(nodes.len())].uid.clone(),
                RelationKind::AssociatedWith,
                0.5,
            )
        })
        .collect::<Vec<_>>();
    Graph::build(&nodes, &relations)
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

/// `count` corruptions of `input`, from a fixed seed so a failing case is reproduced by its
/// index: a byte overwritten, a 4-byte field set to an extreme (`0`, `0x7fff_ffff`,
/// `0xffff_ffff`, which planted as a count or offset points far past the end), the input cut
/// short, or a stretch of it repeated.
#[must_use]
pub fn mutations(input: &[u8], seed: u64, count: usize) -> Vec<Vec<u8>> {
    let mut state = seed | 1;
    let mut draw = move |bound: usize| {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        usize::try_from(state % u64::try_from(bound.max(1)).unwrap_or(1)).unwrap_or(0)
    };
    (0..count)
        .map(|_| {
            let mut bytes = input.to_vec();
            for _ in 0..=draw(3) {
                if bytes.is_empty() {
                    break;
                }
                let at = draw(bytes.len());
                match draw(4) {
                    0 => bytes[at] = u8::try_from(draw(256)).unwrap_or(0),
                    1 => {
                        let extreme = [[0; 4], [0x7f, 0xff, 0xff, 0xff], [0xff; 4]][draw(3)];
                        for (offset, byte) in extreme.iter().enumerate() {
                            if let Some(slot) = bytes.get_mut(at + offset) {
                                *slot = *byte;
                            }
                        }
                    }
                    2 => bytes.truncate(at),
                    _ => {
                        let end = (at + draw(64)).min(bytes.len());
                        let stretch = bytes[at..end].to_vec();
                        bytes.splice(at..at, stretch);
                    }
                }
            }
            bytes
        })
        .collect()
}
