//! Which modules a lookup asks: every one, or only the ones a scan chose, as Spiderfoot's New Scan
//! "By Module" tab and `sf.py -m` choose them.
//!
//! The choice travels with the transport every leg already holds: [`Selected`] wraps a transport
//! and answers [`Transport::runs_module`] from a [`Selection`], and each leg asks it before it
//! sends anything. A module left out sends nothing and leaves no outcome, exactly as a keyed
//! module without its key does. Which names a scan may choose, and what a Spiderfoot module name
//! stands for, is [`crate::module::selection`]'s to say; this type only holds the result.

use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};

use crate::http::{Request, Response, Transport, TransportFailure};

/// The modules a lookup may ask.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Selection {
    /// `None` runs every module.
    only: Option<BTreeSet<String>>,
}

impl Selection {
    /// Every module, as a lookup asked by itself and a scan that chose none run.
    #[must_use]
    pub const fn all() -> Self {
        Self { only: None }
    }

    /// Only the modules named, by their Huntsman names. An empty list runs no module that asks
    /// anything; [`crate::module::selection`] checks names and expands Spiderfoot's.
    #[must_use]
    pub fn only<I, S>(names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            only: Some(names.into_iter().map(Into::into).collect()),
        }
    }

    /// Whether `module` runs. **Pure.**
    #[must_use]
    pub fn runs(&self, module: &str) -> bool {
        self.only
            .as_ref()
            .is_none_or(|names| names.contains(module))
    }

    /// Whether every module runs.
    #[must_use]
    pub const fn is_all(&self) -> bool {
        self.only.is_none()
    }
}

/// `inner`, asking only the modules `selection` runs. Every request, resolution and UDP exchange
/// goes to `inner` unchanged: which module may ask is each leg's question, put to
/// [`Transport::runs_module`] before it sends.
#[derive(Debug)]
pub struct Selected<T> {
    inner: T,
    selection: Selection,
}

impl<T> Selected<T> {
    #[must_use]
    pub const fn new(inner: T, selection: Selection) -> Self {
        Self { inner, selection }
    }
}

impl<T: Transport + Sync> Transport for Selected<T> {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        self.inner.send(request)
    }

    fn resolve(&self, name: &str) -> Result<Vec<IpAddr>, TransportFailure> {
        self.inner.resolve(name)
    }

    fn exchange_udp(
        &self,
        server: SocketAddr,
        message: &[u8],
    ) -> Result<Vec<u8>, TransportFailure> {
        self.inner.exchange_udp(server, message)
    }

    fn runs_module(&self, module: &str) -> bool {
        self.selection.runs(module) && self.inner.runs_module(module)
    }

    /// Shared as itself, so a source asked from another thread is still held to the selection.
    fn shared(&self) -> Option<&(dyn Transport + Sync)> {
        self.inner.shared().map(|_| self as &(dyn Transport + Sync))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source_outcome::SourceOutcomeKind;

    struct Nowhere;

    impl Transport for Nowhere {
        fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
            Err(TransportFailure {
                kind: SourceOutcomeKind::ConnectFailure,
                detail: request.url.clone(),
                blocked: false,
            })
        }
    }

    #[test]
    fn a_selection_runs_what_it_names_and_all_runs_everything() {
        let all = Selection::all();
        assert!(all.is_all() && all.runs("shodan"));
        let some = Selection::only(["spamhaus", "crtsh"]);
        assert!(!some.is_all());
        assert!(some.runs("spamhaus") && some.runs("crtsh"));
        assert!(!some.runs("shodan") && !some.runs("spamhaus.zen"));
        assert!(!Selection::only(Vec::<String>::new()).runs("crtsh"));
    }

    #[test]
    fn a_selected_transport_answers_for_its_selection_and_a_plain_one_runs_everything() {
        assert!(Nowhere.runs_module("shodan"));
        let selected = Selected::new(Nowhere, Selection::only(["crtsh"]));
        assert!(selected.runs_module("crtsh"));
        assert!(!selected.runs_module("shodan"));
        // A selection inside a selection runs only what both run.
        let nested = Selected::new(selected, Selection::only(["crtsh", "shodan"]));
        assert!(nested.runs_module("crtsh") && !nested.runs_module("shodan"));
        // Requests pass through unchanged.
        let failure = nested
            .send(&Request::get("https://crt.sh/"))
            .expect_err("nowhere answers");
        assert_eq!(failure.detail, "https://crt.sh/");
    }
}
