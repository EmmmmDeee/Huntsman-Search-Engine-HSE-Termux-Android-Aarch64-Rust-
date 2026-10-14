//! The indicator sources: providers that answer for one public IP or one domain.
//!
//! Each source is a provider module that turns its own answer into a [`Finding`], a layer-neutral
//! record of what the provider says about the indicator (a summary line, attributes, tags) and
//! the other indicators it names ([`Pivot`]s). `indicator_legs::SOURCES` is the one list the `ip`
//! and `domain` front-ends run, so a new source is one provider module and one entry there, and it
//! is reachable from the CLI, `scan` and the web UI at once.
//!
//! A source runs when [`Api::wanted`] says so: a keyless or key-optional source always does, a
//! key-required source exactly when its key is configured. A configured key is never skipped.

use crate::api_leg::{self, Api, LegError};
use crate::http::{Request, Response, Transport, TransportFailure};
use crate::keys::Keys;

/// Most pivots one finding keeps; the rest are counted in the summary attributes only.
pub const MAX_PIVOTS: usize = 50;

/// The indicator a source is asked about. Every value is already canonical (a public address, a
/// lower-case domain, a canonical email, an E.164 number).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Indicator<'a> {
    Ip(&'a str),
    Domain(&'a str),
    Email(&'a str),
    Phone(&'a str),
}

/// The kind of an [`Indicator`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndicatorKind {
    Ip,
    Domain,
    Email,
    Phone,
}

impl Indicator<'_> {
    #[must_use]
    pub const fn value(&self) -> &str {
        match self {
            Self::Ip(v) | Self::Domain(v) | Self::Email(v) | Self::Phone(v) => v,
        }
    }

    #[must_use]
    pub const fn kind(&self) -> IndicatorKind {
        match self {
            Self::Ip(_) => IndicatorKind::Ip,
            Self::Domain(_) => IndicatorKind::Domain,
            Self::Email(_) => IndicatorKind::Email,
            Self::Phone(_) => IndicatorKind::Phone,
        }
    }
}

/// What kind of indicator a pivot names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PivotKind {
    Domain,
    Ip,
    Asn,
    Organisation,
    Email,
}

/// Another indicator the provider ties to the one asked about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pivot {
    pub kind: PivotKind,
    pub value: String,
    /// Why the provider names it, as one evidence summary.
    pub summary: &'static str,
}

/// What one provider says about one indicator.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Finding {
    pub summary: String,
    pub attrs: Vec<(&'static str, String)>,
    pub tags: Vec<&'static str>,
    pub pivots: Vec<Pivot>,
}

impl Finding {
    #[must_use]
    pub fn new(summary: impl Into<String>) -> Self {
        Self {
            summary: summary.into(),
            ..Self::default()
        }
    }

    /// Add `key = value`, provider text cleaned with [`api_leg::clean`]; blank values are dropped.
    #[must_use]
    pub fn attr(mut self, key: &'static str, value: impl AsRef<str>) -> Self {
        if let Some(value) = api_leg::clean(Some(value.as_ref())) {
            self.attrs.push((key, value));
        }
        self
    }

    #[must_use]
    pub fn opt_attr(self, key: &'static str, value: Option<impl AsRef<str>>) -> Self {
        match value {
            Some(value) => self.attr(key, value),
            None => self,
        }
    }

    /// Add `key = a,b,c` when `values` is not empty.
    #[must_use]
    pub fn list_attr<S: AsRef<str>>(self, key: &'static str, values: &[S]) -> Self {
        let joined: Vec<&str> = values.iter().map(AsRef::as_ref).collect();
        self.attr(key, joined.join(","))
    }

    #[must_use]
    pub fn tag(mut self, tag: &'static str) -> Self {
        if !self.tags.contains(&tag) {
            self.tags.push(tag);
        }
        self
    }

    #[must_use]
    pub fn tag_if(self, condition: bool, tag: &'static str) -> Self {
        if condition { self.tag(tag) } else { self }
    }

    /// Name another indicator; duplicates and anything past [`MAX_PIVOTS`] are dropped.
    #[must_use]
    pub fn pivot(mut self, kind: PivotKind, value: impl AsRef<str>, summary: &'static str) -> Self {
        let Some(value) = api_leg::clean(Some(value.as_ref())) else {
            return self;
        };
        let known = self
            .pivots
            .iter()
            .any(|p| p.kind == kind && p.value.eq_ignore_ascii_case(&value));
        if !known && self.pivots.len() < MAX_PIVOTS {
            self.pivots.push(Pivot {
                kind,
                value,
                summary,
            });
        }
        self
    }
}

/// One source's lookup. `Ok(None)` is the provider's "nothing known", a valid zero.
pub type Lookup =
    fn(&dyn Transport, &Keys, Indicator<'_>, u64) -> Result<Option<Finding>, LegError>;

/// One indicator source.
#[derive(Clone, Copy)]
pub struct Source {
    pub api: &'static Api,
    /// The indicator kinds the source answers for.
    pub kinds: &'static [IndicatorKind],
    pub lookup: Lookup,
}

impl Source {
    /// Whether this source answers for `indicator` and runs with `keys`. **Pure.**
    #[must_use]
    pub fn applies(&self, indicator: Indicator<'_>, keys: &Keys) -> bool {
        self.kinds.contains(&indicator.kind()) && self.api.wanted(keys)
    }
}

impl std::fmt::Debug for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Source")
            .field("api", &self.api.source)
            .field("kinds", &self.kinds)
            .finish_non_exhaustive()
    }
}

/// A borrowed transport of any size as a `dyn Transport`, so [`Lookup`] can be a plain `fn`.
pub struct DynTransport<'a, T: ?Sized>(pub &'a T);

impl<T: Transport + ?Sized> Transport for DynTransport<'_, T> {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        self.0.send(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn findings_drop_blank_values_duplicate_pivots_and_overflow() {
        let mut finding = Finding::new("s")
            .attr("a", "  ")
            .opt_attr("b", None::<&str>)
            .list_attr::<&str>("c", &[])
            .tag("x")
            .tag("x");
        for n in 0..(MAX_PIVOTS + 5) {
            finding = finding.pivot(PivotKind::Domain, format!("h{n}.example"), "p");
        }
        finding = finding.pivot(PivotKind::Domain, "H0.EXAMPLE", "p");
        assert!(finding.attrs.is_empty());
        assert_eq!(finding.tags, ["x"]);
        assert_eq!(finding.pivots.len(), MAX_PIVOTS);
    }
}
