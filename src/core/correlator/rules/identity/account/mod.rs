//! AU correlation rules — handle, platform, key, tracking and data-broker family.
//!
//! Formerly one ~1.9k-line `account.rs`; split into cohesive per-family submodules
//! (the note in `identity/mod.rs` had already flagged this list as overgrown). Every
//! rule remains `pub(in crate::core::correlator)` and is re-exported here via glob, so
//! `identity::*` / `rules::*` — and every existing call site — resolve exactly as before.

mod broker;
mod handle;
mod key;
mod platform;
mod tracking;

pub(in crate::core::correlator) use broker::*;
pub(in crate::core::correlator) use handle::*;
pub(in crate::core::correlator) use key::*;
pub(in crate::core::correlator) use platform::*;
pub(in crate::core::correlator) use tracking::*;

/// Distinct evidence sources on `evidence` matching `pred`, sorted and
/// deduplicated (via `BTreeSet`, not `Vec` + `sort`, so a source with
/// multiple qualifying records lists once, not once per record). Shared by
/// every "confirmed by which sources" rule in this family (AU-035, AU-077,
/// AU-086) that reports which independent sources corroborated a prediction —
/// three near-identical copies before this, invisible to each other once the
/// family split across files.
fn sorted_evidence_sources(
    evidence: &[crate::core::entity::Evidence],
    pred: impl Fn(&crate::core::entity::Evidence) -> bool,
) -> Vec<&str> {
    evidence
        .iter()
        .filter(|ev| pred(ev))
        .map(|ev| ev.source.as_str())
        .collect::<std::collections::BTreeSet<&str>>()
        .into_iter()
        .collect()
}

/// The registrable-ish host of a URL, lowercased with a leading `www.`
/// stripped — so `https://www.X.com/…` and `https://X.com/…` collapse to the
/// same platform. `None` for an unparseable URL or one with no host. Shared by
/// every rule in this family (AU-038, AU-055) that counts DISTINCT platforms a
/// confirmed/owned URL belongs to. Deliberately not
/// [`crate::util::circuit_breaker::host_of`], which does not strip `www.` and
/// would count `www.x.com`/`x.com` as two different platforms — using it
/// verbatim here would silently change AU-038/AU-055 output.
fn www_stripped_host(url_str: &str) -> Option<String> {
    url::Url::parse(url_str).ok().and_then(|u| {
        u.host_str()
            .map(|h| h.trim_start_matches("www.").to_lowercase())
    })
}
