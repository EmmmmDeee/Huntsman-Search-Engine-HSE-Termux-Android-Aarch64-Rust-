//! The only part of this module that touches the network.
//!
//! Isolating it keeps [`super::history`] and [`super::transform`] pure, so the
//! rules that decide what a log *means* are testable against fixtures without an
//! HTTP double — the same split `gleif_lei` uses.
//!
//! # Cost
//! At most two keyless requests per seed: one handle resolution against the
//! public AppView, one audit-log read against `plc.directory`. A seed that is
//! already a DID skips the first.

use crate::core::module::ModuleContext;
use crate::util::atproto::{is_dns_label, is_handle, is_plc_did, web_did_host};
use crate::util::http::{fetch_json_or_404, fetch_json_or_absent, urlencode};

use super::types::{AuditEntry, ResolvedHandle};
use super::{PLC_BASE, RESOLVE_API, SRC};

/// Resolve a scan seed to an AT Protocol DID.
///
/// Accepts a DID verbatim (so a `did:plc:` or `did:web:` value scanned directly
/// costs nothing to resolve) and otherwise treats the seed as a handle. Both
/// candidate handle forms are gated on local validity first: the AppView answers
/// a structurally invalid `actor` with HTTP 400, and issuing a request that
/// cannot succeed is pure cost on every scan.
///
///   * `{seed}.bsky.social` — only when `seed` is one valid DNS label, so a
///     username with an underscore never spends a request.
///   * bare `{seed}` — only when the seed is already a dotted handle
///     (`alice.dev`); a plain token is never a valid actor.
pub(super) async fn resolve_did(
    ctx: &ModuleContext,
    seed: &str,
) -> crate::core::error::Result<Option<String>> {
    // The seed is already a DID — nothing to resolve, and no request is made,
    // so there is no outage to distinguish from an absence here.
    if is_plc_did(seed) || web_did_host(seed).is_some() {
        return Ok(Some(seed.to_string()));
    }

    let mut candidates: Vec<String> = Vec::new();
    if is_dns_label(seed) {
        candidates.push(format!("{seed}.bsky.social"));
    }
    if is_handle(seed) {
        candidates.push(seed.to_string());
    }

    // `fetch_json_or_absent` already models "no such handle" as `Ok(None)` — 400
    // is how the AppView says it, and it must read as a clean miss rather than an
    // error that trips the per-host breaker and suppresses the source for the
    // handles that do exist. That means an `Err` here is a GENUINE failure:
    // transport, 5xx, or a throttle.
    //
    // Those errors were previously discarded by `if let Ok(Some(r))`, so if every
    // candidate failed the function returned `None` — identical to "this handle
    // does not exist anywhere". For an identity-resolution module that negative
    // is the whole answer, and it was being fabricated from an outage.
    let mut attempted = 0usize;
    let mut failed = 0usize;
    for handle in candidates {
        let url = format!("{RESOLVE_API}?handle={}", urlencode(&handle));
        attempted += 1;
        match fetch_json_or_absent::<ResolvedHandle>(&ctx.http, SRC, &url).await {
            Ok(Some(r)) => {
                let did = r.did.trim();
                if !did.is_empty() {
                    return Ok(Some(did.to_string()));
                }
            }
            // A clean miss: this candidate handle genuinely does not exist.
            Ok(None) => {}
            Err(e) => {
                failed += 1;
                tracing::warn!(
                    module = SRC,
                    handle = %handle,
                    error = %e,
                    "handle resolution failed; recorded as a failure, not as \"no such handle\""
                );
            }
        }
    }

    // Fail closed only when EVERY candidate failed and none resolved — the same
    // rule as `cert_intel::never_answered` and `see_know::seeknow_never_answered`.
    //
    // In practice `candidates` holds at most ONE element: `is_dns_label` rejects
    // any value containing a dot and `is_handle` requires one, so the two pushes
    // above are mutually exclusive. The tally is kept in the general form because
    // it is the shape the rest of the codebase uses and because a future
    // candidate source would otherwise silently break the rule — but it is not
    // load-bearing for a mixed miss/failure case, because no such case can arise.
    //
    // The message says only what is known. A failure here can be a transport
    // error, a 5xx, a throttle, OR the per-host circuit breaker short-circuiting
    // the call before any request leaves the process — `breaker_gate` returns an
    // Err without contacting anything, and the breaker is keyed by host, so a
    // sibling module hammering the same AppView host can open it. Claiming "the
    // directory never answered" would then be false in the same way the message
    // `cert_intel::all_sources_failed_msg` replaced was false.
    if every_candidate_failed(attempted, failed) {
        return Err(crate::core::error::Error::module(
            SRC,
            "every candidate handle failed to resolve",
        ));
    }
    Ok(None)
}

/// Fetch the append-only operation log for a `did:plc:` identity.
///
/// `Ok(None)` from a 404 is the clean "this DID was never registered" answer,
/// not a failure. The DID is validated before it reaches the URL — it is
/// interpolated into a path, so [`is_plc_did`] is a security gate, not a
/// nicety.
pub(super) async fn audit_log(ctx: &ModuleContext, did: &str) -> Option<Vec<AuditEntry>> {
    if !is_plc_did(did) {
        return None;
    }
    let url = format!("{PLC_BASE}/{did}/log/audit");
    fetch_json_or_404::<Vec<AuditEntry>>(&ctx.http, SRC, &url)
        .await
        .ok()
        .flatten()
}

/// Whether every candidate handle that was actually tried came back a failure.
///
/// Pure, so the tally is testable without a live AppView. `attempted == 0` is
/// deliberately NOT a failure: a seed that is neither a DNS label nor a handle
/// produces no candidates, so nothing was asked and nothing can have failed.
fn every_candidate_failed(attempted: usize, failed: usize) -> bool {
    attempted > 0 && failed == attempted
}

#[cfg(test)]
mod resolve_tests {
    use super::every_candidate_failed;

    #[test]
    fn nothing_attempted_is_not_a_failure() {
        // A seed that is neither a DNS label nor a handle. No request is made,
        // so an absent DID is a real negative rather than an outage.
        assert!(!every_candidate_failed(0, 0));
    }

    #[test]
    fn the_only_candidate_failing_is_a_failure() {
        assert!(every_candidate_failed(1, 1));
    }

    #[test]
    fn a_clean_miss_is_not_a_failure() {
        // The AppView answered "no such handle" (it signals that with a 400,
        // which `fetch_json_or_absent` maps to Ok(None)). That is evidence.
        assert!(!every_candidate_failed(1, 0));
    }

    #[test]
    fn a_mixed_outcome_is_not_a_failure() {
        // Unreachable today — `is_dns_label` rejects dots and `is_handle`
        // requires one, so at most one candidate exists — but pinned because the
        // predicate is written in the general form and a future candidate source
        // must not silently change the rule.
        assert!(!every_candidate_failed(2, 1));
    }
}
