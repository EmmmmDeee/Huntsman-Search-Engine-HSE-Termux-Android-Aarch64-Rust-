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
pub(super) async fn resolve_did(ctx: &ModuleContext, seed: &str) -> Option<String> {
    if is_plc_did(seed) || web_did_host(seed).is_some() {
        return Some(seed.to_string());
    }

    let mut candidates: Vec<String> = Vec::new();
    if is_dns_label(seed) {
        candidates.push(format!("{seed}.bsky.social"));
    }
    if is_handle(seed) {
        candidates.push(seed.to_string());
    }

    for handle in candidates {
        let url = format!("{RESOLVE_API}?handle={}", urlencode(&handle));
        // 400 is how the AppView says "no such handle", so it must read as a
        // clean miss rather than an error that trips the per-host breaker and
        // suppresses the source for the handles that do exist.
        if let Ok(Some(r)) = fetch_json_or_absent::<ResolvedHandle>(&ctx.http, SRC, &url).await {
            let did = r.did.trim();
            if !did.is_empty() {
                return Some(did.to_string());
            }
        }
    }
    None
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
