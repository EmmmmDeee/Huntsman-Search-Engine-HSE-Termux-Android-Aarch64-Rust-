//! The GLEIF **Level 2** walk — the only part of the corporate-family feature
//! that touches the network.
//!
//! Isolating the fetch here keeps [`super::family`] and [`super::transform`]
//! pure, so the grading and mapping rules are testable against fixtures without
//! an HTTP double — the same split [`super::helpers`] already gets.
//!
//! # Cost
//! At most three requests per seed, all keyless:
//! `/direct-parent`, `/ultimate-parent`, `/direct-children`. GLEIF answers a
//! missing edge with `404`, which is the clean "top of the tree" / "no
//! subsidiaries" signal rather than an error, so [`fetch_json_or_404`] is the
//! correct helper and a `404` must not trip the per-host circuit breaker.

use crate::core::entity::Entity;
use crate::core::module::ModuleContext;
use crate::util::http::fetch_json_or_404;

use super::SRC;
use super::family::{Kinship, build_relative, is_same_entity, note_child_coverage};
use super::helpers::family_url;
use super::types::{GleifOneResp, GleifResp};

/// Cap on subsidiaries emitted per seed.
///
/// A large group consolidates hundreds of entities, and this module runs under
/// one timeout on a phone; the walk has to be bounded. It is never bounded
/// *silently* — [`note_child_coverage`] stamps GLEIF's true total onto every
/// child emitted, so a partial enumeration is legible as partial in the dossier
/// itself, not merely in a log line (the same discipline `sanctions_ofac`'s
/// `MAX_HITS` and `web_crawler`'s `CONTACT_DUMP_LIMIT` follow).
pub(super) const MAX_CHILDREN: usize = 50;

/// Fetch the record on the other end of a single-valued Level-2 edge.
///
/// `Ok(None)` covers both "GLEIF has no such edge" (404) and "the response
/// carried no record", which for this purpose are the same answer.
async fn one_edge(ctx: &ModuleContext, lei: &str, kin: Kinship) -> Option<GleifOneResp> {
    let url = family_url(lei, kin.path())?;
    fetch_json_or_404::<GleifOneResp>(&ctx.http, SRC, &url)
        .await
        .ok()
        .flatten()
}

/// Walk one seed's corporate family and map it to entities.
///
/// # Recursion, as this codebase adopts it
/// This walk is deliberately **depth-1**. Depth is not produced by recursing
/// here; it is produced by the engine re-dispatching `gleif_lei` against the
/// `Organisation` entities this returns, so the climb up a consolidation chain
/// (and the fan-out down it) advances one generation per expansion round and is
/// bounded by the engine's own depth and budget rather than by a call stack.
/// That is the same explicit-frontier form the rest of the engine uses, and it
/// is what keeps a cyclic or adversarially deep corporate graph from becoming an
/// unbounded traversal inside a single module invocation.
pub(super) async fn walk_family(
    ctx: &ModuleContext,
    seed_lei: &str,
    seed_name: &str,
    scan_id: &str,
) -> Vec<Entity> {
    let mut out: Vec<Entity> = Vec::new();

    // Direct parent first: its LEI is what tells us whether the ultimate parent
    // is a distinct entity or the very same one.
    let direct_lei = match one_edge(ctx, seed_lei, Kinship::DirectParent).await {
        Some(resp) => resp.data.as_ref().and_then(|rec| {
            let e = build_relative(rec, seed_lei, seed_name, Kinship::DirectParent, scan_id)?;
            let lei = rec.attributes.as_ref().and_then(|a| a.lei.clone());
            out.push(e);
            lei
        }),
        None => None,
    };

    if let Some(resp) = one_edge(ctx, seed_lei, Kinship::UltimateParent).await
        && let Some(rec) = resp.data.as_ref()
    {
        // A two-level group's direct parent IS its ultimate parent — see
        // [`is_same_entity`]. The already-emitted entity gains the second role
        // rather than the family gaining a duplicate member.
        if is_same_entity(rec, direct_lei.as_deref()) {
            if let Some(e) = out.last_mut() {
                e.tag("ultimate-parent");
            }
        } else if let Some(e) =
            build_relative(rec, seed_lei, seed_name, Kinship::UltimateParent, scan_id)
        {
            out.push(e);
        }
    }

    // Subsidiaries. A collection response, so it carries the true total in
    // `meta.pagination` even when only one page is retrieved.
    let Some(url) = family_url(seed_lei, Kinship::DirectChild.path()) else {
        return out;
    };
    let url = format!("{url}?page%5Bsize%5D={MAX_CHILDREN}");
    let Ok(Some(resp)) = fetch_json_or_404::<GleifResp>(&ctx.http, SRC, &url).await else {
        return out;
    };

    let total = resp
        .meta
        .as_ref()
        .and_then(|m| m.pagination.as_ref())
        .and_then(|p| p.total)
        .unwrap_or(resp.data.len() as u64);

    let first_child = out.len();
    for rec in resp.data.iter().take(MAX_CHILDREN) {
        if let Some(e) = build_relative(rec, seed_lei, seed_name, Kinship::DirectChild, scan_id) {
            out.push(e);
        }
    }
    let emitted = out.len() - first_child;
    if total > emitted as u64 {
        tracing::warn!(
            "{SRC}: '{seed_name}' (LEI {seed_lei}) consolidates {total} direct subsidiaries; \
             emitting {emitted} — the rest are NOT in this scan's results"
        );
    }
    for e in &mut out[first_child..] {
        note_child_coverage(e, emitted, total);
    }
    out
}
