//! Cross-scan historical linking — the local intelligence flywheel.
//!
//! Recall ([`crate::core::engine::ScanEngine::recall_prior_entities`]) is
//! seed-centric: it replays prior scans OF THE SAME subject. But a fresh finding
//! in this scan often appears in a DIFFERENT subject's earlier scan — a shared
//! address, phone, email or named person — and recall never makes that link
//! because the seeds differ. This finalize pass closes the gap: for each specific
//! personal identifier the scan produced, it asks the store whether any earlier
//! scan recorded the same value, and tags the recurrence so each scan compounds
//! the next.
//!
//! Provenance only: the [`crate::core::entity::CROSS_SCAN_SOURCE`] evidence it
//! attaches is non-corroborating (a recurrence can't tell a re-scan of one subject
//! from an independent sighting), so it never inflates confidence — the value is
//! the surfaced cross-investigation LINK, not a score bump. Pure over a
//! [`StoragePort`] (point lookups only, bounded), so it never fails a scan over a
//! history query.

use std::collections::HashMap;

use crate::core::entity::{CROSS_SCAN_SOURCE, Entity, EntityKind, Evidence};
use crate::core::port::StoragePort;

/// Max entities probed against history per scan — bounds the indexed point-queries
/// at finalise on a low-RAM Termux device. Specific identifiers in a scan number a
/// few dozen at most, so this rarely bites; it just caps the pathological case.
const MAX_PROBES: usize = 48;

/// Max point-queries the co-occurrence pass may issue per scan. The pairing pass
/// is heavier than plain recurrence — for each current candidate it fans out to
/// every prior scan that recorded it and reads that scan's entities — so it gets
/// its own, tighter budget so the indexed reads stay bounded on a low-RAM Termux
/// device even when a scan produces many specific identifiers.
const MAX_COOCCURRENCE_PROBES: usize = 48;

/// Max prior scans examined per current candidate. The candidate's prior-scan ids
/// are sorted and truncated to this, so a value seen in very many earlier scans
/// can't fan the read phase out unboundedly (and the cap is applied
/// deterministically — the smallest ids win).
const MAX_PRIOR_SCANS_PER_ENTITY: usize = 8;

/// Max distinct partners recorded per current candidate, so a hub identifier (an
/// address or email shared across very many prior investigations) can't explode
/// the number of co-occurrence evidence rows attached to one entity.
const MAX_PARTNERS_PER_ENTITY: usize = 8;

/// Marker substring embedded in every co-occurrence evidence summary. Lets the
/// second (mutation) phase detect, idempotently, whether a given endpoint already
/// carries the co-occurrence link for a given partner value without re-querying
/// the store — distinguishing it from the plain recurrence evidence, which shares
/// the [`CROSS_SCAN_SOURCE`] source but never contains this phrase.
const COOCCURRENCE_MARKER: &str = "Co-occurred with `";

/// True if `e` is a SPECIFIC personal identifier worth checking against history —
/// the kind of value whose recurrence across scans genuinely bridges two
/// investigations. Excludes infrastructure (every scan touches `google.com`),
/// speculative permutations, coarse geo (a postcode is shared by thousands), and
/// already-recalled nodes (those are known historical by construction).
#[must_use]
pub(super) fn is_cross_scan_candidate(e: &Entity) -> bool {
    if e.has_tag(crate::core::tags::RECALLED) || e.has_tag("name-derived") || e.has_tag("permuted")
    {
        return false;
    }
    match e.kind {
        EntityKind::Email | EntityKind::Phone | EntityKind::CryptoAddress => e.confidence >= 0.40,
        EntityKind::Username => e.confidence >= 0.40 && e.value.len() >= 4,
        EntityKind::Person => e.confidence >= 0.40 && e.value.split_whitespace().count() >= 2,
        // A SPECIFIC address only — a coarse postcode/suburb centroid is shared by
        // far too many people to be a meaningful cross-investigation bridge.
        EntityKind::Address => {
            e.confidence >= 0.40
                && !e.has_tag("coarse")
                && !e.has_tag("postcode-only")
                && !e.has_tag("candidate-suburb")
        }
        _ => false,
    }
}

/// Link this scan's findings to the local intelligence history.
///
/// For each [`is_cross_scan_candidate`] identifier, ask the store whether any
/// EARLIER scan recorded the same value (the entity isn't persisted for this scan
/// yet, so any hit is genuinely prior). A recurrence earns a `cross-scan` tag and a
/// [`CROSS_SCAN_SOURCE`] evidence record naming how many prior scans share it — the
/// bridge that turns a pile of isolated scans into one connected intelligence base.
/// Non-corroborating (never inflates confidence), bounded ([`MAX_PROBES`]),
/// idempotent, and store errors are skipped (a history lookup must never fail a
/// scan). Returns the number of entities bridged.
pub(super) fn link_cross_scan_history(
    store: &dyn StoragePort,
    entities: &mut [Entity],
    scan_id: &str,
) -> usize {
    let mut linked = 0usize;
    let mut probes = 0usize;
    for e in entities.iter_mut() {
        if probes >= MAX_PROBES {
            break;
        }
        if e.has_tag("cross-scan") || !is_cross_scan_candidate(e) {
            continue;
        }
        probes += 1;
        let Ok(ids) = store.scan_ids_for_entity(&e.uid) else {
            continue;
        };
        let prior = ids.iter().filter(|id| id.as_str() != scan_id).count();
        if prior == 0 {
            continue;
        }
        e.tag("cross-scan");
        e.add_evidence(Evidence::new(
            CROSS_SCAN_SOURCE,
            format!(
                "Also recorded in {prior} earlier scan(s) in the local intelligence database — \
                 this identifier bridges investigations"
            ),
        ));
        linked += 1;
    }
    if linked > 0 {
        tracing::info!(
            linked,
            "cross-scan history: findings bridged to earlier investigations"
        );
    }
    linked
}

/// Build the co-occurrence message naming `partner` and the `shared` prior-scan
/// count. Centralised so the summary written in the mutation phase and the
/// idempotency probe in [`endpoint_has_cooccurrence`] can't drift; the
/// [`COOCCURRENCE_MARKER`] prefix is what the probe keys on.
fn cooccurrence_summary(partner: &str, shared: usize) -> String {
    format!(
        "Co-occurred with `{partner}` across {shared} earlier scan(s) in the local \
         intelligence database — a recurring association that bridges investigations"
    )
}

/// True if `e` already carries the co-occurrence evidence for `partner` — a
/// [`CROSS_SCAN_SOURCE`] record whose summary matches [`cooccurrence_summary`]'s
/// marker and names that partner. Drives idempotency: a re-run finds the record
/// and adds nothing. Matches on the partner value (not just the source) so an
/// entity bridged to several partners isn't mistaken for already-linked to a new
/// one, and ignores the plain-recurrence evidence (same source, no marker).
fn endpoint_has_cooccurrence(e: &Entity, partner: &str) -> bool {
    e.evidence.iter().any(|ev| {
        ev.source == CROSS_SCAN_SOURCE
            && ev.summary.starts_with(COOCCURRENCE_MARKER)
            && ev.summary.contains(partner)
    })
}

/// Link this scan's findings to RECURRING ASSOCIATIONS in the local intelligence
/// history — the stronger, data-driven sibling of [`link_cross_scan_history`].
///
/// Recurrence notes that a single value was seen before; co-occurrence notes that
/// two distinct specific identifiers which appeared TOGETHER in an earlier scan
/// BOTH reappear in this one. That recurring pairing is a high-value historical
/// LINK between the two values — the bridge that actually connects entities across
/// investigations — so each endpoint earns a `cross-scan-cooccurrence` tag and a
/// [`CROSS_SCAN_SOURCE`] evidence naming the partner and how many prior scans the
/// pair shared.
///
/// Same contract as [`link_cross_scan_history`]: this runs BEFORE persist, so the
/// current scan's `entities` are read from the in-memory slice (NOT the store, where
/// they don't exist yet); it is pure over a
/// [`StoragePort`], bounded
/// ([`MAX_COOCCURRENCE_PROBES`] / [`MAX_PRIOR_SCANS_PER_ENTITY`] /
/// [`MAX_PARTNERS_PER_ENTITY`]), deterministic (slice order, sorted prior-scan ids
/// and partners), idempotent ([`endpoint_has_cooccurrence`]), and any store `Err`
/// is SKIPPED — a history lookup must never fail a scan. The evidence reuses
/// [`CROSS_SCAN_SOURCE`], which
/// [`is_non_corroborating_source`](crate::core::entity::is_non_corroborating_source)
/// rejects from the corroboration count, so it is PROVENANCE-ONLY and never inflates
/// [`c_effective`](crate::core::entity::Entity::c_effective). Returns the number of
/// entities that gained at least one co-occurrence link.
pub(super) fn link_cross_scan_cooccurrence(
    store: &dyn StoragePort,
    entities: &mut [Entity],
    scan_id: &str,
) -> usize {
    // Current-scan candidate identifiers, read from the in-memory slice (these are
    // not persisted yet). `uid -> index`, so a partner found in a prior scan can be
    // resolved back to the live entity it co-occurs with.
    let current: HashMap<&str, usize> = entities
        .iter()
        .enumerate()
        .filter(|(_, e)| is_cross_scan_candidate(e))
        .map(|(i, e)| (e.uid.as_str(), i))
        .collect();

    // ── Read phase (immutable) ──────────────────────────────────────────────
    // Plan mutations as (endpoint_index, partner_value, shared_prior_scans) so the
    // mutation phase can take `&mut entities` without the read borrows still live.
    let mut planned: Vec<(usize, String, usize)> = Vec::new();
    let mut probes = 0usize;

    for (i, e) in entities.iter().enumerate() {
        if probes >= MAX_COOCCURRENCE_PROBES {
            break;
        }
        if !is_cross_scan_candidate(e) {
            continue;
        }
        probes += 1;
        let Ok(mut prior_ids) = store.scan_ids_for_entity(&e.uid) else {
            continue;
        };
        // Keep only genuinely-prior scans, deduped and sorted so the per-entity cap
        // is applied deterministically (smallest ids win).
        prior_ids.retain(|id| id.as_str() != scan_id);
        prior_ids.sort();
        prior_ids.dedup();
        prior_ids.truncate(MAX_PRIOR_SCANS_PER_ENTITY);
        if prior_ids.is_empty() {
            continue;
        }

        // partner current-index -> distinct prior scans the pair co-occurred in.
        // Keyed by the live-entity INDEX (a `Copy` usize), NOT a `&str` borrowed
        // from the per-iteration `prior_entities` (dropped at the end of each loop);
        // the display value is read from `entities[pidx]` only when planning below.
        let mut partners: HashMap<usize, usize> = HashMap::new();
        for prior_id in &prior_ids {
            if probes >= MAX_COOCCURRENCE_PROBES {
                break;
            }
            probes += 1;
            let Ok(prior_entities) = store.entities_for_scan(prior_id) else {
                continue;
            };
            // Distinct partner indices seen in THIS prior scan, so one prior scan
            // contributes at most 1 to a pair's shared-scan count even if the store
            // returns the partner more than once.
            let mut seen_here: Vec<usize> = Vec::new();
            for pe in &prior_entities {
                let puid = pe.uid.as_str();
                if puid == e.uid.as_str() {
                    continue;
                }
                // The partner must ALSO be a current candidate and itself pass the
                // candidate gate (the index resolves it to the live entity).
                let Some(&pidx) = current.get(puid) else {
                    continue;
                };
                if !is_cross_scan_candidate(&entities[pidx]) || seen_here.contains(&pidx) {
                    continue;
                }
                seen_here.push(pidx);
                *partners.entry(pidx).or_insert(0) += 1;
            }
        }

        // Deterministic, bounded set of partners for this endpoint: resolve each
        // index to its display value, sort by value, cap, and plan one mutation each.
        let mut partner_list: Vec<(&str, usize)> = partners
            .into_iter()
            .map(|(pidx, n)| (entities[pidx].value.as_str(), n))
            .collect();
        partner_list.sort_by(|a, b| a.0.cmp(b.0));
        partner_list.truncate(MAX_PARTNERS_PER_ENTITY);
        for (value, shared) in partner_list {
            planned.push((i, value.to_owned(), shared));
        }
    }

    // ── Mutation phase ──────────────────────────────────────────────────────
    let mut linked = 0usize;
    for (idx, partner_value, shared) in planned {
        let e = &mut entities[idx];
        if endpoint_has_cooccurrence(e, &partner_value) {
            continue; // idempotent: already linked to this partner
        }
        let gained_first = !e.has_tag("cross-scan-cooccurrence");
        e.tag("cross-scan-cooccurrence");
        e.add_evidence(Evidence::new(
            CROSS_SCAN_SOURCE,
            cooccurrence_summary(&partner_value, shared),
        ));
        if gained_first {
            linked += 1;
        }
    }

    if linked > 0 {
        tracing::info!(
            linked,
            "cross-scan co-occurrence: recurring associations bridged"
        );
    }
    linked
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
