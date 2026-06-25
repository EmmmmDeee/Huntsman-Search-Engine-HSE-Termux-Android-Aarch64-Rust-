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
use crate::core::relation::RelationKind;

/// Max entities probed against history per scan — bounds the indexed point-queries
/// at finalise on a low-RAM Termux device. Specific identifiers in a scan number a
/// few dozen at most, so this rarely bites; it just caps the pathological case.
const MAX_PROBES: usize = 48;

/// Prior-scan count threshold at or above which an entity is classified as a
/// "hub" — a high-leverage identifier that bridges three or more distinct
/// investigations. Hub entities get a distinguishing tag and stronger evidence
/// summary so both operators and the AU-078 correlator rule can prioritise them.
const HUB_THRESHOLD: usize = 3;

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

/// Strip ASCII handle separators (`.`, `_`, `-`) and lowercase — the canonical
/// form used for handle comparison across platforms. Duplicated here (rather than
/// calling into `correlator::rules`) to keep the history module independent of the
/// correlator's internals.
fn canonical_username(value: &str) -> String {
    value
        .chars()
        .filter(|&c| c != '.' && c != '_' && c != '-')
        .flat_map(char::to_lowercase)
        .collect()
}

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
            // For Username entities: even when the exact-value lookup fails, try
            // the separator-stripped canonical form.  People reuse handles with
            // different punctuation across platforms, so "j.doe" and "jdoe" share
            // one canonical form — a prior scan that recorded the canonical variant
            // should still bridge to the current entity.
            if e.kind == EntityKind::Username {
                let canon = canonical_username(&e.value);
                if canon != e.value && canon.len() >= 4 {
                    let canon_uid = crate::core::entity::derive_uid(&EntityKind::Username, &canon);
                    if canon_uid != e.uid {
                        if probes >= MAX_PROBES {
                            break;
                        }
                        probes += 1;
                        if let Ok(canon_ids) = store.scan_ids_for_entity(&canon_uid) {
                            let prior =
                                canon_ids.iter().filter(|id| id.as_str() != scan_id).count();
                            if prior > 0 {
                                e.tag("cross-scan");
                                let summary = if prior >= HUB_THRESHOLD {
                                    e.tag("hub-entity");
                                    format!(
                                        "High-leverage hub identifier: canonical form '{canon}' \
                                         recorded in {prior} earlier investigation(s) — bridges \
                                         multiple cases across handle-separator variants"
                                    )
                                } else {
                                    format!(
                                        "Canonical form '{canon}' also recorded in {prior} \
                                         earlier scan(s) — separator-variant handle bridges \
                                         investigations"
                                    )
                                };
                                e.add_evidence(Evidence::new(CROSS_SCAN_SOURCE, summary));
                                linked += 1;
                            }
                        }
                    }
                }
            }
            continue;
        };
        let prior = ids.iter().filter(|id| id.as_str() != scan_id).count();
        if prior == 0 {
            // For Usernames: attempt canonical probe even when the exact UID has
            // no prior history, for the same separator-variant bridging reason.
            if e.kind == EntityKind::Username && !e.has_tag("cross-scan") {
                let canon = canonical_username(&e.value);
                if canon != e.value && canon.len() >= 4 {
                    let canon_uid = crate::core::entity::derive_uid(&EntityKind::Username, &canon);
                    if canon_uid != e.uid {
                        if probes >= MAX_PROBES {
                            break;
                        }
                        probes += 1;
                        if let Ok(canon_ids) = store.scan_ids_for_entity(&canon_uid) {
                            let prior_c =
                                canon_ids.iter().filter(|id| id.as_str() != scan_id).count();
                            if prior_c > 0 {
                                e.tag("cross-scan");
                                let summary = if prior_c >= HUB_THRESHOLD {
                                    e.tag("hub-entity");
                                    format!(
                                        "High-leverage hub identifier: canonical form '{canon}' \
                                         recorded in {prior_c} earlier investigation(s) — bridges \
                                         multiple cases across handle-separator variants"
                                    )
                                } else {
                                    format!(
                                        "Canonical form '{canon}' also recorded in {prior_c} \
                                         earlier scan(s) — separator-variant handle bridges \
                                         investigations"
                                    )
                                };
                                e.add_evidence(Evidence::new(CROSS_SCAN_SOURCE, summary));
                                linked += 1;
                            }
                        }
                    }
                }
            }
            continue;
        }
        e.tag("cross-scan");
        // Hub detection: an identifier seen in 3+ distinct prior scans bridges
        // multiple independent investigations. Tag it separately so the AU-078
        // correlator rule and the UI can surface it as a high-leverage lead.
        let summary = if prior >= HUB_THRESHOLD {
            e.tag("hub-entity");
            format!(
                "High-leverage hub identifier: recorded in {prior} earlier investigations \
                 in the local intelligence database — bridges multiple distinct cases and \
                 should be prioritised for cross-investigation attribution"
            )
        } else {
            format!(
                "Also recorded in {prior} earlier scan(s) in the local intelligence database \
                 — this identifier bridges investigations"
            )
        };
        e.add_evidence(Evidence::new(CROSS_SCAN_SOURCE, summary));
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
        // A recurring pairing seen in 3+ prior scans is a high-confidence
        // structural link — tag it as a hub co-occurrence so AU-078 and the
        // UI can weight it above a one-off association.
        if shared >= HUB_THRESHOLD {
            e.tag("hub-cooccurrence");
        }
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

/// Marker prefix embedded in every relation-recall evidence summary, so the
/// idempotency probe can tell (without re-querying the store) whether an endpoint
/// already carries the recall for a given prior relationship — distinguishing it
/// from the recurrence and co-occurrence evidence that share [`CROSS_SCAN_SOURCE`].
const RELATION_RECALL_MARKER: &str = "Previously linked";

/// Max relation-recall point-queries per scan. Like the co-occurrence pass this
/// fans out to each prior scan that recorded a current candidate and reads that
/// scan's relations, so it gets its own tight budget for a low-RAM Termux device.
const MAX_RELATION_PROBES: usize = 48;

/// Max distinct prior relationships recalled per current candidate, so an entity
/// that participated in very many edges across prior investigations can't explode
/// the number of recall evidence rows attached to it.
const MAX_RECALLED_RELATIONS_PER_ENTITY: usize = 8;

/// True for the IDENTITY-bearing relation kinds worth recalling across scans — the
/// edges that connect a person to their identifiers, aliases, addresses, declared
/// associates, and registrations. Pure-infrastructure edges (subdomain / hosting /
/// DNS resolution / co-location / lineage) are excluded: recalling that a domain
/// once resolved to an IP is not the human-network bridge this pass exists to
/// surface.
fn is_identity_relation(kind: RelationKind) -> bool {
    matches!(
        kind,
        RelationKind::IdentifiedBy
            | RelationKind::AliasOf
            | RelationKind::LocatedAt
            | RelationKind::AssociatedWith
            | RelationKind::RegisteredBy
    )
}

/// Build the relation-recall message naming the prior relationship `kind`, the
/// `partner` value, and the `shared` prior-scan count. Centralised so the summary
/// written in the mutation phase and the idempotency probe in
/// [`endpoint_has_relation_recall`] can't drift; the [`RELATION_RECALL_MARKER`]
/// prefix plus the kind string is what the probe keys on.
fn relation_recall_summary(kind: &str, partner: &str, shared: usize) -> String {
    format!(
        "Previously linked ({kind}) to `{partner}` across {shared} earlier scan(s) in the \
         local intelligence database — a known connection that bridges investigations"
    )
}

/// True if `e` already carries the relation-recall evidence for the `(kind, partner)`
/// prior relationship. Matches on the marker, the kind string, and the partner value
/// so an entity recalled to several prior links isn't mistaken for already carrying a
/// new one, and ignores the recurrence / co-occurrence evidence (same source, no
/// marker).
fn endpoint_has_relation_recall(e: &Entity, kind: &str, partner: &str) -> bool {
    e.evidence.iter().any(|ev| {
        ev.source == CROSS_SCAN_SOURCE
            && ev.summary.starts_with(RELATION_RECALL_MARKER)
            && ev.summary.contains(kind)
            && ev.summary.contains(partner)
    })
}

/// Recall this scan's findings' PRIOR RELATIONSHIPS from the local intelligence
/// history — the semantic complement of [`link_cross_scan_cooccurrence`].
///
/// Recurrence notes a value was seen before; co-occurrence notes two values were
/// seen together before; relation recall notes that a reappearing identifier was
/// explicitly LINKED — `located_at` an address, `identified_by` a handle, `alias_of`
/// another account, `associated_with` a person, `registered_by` an org — to something
/// in an earlier investigation. Pulling that past conclusion forward surfaces a known
/// connection (often to an entity not even present in this scan) the operator would
/// otherwise have to rediscover from scratch — the richest cross-investigation bridge
/// of the three history passes.
///
/// Same contract as its siblings: runs BEFORE persist (current `entities` read from
/// the in-memory slice), pure over a [`StoragePort`], bounded ([`MAX_RELATION_PROBES`]
/// / [`MAX_PRIOR_SCANS_PER_ENTITY`] / [`MAX_RECALLED_RELATIONS_PER_ENTITY`]),
/// deterministic (slice order, sorted prior-scan ids, sorted recalls), idempotent
/// ([`endpoint_has_relation_recall`]), store `Err`s skipped, and provenance-only via
/// the non-corroborating [`CROSS_SCAN_SOURCE`] (never inflates confidence). Only the
/// identity-bearing relation kinds ([`is_identity_relation`]) are recalled. Returns
/// the number of entities that gained at least one recalled relationship.
pub(super) fn link_cross_scan_relations(
    store: &dyn StoragePort,
    entities: &mut [Entity],
    scan_id: &str,
) -> usize {
    // ── Read phase ───────────────────────────────────────────────────────────
    // Plan (endpoint_index, kind_str, partner_value, shared_prior_scans). The kind
    // is carried as its `&'static str` form so nothing borrows the per-iteration
    // relation list and the plan key is `Hash`/`Eq` without changing `RelationKind`.
    let mut planned: Vec<(usize, &'static str, String, usize)> = Vec::new();
    let mut probes = 0usize;

    for (i, e) in entities.iter().enumerate() {
        if probes >= MAX_RELATION_PROBES {
            break;
        }
        if !is_cross_scan_candidate(e) {
            continue;
        }
        probes += 1;
        let Ok(mut prior_ids) = store.scan_ids_for_entity(&e.uid) else {
            continue;
        };
        prior_ids.retain(|id| id.as_str() != scan_id);
        prior_ids.sort();
        prior_ids.dedup();
        prior_ids.truncate(MAX_PRIOR_SCANS_PER_ENTITY);
        if prior_ids.is_empty() {
            continue;
        }

        // (kind_str, partner_value) -> distinct prior scans the link recurred in.
        let mut recalled: HashMap<(&'static str, String), usize> = HashMap::new();
        for prior_id in &prior_ids {
            if probes >= MAX_RELATION_PROBES {
                break;
            }
            probes += 1;
            let Ok(relations) = store.relations_for_scan(prior_id) else {
                continue;
            };
            // Distinct (kind, partner) recalled from THIS prior scan, so one prior
            // scan contributes at most 1 to a link's shared-scan count.
            let mut seen_here: Vec<(&'static str, String)> = Vec::new();
            for r in &relations {
                if !is_identity_relation(r.kind) {
                    continue;
                }
                let partner_uid = if r.from_uid == e.uid {
                    &r.to_uid
                } else if r.to_uid == e.uid {
                    &r.from_uid
                } else {
                    continue;
                };
                // Resolve the partner's display value (a bounded point lookup).
                let Ok(Some(partner)) = store.get_entity(partner_uid) else {
                    continue;
                };
                let key = (r.kind.as_str(), partner.value);
                if seen_here.contains(&key) {
                    continue;
                }
                seen_here.push(key.clone());
                *recalled.entry(key).or_insert(0) += 1;
            }
        }

        // Deterministic, bounded recall set: tuple-sorted by (kind, partner value),
        // then capped. The key is unique, so the trailing count never affects order.
        let mut recall_list: Vec<((&'static str, String), usize)> = recalled.into_iter().collect();
        recall_list.sort();
        recall_list.truncate(MAX_RECALLED_RELATIONS_PER_ENTITY);
        for ((kind, partner_value), shared) in recall_list {
            planned.push((i, kind, partner_value, shared));
        }
    }

    // ── Mutation phase ───────────────────────────────────────────────────────
    let mut linked = 0usize;
    for (idx, kind, partner_value, shared) in planned {
        let e = &mut entities[idx];
        if endpoint_has_relation_recall(e, kind, &partner_value) {
            continue; // idempotent: already carries this recalled relationship
        }
        let gained_first = !e.has_tag("cross-scan-relation");
        e.tag("cross-scan-relation");
        e.add_evidence(Evidence::new(
            CROSS_SCAN_SOURCE,
            relation_recall_summary(kind, &partner_value, shared),
        ));
        if gained_first {
            linked += 1;
        }
    }

    if linked > 0 {
        tracing::info!(
            linked,
            "cross-scan relation recall: prior connections surfaced"
        );
    }
    linked
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
