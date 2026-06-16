//! Prior-scan recall: re-inject the local database as a live intelligence
//! source at the start of every scan.
//!
//! [`recall_prior_entities`] is the single entry point; it is called once from
//! [`super::ScanEngine::run_with_ledger`] before the seed-dispatch round.

use std::collections::{HashMap, HashSet};

use tracing::warn;

use crate::core::{
    entity::{Entity, EntityKind, Evidence, derive_uid, normalise},
    port::StoragePort,
    scan::Target,
    tags,
};

/// Recall everything the local database already knows about `target`, for
/// injection into the working set — so the persistent store is a SOURCE for
/// every scan, not just a sink.  A target ever scanned before re-enters the
/// graph pre-populated with the entities prior runs (and their expansion
/// rounds) discovered, ready to corroborate live findings and seed expansion.
/// This is what makes the database "utilised as a source for all recursion and
/// future scans".
///
/// The store is content-addressed (same kind+value ⇒ same uid) with a
/// per-entity observation history, so the relevant prior scans are those that
/// observed the exact seed identity, plus any that observed an entity whose
/// value equals the target (robust to `FullName` re-formatting, and catching
/// scans where the target surfaced as a *discovered* node rather than the
/// seed). Each recalled entity is stamped with the current scan id (a
/// first-class member of this scan's graph — so it counts as observed now and
/// chains into future recalls), tagged [`crate::core::tags::RECALLED`], and
/// carries its stored confidence; live modules merge onto it by uid.
///
/// Bounded (`MAX_PRIOR_SCANS` scans, `MAX_ENTITIES` nodes, confidence-sorted
/// so the caps drop the weakest leads first) to keep the working set sane on a
/// 4 GB device.  Best-effort: storage errors log and yield nothing rather than
/// failing the scan.
pub(super) fn recall_prior_entities(
    store: &dyn StoragePort,
    target: &Target,
    scan_id: &str,
) -> Vec<Entity> {
    const MAX_PRIOR_SCANS: usize = 8;
    const MAX_ENTITIES: usize = 300;
    const VALUE_MATCH_CAP: usize = 64;

    // Order/case/punctuation-insensitive token-set key (pure-digit tokens
    // dropped) so a FullName seed survives the reformatting name parsing
    // applies to the stored Person anchor — case ("jordan meyers" vs the
    // stored title-cased "Jordan Meyers"), comma order ("Meyers, Jordan"),
    // and a trailing year ("Jordan Meyers 1987" → "Jordan Meyers"). Exact
    // equality on the sorted alphabetic tokens stays conservative: it never
    // conflates "John Smith" with "John A Smith" or a different name.
    fn token_set_key(s: &str) -> String {
        let lower = s.to_lowercase();
        let mut toks: Vec<&str> = lower
            .split(|c: char| !c.is_alphanumeric())
            .filter(|t| !t.is_empty() && !t.bytes().all(|b| b.is_ascii_digit()))
            .collect();
        toks.sort_unstable();
        toks.join(" ")
    }

    // Gather candidate scan-id lists from both recall paths, then flatten
    // into a recency-ordered, de-duplicated list (excluding this scan).
    let kind = target.kind.to_entity_kind();
    let seed_uid = derive_uid(&kind, &normalise(&kind, &target.value));
    let mut id_lists: Vec<Vec<String>> = Vec::new();
    match store.scan_ids_for_entity(&seed_uid) {
        Ok(ids) => id_lists.push(ids),
        Err(e) => warn!(scan_id, error = %e, "recall: seed history lookup failed"),
    }
    // Value-match fallback — catches scans where the target surfaced as a
    // discovered node, and rescues the FullName seed whose stored anchor was
    // reformatted (the seed_uid above derives from the raw, un-title-cased
    // input, so it misses for names). A Person seed matches on the token-set
    // key; exact-valued kinds keep strict case-insensitive equality (their
    // seed_uid path is already exact, and a looser key could mis-pull a
    // structurally-different value, e.g. reorder an email's tokens).
    let is_name = matches!(kind, EntityKind::Person);
    let key = |v: &str| -> String {
        if is_name {
            token_set_key(v)
        } else {
            v.trim().to_lowercase()
        }
    };
    let target_key = key(&target.value);
    // Search the digit-stripped token form for a name so a trailing year
    // can't defeat the all-tokens-required FTS match; the raw value otherwise.
    let search_q = if is_name {
        token_set_key(&target.value)
    } else {
        target.value.trim().to_string()
    };
    if !target_key.is_empty()
        && !search_q.is_empty()
        && let Ok(matches) = store.search_entities(&search_q, VALUE_MATCH_CAP)
    {
        for m in matches {
            if key(&m.value) == target_key
                && let Ok(ids) = store.scan_ids_for_entity(&m.uid)
            {
                id_lists.push(ids);
            }
        }
    }
    let mut prior: Vec<String> = Vec::new();
    let mut seen_scan: HashSet<String> = HashSet::new();
    for id in id_lists.into_iter().flatten() {
        if id != scan_id && seen_scan.insert(id.clone()) {
            prior.push(id);
        }
    }
    if prior.is_empty() {
        return Vec::new();
    }

    // Pull each relevant prior scan's entity graph, dedup-merging across
    // scans, then stamp/tag every node for this scan. `entities_filtered`
    // (not `entities_for_scan`) bounds the pull: it applies a SQL `LIMIT` on
    // the confidence-DESC preorder and skips the Rust relevance re-sort —
    // both wasted here, since recall confidence-sorts and caps the merged
    // set anyway. So a heavily-scanned prior target can't make scan start
    // deserialise its entire historical graph on a 4 GB device.
    let mut merged: HashMap<String, Entity> = HashMap::new();
    for pid in prior.into_iter().take(MAX_PRIOR_SCANS) {
        let ents = match store.entities_filtered(&pid, None, None, None) {
            Ok(e) => e,
            Err(e) => {
                warn!(scan_id, prior = %pid, error = %e, "recall: prior entities load failed");
                continue;
            }
        };
        for mut e in ents {
            e.scan_id = scan_id.to_string();
            e.tag(tags::RECALLED);
            e.add_evidence(Evidence::new(
                "recall",
                "Recalled from the local intelligence database (prior scan)",
            ));
            if let Some(existing) = merged.get_mut(&e.uid) {
                existing.merge(e);
            } else {
                merged.insert(e.uid.clone(), e);
            }
        }
    }

    let mut out: Vec<Entity> = merged.into_values().collect();
    // A recalled node contributes ZERO corroboration. Recall re-injects
    // STORED data the database already counts, so re-persisting it must be
    // idempotent: with corroboration 0 the GREATEST-merge keeps the DB's
    // true count (`absorb` sums then floors at 1) instead of compounding it
    // every re-scan. A live module that re-discovers the entity this scan
    // still adds its own +1 on top. Applied AFTER the cross-scan dedup merge
    // above (which would otherwise floor a duplicate back up to 1).
    for e in &mut out {
        e.corroboration = 0;
    }
    out.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    out.truncate(MAX_ENTITIES);
    out
}
