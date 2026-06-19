//! Engine helper passes invoked around dispatch.
//!
//! Two cross-cutting passes split out of `mod.rs` so the file reads as the
//! scan-loop orchestration: the post-scan address-locality consolidation
//! (run once at finalise) and the API-key hot-inject cascade (run per round
//! and per module by the dispatchers). `pub(super)` + a re-export in `mod.rs`
//! keeps `super::hot_inject_keys` valid for the `dispatch` sibling.

use std::collections::HashMap;

use tracing::info;

use crate::core::entity::{Entity, EntityKind};

/// Collapse `Address` entities that denote the **same locality** — differing
/// only by a trailing postcode, case or punctuation — into a single entity,
/// keeping the most specific spelling and folding the rest's evidence and
/// corroboration into it.
///
/// Why at finalise, not in a module: the engine's per-entity UID merge keys on
/// the exact normalised value, so `"Murrumbateman, NSW"` and `"Murrumbateman,
/// NSW 2582"` hash to different UIDs and survive as two Address entities for one
/// place — inflating the location count in the geo correlations (a live scan
/// showed AU-018 reporting a subject co-located with "2" addresses for one
/// suburb). Running here, after every module (API sources included) and every
/// expansion round has folded into `entities`, makes this the codebase-wide,
/// recursion-spanning backstop to the per-module dedup in `search_engines`.
///
/// The survivor is the longest value in the locality group (the postcode-bearing
/// form), with a lexicographic tie-break for determinism; only addresses sharing
/// a [`crate::util::address_au::locality_key`] are merged, so a street address is
/// never folded into a bare suburb.
pub(super) fn consolidate_address_localities(entities: &mut Vec<Entity>) {
    let mut groups: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, e) in entities.iter().enumerate() {
        if e.kind == EntityKind::Address {
            let key = crate::util::address_au::locality_key(&e.value);
            if !key.is_empty() {
                groups.entry(key).or_default().push(i);
            }
        }
    }

    let mut remove = vec![false; entities.len()];
    let mut folds: Vec<(usize, Entity)> = Vec::new();
    for idxs in groups.values() {
        if idxs.len() < 2 {
            continue;
        }
        // Most specific = longest value; tie → lexicographically smallest, so
        // the survivor is independent of discovery order (Determinism).
        let survivor = *idxs
            .iter()
            .max_by(|&&a, &&b| {
                entities[a]
                    .value
                    .len()
                    .cmp(&entities[b].value.len())
                    .then_with(|| entities[b].value.cmp(&entities[a].value))
            })
            .expect("group is non-empty");
        for &victim in idxs {
            if victim != survivor {
                folds.push((survivor, entities[victim].clone()));
                remove[victim] = true;
            }
        }
    }
    if folds.is_empty() {
        return;
    }
    for (survivor, victim) in folds {
        entities[survivor].absorb(victim);
    }
    let mut idx = 0;
    entities.retain(|_| {
        let keep = !remove[idx];
        idx += 1;
        keep
    });
}

/// Promote geo-corroborated family (free, offline, per scan).
///
/// When the scan has a confirmed subject location, a `family-candidate` (shared
/// surname, from the AU registers / residential directories) whose postcode
/// resolves into the subject's area is confirmed by a SECOND, INDEPENDENT free
/// signal — the subject's own GPS fix. It earns a `geo_corroboration` evidence
/// record and a `geo-corroborated` tag, lifting it from a lone register candidate
/// to a reliable relative: the agreement of two independent signals is genuine
/// corroboration (unlike the `recall` / `geo_normalize` self-passes that are
/// explicitly excluded from the count). Free, offline, idempotent — re-running, or
/// a recall on a later scan, never double-stamps. The shared detector lives in
/// [`crate::core::geo_family`] (the correlator's AU-061 surfaces the same finding).
/// Returns the number promoted.
pub(super) fn promote_geo_corroborated_family(entities: &mut [Entity]) -> usize {
    use crate::core::entity::Evidence;
    use crate::core::geo_family::{
        distance_to_subject, is_geo_corroborated_family, subject_locations,
    };

    let subject = subject_locations(entities);
    if subject.is_empty() {
        return 0;
    }
    let mut promoted = 0usize;
    for e in entities.iter_mut() {
        if e.has_tag("geo-corroborated") || !is_geo_corroborated_family(e, &subject) {
            continue;
        }
        let km = distance_to_subject(e, &subject).unwrap_or_default();
        e.tag("geo-corroborated");
        e.add_evidence(Evidence::new(
            "geo_corroboration",
            format!(
                "Shared-surname relative ~{km:.0} km from the subject's confirmed location — \
                 geo and surname independently corroborate the relationship"
            ),
        ));
        promoted += 1;
    }
    if promoted > 0 {
        info!(
            promoted,
            "geo-corroborated family promoted to reliable (free, offline, cross-angle)"
        );
    }
    promoted
}

/// Flag geo-discordant namesakes (free, offline, per scan).
///
/// The negative complement of [`promote_geo_corroborated_family`]: when the scan
/// has a confirmed subject location, a `family-candidate` whose locality resolves
/// BEYOND [`crate::core::geo_family::NAMESAKE_GEO_KM`] from the subject shares only
/// the surname, not the region — more likely a coincidental namesake than a
/// household relative. It earns a `geo-discordant` tag so the Leads ranking
/// de-prioritises it (with a plain "different region — possible namesake" reason)
/// and the analyst can tell the real local family from interstate look-alikes.
///
/// Crucially this adds ONLY a tag — never an evidence record and never a
/// confidence change. A discord is a *negative* signal; attaching it as evidence
/// would (like any new source) inflate [`Entity::source_count`] and PROMOTE the
/// very namesake it means to demote, and a far relative could still be genuine, so
/// the entity is re-ordered, never down-graded or deleted. Free, offline,
/// idempotent. The shared detector lives in [`crate::core::geo_family`]. Returns
/// the number flagged.
pub(super) fn flag_geo_discordant_namesakes(entities: &mut [Entity]) -> usize {
    use crate::core::geo_family::{is_geo_discordant_namesake, subject_locations};

    let subject = subject_locations(entities);
    if subject.is_empty() {
        return 0;
    }
    let mut flagged = 0usize;
    for e in entities.iter_mut() {
        if e.has_tag("geo-discordant") || !is_geo_discordant_namesake(e, &subject) {
            continue;
        }
        e.tag("geo-discordant");
        flagged += 1;
    }
    if flagged > 0 {
        info!(
            flagged,
            "geo-discordant namesakes flagged (free, offline — sharpens family precision)"
        );
    }
    flagged
}

/// Pull any newly-available pooled API key into `keys` for every service that
/// doesn't already have one. This is the key-cascade that makes recursion pay
/// off: a key a module just discovered (oathnet breach data, api_key_probe
/// validation, web_crawler scraping) becomes usable by the next module in the
/// round and by the next expansion round. Idempotent — only fills gaps, never
/// overwrites an operator-supplied key. Shared by `run_expansion` (per-round
/// refresh) and both dispatchers (per-module hot-inject).
pub(super) fn hot_inject_keys(keys: &mut HashMap<String, String>) {
    let pool = crate::util::key_pool::global_pool();
    for svc in crate::util::key_pool::service_defs() {
        if keys.contains_key(svc.env_var) {
            continue;
        }
        if let Some(key) = pool.next_key(svc.name) {
            let roi = crate::util::key_roi::classify(svc.name);
            info!(
                service = svc.name,
                env_var = svc.env_var,
                roi = roi.label(),
                "hot-inject: pooled key available ({} tier)",
                roi.label()
            );
            keys.insert(svc.env_var.to_string(), key);
        }
    }
}
