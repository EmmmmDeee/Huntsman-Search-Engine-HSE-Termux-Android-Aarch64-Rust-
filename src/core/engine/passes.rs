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
use crate::core::relation::Relation;

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
pub(super) fn consolidate_address_localities(entities: &mut Vec<Entity>) -> Vec<(String, String)> {
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
        return Vec::new();
    }
    // (victim_uid, survivor_uid) for each fold — the caller detaches the victim's
    // per-scan observation row (the fold only removes it from THIS Vec; the
    // checkpoint path already made it a durable observation) and re-points any
    // lineage edge that named a victim at its survivor.
    let folded: Vec<(String, String)> = folds
        .iter()
        .map(|(s, v)| (v.uid.clone(), entities[*s].uid.clone()))
        .collect();
    for (survivor, victim) in folds {
        entities[survivor].absorb(victim);
    }
    let mut idx = 0;
    entities.retain(|_| {
        let keep = !remove[idx];
        idx += 1;
        keep
    });
    folded
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
            crate::core::entity::GEO_CORROBORATION_SOURCE,
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

/// Tight radius (km) within which a same-name breach candidate's locality is
/// taken to CONFIRM it is the subject — not a distant namesake. Deliberately far
/// tighter than [`crate::core::geo_family::FAMILY_GEO_KM`] (a relative *somewhere*
/// in the region): a breach/stealer row keyed on the subject's name that resolves
/// to the SAME locality/metro as the subject's independently-confirmed location is
/// almost certainly the subject's own record, so 25 km (one metropolitan area)
/// keeps the re-promotion conservative.
const BREACH_GEO_KM: f64 = 25.0;

/// Re-promote a geo-corroborated **breach candidate** — the people-centric
/// "return to old data when downstream adds credibility" pass.
///
/// A name search returns breach/stealer rows for EVERY same-name person, so each
/// is quarantined as a `candidate` (it might be a namesake, not the subject). When
/// a later round independently confirms the subject's own location (a name-matched
/// register address or a GPS fix — [`crate::core::geo_family::subject_locations`]), a same-name breach
/// candidate whose own locality resolves to within [`BREACH_GEO_KM`] of that fix
/// is no longer ambiguous: the same name AND the same place is the subject. This
/// lifts it out of quarantine (drops `candidate`, raises confidence to Probable,
/// stamps `breach-corroborated` + a geo-corroboration evidence record) so its
/// identifiers (the leaked email/phone/address) enter correlation, expansion and
/// the graded views instead of staying a hidden candidate.
///
/// Conservative and non-circular by construction: the subject anchor comes ONLY
/// from confirmed (non-candidate) locations, the radius is one metro, and
/// `family-candidate` rows are left to [`promote_geo_corroborated_family`] /
/// AU-061. Free, offline, idempotent (the `breach-corroborated` tag guards
/// re-runs). Returns the number promoted.
pub(super) fn promote_breach_candidate_geo_corroborated(entities: &mut [Entity]) -> usize {
    use crate::core::entity::Evidence;
    use crate::core::geo_family::{distance_to_subject, subject_locations};

    let subject = subject_locations(entities);
    if subject.is_empty() {
        return 0; // no confirmed subject location → nothing to corroborate against
    }
    let mut promoted = 0usize;
    for e in entities.iter_mut() {
        // Only un-promoted BREACH candidates; family-candidates are AU-061's job.
        if !e.has_tag(crate::core::tags::CANDIDATE)
            || e.has_tag("breach-corroborated")
            || e.has_tag("family-candidate")
            || !e.has_tag("breach")
        {
            continue;
        }
        let Some(km) = distance_to_subject(e, &subject) else {
            continue; // its locality doesn't resolve offline → cannot corroborate
        };
        if km > BREACH_GEO_KM {
            continue; // a different metro → still a possible namesake, stay quarantined
        }
        // Same name AND same place: resolve the namesake doubt. Un-quarantine and
        // lift to Probable so the record's identifiers become first-class findings.
        e.tags.retain(|t| t != crate::core::tags::CANDIDATE);
        e.tag("breach-corroborated");
        e.confidence = e.confidence.max(0.50);
        e.add_evidence(Evidence::new(
            crate::core::entity::GEO_CORROBORATION_SOURCE,
            format!(
                "Same-name breach record ~{km:.0} km from the subject's confirmed location \
                 (within {BREACH_GEO_KM:.0} km) — same name AND same locality confirm this is the \
                 subject's own record, not a namesake"
            ),
        ));
        promoted += 1;
    }
    if promoted > 0 {
        info!(
            promoted,
            "breach candidates geo-corroborated to the subject and re-promoted (free, offline)"
        );
    }
    promoted
}

/// Promote multi-pathway-corroborated identities (free, offline, per scan).
///
/// AU-062 proves which identity entities are joined by **≥2 edge-disjoint
/// pathways spanning ≥2 orthogonal source families** — a connection re-derivable
/// down several independent routes, robust to any single source going dark. This
/// pass feeds that proof back into the entities themselves: each endpoint of such
/// a link earns a `multipath-corroborated` tag and a `multipath_corroboration`
/// evidence record, lifting its corroboration → `c_effective` → classification
/// band so the scan's OUTPUT reflects what its own correlation established — a
/// confirmed connection measurably strengthens the entities it connects.
///
/// Built on the SAME [`crate::core::correlator::multipath_corroborated_links`]
/// detector the AU-062 rule uses, so the rule and the boost can never disagree
/// (one finder, no drift). The boost lifts only the two identity ENDPOINTS of
/// each link, never the intermediates (a conduit domain is not itself
/// corroborated). The `multipath_corroboration` source classifies as the
/// unscored `"other"` family, so it never feeds back to inflate AU-062's own
/// orthogonality count on a later recall. Free, offline, idempotent — the tag
/// guard means re-running, or a recall on a later scan, never double-stamps.
/// Returns the number promoted.
pub(super) fn promote_multipath_corroborated(
    entities: &mut [Entity],
    relations: &[Relation],
) -> usize {
    use crate::core::correlator::{RuleContext, multipath_corroborated_links};
    use crate::core::entity::Evidence;

    // Resolve the corroborated endpoints (and the reason for each) up front, so
    // the immutable borrow the detector takes on `entities` is released before
    // the mutable promotion walk below.
    let context = RuleContext::new(entities);
    let links = multipath_corroborated_links(&context, relations);
    if links.is_empty() {
        return 0;
    }
    let mut reason_by_uid: HashMap<String, String> = HashMap::new();
    for link in &links {
        let reason = format!(
            "Linked across {} independent pathway{} spanning {} orthogonal source famil{} [{}] \
             — the connection is corroborated by multiple routes, not a single chain",
            link.pathways,
            if link.pathways == 1 { "" } else { "s" },
            link.families.len(),
            if link.families.len() == 1 { "y" } else { "ies" },
            link.families.join(", "),
        );
        // First reason wins for a hub endpoint shared by several links — one
        // evidence record per entity is enough; the tag carries the signal.
        reason_by_uid
            .entry(link.a_uid.clone())
            .or_insert_with(|| reason.clone());
        reason_by_uid.entry(link.b_uid.clone()).or_insert(reason);
    }

    let mut promoted = 0usize;
    for e in entities.iter_mut() {
        if e.has_tag("multipath-corroborated") {
            continue;
        }
        if let Some(reason) = reason_by_uid.get(&e.uid) {
            e.tag("multipath-corroborated");
            e.add_evidence(Evidence::new(
                crate::core::entity::MULTIPATH_CORROBORATION_SOURCE,
                reason.clone(),
            ));
            promoted += 1;
        }
    }
    if promoted > 0 {
        info!(
            promoted,
            "multi-pathway-corroborated identities promoted (free, offline — confirmed links strengthen the scan)"
        );
    }
    promoted
}

/// Promote cross-scan-corroborated identities (free, offline, per scan).
///
/// The cross-scan counterpart to [`promote_multipath_corroborated`]. A *fragile*
/// single-pathway identity link (the AU-063 gap) is corroborated not by a second
/// in-scan route but by the engine's accumulated cross-scan knowledge: when the
/// link's own route SHAPE has been independently confirmed in prior scans, the
/// attribution METHOD is proven, and that historical proof is the orthogonal
/// pathway that fills the gap (the engine-emitted AU-066 finding). Each listed
/// endpoint earns a `cross-scan-corroborated` tag and a `cross_scan_corroboration`
/// evidence record, lifting its corroboration → `c_effective` → classification
/// band so the scan's OUTPUT reflects the accumulated knowledge.
///
/// Conservative by design: the engine gates the `boost` set on a route proven in
/// **≥2 prior scans** (stricter than the AU-065 finding's ≥1), and the evidence
/// source classifies as the unscored `"other"` family, so it never feeds back to
/// inflate the in-scan orthogonality measure. Free, offline, idempotent via the
/// tag. `boost` maps each endpoint UID to its human reason; returns the number
/// promoted.
pub(super) fn promote_cross_scan_corroborated(
    entities: &mut [Entity],
    boost: &HashMap<String, String>,
) -> usize {
    use crate::core::entity::Evidence;

    if boost.is_empty() {
        return 0;
    }
    let mut promoted = 0usize;
    for e in entities.iter_mut() {
        if e.has_tag("cross-scan-corroborated") {
            continue;
        }
        if let Some(reason) = boost.get(&e.uid) {
            e.tag("cross-scan-corroborated");
            e.add_evidence(Evidence::new(
                crate::core::entity::CROSS_SCAN_CORROBORATION_SOURCE,
                reason.clone(),
            ));
            promoted += 1;
        }
    }
    if promoted > 0 {
        info!(
            promoted,
            "cross-scan-corroborated identities promoted (free, offline — accumulated route knowledge fills the gap)"
        );
    }
    promoted
}

/// Flag geo-discordant namesakes (free, offline, per scan).
///
/// The negative complement of [`promote_geo_corroborated_family`]: when the scan
/// has a confirmed subject location, a `family-candidate` whose locality resolves
/// BEYOND [`crate::core::geo_family::NAMESAKE_GEO_KM`] from the subject shares the
/// surname but not the region — *and* the shared surname is COMMON. Both must hold:
/// a far bearer of a DISTINCTIVE surname (a rare-surname subject's interstate kin)
/// is far more likely a relative who moved than a coincidental stranger, so it is
/// never flagged ([`crate::core::geo_family::is_namesake`]). A flagged entity earns
/// a `geo-discordant` tag so the Leads ranking de-prioritises it (with a plain
/// "different region — possible namesake" reason) and the analyst can tell the real
/// local family from interstate look-alikes.
///
/// Crucially this adds ONLY a tag — never an evidence record and never a
/// confidence change. A discord is a *negative* signal; attaching it as evidence
/// would (like any new source) inflate [`Entity::source_count`] and PROMOTE the
/// very namesake it means to demote, and a far relative could still be genuine, so
/// the entity is re-ordered, never down-graded or deleted. Free, offline,
/// idempotent. The shared detector lives in [`crate::core::geo_family`]. Returns
/// the number flagged.
pub(super) fn flag_geo_discordant_namesakes(entities: &mut [Entity]) -> usize {
    use crate::core::geo_family::{is_namesake, subject_locations};

    let subject = subject_locations(entities);
    if subject.is_empty() {
        return 0;
    }
    // The family surname every `family-candidate` shares — the subject's. Resolved
    // once; its commonness gates the whole pass (a rare surname → no namesakes).
    let subject_surname_common = crate::core::geo_family::subject_surname(entities)
        .map(|s| crate::util::surnames::is_common(&s));

    let mut flagged = 0usize;
    for e in entities.iter_mut() {
        if e.has_tag("geo-discordant") {
            continue;
        }
        // Prefer the scan-wide subject surname; fall back to the candidate's own
        // name (a Person carries it; a bare Address can't be judged without a
        // subject, so it stays unflagged — conservative).
        let common = subject_surname_common.unwrap_or_else(|| {
            crate::util::surnames::surname_of(&e.value)
                .is_some_and(|s| crate::util::surnames::is_common(&s))
        });
        if !is_namesake(e, &subject, common) {
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
