//! Self-contained sub-passes of `ScanEngine::finalise_scan`, split out so the
//! parent function reads as a sequence of named steps rather than one long
//! block. Each function here still does real storage/event I/O (finalise is
//! inherently a persistence pass) — the win is naming and isolating a
//! cohesive concern, not purity.

use std::collections::{HashMap, HashSet};

use tracing::info;

use crate::core::entity::unix_now;
use crate::core::event::EventKind;
use crate::core::port::StoragePort;

use super::EventEmitter;
use super::expansion::correlation_key;

/// Cross-scan pathway-template learning (C1 universal linking).
///
/// Generalises this scan's confirmed connections into direction-canonical
/// routes: a route a *prior* scan already proved is credited here as
/// historically corroborated (**AU-065** — storage-dependent, so it can't be
/// a pure correlator rule), and a *fragile* single-pathway link (the AU-063
/// gap) whose route shape is proven in ≥2 prior scans is the **AU-066**
/// finding — accumulated cross-scan knowledge is the orthogonal pathway that
/// fills the gap. Every route this scan itself produced is recorded via
/// [`StoragePort::record_pathway_template`], so a link learned once lifts
/// every later scan.
///
/// Returns the AU-066 boost map (identity uid → the reason a boost applies),
/// for the caller to feed into `promote_cross_scan_corroborated`. Best-effort
/// throughout: a storage hiccup degrades to "no cross-scan credit this
/// pass," never aborts the finalised scan — mirrors every other finalise
/// sub-step's error-handling contract.
pub(super) fn apply_cross_scan_pathway_learning(
    store: &dyn StoragePort,
    emitter: &EventEmitter,
    scan_id: &str,
    emitted_corr: &mut HashSet<String>,
) -> HashMap<String, String> {
    let mut xscan_boost: HashMap<String, String> = HashMap::new();
    let Ok(ents) = store.entities_for_scan(scan_id) else {
        return xscan_boost;
    };
    let Ok(rels) = store.relations_for_scan(scan_id) else {
        return xscan_boost;
    };

    // The fragile single-route identity pairs (a<b) — exactly AU-063's notion
    // of an uncorroborated link, via the shared detector so the gap the lead
    // flags is the gap this pass fills.
    let fragile: HashSet<(String, String)> =
        crate::core::correlator::single_route_identity_links(&ents, &rels)
            .into_iter()
            .map(|l| (l.a_uid, l.b_uid))
            .collect();

    for ct in crate::core::relation::connection_templates(&ents, &rels, 4) {
        let prior = store.pathway_template_count(&ct.template).unwrap_or(0);
        if prior >= 1 {
            emit_au065(store, emitter, scan_id, emitted_corr, &ct, prior);
        }
        // AU-066 — cross-scan route fills a single-pathway gap. A fragile link
        // whose route shape is proven in ≥2 PRIOR scans (stricter than
        // AU-065's ≥1, to keep the gap-fill conservative) is corroborated by
        // the proven attribution method itself: the accumulated cross-scan
        // pathway is the orthogonal route the AU-063 gap was missing. Its
        // endpoints are queued for the boost.
        if prior >= 2 {
            emit_au066_and_queue_boost(
                store,
                emitter,
                scan_id,
                emitted_corr,
                &ct,
                prior,
                &fragile,
                &mut xscan_boost,
            );
        }
        let _ = store.record_pathway_template(&ct.template);
    }
    xscan_boost
}

/// AU-065: this route was already proven in ≥1 prior scan — emit the
/// cross-scan-corroborated-route correlation once (deduped via
/// `emitted_corr`, exactly like every other correlation this scan streams).
fn emit_au065(
    store: &dyn StoragePort,
    emitter: &EventEmitter,
    scan_id: &str,
    emitted_corr: &mut HashSet<String>,
    ct: &crate::core::relation::ConnectionTemplate,
    prior: u32,
) {
    let mut uids: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for (f, t) in &ct.pairs {
        uids.insert(f.clone());
        uids.insert(t.clone());
    }
    let c = crate::core::correlator::Correlation::new(
        "AU-065",
        "Cross-scan corroborated route",
        crate::core::correlator::Severity::Medium,
        format!(
            "the route [{}] connecting {} identity pair(s) here was confirmed in \
             {} prior scan(s) — a historically proven attribution pattern, not a one-off",
            ct.template,
            ct.pairs.len(),
            prior,
        ),
        uids.into_iter().collect::<Vec<_>>(),
        scan_id,
        unix_now(),
    );
    if store.upsert_correlation(&c).is_ok() && emitted_corr.insert(correlation_key(&c)) {
        emitter.emit(scan_id, EventKind::CorrelationFound { correlation: c });
    }
}

/// AU-066: a fragile (single-route) link's route shape was independently
/// proven in ≥2 prior scans — emit the gap-fill correlation for each such
/// pair and queue its two endpoints in `xscan_boost` for the caller's
/// conservative corroboration boost.
#[allow(clippy::too_many_arguments)]
fn emit_au066_and_queue_boost(
    store: &dyn StoragePort,
    emitter: &EventEmitter,
    scan_id: &str,
    emitted_corr: &mut HashSet<String>,
    ct: &crate::core::relation::ConnectionTemplate,
    prior: u32,
    fragile: &HashSet<(String, String)>,
    xscan_boost: &mut HashMap<String, String>,
) {
    for (f, t) in &ct.pairs {
        if !fragile.contains(&(f.clone(), t.clone())) {
            continue; // only fragile (single-route) links are gaps to fill
        }
        let reason = format!(
            "the single-pathway link's route shape [{}] was independently confirmed in \
             {prior} prior scans — the proven attribution method is the orthogonal \
             pathway that fills the single-route gap",
            ct.template,
        );
        let c = crate::core::correlator::Correlation::new(
            "AU-066",
            "Cross-scan route fills single-pathway gap",
            crate::core::correlator::Severity::Medium,
            reason.clone(),
            vec![f.clone(), t.clone()],
            scan_id,
            unix_now(),
        );
        if store.upsert_correlation(&c).is_ok() && emitted_corr.insert(correlation_key(&c)) {
            emitter.emit(scan_id, EventKind::CorrelationFound { correlation: c });
        }
        xscan_boost
            .entry(f.clone())
            .or_insert_with(|| reason.clone());
        xscan_boost.entry(t.clone()).or_insert(reason);
    }
}

/// Corroboration boosts: confirmed links strengthen the entities.
///
/// Two orthogonal corroboration signals feed back into the entity set so the
/// scan's OUTPUT reflects what its own analysis established:
///   * multipath (C2): a link AU-062 proved via ≥2 edge-disjoint,
///     source-orthogonal IN-SCAN routes — robust to any one source going dark
///     (built on the SAME detector the rule uses).
///   * cross-scan (AU-066): a fragile single-route link whose route shape is
///     proven in ≥2 PRIOR scans — accumulated knowledge fills the gap (see
///     [`apply_cross_scan_pathway_learning`], whose `xscan_boost` output this
///     consumes).
///
/// Both tag + evidence-stamp only the identity ENDPOINTS, are idempotent via
/// their tags, and use unscored ("other") evidence sources so they never feed
/// back to inflate the in-scan orthogonality measure. Best-effort and
/// conditional: the single re-persist runs only when a boost actually fires
/// and never aborts a finalised scan.
pub(super) fn apply_corroboration_boosts(
    store: &dyn StoragePort,
    scan_id: &str,
    entities: &mut [crate::core::entity::Entity],
    xscan_boost: &HashMap<String, String>,
) {
    let mut boosted_any = false;
    if let Ok(rels) = store.relations_for_scan(scan_id) {
        boosted_any |= super::passes::promote_multipath_corroborated(entities, &rels) > 0;
    }
    boosted_any |= super::passes::promote_cross_scan_corroborated(entities, xscan_boost) > 0;
    if !boosted_any {
        return;
    }
    let boosted: Vec<crate::core::entity::Entity> = entities
        .iter_mut()
        .filter(|e| e.has_tag("multipath-corroborated") || e.has_tag("cross-scan-corroborated"))
        .map(|e| {
            e.canonicalize_order();
            e.clone()
        })
        .collect();
    match store.upsert_entities_batch(&boosted) {
        Ok(n) => info!(
            scan_id,
            boosted = n,
            "corroboration-boosted identities re-persisted (confirmed links strengthened the scan)"
        ),
        Err(e) => tracing::warn!(
            scan_id,
            error = %e,
            "corroboration boost re-persist failed (non-fatal)"
        ),
    }
}
