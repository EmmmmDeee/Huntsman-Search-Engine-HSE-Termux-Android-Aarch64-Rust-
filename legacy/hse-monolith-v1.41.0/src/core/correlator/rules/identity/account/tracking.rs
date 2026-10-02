//! Tracking-signal rules — shared tracking ids and recurring co-occurrence links.
//! Split from `account.rs`; rules re-exported by `super`.

use super::super::*;

/// AU-044 — Shared web-analytics ID ⇒ common ownership. A Google Analytics /
/// AdSense / Tag-Manager / Facebook-Pixel id that appears on two or more
/// otherwise-unrelated sites is strong evidence the same operator runs them — the
/// "affiliate" pivot. `web_crawler` records the carrying site in each
/// `TrackingId` evidence entry's `source_domain`; entities merge by value, so a
/// shared id accumulates one evidence row per site. Fires when ≥2 distinct sites
/// carry the same id.
pub(in crate::core::correlator) fn rule_au_044_shared_tracking_id(
    context: &RuleContext,
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let entities = context.entities();
    entities
        .iter()
        .filter(|e| e.kind == EntityKind::TrackingId)
        .filter_map(|e| {
            let mut sites: Vec<&str> = e
                .evidence
                .iter()
                .filter_map(|ev| ev.attributes.get("source_domain").map(String::as_str))
                .collect();
            sites.sort_unstable();
            sites.dedup();
            if sites.len() < 2 {
                return None;
            }
            Some(Correlation::new(
                "AU-044",
                "Shared web-analytics ID (common ownership)",
                Severity::High,
                format!(
                    "Tracking id '{}' appears on {} sites ({}) — a shared analytics/ads id \
                     indicates the sites share an owner or operator",
                    e.value,
                    sites.len(),
                    sites.join(", ")
                ),
                vec![e.uid.clone()],
                scan_id,
                ts,
            ))
        })
        .collect()
}

/// AU-080 — Recurring co-occurrence identity association.
///
/// The cross-scan history pass tags entities that have appeared together in
/// prior investigations with `cross-scan-cooccurrence` and records the
/// partner's value in the evidence summary.  When both endpoints of a
/// historical co-occurrence appear in the current scan, the recurring
/// pairing is surfaced as an explicit correlation: two identifiers that
/// co-occur across multiple independent investigations are almost certainly
/// linked to the same subject.
///
/// Severity scales with frequency:
///   * High when either endpoint carries `hub-cooccurrence` (≥ 3 prior
///     scans) — a structurally significant, high-frequency association.
///   * Medium for pairs seen in fewer than 3 prior scans (a recurring
///     association, but not yet elevated to hub status).
///
/// Evidence is provenance-only (non-corroborating by design); this rule
/// surfaces the association as a visible finding without inflating C_eff.
pub(in crate::core::correlator) fn rule_au_080_recurring_cooccurrence_link(
    context: &RuleContext,
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let entities = context.entities();
    // The co-occurrence evidence summary prefix written by the history pass.
    const COOCCURRENCE_PREFIX: &str = "Co-occurred with `";

    // Index entities by value for O(1) lookup of co-occurrence partners.
    let entity_by_value: HashMap<&str, &Entity> =
        entities.iter().map(|e| (e.value.as_str(), e)).collect();

    // A recurring co-occurrence is only signal between entities that are
    // themselves corroborated. A name's GENERATED permutations — variant handles
    // and speculative mailboxes minted identically on every scan — "co-occur
    // across investigations" purely by construction, not by any real-world
    // association, and an unbounded pass over them is the single largest source
    // of correlation noise (a live 57-entity scan emitted ~100 of these). Gate
    // both endpoints on a confidence floor, then rank what survives and bound the
    // O(pairs) tail below so the few hub-level pairings that are the actual
    // signal are not buried.
    const MIN_CONF: f64 = crate::core::relation::IDENTITY_LINK_MIN_CONF;
    const MAX_PAIRS: usize = 12;
    // Distinct entities named in the rolled-up tail edge — bounded so the summary
    // cannot itself become a giant hyperedge.
    const ROLLUP_UID_CAP: usize = 25;
    // (is_hub, shared_scans, correlation), kept together so the tail can be
    // ranked strongest-first before it is bounded.
    let mut ranked: Vec<(bool, usize, Correlation)> = Vec::new();
    // Deduplicate pairs (order-independent) so A→B and B→A don't both fire.
    let mut seen: HashSet<[String; 2]> = HashSet::new();

    for entity in entities
        .iter()
        .filter(|e| e.has_tag("cross-scan-cooccurrence") && e.confidence >= MIN_CONF)
    {
        for ev in &entity.evidence {
            // Only parse cross-scan-history co-occurrence records.
            if ev.source != "cross_scan_history" {
                continue;
            }
            let Some(after_prefix) = ev.summary.strip_prefix(COOCCURRENCE_PREFIX) else {
                continue;
            };
            // Partner value is wrapped in backticks: `{value}` across ...
            let Some(backtick_end) = after_prefix.find('`') else {
                continue;
            };
            let partner_value = &after_prefix[..backtick_end];
            let Some(&partner_e) = entity_by_value.get(partner_value) else {
                continue;
            };
            // The partner must clear the same floor: a corroborated endpoint
            // recurring with a bare generated candidate is still noise.
            if partner_e.confidence < MIN_CONF {
                continue;
            }

            // Deduplicate the pair (alphabetical order of UIDs).
            let mut pair = [entity.uid.clone(), partner_e.uid.clone()];
            pair.sort();
            if !seen.insert(pair) {
                continue;
            }

            // Parse shared scan count from "... across {n} earlier scan(s)..."
            let shared: usize = after_prefix[backtick_end + 1..]
                .trim_start()
                .strip_prefix("across ")
                .and_then(|s| s.split_whitespace().next())
                .and_then(|s| s.parse().ok())
                .unwrap_or(1);

            let is_hub =
                entity.has_tag("hub-cooccurrence") || partner_e.has_tag("hub-cooccurrence");
            let severity = if is_hub {
                Severity::High
            } else {
                Severity::Medium
            };

            let mut uids = vec![entity.uid.clone(), partner_e.uid.clone()];
            uids.sort_unstable();
            ranked.push((
                is_hub,
                shared,
                Correlation {
                    rule_id: "AU-080".into(),
                    rule_name: "Recurring co-occurrence identity association".into(),
                    severity,
                    description: format!(
                        "{} '{}' and {} '{}' have appeared together in {shared} prior \
                         investigation(s) — a recurring structural association in the local \
                         intelligence database that bridges cases{}",
                        entity.kind,
                        entity.value,
                        partner_e.kind,
                        partner_e.value,
                        if is_hub { " (hub-level frequency)" } else { "" },
                    ),
                    entity_uids: uids,
                    scan_id: scan_id.into(),
                    ts,
                    rank: 0.0,
                },
            ));
        }
    }

    // Strongest first: hub-level pairings, then higher prior-scan frequency,
    // with a deterministic uid tie-break so the kept set is stable across runs
    // (the store orders by uid and the dossier diffs on it).
    ranked.sort_by(|a, b| {
        b.0.cmp(&a.0)
            .then(b.1.cmp(&a.1))
            .then_with(|| a.2.entity_uids.cmp(&b.2.entity_uids))
    });

    if ranked.len() <= MAX_PAIRS {
        return ranked.into_iter().map(|(_, _, c)| c).collect();
    }

    // Bound the O(pairs) tail. The suppressed pairs are the low-frequency long
    // tail that buries the signal; roll them into ONE honest summary rather than
    // dropping them silently — each pair's co-occurrence evidence stays on the
    // entities themselves, so the underlying data is not lost, only de-duplicated
    // in the correlation view.
    let suppressed = ranked.len() - MAX_PAIRS;
    let mut out: Vec<Correlation> = ranked.drain(..MAX_PAIRS).map(|(_, _, c)| c).collect();
    let mut tail_uids: Vec<String> = ranked
        .into_iter()
        .flat_map(|(_, _, c)| c.entity_uids)
        .collect();
    tail_uids.sort_unstable();
    tail_uids.dedup();
    tail_uids.truncate(ROLLUP_UID_CAP);
    out.push(Correlation {
        rule_id: "AU-080".into(),
        rule_name: "Recurring co-occurrence identity association".into(),
        severity: Severity::Low,
        description: format!(
            "{suppressed} further recurring co-occurrence pair(s), below the top {MAX_PAIRS} by \
             frequency, were rolled up to reduce noise — each pairing's evidence remains on the \
             entities involved"
        ),
        entity_uids: tail_uids,
        scan_id: scan_id.into(),
        ts,
        rank: 0.0,
    });
    out
}
