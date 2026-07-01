//! Dossier renderer for `hse scan --output dossier`.
//!
//! Separated from the scan command loop so the render logic is independently
//! readable and testable.

use crate::core::{correlator::Correlation, entity::Entity, relation::Relation, scan::Scan};

/// Bundled args for [`print_dossier`] — a plain struct rather than 8 loose
/// parameters (`clippy::too_many_arguments`), mirroring the `DispatchCx`/
/// `DispatchState` precedent (`PROBLEM_TREE` T2.5) rather than an `#[allow]`.
pub(super) struct DossierArgs<'a> {
    pub(super) scan: &'a Scan,
    pub(super) entities: &'a [Entity],
    pub(super) correlations: &'a [Correlation],
    pub(super) relations: &'a [Relation],
    pub(super) kind: &'a str,
    pub(super) value: &'a str,
    pub(super) leverage: &'a [crate::core::engine::LeverageRanked],
    pub(super) store: &'a dyn crate::core::port::StoragePort,
}

pub(super) fn print_dossier(args: DossierArgs<'_>) {
    let DossierArgs {
        scan,
        entities,
        correlations,
        relations,
        kind,
        value,
        leverage,
        store,
    } = args;
    use std::collections::BTreeMap;

    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║  HUNTSMAN SEARCH ENGINE — INTELLIGENCE DOSSIER              ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();
    println!("  Target:    {kind} = {value}");
    println!("  Scan ID:   {}", &scan.id[..16]);
    println!("  Status:    {}", scan.status.as_str());
    println!("  Entities:  {}", scan.entity_count);
    println!(
        "  Modules:   {} run, {} errored, {} deduped",
        scan.modules_run, scan.modules_errored, scan.modules_deduped
    );

    // Exposure Index — the calibrated 0–100 headline (with its transparent
    // breakdown) an operator reads first, aggregated from the breach/sensitive-PII/
    // identifier/correlation signals already computed below.
    let exposure = crate::core::exposure::assess(entities, correlations);
    println!("  {}", exposure.summary_line());
    for c in &exposure.components {
        println!(
            "    · {:<22} {:>2}/{:<2}  {}",
            c.name, c.score, c.max, c.detail
        );
    }
    println!();

    // Cross-scan enrichment leverage — this scan's identifiers that also appear in
    // earlier investigations in the local intelligence base, ranked by how many
    // they bridge (data_retention_design §4.1). Only genuine bridges (degree ≥ 2)
    // are shown here; the complete ranking is in `--output json`. Absent on a
    // first-ever scan, where nothing bridges yet — that is correct, not a gap.
    let bridges: Vec<&crate::core::engine::LeverageRanked> = leverage
        .iter()
        .filter(|l| l.cross_scan_degree >= 2)
        .collect();
    if !bridges.is_empty() {
        println!("  Cross-scan leverage (identifiers bridging prior investigations):");
        for l in bridges.iter().take(8) {
            println!(
                "    · {} {} — bridges {} investigations",
                l.kind, l.value, l.cross_scan_degree
            );
        }
        println!();
    }

    let mut by_kind: BTreeMap<String, Vec<&Entity>> = BTreeMap::new();
    for e in entities {
        by_kind.entry(e.kind.to_string()).or_default().push(e);
    }

    let kind_order = [
        "person",
        "email",
        "phone",
        "username",
        "credential",
        "api_key",
        "password",
        "address",
        "coordinates",
        "organisation",
        "abn_acn",
        "asn",
        "domain",
        "ip_address",
        "url",
        "mac_address",
        "device_id",
    ];

    for kind_name in &kind_order {
        let Some(group) = by_kind.get(*kind_name) else {
            continue;
        };
        let header = match *kind_name {
            "person" => "PERSONS",
            "email" => "EMAIL ADDRESSES",
            "phone" => "PHONE NUMBERS",
            "username" => "USERNAMES / HANDLES",
            "credential" => "CREDENTIALS (from breach/stealer data)",
            "api_key" => "API KEYS (from breach/stealer data)",
            "password" => "PASSWORDS (from breach/stealer data)",
            "address" => "PHYSICAL ADDRESSES / LOCATIONS",
            "coordinates" => "GPS COORDINATES",
            "organisation" => "ORGANISATIONS",
            "abn_acn" => "ABN / ACN (Australian Business Numbers)",
            "domain" => "DOMAINS",
            "ip_address" => "IP ADDRESSES",
            "url" => "URLS / PROFILES",
            "mac_address" => "MAC ADDRESSES (network devices)",
            "device_id" => "DEVICE IDENTIFIERS",
            other => other,
        };

        println!("━━━ {} ({}) ━━━", header, group.len());
        println!();

        let mut sorted = group.clone();
        sorted.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        for e in &sorted {
            let c_eff = e.c_effective();
            let class = e.classify();
            println!(
                "  {} [{}]  conf={:.2}  c_eff={:.2}  corr={}",
                e.value, class, e.confidence, c_eff, e.corroboration
            );

            if !e.tags.is_empty() {
                println!("    tags: {}", e.tags.join(", "));
            }

            // Compact MITRE ATT&CK provenance: the inline `attack:<ID>` tags the
            // engine stamps onto every admitted entity, resolved to their
            // Reconnaissance technique names. Surfaces, per finding, exactly which
            // collection technique(s) produced it — the alignment lives in the
            // data, not a separate coverage report. (CLI may import core::attack.)
            let mitre: Vec<String> = e
                .tags
                .iter()
                .filter_map(|t| t.strip_prefix("attack:"))
                .map(|id| {
                    crate::core::attack::technique(id)
                        .map_or_else(|| id.to_string(), |t| format!("{} {}", t.id, t.name))
                })
                .collect();
            if !mitre.is_empty() {
                println!("    MITRE ATT&CK: {}", mitre.join("; "));
            }

            for ev in &e.evidence {
                println!(
                    "    ├─ {src} — {summary}",
                    src = ev.source,
                    summary = ev.summary
                );
                for (k, v) in &ev.attributes {
                    if !v.is_empty() {
                        println!("    │  {k}: {v}");
                    }
                }
            }
            println!();
        }
    }

    if !correlations.is_empty() {
        println!("━━━ CORRELATIONS ({}) ━━━", correlations.len());
        println!();
        for c in correlations {
            let sev = match c.severity.to_string().as_str() {
                "CRITICAL" => "🔴 CRITICAL",
                "HIGH" => "🟠 HIGH",
                "MEDIUM" => "🟡 MEDIUM",
                _ => "🔵 LOW",
            };
            println!("  {} [{}] {}", c.rule_id, sev, c.rule_name);
            println!("    {}", c.description);
            println!();
        }
    }

    if !relations.is_empty() {
        use std::collections::HashMap;
        let by_uid: HashMap<&str, &Entity> = entities.iter().map(|e| (e.uid.as_str(), e)).collect();
        let label = |uid: &str| -> String {
            by_uid.get(uid).map_or_else(
                || format!("{}…", &uid[..uid.len().min(8)]),
                |e| super::super::truncate(&e.value, 40),
            )
        };
        println!("━━━ RELATIONS ({}) ━━━", relations.len());
        println!();
        for r in relations {
            println!(
                "  {}  ──{}──▶  {}   (conf={:.2})",
                label(&r.from_uid),
                r.kind,
                label(&r.to_uid),
                r.confidence
            );
        }
        println!();
    }

    print_connections(entities, relations);
    print_resolved_identities(entities, relations);
    print_connection_brokers(entities, relations);

    print_diagnostics(scan, entities, kind, value, &scan.id, store);
}

/// CONNECTIONS — graph-free link analysis (PROBLEM_TREE C1, the
/// "Maltego-without-graphs" play). Renders the shortest typed *thread* tying
/// each discovered identity back through the graph — the analytic conclusion an
/// analyst would otherwise pivot a canvas to find. Reuses the very
/// [`crate::core::relation::identity_paths`] primitive AU-060 fires on, so the
/// rendered chain and the correlation can never disagree.
fn print_connections(entities: &[Entity], relations: &[Relation]) {
    use std::collections::HashMap;

    let connections = crate::core::relation::identity_paths(entities, relations, 4);
    if connections.is_empty() {
        return;
    }

    let by_uid: HashMap<&str, &Entity> = entities.iter().map(|e| (e.uid.as_str(), e)).collect();
    // A uid label: the entity's (truncated) value + its kind, or a short uid
    // stub if the node is somehow absent. UIDs are hex (ASCII) — byte-safe slice.
    let label = |uid: &str| -> (String, String) {
        by_uid.get(uid).map_or_else(
            || (format!("{}…", &uid[..uid.len().min(8)]), "?".to_string()),
            |e| (super::super::truncate(&e.value, 36), e.kind.to_string()),
        )
    };

    const SHOWN: usize = 25;
    println!(
        "━━━ CONNECTIONS ({}) — identity link analysis ━━━",
        connections.len()
    );
    println!();
    println!("  The shortest typed path tying each identity back through the graph");
    println!("  (a chain is only as strong as its weakest edge):");
    println!();
    // Build the traversal graph ONCE and reuse it for every connection's
    // corroboration-multiplicity lookup below.
    let adj = crate::core::relation::sorted_confined_adjacency(entities, relations);
    for c in connections.iter().take(SHOWN) {
        let (fv, fk) = label(&c.from_uid);
        let mut line = format!("  {fv} ({fk})");
        let last = c.steps.len().saturating_sub(1);
        for (i, step) in c.steps.iter().enumerate() {
            let (sv, sk) = label(&step.to_uid);
            if i == last {
                // Annotate the destination identity with its kind.
                line.push_str(&format!("  ──{}──▶  {sv} ({sk})", step.kind));
            } else {
                line.push_str(&format!("  ──{}──▶  {sv}", step.kind));
            }
        }
        println!("{line}");
        // Corroboration multiplicity: how many edge-disjoint routes confirm this
        // link (AU-062's signal). >1 means the connection survives any single
        // pathway going dark — the orthogonal-route robustness.
        let routes =
            crate::core::relation::disjoint_pathways_in(&adj, &c.from_uid, &c.to_uid, 5, 4).len();
        let corroboration = if routes >= 2 {
            format!(" · corroborated via {routes} independent pathways")
        } else {
            String::new()
        };
        // Best-achievable reliability: the widest (max-bottleneck) route's weakest
        // link, shown when it beats the shortest path's — the most-trustworthy way
        // these two connect may be stronger than the shortest chain suggests
        // (AU-069's signal). Reuses the adjacency already built above.
        let best = crate::core::relation::strongest_path_in(&adj, &c.from_uid, &c.to_uid, 5)
            .map_or(c.min_confidence, |p| p.min_confidence);
        let best_route = if best > c.min_confidence + 1e-9 {
            format!(" · strongest route conf {best:.2}")
        } else {
            String::new()
        };
        println!(
            "    {} hop{}, weakest edge conf={:.2}{}{}",
            c.hops,
            if c.hops == 1 { "" } else { "s" },
            c.min_confidence,
            best_route,
            corroboration
        );
        println!();
    }
    if connections.len() > SHOWN {
        println!("  … {} more connection(s)", connections.len() - SHOWN);
        println!();
    }
}

/// RESOLVED IDENTITIES — the cluster-level synthesis of CONNECTIONS (AU-067).
/// Where the link analysis above ties identities together pairwise, this collapses
/// every transitively-connected identity into one *resolved identity* — the
/// connected component of the identity graph — held together only as firmly as its
/// weakest link. Reuses [`crate::core::relation::resolve_identity_clusters`], so
/// the grouping can't disagree with the pairwise threads above or the AU-067
/// correlation. Shows only ≥3-member resolutions; a 2-member cluster is a single
/// link already rendered under CONNECTIONS.
fn print_resolved_identities(entities: &[Entity], relations: &[Relation]) {
    use std::collections::HashMap;

    // Same weakest-link floor AU-067 resolves under (Probable tier): a link below
    // it is too weak to *bind* two identities, so a single tenuous edge can't fuse
    // dozens of unrelated namesakes into "one person" in this section.
    const MIN_CONF: f64 = 0.50;

    let clusters: Vec<_> =
        crate::core::relation::resolve_identity_clusters(entities, relations, 4, MIN_CONF)
            .into_iter()
            .filter(|c| c.members.len() >= 3)
            .collect();
    if clusters.is_empty() {
        return;
    }

    let by_uid: HashMap<&str, &Entity> = entities.iter().map(|e| (e.uid.as_str(), e)).collect();
    let label = |uid: &str| -> String {
        by_uid.get(uid).map_or_else(
            || format!("{}…", &uid[..uid.len().min(8)]),
            |e| format!("{} ({})", super::super::truncate(&e.value, 36), e.kind),
        )
    };

    println!(
        "━━━ RESOLVED IDENTITIES ({}) — distinct identifiers that are one person ━━━",
        clusters.len()
    );
    println!();
    println!("  Every identity transitively linked into one (weakest-link confidence):");
    println!();
    for (i, c) in clusters.iter().enumerate() {
        println!(
            "  #{} — {} identifiers, weakest link conf={:.2}:",
            i + 1,
            c.members.len(),
            c.min_confidence
        );
        for uid in &c.members {
            println!("      • {}", label(uid));
        }
        println!();
    }
}

/// CONNECTION BROKERS — the node-criticality synthesis (AU-070). Where CONNECTIONS
/// ties identities pairwise and RESOLVED IDENTITIES collapses them into clusters,
/// this names the **single nodes the network hangs on**: an entity whose removal
/// would fragment ≥3 otherwise-linked identities (the graph's articulation points,
/// in identity terms). Reuses [`crate::core::relation::connection_brokers`] over the
/// same confined adjacency the threads above traverse, so it can't disagree with
/// them or the AU-070 correlation. These are the prime pivots: corroborating a
/// broker hardens every connection that runs through it.
fn print_connection_brokers(entities: &[Entity], relations: &[Relation]) {
    use std::collections::HashMap;

    // Same Probable confidence floor and ≥3-identity floor AU-070 fires under: a
    // weak link can't make a node a broker (no fusing strangers), and a 2-identity
    // bridge is a single fragile pair already rendered under CONNECTIONS.
    const MIN_CONF: f64 = 0.50;
    let adj = crate::core::relation::sorted_confined_adjacency(entities, relations);
    let ids = crate::core::relation::identity_uids(entities);
    let brokers: Vec<_> = crate::core::relation::connection_brokers(&adj, &ids, MIN_CONF)
        .into_iter()
        .filter(|b| b.brokered.len() >= 3)
        .collect();
    if brokers.is_empty() {
        return;
    }

    let by_uid: HashMap<&str, &Entity> = entities.iter().map(|e| (e.uid.as_str(), e)).collect();
    let label = |uid: &str| -> String {
        by_uid.get(uid).map_or_else(
            || format!("{}…", &uid[..uid.len().min(8)]),
            |e| format!("{} ({})", super::super::truncate(&e.value, 36), e.kind),
        )
    };

    println!(
        "━━━ CONNECTION BROKERS ({}) — single points that hold the network together ━━━",
        brokers.len()
    );
    println!();
    println!("  Remove one of these and the identities beneath it fall apart — the prime");
    println!("  pivots to corroborate (hardening a broker hardens every link through it):");
    println!();
    for (i, b) in brokers.iter().enumerate() {
        println!(
            "  #{} — {} brokers {} identities:",
            i + 1,
            label(&b.uid),
            b.brokered.len()
        );
        for uid in &b.brokered {
            println!("      • {}", label(uid));
        }
        println!();
    }
}

/// Names of `KeyGated`/`Paid` modules that ran and finished with **zero**
/// entities this scan — the set the "ROI" hint warns about spending a
/// budgeted API call for nothing. Sourced from the scan's own `ModuleDone`
/// events (`found == 0`), NOT [`crate::util::diagnostics::analyse`]'s
/// `modules_by_yield`: that list is built purely from emitted entities'
/// evidence, so a module that ran and yielded nothing never appears in it at
/// all — a hint that filtered `modules_by_yield` for `entities_emitted == 0`
/// could therefore never fire. Pure and deterministic (sorted, deduped), so
/// it's testable without a live module run.
fn zero_yield_keyed_or_paid_modules(
    events: &[crate::core::event::Event],
    cost_by_module: &std::collections::HashMap<String, crate::core::module::ModuleCost>,
) -> Vec<String> {
    use crate::core::event::EventKind;
    use crate::core::module::ModuleCost;

    let mut names: Vec<String> = events
        .iter()
        .filter_map(|ev| match &ev.kind {
            EventKind::ModuleDone { module, found: 0 }
                if matches!(
                    cost_by_module.get(module.as_str()),
                    Some(ModuleCost::KeyGated | ModuleCost::Paid)
                ) =>
            {
                Some(module.clone())
            }
            _ => None,
        })
        .collect();
    names.sort();
    names.dedup();
    names
}

/// True if the scan ran long (`wall_time_ms` > 60s) **and** at least one
/// module finished with zero entities — a signal worth tightening
/// `module_timeout_ms` over. Reads the scan's own `ModuleDone` events, the
/// same durable source [`zero_yield_keyed_or_paid_modules`] uses, rather
/// than `ScanDiagnostics::modules_by_yield` — built only from emitted
/// entities' evidence, so a zero-yield module is absent from it, never
/// present-at-zero (the premise that made the original hint unreachable;
/// `PROBLEM_TREE` T2.14 / `SOLUTION_TREE` SOL-HINT-NOISE).
fn scan_ran_long_with_a_zero_yield_module(
    wall_time_ms: u64,
    events: &[crate::core::event::Event],
) -> bool {
    use crate::core::event::EventKind;
    wall_time_ms > 60_000
        && events
            .iter()
            .any(|ev| matches!(&ev.kind, EventKind::ModuleDone { found: 0, .. }))
}

fn print_diagnostics(
    scan: &Scan,
    entities: &[Entity],
    kind: &str,
    value: &str,
    sid: &str,
    store: &dyn crate::core::port::StoragePort,
) {
    let wall_ms = scan
        .finished_at
        .and_then(|f| f.checked_sub(scan.started_at))
        .unwrap_or(0)
        .saturating_mul(1000);
    let mut diag = crate::util::diagnostics::analyse(sid, kind, value, wall_ms, entities);

    println!("━━━ DIAGNOSTICS ━━━");
    println!();
    println!("  Scan wall-time:  {} ms", diag.wall_time_ms);

    use crate::core::module::ModuleCost;
    let cost_by_module: std::collections::HashMap<String, ModuleCost> = crate::modules::registry()
        .iter()
        .map(|m| (m.name().to_string(), m.cost()))
        .collect();
    let cost_label = |name: &str| match cost_by_module.get(name) {
        Some(ModuleCost::Free) => "free",
        Some(ModuleCost::KeyGated) => "key",
        Some(ModuleCost::Paid) => "paid",
        None => "·",
    };

    println!("  Modules ranked by yield (cost tier shown for ROI tuning):");
    for m in diag.modules_by_yield.iter().take(15) {
        let kinds = m.unique_kinds.join(",");
        println!(
            "    {:4}  {:<5} {:<22} conf={:.2}  novelty={:5.1}%  kinds={}",
            m.entities_emitted,
            cost_label(&m.name),
            m.name,
            m.mean_confidence,
            m.novelty_ratio * 100.0,
            kinds
        );
    }
    let events = store.events_for_scan(sid).unwrap_or_default();
    let wasted = zero_yield_keyed_or_paid_modules(&events, &cost_by_module);
    if !wasted.is_empty() {
        println!(
            "  ROI: {} keyed/paid module(s) yielded nothing — consider --exclude {}",
            wasted.len(),
            wasted.join(",")
        );
    }
    if scan_ran_long_with_a_zero_yield_module(diag.wall_time_ms, &events) {
        diag.optimization_hints.push(
            "scan exceeded 60s with at least one zero-yield module — tighten module_timeout_ms"
                .to_string(),
        );
    }
    println!();

    println!("  Source confidence (n / mean / p50 / p90):");
    let mut srcs: Vec<_> = diag.source_confidence.iter().collect();
    srcs.sort_by_key(|(_, s)| std::cmp::Reverse(s.n));
    for (src, s) in srcs.iter().take(15) {
        println!(
            "    {:<22} n={:<4} mean={:.2}  p50={:.2}  p90={:.2}",
            src, s.n, s.mean, s.p50, s.p90
        );
    }
    println!();

    let g = &diag.geo_precision;
    println!("━━━ GEO INTELLIGENCE ━━━");
    println!();
    // Headline answer first: the single best location estimate when AU-059's
    // cross-seed synergy gate fires (≥2 AU coordinates across ≥2 orthogonal
    // source classes). Same structured fix the API export and the AU-059 finding
    // carry — one computation, three renderings.
    if let Some(fix) = crate::core::correlator::au059_synergy_fix(entities) {
        println!(
            "  Best location estimate: {:.4},{:.4} ± {:.1} km  (geohash={}, state={})",
            fix.lat, fix.lon, fix.radius_km, fix.geohash, fix.state
        );
        println!(
            "    cross-seed synergy: {} AU coordinate(s) across {} orthogonal source class(es) [{}], confidence {:.2}",
            fix.count,
            fix.class_names.len(),
            fix.class_names.join(", "),
            fix.synergy_confidence
        );
        println!();
    } else if let Some(est) = crate::core::correlator::best_au_location_estimate(entities) {
        // Single-signal fallback: the common scan has one location signal, not the
        // ≥2-class synergy AU-059 requires. Surface the best available fix anyway —
        // every located subject gets a headline answer with its precision + basis.
        let near = est
            .locality
            .as_deref()
            .map_or_else(String::new, |l| format!(", near {l}"));
        println!(
            "  Best location estimate: {:.4},{:.4} ± {:.1} km  (geohash={}, state={}{})",
            est.lat, est.lon, est.radius_km, est.geohash, est.state, near
        );
        println!(
            "    basis: {} (confidence {:.2}) — single-signal fix",
            est.basis, est.confidence
        );
        println!();
    }
    println!(
        "  Coordinates: {} total ({} with geohash, {} with timezone)",
        g.coordinates_count, g.coords_with_geohash, g.coords_with_timezone
    );
    println!(
        "  Addresses:   {} total ({} state, {} country, {} ISO, {} postal)",
        g.address_count,
        g.addresses_with_state,
        g.addresses_with_country,
        g.addresses_with_iso,
        g.addresses_with_postal
    );
    if !g.iso_countries.is_empty() {
        println!("  ISO countries: {}", g.iso_countries.join(", "));
    }
    if !g.timezones.is_empty() {
        println!("  Timezones:     {}", g.timezones.join(", "));
    }
    println!(
        "  Multi-source convergence: {}",
        if g.multi_source_convergence {
            "YES (≥2 coords within 5km)"
        } else {
            "no"
        }
    );
    println!();

    if !diag.proximity_graph.is_empty() {
        println!("  Proximity graph (top 15 closest coord pairs):");
        for edge in diag.proximity_graph.iter().take(15) {
            let label = if edge.same_country {
                format!(
                    " [same country: {}]",
                    edge.from_country.as_deref().unwrap_or("?")
                )
            } else if edge.from_country.is_some() || edge.to_country.is_some() {
                format!(
                    " [{} ↔ {}]",
                    edge.from_country.as_deref().unwrap_or("?"),
                    edge.to_country.as_deref().unwrap_or("?")
                )
            } else {
                String::new()
            };
            println!(
                "    {:>10.3} km   {} ↔ {}{}",
                edge.distance_km, edge.from_value, edge.to_value, label
            );
        }
        println!();
    }

    let timeline = crate::core::timeline::reconstruct(entities);
    println!("━━━ TIMELINE ({} events) ━━━", timeline.len());
    println!();
    if timeline.is_empty() {
        println!("  No dated events reconstructed from the current entity set.");
    } else {
        for ev in timeline.iter().take(40) {
            println!(
                "  {:<19}  {:<16}  {} [{}]",
                ev.iso,
                ev.kind.as_str(),
                ev.entity_value,
                ev.source
            );
        }
        if timeline.len() > 40 {
            println!("  … {} more", timeline.len() - 40);
        }
    }
    println!();

    println!("━━━ ENRICHMENT LINEAGE ━━━");
    println!();
    let mut lineage_sorted = diag.enrichment_lineage.clone();
    lineage_sorted.sort_by_key(|n| std::cmp::Reverse(n.source_chain.len()));
    for node in lineage_sorted.iter().take(20) {
        println!(
            "  [{}] {} (conf={:.2}, corr={})",
            node.kind, node.value_preview, node.confidence, node.corroboration
        );
        println!("    sources: {}", node.source_chain.join(" → "));
    }
    println!();

    println!("━━━ OPTIMIZATION HINTS ━━━");
    println!();
    for hint in &diag.optimization_hints {
        println!("  • {hint}");
    }
    println!();

    println!("━━━ END OF DOSSIER ━━━");
}

#[cfg(test)]
mod tests {
    use super::{scan_ran_long_with_a_zero_yield_module, zero_yield_keyed_or_paid_modules};
    use crate::core::event::{Event, EventKind};
    use crate::core::module::ModuleCost;
    use std::collections::HashMap;

    fn costs() -> HashMap<String, ModuleCost> {
        [
            ("shodan".to_string(), ModuleCost::Paid),
            ("hunter_io".to_string(), ModuleCost::KeyGated),
            ("search_engines".to_string(), ModuleCost::Free),
        ]
        .into_iter()
        .collect()
    }

    /// The whole point of this helper: a `KeyGated`/`Paid` module that ran and
    /// found nothing must be reported, even though it is entirely absent from
    /// `ScanDiagnostics::modules_by_yield` (built only from emitted entities).
    #[test]
    fn flags_a_zero_yield_keyed_or_paid_module() {
        let events = vec![Event::new(
            "s",
            EventKind::ModuleDone {
                module: "shodan".into(),
                found: 0,
            },
        )];
        assert_eq!(
            zero_yield_keyed_or_paid_modules(&events, &costs()),
            vec!["shodan".to_string()]
        );
    }

    /// A module that DID find something must not be flagged, however costly.
    #[test]
    fn ignores_a_module_that_found_something() {
        let events = vec![Event::new(
            "s",
            EventKind::ModuleDone {
                module: "shodan".into(),
                found: 3,
            },
        )];
        assert!(zero_yield_keyed_or_paid_modules(&events, &costs()).is_empty());
    }

    /// A free module that yields nothing is not a wasted spend — nothing to
    /// warn about, so it must not appear.
    #[test]
    fn ignores_a_free_module_with_zero_yield() {
        let events = vec![Event::new(
            "s",
            EventKind::ModuleDone {
                module: "search_engines".into(),
                found: 0,
            },
        )];
        assert!(zero_yield_keyed_or_paid_modules(&events, &costs()).is_empty());
    }

    /// Output is sorted and deduped — deterministic regardless of event order
    /// or a module appearing more than once (e.g. re-dispatched on expansion).
    #[test]
    fn output_is_sorted_and_deduped() {
        let mk = |m: &str| {
            Event::new(
                "s",
                EventKind::ModuleDone {
                    module: m.into(),
                    found: 0,
                },
            )
        };
        let events = vec![mk("shodan"), mk("hunter_io"), mk("shodan")];
        assert_eq!(
            zero_yield_keyed_or_paid_modules(&events, &costs()),
            vec!["hunter_io".to_string(), "shodan".to_string()]
        );
    }

    fn zero_yield_event() -> Event {
        Event::new(
            "s",
            EventKind::ModuleDone {
                module: "search_engines".into(),
                found: 0,
            },
        )
    }

    /// The reinstated T2.14 hint: a long scan with a module that found
    /// nothing is exactly the "tighten module_timeout_ms" signal, sourced
    /// from the same durable `ModuleDone` events as the ROI hint (not
    /// `modules_by_yield`, which can never see a zero-yield module at all).
    #[test]
    fn fires_when_scan_is_long_and_a_module_yielded_nothing() {
        assert!(scan_ran_long_with_a_zero_yield_module(
            61_000,
            &[zero_yield_event()]
        ));
    }

    /// Exactly at the 60s boundary must NOT fire — "exceeded 60s" is a
    /// strict `>`, not `>=`.
    #[test]
    fn does_not_fire_exactly_at_the_sixty_second_boundary() {
        assert!(!scan_ran_long_with_a_zero_yield_module(
            60_000,
            &[zero_yield_event()]
        ));
    }

    /// A short scan is never flagged, however many modules yielded nothing.
    #[test]
    fn does_not_fire_when_the_scan_is_short() {
        assert!(!scan_ran_long_with_a_zero_yield_module(
            5_000,
            &[zero_yield_event()]
        ));
    }

    /// A long scan where every module found something is not flagged either.
    #[test]
    fn does_not_fire_when_every_module_yielded_something() {
        let events = vec![Event::new(
            "s",
            EventKind::ModuleDone {
                module: "search_engines".into(),
                found: 12,
            },
        )];
        assert!(!scan_ran_long_with_a_zero_yield_module(61_000, &events));
    }
}
