//! Adaptive routing reader and main analysis entry point.

use std::collections::HashMap;

use super::cluster::{cluster_coordinates, cluster_entities_fuzzy};
use super::types::{
    AdaptiveRouting, ConfidenceStats, CoordinateCluster, EntityCluster, EntityOverlap,
    GeoPrecisionReport, LineageNode, ModuleHistoricalScore, ModulePerformance, ProximityEdge,
    ScanDiagnostics,
};
use crate::core::entity::Entity;

/// Read the cross-scan ledger and produce per-module routing recommendations.
pub fn read_adaptive_routing() -> AdaptiveRouting {
    use super::types::ModuleLedger;
    let path = crate::util::paths::data_file("module_stats.json");
    let Ok(text) = std::fs::read_to_string(&path) else {
        return AdaptiveRouting::default();
    };
    let Ok(ledger): std::result::Result<ModuleLedger, _> = serde_json::from_str(&text) else {
        return AdaptiveRouting::default();
    };

    let mut scores: Vec<ModuleHistoricalScore> = ledger
        .per_module
        .iter()
        .map(|(name, e)| ModuleHistoricalScore {
            name: name.clone(),
            scans_present: e.scans_present,
            mean_entities_per_scan: e.mean_entities_per_scan,
            zero_yield_rate: e.zero_yield_rate,
        })
        .collect();
    scores.sort_by(|a, b| {
        b.mean_entities_per_scan
            .partial_cmp(&a.mean_entities_per_scan)
            .unwrap_or(std::cmp::Ordering::Equal)
            // Stable tiebreak by name: `per_module` is a HashMap, so equal-yield
            // modules must order deterministically for a reproducible ranking.
            .then_with(|| a.name.cmp(&b.name))
    });

    // Skip recommendations: ≥80% zero-yield over ≥5 scans.
    let recommended_skips: Vec<String> = scores
        .iter()
        .filter(|s| s.scans_present >= 5 && s.zero_yield_rate >= 0.80)
        .map(|s| s.name.clone())
        .collect();

    // Priority recommendations: top-5 by historical mean yield, scans ≥3.
    let recommended_priorities: Vec<String> = scores
        .iter()
        .filter(|s| s.scans_present >= 3 && s.mean_entities_per_scan >= 5.0)
        .take(5)
        .map(|s| s.name.clone())
        .collect();

    AdaptiveRouting {
        ledger_scans: ledger.total_scans,
        historical_rank: scores,
        recommended_skips,
        recommended_priorities,
    }
}

/// Compute full diagnostics from a finalised scan's entity set and dispatch log.
///
/// `events` is the scan's `ModuleDone`/… event stream (the caller reads it from
/// its `StoragePort` and passes the plain slice — `util` takes the `core::event`
/// data type, never the storage trait). It carries the one signal the entity set
/// cannot: a module that ran and found nothing emits no evidence, so it is absent
/// from `entities`/`modules_by_yield` entirely; only the `ModuleDone { found: 0 }`
/// event records that it ran at all. That drives the scan-level slow-with-waste
/// hint below.
pub fn analyse(
    scan_id: &str,
    seed_kind: &str,
    seed_value: &str,
    wall_time_ms: u64,
    entities: &[Entity],
    events: &[crate::core::event::Event],
) -> ScanDiagnostics {
    let EntityAccumulation {
        by_source,
        source_conf,
        kind_counts,
        entity_sources,
        lineage,
        mut geo,
        coord_pairs,
    } = accumulate_entities(entities);

    // Pairwise Haversine distances — proximity graph (top-25 closest).
    let proximity_graph = build_proximity_graph(&coord_pairs);

    // Spatial clustering: ~5km single-linkage groups into "places".
    let coordinate_clusters = cluster_coordinates(&coord_pairs);

    // Fuzzy entity resolution for Person/Address/Organisation.
    let entity_clusters = cluster_entities_fuzzy(entities);

    // Closed feedback loop: read the cross-scan ledger.
    let adaptive_routing = read_adaptive_routing();

    // Multi-source convergence: are any two coordinates within 5 km? The closest pair is
    // already `proximity_graph[0]` (sorted ascending above) and was computed with the
    // shared `haversine_km`, so read the answer off it instead of re-scanning with a
    // separate latitude-biased degree metric (`0.045°` is ~5 km only at the equator; at
    // AU latitudes a degree of longitude is ~20% shorter, so that test disagreed with the
    // 5 km `coordinate_clusters` shown beside it in the dossier). `<= 5.0` matches
    // `cluster_coordinates`' `THRESHOLD_KM` exactly, so the flag and the clusters agree.
    geo.multi_source_convergence = proximity_graph
        .first()
        .is_some_and(|e| e.distance_km <= 5.0);

    // Confidence stats per source
    let source_confidence = compute_source_confidence(source_conf);

    // Compute novelty + finalise modules_by_yield
    let modules_by_yield =
        finalize_modules_by_yield(by_source, &entity_sources, &source_confidence);

    // Cross-source overlaps with ≥2 distinct sources
    let cross_source_overlap = compute_cross_source_overlap(entity_sources);

    // Optimization hints based on what we observed.
    let mut hints = build_optimization_hints(&modules_by_yield, &geo, wall_time_ms, events);

    // Persist a digest to the cross-scan ledger
    super::ledger::persist_ledger(&modules_by_yield, &kind_counts);

    // Adaptive hints from the closed feedback loop, plus entity-resolution and
    // spatial-clustering summaries.
    append_adaptive_and_clustering_hints(
        &mut hints,
        &adaptive_routing,
        &entity_clusters,
        &coordinate_clusters,
        &geo,
    );

    ScanDiagnostics {
        scan_id: scan_id.into(),
        seed_kind: seed_kind.into(),
        seed_value: seed_value.into(),
        wall_time_ms,
        modules_by_yield,
        source_confidence,
        entity_kind_counts: kind_counts.into_iter().collect(),
        geo_precision: geo,
        proximity_graph,
        coordinate_clusters,
        entity_clusters,
        cross_source_overlap,
        adaptive_routing,
        optimization_hints: hints,
        enrichment_lineage: lineage,
    }
}

/// The per-entity accumulation pass's output: everything downstream
/// aggregation (proximity graph, confidence stats, novelty, overlap) is
/// computed from.
struct EntityAccumulation {
    by_source: HashMap<String, ModulePerformance>,
    source_conf: HashMap<String, Vec<f64>>,
    kind_counts: HashMap<String, usize>,
    entity_sources: HashMap<(String, String), Vec<String>>,
    lineage: Vec<LineageNode>,
    geo: GeoPrecisionReport,
    coord_pairs: Vec<(f64, f64, String, std::collections::HashSet<String>, f64)>,
}

/// Walk every entity once, tallying per-kind counts, per-source performance
/// and confidence samples, cross-source overlap keys, lineage nodes, and the
/// geo-precision report (plus the raw coordinate list the proximity graph
/// and spatial clustering are built from downstream).
fn accumulate_entities(entities: &[Entity]) -> EntityAccumulation {
    let mut by_source: HashMap<String, ModulePerformance> = HashMap::new();
    let mut source_conf: HashMap<String, Vec<f64>> = HashMap::new();
    let mut kind_counts: HashMap<String, usize> = HashMap::new();
    let mut entity_sources: HashMap<(String, String), Vec<String>> = HashMap::new();
    let mut lineage: Vec<LineageNode> = Vec::new();
    let mut geo = GeoPrecisionReport::default();
    let mut tz_seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut iso_seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut coord_pairs: Vec<(f64, f64, String, std::collections::HashSet<String>, f64)> =
        Vec::new();

    for e in entities {
        *kind_counts.entry(e.kind.to_string()).or_insert(0) += 1;

        // Per-source aggregation
        let mut sources_for_entity: Vec<String> = Vec::new();
        for ev in &e.evidence {
            let s = ev.source.clone();
            sources_for_entity.push(s.clone());
            let perf = by_source
                .entry(s.clone())
                .or_insert_with(|| ModulePerformance {
                    name: s.clone(),
                    ..Default::default()
                });
            perf.evidence_count = perf.evidence_count.saturating_add(1);
            if !perf.unique_kinds.contains(&e.kind.to_string()) {
                perf.unique_kinds.push(e.kind.to_string());
            }
            source_conf.entry(s).or_default().push(e.confidence);
        }
        sources_for_entity.sort();
        sources_for_entity.dedup();
        // Count this entity ONCE per DISTINCT source that emitted it. Doing it in
        // the evidence loop above tracked evidence_count in lockstep, so an entity
        // carrying several evidence records from one source (e.g. overpass attaches
        // two SRC records to one Coordinates node) was counted as several entities —
        // inflating the persisted total_entities / mean_entities_per_scan that drive
        // --adaptive routing. entities_emitted is an entity count, not an evidence count.
        for s in &sources_for_entity {
            if let Some(perf) = by_source.get_mut(s) {
                perf.entities_emitted = perf.entities_emitted.saturating_add(1);
            }
        }

        // Overlap (cross-source corroboration)
        let key = (e.kind.to_string(), e.value.clone());
        entity_sources
            .entry(key)
            .or_default()
            .extend(sources_for_entity.iter().cloned());

        // Lineage
        let preview = if e.value.len() > 60 {
            format!("{}…", crate::util::str_util::truncate_safe(&e.value, 57))
        } else {
            e.value.clone()
        };
        lineage.push(LineageNode {
            entity_uid: e.uid.clone(),
            kind: e.kind.to_string(),
            value_preview: preview,
            source_chain: sources_for_entity,
            confidence: e.confidence,
            corroboration: e.corroboration,
        });

        // Geo precision tally
        match e.kind.to_string().as_str() {
            "coordinates" => {
                geo.coordinates_count += 1;
                let geohash_present = e
                    .evidence
                    .iter()
                    .any(|ev| ev.attributes.contains_key("geohash"));
                let tz_present = e
                    .evidence
                    .iter()
                    .any(|ev| ev.attributes.contains_key("timezone"));
                if geohash_present {
                    geo.coords_with_geohash += 1;
                }
                if tz_present {
                    geo.coords_with_timezone += 1;
                    for ev in &e.evidence {
                        if let Some(tz) = ev.attributes.get("timezone") {
                            tz_seen.insert(tz.clone());
                        }
                    }
                }
                if let Some((lat, lon)) = crate::util::geohash::parse_coords(&e.value) {
                    let mut srcs: std::collections::HashSet<String> =
                        std::collections::HashSet::new();
                    for ev in &e.evidence {
                        srcs.insert(ev.source.clone());
                    }
                    coord_pairs.push((lat, lon, e.value.clone(), srcs, e.c_effective()));
                }
            }
            "address" => {
                geo.address_count += 1;
                for ev in &e.evidence {
                    if ev.attributes.contains_key("addr_state") {
                        geo.addresses_with_state += 1;
                    }
                    if ev.attributes.contains_key("addr_country") {
                        geo.addresses_with_country += 1;
                    }
                    if ev.attributes.contains_key("addr_postal") {
                        geo.addresses_with_postal += 1;
                    }
                    if let Some(iso) = ev.attributes.get("addr_iso") {
                        geo.addresses_with_iso += 1;
                        iso_seen.insert(iso.clone());
                    }
                }
            }
            _ => {}
        }
    }
    geo.timezones = tz_seen.into_iter().collect();
    geo.iso_countries = iso_seen.into_iter().collect();

    EntityAccumulation {
        by_source,
        source_conf,
        kind_counts,
        entity_sources,
        lineage,
        geo,
        coord_pairs,
    }
}

/// Pairwise Haversine distance between every coordinate pair, sorted
/// ascending and capped to the 25 closest — the proximity graph shown in the
/// dossier.
fn build_proximity_graph(
    coord_pairs: &[(f64, f64, String, std::collections::HashSet<String>, f64)],
) -> Vec<ProximityEdge> {
    let mut proximity_graph: Vec<ProximityEdge> = Vec::new();
    for (i, (la1, lo1, v1, _, _)) in coord_pairs.iter().enumerate() {
        for (la2, lo2, v2, _, _) in coord_pairs.iter().skip(i + 1) {
            let d = crate::util::geohash::haversine_km(*la1, *lo1, *la2, *lo2);
            let from_country =
                crate::util::geohash::reverse_country_iso(*la1, *lo1).map(str::to_string);
            let to_country =
                crate::util::geohash::reverse_country_iso(*la2, *lo2).map(str::to_string);
            let same_country = from_country.is_some() && from_country == to_country;
            proximity_graph.push(ProximityEdge {
                from_value: v1.clone(),
                to_value: v2.clone(),
                distance_km: (d * 1000.0).round() / 1000.0,
                from_country,
                to_country,
                same_country,
            });
        }
    }
    proximity_graph.sort_by(|a, b| {
        a.distance_km
            .partial_cmp(&b.distance_km)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    proximity_graph.truncate(25);
    proximity_graph
}

/// Per-source confidence distribution (n/mean/min/max/p50/p90) over every
/// entity that source contributed evidence to.
fn compute_source_confidence(
    source_conf: HashMap<String, Vec<f64>>,
) -> std::collections::BTreeMap<String, ConfidenceStats> {
    source_conf
        .into_iter()
        .map(|(src, mut vals)| {
            vals.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            let n = vals.len();
            let mean = if n > 0 {
                vals.iter().sum::<f64>() / n as f64
            } else {
                0.0
            };
            let stats = ConfidenceStats {
                n,
                mean,
                min: vals.first().copied().unwrap_or(0.0),
                max: vals.last().copied().unwrap_or(0.0),
                p50: vals.get(n / 2).copied().unwrap_or(0.0),
                p90: vals
                    .get((n as f64 * 0.9) as usize)
                    .copied()
                    .unwrap_or(vals.last().copied().unwrap_or(0.0)),
            };
            (src, stats)
        })
        .collect()
}

/// Fill in each source's mean confidence and novelty ratio (share of its
/// entities no other source also emitted), then sort into the final
/// yield-descending `modules_by_yield` list.
fn finalize_modules_by_yield(
    mut by_source: HashMap<String, ModulePerformance>,
    entity_sources: &HashMap<(String, String), Vec<String>>,
    source_confidence: &std::collections::BTreeMap<String, ConfidenceStats>,
) -> Vec<ModulePerformance> {
    for perf in by_source.values_mut() {
        let conf = source_confidence.get(&perf.name).map_or(0.0, |s| s.mean);
        perf.mean_confidence = conf;
        let unique = entity_sources
            .iter()
            .filter(|(_, srcs)| srcs.len() == 1 && srcs[0] == perf.name)
            .count();
        perf.novelty_ratio = if perf.entities_emitted > 0 {
            unique as f64 / perf.entities_emitted as f64
        } else {
            0.0
        };
    }

    let mut modules_by_yield: Vec<ModulePerformance> = by_source.into_values().collect();
    // Yield desc, then name as a STABLE tiebreak: `by_source` is a HashMap, so
    // equal-yield modules would otherwise serialise in a random order and break
    // byte-reproducibility of the diagnostics report.
    modules_by_yield.sort_by(|a, b| {
        b.entities_emitted
            .cmp(&a.entities_emitted)
            .then_with(|| a.name.cmp(&b.name))
    });
    modules_by_yield
}

/// Entities two or more distinct sources both emitted — cross-source
/// corroboration, capped to the top 50 by source count.
fn compute_cross_source_overlap(
    entity_sources: HashMap<(String, String), Vec<String>>,
) -> Vec<EntityOverlap> {
    let mut cross_source_overlap: Vec<EntityOverlap> = entity_sources
        .into_iter()
        .filter_map(|((k, v), mut srcs)| {
            srcs.sort();
            srcs.dedup();
            if srcs.len() >= 2 {
                Some(EntityOverlap {
                    kind: k,
                    value: v,
                    sources: srcs,
                })
            } else {
                None
            }
        })
        .collect();
    // Overlap count desc, then (kind, value) as a stable tiebreak — built from
    // the `entity_sources` HashMap, so ties need an explicit order to stay
    // reproducible.
    cross_source_overlap.sort_by(|a, b| {
        b.sources
            .len()
            .cmp(&a.sources.len())
            .then_with(|| a.kind.cmp(&b.kind))
            .then_with(|| a.value.cmp(&b.value))
    });
    cross_source_overlap.truncate(50);
    cross_source_overlap
}

/// Module-quality and geo-coverage hints, plus the event-sourced scan-level
/// slow-with-waste hint. Falls back to a single "well-tuned" line when none
/// of the above fired — this fallback check runs BEFORE the adaptive-routing
/// and clustering hints are appended by the caller, so it reflects only this
/// batch (matching the pre-split behaviour exactly).
///
/// The scan-level "slow scan with wasted modules" hint IS here (T2.14),
/// event-sourced: `modules_by_yield` is built exclusively from emitted
/// entities' evidence, so a module that ran and found nothing is absent from
/// it entirely — only the `ModuleDone { found: 0 }` events record that it
/// ran. So this reads `events`, not `entities`. It fires as ONE aggregate
/// line, gated on a >60s wall time, so a normal scan's dozens of
/// legitimately-empty modules never flood the hints. A per-module zero-yield
/// hint (one line per empty module) is still deferred (PROBLEM_TREE T2.14):
/// it needs an explicit noise decision (cap to worst-N, cost-gate, or
/// bounded count) before it earns a line.
fn build_optimization_hints(
    modules_by_yield: &[ModulePerformance],
    geo: &GeoPrecisionReport,
    wall_time_ms: u64,
    events: &[crate::core::event::Event],
) -> Vec<String> {
    let mut hints: Vec<String> = Vec::new();
    for perf in modules_by_yield {
        if perf.mean_confidence < 0.35 && perf.entities_emitted > 10 {
            hints.push(format!(
                "module '{}' produced {} entities at low mean confidence ({:.2}) — noisy source",
                perf.name, perf.entities_emitted, perf.mean_confidence
            ));
        }
        if perf.novelty_ratio < 0.05 && perf.entities_emitted > 20 {
            hints.push(format!(
                "module '{}' entities are {:.0}% redundant with other sources — candidate for downranking",
                perf.name,
                100.0 * (1.0 - perf.novelty_ratio)
            ));
        }
    }
    if geo.coordinates_count == 0 && geo.address_count > 0 {
        hints.push(format!(
            "{} addresses found but 0 coordinates — geocode module did not resolve any",
            geo.address_count
        ));
    }
    if geo.coordinates_count > 0 && geo.coords_with_geohash == 0 {
        hints.push(
            "coordinates present but no geohash attached — geo_normalize ran late or skipped"
                .into(),
        );
    }
    if !geo.multi_source_convergence && geo.coordinates_count > 1 {
        hints.push("multiple coordinates but no two are within 5km — geo-convergence not achieved; consider raising depth".into());
    }

    // Scan-level slow-with-waste hint (T2.14, event-sourced). Only fires when the
    // scan was slow (>60s) AND at least one module ran but found nothing, so
    // trimming dead modules would materially cut wall time. One aggregate line
    // (bounded count, worst names capped) — never one-per-module — so it stays
    // signal, not noise. Deterministic: names are sorted before the cap.
    const SLOW_SCAN_MS: u64 = 60_000;
    if wall_time_ms > SLOW_SCAN_MS {
        use crate::core::event::EventKind;
        let mut zero_yield: Vec<&str> = events
            .iter()
            .filter_map(|ev| match &ev.kind {
                EventKind::ModuleDone { module, found: 0 } => Some(module.as_str()),
                _ => None,
            })
            .collect();
        zero_yield.sort_unstable();
        zero_yield.dedup();
        if !zero_yield.is_empty() {
            const NAMES_SHOWN: usize = 5;
            let shown = zero_yield
                .iter()
                .take(NAMES_SHOWN)
                .copied()
                .collect::<Vec<_>>()
                .join(", ");
            let more = zero_yield.len().saturating_sub(NAMES_SHOWN);
            let suffix = if more > 0 {
                format!(" (+{more} more)")
            } else {
                String::new()
            };
            hints.push(format!(
                "scan exceeded {}s ({:.1}s) with {} zero-yield module(s): {}{} — consider --exclude or --adaptive to trim dispatch",
                SLOW_SCAN_MS / 1000,
                wall_time_ms as f64 / 1000.0,
                zero_yield.len(),
                shown,
                suffix
            ));
        }
    }

    if hints.is_empty() {
        hints
            .push("no optimization signals detected — pipeline is well-tuned for this seed".into());
    }
    hints
}

/// Append the closed-feedback-loop (adaptive-routing) hints plus the
/// entity-resolution and spatial-clustering summaries. Runs AFTER the ledger
/// persist and the `build_optimization_hints` empty-fallback check, so these
/// lines can coexist with a "well-tuned" fallback line above them — matching
/// the pre-split behaviour exactly.
fn append_adaptive_and_clustering_hints(
    hints: &mut Vec<String>,
    adaptive_routing: &AdaptiveRouting,
    entity_clusters: &[EntityCluster],
    coordinate_clusters: &[CoordinateCluster],
    geo: &GeoPrecisionReport,
) {
    if !adaptive_routing.recommended_skips.is_empty() {
        hints.push(format!(
            "adaptive-routing: {} module(s) historically zero-yield ≥80% of the time over ≥5 scans — candidates for --adaptive skip: {}",
            adaptive_routing.recommended_skips.len(),
            adaptive_routing.recommended_skips.join(", ")
        ));
    }
    if !adaptive_routing.recommended_priorities.is_empty() {
        hints.push(format!(
            "adaptive-routing: high-yield modules from historical ledger: {}",
            adaptive_routing.recommended_priorities.join(", ")
        ));
    }
    if !entity_clusters.is_empty() {
        let total: usize = entity_clusters.iter().map(|c| c.member_count).sum();
        hints.push(format!(
            "entity-resolution: {} fuzzy clusters collapse {} raw entities → {} resolved identities",
            entity_clusters.len(),
            total,
            entity_clusters.len()
        ));
    }
    if coordinate_clusters.len() < geo.coordinates_count && !coordinate_clusters.is_empty() {
        hints.push(format!(
            "spatial-clustering: {} raw coordinates collapse into {} geographic clusters (mean diameter {:.2}km)",
            geo.coordinates_count,
            coordinate_clusters.len(),
            coordinate_clusters.iter().map(|c| c.diameter_km).sum::<f64>() / coordinate_clusters.len() as f64
        ));
    }
}
