//! Adaptive routing reader and main analysis entry point.

use std::collections::HashMap;

use super::cluster::{cluster_coordinates, cluster_entities_fuzzy};
use super::types::{
    AdaptiveRouting, ConfidenceStats, EntityOverlap, GeoPrecisionReport, LineageNode,
    ModuleHistoricalScore, ModulePerformance, ProximityEdge, ScanDiagnostics,
};
use crate::core::entity::Entity;

/// Read the cross-scan ledger and produce per-module routing recommendations.
pub fn read_adaptive_routing() -> AdaptiveRouting {
    use super::types::ModuleLedger;
    let path = {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        std::path::PathBuf::from(home)
            .join(".huntsman")
            .join("module_stats.json")
    };
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

/// Compute full diagnostics from a finalised scan's entity set.
pub fn analyse(
    scan_id: &str,
    seed_kind: &str,
    seed_value: &str,
    wall_time_ms: u64,
    entities: &[Entity],
) -> ScanDiagnostics {
    let mut by_source: HashMap<String, ModulePerformance> = HashMap::new();
    let mut source_conf: HashMap<String, Vec<f64>> = HashMap::new();
    let mut kind_counts: HashMap<String, usize> = HashMap::new();
    let mut entity_sources: HashMap<(String, String), Vec<String>> = HashMap::new();
    let mut lineage: Vec<LineageNode> = Vec::new();
    let mut geo = GeoPrecisionReport::default();
    let mut tz_seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut iso_seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut coord_pairs: Vec<(f64, f64, String, std::collections::HashSet<String>)> = Vec::new();

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
            perf.entities_emitted = perf.entities_emitted.saturating_add(1);
            perf.evidence_count = perf.evidence_count.saturating_add(1);
            if !perf.unique_kinds.contains(&e.kind.to_string()) {
                perf.unique_kinds.push(e.kind.to_string());
            }
            source_conf.entry(s).or_default().push(e.confidence);
        }
        sources_for_entity.sort();
        sources_for_entity.dedup();

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
                    coord_pairs.push((lat, lon, e.value.clone(), srcs));
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

    // Pairwise Haversine distances — proximity graph (top-25 closest).
    let mut proximity_graph: Vec<ProximityEdge> = Vec::new();
    for (i, (la1, lo1, v1, _)) in coord_pairs.iter().enumerate() {
        for (la2, lo2, v2, _) in coord_pairs.iter().skip(i + 1) {
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

    // Spatial clustering: ~5km single-linkage groups into "places".
    let coordinate_clusters = cluster_coordinates(&coord_pairs);

    // Fuzzy entity resolution for Person/Address/Organisation.
    let entity_clusters = cluster_entities_fuzzy(entities);

    // Closed feedback loop: read the cross-scan ledger.
    let adaptive_routing = read_adaptive_routing();

    // Multi-source convergence: any two coordinates within ~5km?
    'outer: for (i, (la1, lo1, _, _)) in coord_pairs.iter().enumerate() {
        for (la2, lo2, _, _) in coord_pairs.iter().skip(i + 1) {
            let dist_deg = ((la1 - la2).powi(2) + (lo1 - lo2).powi(2)).sqrt();
            // ~0.045° ≈ 5km at the equator (rough)
            if dist_deg < 0.045 {
                geo.multi_source_convergence = true;
                break 'outer;
            }
        }
    }

    // Confidence stats per source
    let source_confidence: std::collections::BTreeMap<String, ConfidenceStats> = source_conf
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
        .collect();

    // Compute novelty + finalise modules_by_yield
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

    // Cross-source overlaps with ≥2 distinct sources
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

    // Optimization hints based on what we observed
    let mut hints: Vec<String> = Vec::new();
    for perf in &modules_by_yield {
        if perf.entities_emitted == 0 {
            hints.push(format!(
                "module '{}' returned 0 entities — consider excluding for this target kind",
                perf.name
            ));
        }
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
    if wall_time_ms > 60_000 && modules_by_yield.iter().any(|m| m.entities_emitted == 0) {
        hints.push(
            "scan exceeded 60s with at least one zero-yield module — tighten module_timeout_ms"
                .into(),
        );
    }
    if hints.is_empty() {
        hints
            .push("no optimization signals detected — pipeline is well-tuned for this seed".into());
    }

    // Persist a digest to the cross-scan ledger
    super::ledger::persist_ledger(&modules_by_yield, &kind_counts);

    // Adaptive hints from the closed feedback loop
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
