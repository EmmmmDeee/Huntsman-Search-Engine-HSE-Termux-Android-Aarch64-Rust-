//! Scan diagnostics — per-scan introspection that ranks module
//! performance, calibrates confidence per source, surfaces optimization
//! signals, and persists a cross-scan ledger for adaptive routing.
//!
//! The ledger ($HOME/.huntsman/module_stats.json) tracks rolling
//! averages of entities/sec, error rates, and yield-per-target for
//! every module. Future scans can read this to deprioritise
//! consistently weak modules (not yet wired — present as data only).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

use crate::core::entity::Entity;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanDiagnostics {
    pub scan_id: String,
    pub seed_kind: String,
    pub seed_value: String,
    pub wall_time_ms: u64,
    pub modules_by_yield: Vec<ModulePerformance>,
    pub source_confidence: HashMap<String, ConfidenceStats>,
    pub entity_kind_counts: HashMap<String, usize>,
    pub geo_precision: GeoPrecisionReport,
    /// Pairwise Haversine distances (km) between every Coordinates entity
    /// pair — top 25 closest. Reveals geo-convergence clusters and lone
    /// outliers in the same scan.
    pub proximity_graph: Vec<ProximityEdge>,
    /// Spatial clustering: groups of coordinates within ~5km of each
    /// other. Each cluster represents one "place" inferred from multiple
    /// sources. Reduces 50 noisy points into N geographic claims.
    pub coordinate_clusters: Vec<CoordinateCluster>,
    /// Fuzzy clustering of Person and Address entities by normalized
    /// string similarity. Resolves "Jordan Meyer" / "Jordan L Meyer" /
    /// "J Meyer" into one cluster with a canonical representative.
    pub entity_clusters: Vec<EntityCluster>,
    pub cross_source_overlap: Vec<EntityOverlap>,
    /// Closed feedback loop: reads ~/.huntsman/module_stats.json and
    /// produces per-module routing recommendations based on historical
    /// yield for this target kind. The --adaptive flag acts on these.
    pub adaptive_routing: AdaptiveRouting,
    pub optimization_hints: Vec<String>,
    pub enrichment_lineage: Vec<LineageNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CoordinateCluster {
    /// Median lat/lon of cluster members.
    pub centroid_lat: f64,
    pub centroid_lon: f64,
    pub centroid_geohash: String,
    /// Member coordinate values (the original "lat,lon" strings).
    pub members: Vec<String>,
    pub member_count: usize,
    /// Diameter in km — distance between the two farthest members.
    pub diameter_km: f64,
    pub country_iso: Option<String>,
    pub timezone: String,
    /// How many independent modules contributed coords to this cluster.
    pub source_diversity: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityCluster {
    pub kind: String,
    /// Best representative value (longest member, ties broken alphabetically).
    pub canonical_value: String,
    /// All raw member values that fuzzy-matched.
    pub members: Vec<String>,
    pub member_count: usize,
    /// Highest confidence across all members.
    pub max_confidence: f64,
    /// Total corroboration sum across members.
    pub total_corroboration: u32,
    /// Distinct sources contributing to any cluster member.
    pub source_diversity: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AdaptiveRouting {
    /// Total scans in the ledger.
    pub ledger_scans: u64,
    /// Modules ranked by historical mean_entities_per_scan, highest first.
    pub historical_rank: Vec<ModuleHistoricalScore>,
    /// Modules with high zero-yield rate (≥80%) over enough scans (≥5)
    /// to be statistically meaningful. Candidates for --adaptive skip.
    pub recommended_skips: Vec<String>,
    /// Modules with consistently high yield (top-5 by mean_entities_per_scan).
    /// Candidates for elevated priority.
    pub recommended_priorities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ModuleHistoricalScore {
    pub name: String,
    pub scans_present: u64,
    pub mean_entities_per_scan: f64,
    pub zero_yield_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProximityEdge {
    pub from_value: String,
    pub to_value: String,
    pub distance_km: f64,
    pub from_country: Option<String>,
    pub to_country: Option<String>,
    pub same_country: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ModulePerformance {
    pub name: String,
    pub entities_emitted: usize,
    pub evidence_count: usize,
    pub mean_confidence: f64,
    pub unique_kinds: Vec<String>,
    /// Ratio of entities this module emitted alone vs. those also
    /// emitted by another source. Higher = more unique value.
    pub novelty_ratio: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConfidenceStats {
    pub n: usize,
    pub mean: f64,
    pub min: f64,
    pub max: f64,
    pub p50: f64,
    pub p90: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GeoPrecisionReport {
    pub coordinates_count: usize,
    pub address_count: usize,
    pub addresses_with_state: usize,
    pub addresses_with_country: usize,
    pub addresses_with_postal: usize,
    pub addresses_with_iso: usize,
    pub coords_with_geohash: usize,
    pub coords_with_timezone: usize,
    /// True if two or more independent sources produced coordinates
    /// within 5km of each other (geo-convergence signal).
    pub multi_source_convergence: bool,
    /// IANA timezones surfaced.
    pub timezones: Vec<String>,
    /// ISO country codes surfaced.
    pub iso_countries: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityOverlap {
    pub kind: String,
    pub value: String,
    pub sources: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineageNode {
    pub entity_uid: String,
    pub kind: String,
    pub value_preview: String,
    pub source_chain: Vec<String>,
    pub confidence: f64,
    pub corroboration: u32,
}

/// Normalise a name/address for fuzzy comparison — lowercase, strip
/// punctuation, collapse whitespace, drop common stop tokens.
fn normalize_for_fuzzy(s: &str) -> String {
    let lower = s.to_lowercase();
    let stripped: String = lower
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c.is_whitespace() {
                c
            } else {
                ' '
            }
        })
        .collect();
    let mut tokens: Vec<&str> = stripped
        .split_whitespace()
        .filter(|t| !matches!(*t, "mr" | "mrs" | "ms" | "dr" | "the" | "jr" | "sr"))
        .collect();
    tokens.sort_unstable();
    tokens.dedup();
    tokens.join(" ")
}

/// Token-set Jaccard similarity, with a substring-containment bonus for
/// short tokens (e.g. middle initials).
fn name_similarity(a: &str, b: &str) -> f64 {
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let ta: std::collections::HashSet<&str> = a.split_whitespace().collect();
    let tb: std::collections::HashSet<&str> = b.split_whitespace().collect();
    if ta.is_empty() || tb.is_empty() {
        return 0.0;
    }
    let intersection = ta.intersection(&tb).count();
    let union = ta.union(&tb).count();
    let jaccard = intersection as f64 / union as f64;
    // Substring bonus: if every token in the shorter set is a prefix of
    // some token in the longer set, treat as near-match.
    let (short, long) = if ta.len() <= tb.len() {
        (&ta, &tb)
    } else {
        (&tb, &ta)
    };
    let prefix_hits = short
        .iter()
        .filter(|t| long.iter().any(|l| l.starts_with(*t) || t.starts_with(l)))
        .count();
    let prefix_score = prefix_hits as f64 / short.len() as f64;
    (jaccard * 0.7 + prefix_score * 0.3).min(1.0)
}

/// Country-coherence score for a coordinate cluster relative to a
/// previously anchored country (audit O-001). Returns a multiplier
/// in [0.0, 1.0] that downweights coordinate clusters whose country
/// differs from the scan's anchored country unless backed by multiple
/// independent sources.
///
/// Rationale: SERP-derived coordinates often leak across borders
/// (e.g. a US Philadelphia centroid surfacing on an AU-anchored
/// subject scan). Single-source cross-border coordinates are almost
/// always noise; multi-source cross-border coordinates may be real
/// travel or a sibling entity and are kept at reduced weight.
pub fn country_coherence_weight(cluster: &CoordinateCluster, anchor_iso: &str) -> f64 {
    let Some(iso) = cluster.country_iso.as_deref() else {
        // Unknown country: neutral.
        return 0.7;
    };
    if iso.eq_ignore_ascii_case(anchor_iso) {
        return 1.0;
    }
    match cluster.source_diversity {
        0 | 1 => 0.05, // single-source cross-border is almost certainly noise
        2 => 0.30,
        _ => 0.60,
    }
}

/// Filter a list of coordinate clusters down to those that pass the
/// country-coherence threshold for the given anchor ISO.
pub fn filter_country_coherent(
    clusters: Vec<CoordinateCluster>,
    anchor_iso: &str,
    threshold: f64,
) -> Vec<CoordinateCluster> {
    clusters
        .into_iter()
        .filter(|c| country_coherence_weight(c, anchor_iso) >= threshold)
        .collect()
}

/// Cluster Person and Address entities by fuzzy name similarity.
/// Threshold 0.6 = "Jordan Meyer" ↔ "Jordan L Meyer" match.
fn cluster_entities_fuzzy(entities: &[Entity]) -> Vec<EntityCluster> {
    use std::collections::BTreeMap;
    let mut groups: BTreeMap<String, Vec<&Entity>> = BTreeMap::new();

    for e in entities {
        if !matches!(
            e.kind.to_string().as_str(),
            "person" | "address" | "organisation"
        ) {
            continue;
        }
        let norm = normalize_for_fuzzy(&e.value);
        if norm.is_empty() {
            continue;
        }
        // Find an existing group whose centroid is similar enough.
        let mut assigned = false;
        let group_keys: Vec<String> = groups.keys().cloned().collect();
        for key in group_keys {
            if name_similarity(&key, &norm) >= 0.6 {
                groups.entry(key).or_default().push(e);
                assigned = true;
                break;
            }
        }
        if !assigned {
            groups.entry(norm).or_default().push(e);
        }
    }

    let mut clusters: Vec<EntityCluster> = groups
        .into_iter()
        .filter(|(_, members)| !members.is_empty())
        .map(|(_, members)| {
            // Canonical = longest value, tiebreak alphabetical
            let mut canonical = members[0].value.clone();
            for m in &members[1..] {
                if m.value.len() > canonical.len()
                    || (m.value.len() == canonical.len() && m.value < canonical)
                {
                    canonical = m.value.clone();
                }
            }
            let max_conf = members.iter().map(|e| e.confidence).fold(0.0f64, f64::max);
            let total_corr = members.iter().map(|e| e.corroboration).sum();
            let mut sources: std::collections::HashSet<String> = std::collections::HashSet::new();
            for m in &members {
                for ev in &m.evidence {
                    sources.insert(ev.source.clone());
                }
            }
            let raw_values: Vec<String> = members.iter().map(|e| e.value.clone()).collect();
            EntityCluster {
                kind: members[0].kind.to_string(),
                canonical_value: canonical,
                member_count: raw_values.len(),
                members: raw_values,
                max_confidence: max_conf,
                total_corroboration: total_corr,
                source_diversity: sources.len(),
            }
        })
        // Diversity floor (audit O-002): a fuzzy-name cluster from a
        // single source is identity-pollution risk unless deeply
        // populated. Require either 2+ independent sources, OR 3+
        // member records from the same source (frequency-as-signal).
        .filter(|c| c.member_count >= 2 && (c.source_diversity >= 2 || c.member_count >= 3))
        .collect();

    // Sort: most-corroborated clusters first
    clusters.sort_by_key(|c| std::cmp::Reverse(c.total_corroboration));
    clusters.truncate(30);
    clusters
}

/// Cluster coordinates by ~5km proximity using single-linkage.
fn cluster_coordinates(
    coords: &[(f64, f64, String, std::collections::HashSet<String>)],
) -> Vec<CoordinateCluster> {
    const THRESHOLD_KM: f64 = 5.0;
    let mut parent: Vec<usize> = (0..coords.len()).collect();
    fn find(parent: &mut [usize], i: usize) -> usize {
        if parent[i] != i {
            parent[i] = find(parent, parent[i]);
        }
        parent[i]
    }
    for i in 0..coords.len() {
        for j in (i + 1)..coords.len() {
            let d = crate::util::geohash::haversine_km(
                coords[i].0,
                coords[i].1,
                coords[j].0,
                coords[j].1,
            );
            if d <= THRESHOLD_KM {
                let ri = find(&mut parent, i);
                let rj = find(&mut parent, j);
                if ri != rj {
                    parent[ri] = rj;
                }
            }
        }
    }

    let mut groups: std::collections::BTreeMap<usize, Vec<usize>> =
        std::collections::BTreeMap::new();
    for i in 0..coords.len() {
        let root = find(&mut parent, i);
        groups.entry(root).or_default().push(i);
    }

    let mut clusters: Vec<CoordinateCluster> = groups
        .into_values()
        .map(|indices| {
            let lats: Vec<f64> = indices.iter().map(|&i| coords[i].0).collect();
            let lons: Vec<f64> = indices.iter().map(|&i| coords[i].1).collect();
            let n = lats.len();
            let mut lat_sorted = lats.clone();
            lat_sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            let mut lon_sorted = lons.clone();
            lon_sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            let centroid_lat = lat_sorted[n / 2];
            let centroid_lon = lon_sorted[n / 2];
            // Diameter
            let mut diameter = 0.0f64;
            for i in 0..n {
                for j in (i + 1)..n {
                    let d = crate::util::geohash::haversine_km(lats[i], lons[i], lats[j], lons[j]);
                    if d > diameter {
                        diameter = d;
                    }
                }
            }
            let mut all_sources: std::collections::HashSet<String> =
                std::collections::HashSet::new();
            for &i in &indices {
                for s in &coords[i].3 {
                    all_sources.insert(s.clone());
                }
            }
            CoordinateCluster {
                centroid_lat,
                centroid_lon,
                centroid_geohash: crate::util::geohash::geohash(centroid_lat, centroid_lon, 7),
                members: indices.iter().map(|&i| coords[i].2.clone()).collect(),
                member_count: n,
                diameter_km: (diameter * 1000.0).round() / 1000.0,
                country_iso: crate::util::geohash::reverse_country_iso(centroid_lat, centroid_lon)
                    .map(str::to_string),
                timezone: crate::util::geohash::timezone_for(centroid_lat, centroid_lon)
                    .to_string(),
                source_diversity: all_sources.len(),
            }
        })
        .collect();

    clusters.sort_by_key(|c| std::cmp::Reverse(c.member_count));
    clusters
}

/// Read the cross-scan ledger and produce per-module routing recommendations.
pub fn read_adaptive_routing() -> AdaptiveRouting {
    let path = ledger_path();
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
            format!("{}…", &e.value[..57])
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
    let source_confidence: HashMap<String, ConfidenceStats> = source_conf
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
        let conf = source_confidence
            .get(&perf.name)
            .map(|s| s.mean)
            .unwrap_or(0.0);
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
    modules_by_yield.sort_by_key(|m| std::cmp::Reverse(m.entities_emitted));

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
    cross_source_overlap.sort_by_key(|o| std::cmp::Reverse(o.sources.len()));
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
    persist_ledger(&modules_by_yield, &kind_counts);

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
        entity_kind_counts: kind_counts,
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

/// Persistent cross-scan ledger. Stored under $HOME/.huntsman/.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ModuleLedger {
    pub total_scans: u64,
    pub last_updated: u64,
    pub per_module: HashMap<String, LedgerEntry>,
    pub kind_distribution: HashMap<String, u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LedgerEntry {
    pub scans_present: u64,
    pub total_entities: u64,
    pub mean_entities_per_scan: f64,
    pub zero_yield_scans: u64,
    pub zero_yield_rate: f64,
}

fn ledger_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home)
        .join(".huntsman")
        .join("module_stats.json")
}

fn persist_ledger(modules: &[ModulePerformance], kinds: &HashMap<String, usize>) {
    let path = ledger_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let mut ledger: ModuleLedger = std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    ledger.total_scans = ledger.total_scans.saturating_add(1);
    ledger.last_updated = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    for m in modules {
        let entry = ledger.per_module.entry(m.name.clone()).or_default();
        entry.scans_present = entry.scans_present.saturating_add(1);
        entry.total_entities = entry
            .total_entities
            .saturating_add(m.entities_emitted as u64);
        if m.entities_emitted == 0 {
            entry.zero_yield_scans = entry.zero_yield_scans.saturating_add(1);
        }
        entry.mean_entities_per_scan = entry.total_entities as f64 / entry.scans_present as f64;
        entry.zero_yield_rate = entry.zero_yield_scans as f64 / entry.scans_present as f64;
    }
    for (kind, n) in kinds {
        let counter = ledger.kind_distribution.entry(kind.clone()).or_default();
        *counter = counter.saturating_add(*n as u64);
    }

    if let Ok(s) = serde_json::to_string_pretty(&ledger) {
        let _ = std::fs::write(&path, s);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::entity::{Entity, EntityKind, Evidence};

    fn ent(kind: EntityKind, val: &str, conf: f64, source: &str) -> Entity {
        let mut e = Entity::new(kind, val, conf, "test-scan-id");
        e.add_evidence(Evidence::new(source, format!("test ev from {source}")));
        e
    }

    #[test]
    fn analyse_empty_scan() {
        let d = analyse("sid", "email", "x@y.com", 100, &[]);
        assert_eq!(d.modules_by_yield.len(), 0);
        assert_eq!(d.geo_precision.coordinates_count, 0);
        assert!(!d.optimization_hints.is_empty());
    }

    #[test]
    fn analyse_ranks_modules_by_yield() {
        let entities = vec![
            ent(EntityKind::Email, "a@b.com", 0.8, "modA"),
            ent(EntityKind::Email, "c@d.com", 0.8, "modA"),
            ent(EntityKind::Email, "e@f.com", 0.8, "modA"),
            ent(EntityKind::Username, "alice", 0.7, "modB"),
        ];
        let d = analyse("sid", "email", "x@y.com", 100, &entities);
        assert_eq!(d.modules_by_yield[0].name, "modA");
        assert_eq!(d.modules_by_yield[0].entities_emitted, 3);
        assert_eq!(d.modules_by_yield[1].name, "modB");
    }

    #[test]
    fn analyse_computes_confidence_stats() {
        let entities = vec![
            ent(EntityKind::Email, "a", 0.5, "src"),
            ent(EntityKind::Email, "b", 0.7, "src"),
            ent(EntityKind::Email, "c", 0.9, "src"),
        ];
        let d = analyse("sid", "email", "x@y.com", 50, &entities);
        let s = &d.source_confidence["src"];
        assert_eq!(s.n, 3);
        assert!((s.mean - 0.7).abs() < 0.01);
        assert_eq!(s.min, 0.5);
        assert_eq!(s.max, 0.9);
    }

    #[test]
    fn analyse_geo_precision_counts() {
        let mut c = Entity::new(EntityKind::Coordinates, "-33.86,151.21", 0.8, "sid");
        c.add_evidence(
            Evidence::new("ip_geo", "coord ev")
                .with_attr("geohash", "r3gx2f7")
                .with_attr("timezone", "Australia/Sydney"),
        );
        let mut a = Entity::new(EntityKind::Address, "Sydney, NSW, AU", 0.7, "sid");
        a.add_evidence(
            Evidence::new("breach", "addr")
                .with_attr("addr_state", "NSW")
                .with_attr("addr_country", "Australia")
                .with_attr("addr_iso", "AU"),
        );
        let d = analyse("sid", "name", "X", 100, &[c, a]);
        assert_eq!(d.geo_precision.coordinates_count, 1);
        assert_eq!(d.geo_precision.coords_with_geohash, 1);
        assert_eq!(d.geo_precision.coords_with_timezone, 1);
        assert_eq!(d.geo_precision.address_count, 1);
        assert_eq!(d.geo_precision.addresses_with_iso, 1);
        assert!(d.geo_precision.iso_countries.contains(&"AU".to_string()));
    }

    #[test]
    fn analyse_detects_cross_source_overlap() {
        let mut e1 = Entity::new(EntityKind::Email, "shared@x.com", 0.8, "sid");
        e1.add_evidence(Evidence::new("modA", "ev"));
        let mut e2 = Entity::new(EntityKind::Email, "shared@x.com", 0.8, "sid");
        e2.add_evidence(Evidence::new("modB", "ev"));
        let d = analyse("sid", "email", "x@y.com", 50, &[e1, e2]);
        assert_eq!(d.cross_source_overlap.len(), 1);
        assert_eq!(d.cross_source_overlap[0].sources.len(), 2);
    }

    #[test]
    fn analyse_emits_optimization_hints_for_zero_yield() {
        let d = analyse("sid", "email", "x@y.com", 100, &[]);
        // empty entities → always at least one hint
        assert!(!d.optimization_hints.is_empty());
    }

    #[test]
    fn name_similarity_matches_partial_names() {
        let a = normalize_for_fuzzy("Jordan Meyer");
        let b = normalize_for_fuzzy("Jordan L Meyer");
        let c = normalize_for_fuzzy("J Meyer");
        // Jordan Meyer ↔ Jordan L Meyer should be > 0.6
        assert!(
            name_similarity(&a, &b) >= 0.6,
            "got {}",
            name_similarity(&a, &b)
        );
        // Both should match J Meyer at least via prefix bonus
        assert!(name_similarity(&a, &c) >= 0.4);
    }

    #[test]
    fn name_similarity_rejects_unrelated() {
        let a = normalize_for_fuzzy("Jordan Meyer");
        let b = normalize_for_fuzzy("Sarah Connor");
        assert!(name_similarity(&a, &b) < 0.3);
    }

    #[test]
    fn cluster_entities_collapses_name_variants() {
        let mut e1 = Entity::new(EntityKind::Person, "Jordan Meyer", 0.8, "sid");
        e1.add_evidence(Evidence::new("oathnet_pro", "ev"));
        let mut e2 = Entity::new(EntityKind::Person, "Jordan L Meyer", 0.75, "sid");
        e2.add_evidence(Evidence::new("see_know", "ev"));
        let mut e3 = Entity::new(EntityKind::Person, "Sarah Connor", 0.8, "sid");
        e3.add_evidence(Evidence::new("oathnet_pro", "ev"));
        let d = analyse("sid", "name", "Jordan Meyer", 100, &[e1, e2, e3]);
        // First two should form a cluster; Sarah Connor stays singleton (skipped)
        assert!(!d.entity_clusters.is_empty());
        let cluster = &d.entity_clusters[0];
        assert_eq!(cluster.member_count, 2);
        assert_eq!(cluster.source_diversity, 2);
    }

    #[test]
    fn cluster_coordinates_groups_nearby_points() {
        // Sydney Opera House + Sydney Harbour Bridge (~600m apart) should cluster.
        let mut e1 = Entity::new(EntityKind::Coordinates, "-33.8568,151.2153", 0.8, "sid");
        e1.add_evidence(
            Evidence::new("ip_geo", "ev")
                .with_attr("geohash", "r3gx2f7")
                .with_attr("timezone", "Australia/Sydney"),
        );
        let mut e2 = Entity::new(EntityKind::Coordinates, "-33.8523,151.2108", 0.7, "sid");
        e2.add_evidence(
            Evidence::new("ipinfo", "ev")
                .with_attr("geohash", "r3gx2f7")
                .with_attr("timezone", "Australia/Sydney"),
        );
        let d = analyse("sid", "ip", "1.1.1.1", 100, &[e1, e2]);
        assert_eq!(d.coordinate_clusters.len(), 1);
        assert_eq!(d.coordinate_clusters[0].member_count, 2);
        assert!(d.coordinate_clusters[0].diameter_km < 1.0);
        assert_eq!(d.coordinate_clusters[0].country_iso.as_deref(), Some("AU"));
    }

    fn make_cluster(iso: &str, diversity: usize) -> CoordinateCluster {
        CoordinateCluster {
            centroid_lat: 0.0,
            centroid_lon: 0.0,
            centroid_geohash: String::new(),
            members: vec!["0.0,0.0".to_string()],
            member_count: 1,
            diameter_km: 0.0,
            country_iso: Some(iso.to_string()),
            timezone: String::new(),
            source_diversity: diversity,
        }
    }

    #[test]
    fn country_coherence_keeps_anchor_match_at_full_weight() {
        let c = make_cluster("AU", 1);
        assert_eq!(country_coherence_weight(&c, "AU"), 1.0);
    }

    #[test]
    fn country_coherence_downweights_single_source_cross_border() {
        let c = make_cluster("US", 1);
        assert_eq!(country_coherence_weight(&c, "AU"), 0.05);
    }

    #[test]
    fn country_coherence_partially_keeps_multi_source_cross_border() {
        assert_eq!(country_coherence_weight(&make_cluster("US", 2), "AU"), 0.30);
        assert_eq!(country_coherence_weight(&make_cluster("US", 3), "AU"), 0.60);
    }

    #[test]
    fn country_coherence_neutralises_unknown_country() {
        let c = CoordinateCluster {
            centroid_lat: 0.0,
            centroid_lon: 0.0,
            centroid_geohash: String::new(),
            members: vec![],
            member_count: 0,
            diameter_km: 0.0,
            country_iso: None,
            timezone: String::new(),
            source_diversity: 1,
        };
        assert_eq!(country_coherence_weight(&c, "AU"), 0.7);
    }

    #[test]
    fn filter_country_coherent_drops_noise() {
        let clusters = vec![
            make_cluster("AU", 1), // 1.0 -> kept
            make_cluster("US", 1), // 0.05 -> dropped at threshold 0.5
            make_cluster("US", 3), // 0.60 -> kept at threshold 0.5
        ];
        let kept = filter_country_coherent(clusters, "AU", 0.5);
        assert_eq!(kept.len(), 2);
    }

    #[test]
    fn fuzzy_cluster_drops_single_source_doublet() {
        // Two address entities, both from the same source. With the
        // diversity floor in place, this should NOT be reported as a
        // cluster (member_count=2, source_diversity=1).
        let mut e1 = Entity::new(EntityKind::Address, "Haigen Li", 0.3, "sid");
        e1.add_evidence(Evidence::new("oathnet_pro", "ev"));
        let mut e2 = Entity::new(EntityKind::Address, "Haigen Li, Pingan Asset", 0.3, "sid");
        e2.add_evidence(Evidence::new("oathnet_pro", "ev"));
        let d = analyse("sid", "name", "Haigen Bamford", 100, &[e1, e2]);
        // Identity-pollution candidate filtered out.
        let polluted = d
            .entity_clusters
            .iter()
            .any(|c| c.canonical_value.contains("Pingan"));
        assert!(!polluted);
    }

    #[test]
    fn fuzzy_cluster_keeps_triplet_from_single_source() {
        // Three same-source records is frequency-as-signal; kept.
        let mut e1 = Entity::new(EntityKind::Person, "Haigen Bamford", 0.5, "sid");
        e1.add_evidence(Evidence::new("oathnet_pro", "ev"));
        let mut e2 = Entity::new(EntityKind::Person, "HAIGEN BAMFORD", 0.5, "sid");
        e2.add_evidence(Evidence::new("oathnet_pro", "ev"));
        let mut e3 = Entity::new(EntityKind::Person, "haigen bamford", 0.5, "sid");
        e3.add_evidence(Evidence::new("oathnet_pro", "ev"));
        let d = analyse("sid", "name", "Haigen Bamford", 100, &[e1, e2, e3]);
        let found = d
            .entity_clusters
            .iter()
            .any(|c| c.canonical_value.to_lowercase().contains("haigen"));
        assert!(found);
    }
}
