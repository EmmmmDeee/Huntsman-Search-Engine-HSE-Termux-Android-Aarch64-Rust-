//! Fuzzy match, clustering, and geo helpers.

use super::types::{CoordinateCluster, EntityCluster};
use crate::core::entity::Entity;

/// Normalise a name/address for fuzzy comparison — lowercase, strip
/// punctuation, collapse whitespace, drop common stop tokens.
pub(super) fn normalize_for_fuzzy(s: &str) -> String {
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
pub(super) fn name_similarity(a: &str, b: &str) -> f64 {
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
pub(super) fn cluster_entities_fuzzy(entities: &[Entity]) -> Vec<EntityCluster> {
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
pub(super) fn cluster_coordinates(
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
