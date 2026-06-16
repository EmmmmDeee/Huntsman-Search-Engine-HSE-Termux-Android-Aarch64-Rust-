//! GEOINT correlation rules — spatial clustering / convergence family.
//!
//! Clusters confirmed `Coordinates` entities by proximity (AU-014, AU-017),
//! walks the `CoLocatedWith` graph for transitive co-location (AU-032), and
//! synthesises a single best-estimate fix (AU-057). See `super::super`
//! (rules/mod.rs) for the shared helpers; all reach them via `use super::*` →
//! `geo/mod.rs` → `use super::*` → `rules/mod.rs`.

use super::*;

use crate::util::geohash::geohash;

pub(in crate::core::correlator) fn rule_au_014_geo_cluster(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    const GEO_TAGS: &[&str] = &["geoint", "wifi-observed"];
    entities_of_kind(entities, EntityKind::Coordinates)
        .into_iter()
        .filter_map(|e| {
            let hits: Vec<&str> = GEO_TAGS.iter().copied().filter(|t| e.has_tag(t)).collect();
            // Corroborating sources only: the deterministic `geo_normalize`
            // enrichment pass is not an independent geo observation, so a lone
            // postcode-centroid it touched must not look like a "cluster".
            let sources = e.corroborating_sources();
            if hits.len() >= 2 || sources.len() >= 2 {
                Some(Correlation {
                    rule_id: "AU-014".into(),
                    rule_name: "Geolocation cluster".into(),
                    severity: Severity::Medium,
                    description: format!(
                        "Coordinates '{}' confirmed by {} geo source(s)",
                        e.value,
                        sources.len().max(hits.len())
                    ),
                    entity_uids: vec![e.uid.clone()],
                    scan_id: scan_id.into(),
                    ts,
                    rank: 0.0,
                })
            } else {
                None
            }
        })
        .collect()
}

pub(in crate::core::correlator) fn rule_au_017_multi_geo_convergence(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    // Cheap precondition: fewer than two confirmed coordinate entities can never
    // form a cluster, so bail before parsing anything.
    if entities
        .iter()
        .filter(|e| e.kind == EntityKind::Coordinates && e.confidence >= 0.50)
        .take(2)
        .count()
        < 2
    {
        return Vec::new();
    }
    // Parse once through the canonical, range-validating helper so out-of-range
    // junk ("200,300") is dropped here rather than silently clustered. Each
    // surviving entity carries its (lat, lon) so the inner loop never re-parses.
    // Filter and parse fuse into one pass — no intermediate `coords` Vec.
    let mut parsed: Vec<(&Entity, (f64, f64))> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Coordinates && e.confidence >= 0.50)
        .filter_map(|c| crate::util::geohash::parse_coords(&c.value).map(|ll| (c, ll)))
        .collect();
    // Deterministic clustering: the greedy single-link assignment below
    // compares each point against the FIRST member of each cluster, so both
    // which point founds a cluster and which cluster a borderline point joins
    // depend on iteration order. The live pass feeds entities in HashMap
    // (randomised) order, so a chain geometry (A–B close, B–C close, A–C far)
    // clustered as {A,B} on one run and {A,B,C} on another — different uid
    // sets that the live and finalise passes then both persist as distinct
    // AU-017 rows. Sort by uid so identical entity sets always cluster
    // identically, whatever order the caller iterated.
    parsed.sort_by(|a, b| a.0.uid.cmp(&b.0.uid));
    let mut clusters: Vec<Vec<(&Entity, (f64, f64))>> = Vec::new();
    for &(c, (lat, lon)) in &parsed {
        let mut found = false;
        for cluster in &mut clusters {
            let (_, (rl, ro)) = cluster[0];
            if (lat - rl).abs() < 0.5 && (lon - ro).abs() < 0.5 {
                cluster.push((c, (lat, lon)));
                found = true;
                break;
            }
        }
        if !found {
            clusters.push(vec![(c, (lat, lon))]);
        }
    }
    clusters
        .into_iter()
        .filter(|cl| cl.len() >= 2)
        .map(|cl| {
            let uids: Vec<String> = cl.iter().map(|(e, _)| e.uid.clone()).collect();
            let sources: HashSet<&str> = cl
                .iter()
                .flat_map(|(e, _)| e.evidence.iter().map(|ev| ev.source.as_str()))
                .collect();
            Correlation {
                rule_id: "AU-017".into(),
                rule_name: "Multi-source geographic convergence".into(),
                severity: Severity::High,
                description: format!(
                    "{} coordinate entities converge within 0.5° (~55km), from {} source(s)",
                    cl.len(),
                    sources.len()
                ),
                entity_uids: uids,
                scan_id: scan_id.into(),
                ts,
                rank: 0.0,
            }
        })
        .collect()
}

/// AU-032 — Geographic co-location cluster (graph-aware). Walks the
/// `CoLocatedWith` edge graph and reports each connected component of
/// `COLOCATION_CLUSTER_MIN`+ Coordinates entities — i.e. three or more
/// independent coordinate sources that transitively converge within
/// `CO_LOCATION_KM`. This is the graph-structural (transitive-closure) signal
/// the pairwise geo rules (AU-017/AU-030) don't surface. Deterministic:
/// component membership is edge-defined and the output is uid-sorted.
pub(in crate::core::correlator) fn rule_au_032_colocation_cluster(
    entities: &[Entity],
    relations: &[Relation],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    use std::collections::{HashMap, HashSet};

    // Undirected adjacency from CoLocatedWith edges only.
    let mut adj: HashMap<&str, Vec<&str>> = HashMap::new();
    for r in relations {
        if r.kind == RelationKind::CoLocatedWith {
            adj.entry(r.from_uid.as_str()).or_default().push(&r.to_uid);
            adj.entry(r.to_uid.as_str()).or_default().push(&r.from_uid);
        }
    }
    if adj.is_empty() {
        return Vec::new();
    }

    let by_uid: HashMap<&str, &Entity> = entities.iter().map(|e| (e.uid.as_str(), e)).collect();

    // Connected components via DFS (stack). Iterate seed nodes in sorted order
    // so the emitted clusters are deterministic regardless of edge ordering.
    let mut nodes: Vec<&str> = adj.keys().copied().collect();
    nodes.sort_unstable();
    let mut visited: HashSet<&str> = HashSet::new();
    let mut out = Vec::new();
    for &start in &nodes {
        if !visited.insert(start) {
            continue;
        }
        let mut comp = vec![start];
        let mut stack = vec![start];
        while let Some(n) = stack.pop() {
            if let Some(neighbours) = adj.get(n) {
                for &m in neighbours {
                    if visited.insert(m) {
                        comp.push(m);
                        stack.push(m);
                    }
                }
            }
        }
        if comp.len() >= COLOCATION_CLUSTER_MIN {
            comp.sort_unstable();
            let sample = by_uid.get(comp[0]).map_or(comp[0], |e| e.value.as_str());
            let uids: Vec<String> = comp.iter().map(|u| (*u).to_string()).collect();
            out.push(Correlation::new(
                "AU-032",
                "Geographic co-location cluster",
                Severity::Medium,
                format!(
                    "{} coordinates converge within {:.0} km (e.g. {})",
                    comp.len(),
                    crate::core::relation::CO_LOCATION_KM,
                    sample
                ),
                uids,
                scan_id,
                ts,
            ));
        }
    }
    out
}

/// AU-057 — Synthesised location fix (weighted geometric median).
///
/// Collects all confirmed (`confidence ≥ 0.60`) `Coordinates` entities, weights
/// each by its confidence, and computes the
/// [`crate::util::geometry::weighted_geometric_median`] — the point that
/// minimises the confidence-weighted sum of great-circle distances to all
/// inputs. This converts the qualitative "sources agree" assertion from
/// AU-017/AU-030 into a single computable best-estimate lat/lon.
///
/// Requires ≥ 2 valid inputs; `High` at ≥ 3 inputs, `Medium` at 2.
pub(in crate::core::correlator) fn rule_au_057_synthesised_location_fix(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let candidates: Vec<(&Entity, (f64, f64))> =
        entities_of_kind(entities, EntityKind::Coordinates)
            .into_iter()
            .filter(|e| e.confidence >= 0.60)
            .filter_map(|e| crate::util::geohash::parse_coords(&e.value).map(|ll| (e, ll)))
            .collect();

    if candidates.len() < 2 {
        return Vec::new();
    }

    let weighted: Vec<((f64, f64), f64)> = candidates
        .iter()
        .map(|(e, ll)| (*ll, e.confidence))
        .collect();

    let Some((lat, lon)) = crate::util::geometry::weighted_geometric_median(&weighted) else {
        return Vec::new();
    };

    let gh = geohash(lat, lon, 5);
    let severity = if candidates.len() >= 3 {
        Severity::High
    } else {
        Severity::Medium
    };
    let uids: Vec<String> = candidates.iter().map(|(e, _)| e.uid.clone()).collect();

    vec![Correlation::new(
        "AU-057",
        "Synthesised location fix (weighted median)",
        severity,
        format!(
            "Weighted geometric median of {} confirmed coordinate(s): ({lat:.4}, {lon:.4}) \
             geohash={gh} — MITRE T1591.001",
            candidates.len()
        ),
        uids,
        scan_id,
        ts,
    )]
}
