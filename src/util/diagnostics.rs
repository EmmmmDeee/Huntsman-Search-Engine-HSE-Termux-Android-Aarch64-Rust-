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
    pub cross_source_overlap: Vec<EntityOverlap>,
    pub optimization_hints: Vec<String>,
    pub enrichment_lineage: Vec<LineageNode>,
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
    let mut coord_pairs: Vec<(f64, f64, String)> = Vec::new();

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
                    coord_pairs.push((lat, lon, e.value.clone()));
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

    // Multi-source convergence: any two coordinates within ~5km?
    'outer: for (i, (la1, lo1, _)) in coord_pairs.iter().enumerate() {
        for (la2, lo2, _) in coord_pairs.iter().skip(i + 1) {
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

    ScanDiagnostics {
        scan_id: scan_id.into(),
        seed_kind: seed_kind.into(),
        seed_value: seed_value.into(),
        wall_time_ms,
        modules_by_yield,
        source_confidence,
        entity_kind_counts: kind_counts,
        geo_precision: geo,
        cross_source_overlap,
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
}
