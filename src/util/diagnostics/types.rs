//! All public diagnostic structs.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanDiagnostics {
    pub scan_id: String,
    pub seed_kind: String,
    pub seed_value: String,
    pub wall_time_ms: u64,
    pub modules_by_yield: Vec<ModulePerformance>,
    // BTreeMap (not HashMap) so the serialised JSON has a stable, sorted key
    // order: identical inputs must produce byte-identical diagnostics, or the
    // "findings reproduce identically" guarantee (and any hash/diff/cache of a
    // report) breaks. HashMap iteration order is randomised per instance.
    pub source_confidence: std::collections::BTreeMap<String, ConfidenceStats>,
    pub entity_kind_counts: std::collections::BTreeMap<String, usize>,
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
    /// Confidence-weighted geometric median (Weiszfeld, outlier-robust).
    /// Falls back to positional median when < 2 distinct points exist.
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
    /// Robust uncertainty radius: median distance from the geometric median
    /// to all cluster members (same 0.5 breakdown point as the median).
    pub median_radius_km: f64,
    /// Worst-case bounding radius: Welzl minimum-enclosing-circle radius.
    /// Every cluster member lies within `enclosing_radius_km` km of the centroid
    /// by great-circle distance (radial bound, not a per-axis ± box bound).
    pub enclosing_radius_km: f64,
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
