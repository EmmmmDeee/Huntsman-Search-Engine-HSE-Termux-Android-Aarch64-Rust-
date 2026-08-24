//! All public diagnostic structs.
//!
//! These are the serialised shape of `hse diagnostics` — every field below is a
//! key in that JSON, so a rename here is a breaking change to anything parsing
//! the output. Documented per-field for that reason: the doc comment is the
//! schema description an operator reads.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Everything measured about one completed scan.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanDiagnostics {
    /// Id of the scan these diagnostics describe.
    pub scan_id: String,
    /// Target kind the scan was seeded with (`email`, `domain`, …).
    pub seed_kind: String,
    /// The seed value itself, as supplied.
    pub seed_value: String,
    /// Total wall-clock duration of the scan, milliseconds.
    pub wall_time_ms: u64,
    /// Per-module performance, ordered by how much each module yielded.
    pub modules_by_yield: Vec<ModulePerformance>,
    /// Confidence distribution per source.
    // BTreeMap (not HashMap) so the serialised JSON has a stable, sorted key
    // order: identical inputs must produce byte-identical diagnostics, or the
    // "findings reproduce identically" guarantee (and any hash/diff/cache of a
    // report) breaks. HashMap iteration order is randomised per instance.
    pub source_confidence: std::collections::BTreeMap<String, ConfidenceStats>,
    /// How many entities of each kind the scan produced. Sorted by key, for the
    /// same byte-identical-output reason as `source_confidence`.
    pub entity_kind_counts: std::collections::BTreeMap<String, usize>,
    /// How precise the scan's geographic output was.
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
    /// Entities that more than one source independently produced — the
    /// corroboration the confidence model rests on.
    pub cross_source_overlap: Vec<EntityOverlap>,
    /// Closed feedback loop: reads ~/.huntsman/module_stats.json and
    /// produces per-module routing recommendations based on historical
    /// yield for this target kind. The --adaptive flag acts on these.
    pub adaptive_routing: AdaptiveRouting,
    /// Human-readable suggestions for making the next scan of this seed
    /// kind cheaper or more productive.
    pub optimization_hints: Vec<String>,
    /// Per-entity provenance: which sources contributed to each finding.
    pub enrichment_lineage: Vec<LineageNode>,
}

/// A group of coordinates close enough together to be treated as one place.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CoordinateCluster {
    /// Confidence-weighted geometric median (Weiszfeld, outlier-robust).
    /// Falls back to positional median when < 2 distinct points exist.
    pub centroid_lat: f64,
    /// Longitude of the same centroid.
    pub centroid_lon: f64,
    /// The centroid encoded as a precision-7 geohash (~76 m cell).
    pub centroid_geohash: String,
    /// Member coordinate values (the original "lat,lon" strings).
    pub members: Vec<String>,
    /// Number of coordinates in the cluster.
    pub member_count: usize,
    /// Diameter in km — distance between the two farthest members.
    pub diameter_km: f64,
    /// ISO country code the centroid falls in, when it resolves offline.
    pub country_iso: Option<String>,
    /// IANA timezone of the centroid.
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

/// A set of `Person`/`Address` values that fuzzy-matched into one identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityCluster {
    /// Entity kind the cluster's members share.
    pub kind: String,
    /// Best representative value (longest member, ties broken alphabetically).
    pub canonical_value: String,
    /// All raw member values that fuzzy-matched.
    pub members: Vec<String>,
    /// Number of members in the cluster.
    pub member_count: usize,
    /// Highest confidence across all members.
    pub max_confidence: f64,
    /// Total corroboration sum across members.
    pub total_corroboration: u32,
    /// Distinct sources contributing to any cluster member.
    pub source_diversity: usize,
}

/// Routing advice derived from the cross-scan module ledger.
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

/// One module's lifetime record, as the ledger scores it.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ModuleHistoricalScore {
    /// Module name.
    pub name: String,
    /// Scans in which this module ran.
    pub scans_present: u64,
    /// Mean entities emitted per scan the module ran in.
    pub mean_entities_per_scan: f64,
    /// Fraction of those scans in which it emitted nothing, 0.0–1.0.
    pub zero_yield_rate: f64,
}

/// The distance between two Coordinates entities from the same scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProximityEdge {
    /// One endpoint's coordinate value.
    pub from_value: String,
    /// The other endpoint's coordinate value.
    pub to_value: String,
    /// Great-circle distance between them, km.
    pub distance_km: f64,
    /// ISO country of `from_value`, when it resolves.
    pub from_country: Option<String>,
    /// ISO country of `to_value`, when it resolves.
    pub to_country: Option<String>,
    /// Whether both endpoints resolved to the same country.
    pub same_country: bool,
}

/// What one module contributed to this scan.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ModulePerformance {
    /// Module name.
    pub name: String,
    /// Entities the module emitted.
    pub entities_emitted: usize,
    /// Evidence records attached to those entities.
    pub evidence_count: usize,
    /// Mean confidence across the module's entities.
    pub mean_confidence: f64,
    /// Distinct entity kinds the module produced.
    pub unique_kinds: Vec<String>,
    /// Ratio of entities this module emitted alone vs. those also
    /// emitted by another source. Higher = more unique value.
    pub novelty_ratio: f64,
}

/// Summary statistics over one source's confidence values.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConfidenceStats {
    /// Number of entities in the sample.
    pub n: usize,
    /// Arithmetic mean confidence.
    pub mean: f64,
    /// Lowest confidence observed.
    pub min: f64,
    /// Highest confidence observed.
    pub max: f64,
    /// Median (50th percentile).
    pub p50: f64,
    /// 90th percentile.
    pub p90: f64,
}

/// How complete and precise the scan's geographic output was.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GeoPrecisionReport {
    /// Coordinates entities produced.
    pub coordinates_count: usize,
    /// Address entities produced.
    pub address_count: usize,
    /// Of those addresses, how many carry a state/region.
    pub addresses_with_state: usize,
    /// How many carry a country.
    pub addresses_with_country: usize,
    /// How many carry a postal code.
    pub addresses_with_postal: usize,
    /// How many carry an ISO country code.
    pub addresses_with_iso: usize,
    /// Coordinates that were successfully geohashed.
    pub coords_with_geohash: usize,
    /// Coordinates resolved to an IANA timezone.
    pub coords_with_timezone: usize,
    /// True if two or more independent sources produced coordinates
    /// within 5km of each other (geo-convergence signal).
    pub multi_source_convergence: bool,
    /// IANA timezones surfaced.
    pub timezones: Vec<String>,
    /// ISO country codes surfaced.
    pub iso_countries: Vec<String>,
}

/// One entity that more than one source independently produced.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityOverlap {
    /// Entity kind.
    pub kind: String,
    /// Entity value.
    pub value: String,
    /// The sources that each produced it.
    pub sources: Vec<String>,
}

/// Provenance for a single entity: what produced it and how well corroborated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineageNode {
    /// Stable uid of the entity.
    pub entity_uid: String,
    /// Entity kind.
    pub kind: String,
    /// The value, truncated to 60 characters with an ellipsis when longer, so a
    /// lineage dump stays readable and does not restate a full credential blob.
    pub value_preview: String,
    /// Every source that contributed to this entity.
    pub source_chain: Vec<String>,
    /// Final confidence after merging.
    pub confidence: f64,
    /// Independent corroboration count.
    pub corroboration: u32,
}

/// Persistent cross-scan ledger. Stored under $HOME/.huntsman/.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ModuleLedger {
    /// Scans recorded since the ledger was created.
    pub total_scans: u64,
    /// Unix seconds at the last ledger write.
    pub last_updated: u64,
    /// Per-module lifetime tallies, keyed by module name.
    pub per_module: HashMap<String, LedgerEntry>,
    /// Lifetime count of entities produced per kind.
    pub kind_distribution: HashMap<String, u64>,
}

/// One module's accumulated totals in the [`ModuleLedger`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LedgerEntry {
    /// Scans in which this module ran.
    pub scans_present: u64,
    /// Entities emitted across all of them.
    pub total_entities: u64,
    /// `total_entities / scans_present`.
    pub mean_entities_per_scan: f64,
    /// How many of those scans produced nothing.
    pub zero_yield_scans: u64,
    /// `zero_yield_scans / scans_present`, 0.0–1.0.
    pub zero_yield_rate: f64,
}
