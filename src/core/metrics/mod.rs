//! Per-scan quality / telemetry measures — the evidence-driven optimisation
//! substrate.
//!
//! The engine ranks expansion candidates and the correlator flags clusters, but
//! neither answers the operator's blunt after-the-fact question: *how much
//! intelligence did this scan actually produce, and how well-corroborated is
//! it?* Tuning a scan (depth, budget, which modules to enable) needs an
//! objective, reproducible yardstick to optimise against — otherwise every
//! change is judged by eyeballing the entity table. This module is that
//! yardstick.
//!
//! [`compute`] is **pure synthesis** over a scan's already-derived [`Entity`] set
//! and [`Relation`] set. It is **read-only** —
//! it borrows both slices, mutates nothing, performs no I/O, contacts no
//! module, and never depends on a clock or on input order. Run it twice on the
//! same (unordered) inputs and you get a byte-identical [`ScanMetrics`].
//!
//! # Why these measures
//! Each field is an *objective* signal — a count, a fraction, or a deterministic
//! statistic — chosen because it captures one independent axis of scan quality:
//!
//! * **Volume** ([`ScanMetrics::total_entities`],
//!   [`ScanMetrics::entities_by_kind`], [`ScanMetrics::total_relations`],
//!   [`ScanMetrics::relations_by_kind`]) — raw yield and its shape across kinds.
//!   A scan that returns 4 000 CDN domains and one person looks very different
//!   here from a balanced identity sweep, which is exactly the infrastructure
//!   skew the convex allocator exists to resist.
//! * **Reliability** ([`ScanMetrics::tier_counts`],
//!   [`ScanMetrics::mean_confidence`], [`ScanMetrics::median_confidence`],
//!   [`ScanMetrics::corroborated_fraction`]) — how much of the yield is trusted
//!   versus speculative. The tier histogram and the multi-source fraction are
//!   the honest cross-correlation view; mean *and* median are both kept because
//!   a long tail of candidates drags the mean while the median reports the
//!   typical finding.
//! * **Connectivity** ([`ScanMetrics::linked_entity_fraction`],
//!   [`ScanMetrics::graph_density`]) — whether the findings form an attributed
//!   graph or a pile of orphan nodes. A person scan that produced nodes but no
//!   edges is a weaker result than one whose entities link into one footprint.
//! * **Provenance & continuity** ([`ScanMetrics::distinct_evidence_sources`],
//!   [`ScanMetrics::cross_scan_bridges`]) — breadth of independent sourcing and
//!   how much the scan tied into the historical flywheel.
//!
//! # Determinism discipline
//! All aggregates are order-independent. Per-kind counts are accumulated through
//! a [`BTreeMap`] so the emitted `Vec` is sorted by kind name; the UID and source
//! sets are [`BTreeSet`]s; and the floating-point statistics sum a **sorted copy**
//! of the confidences so the result does not depend on the order the entities were
//! supplied in. There is no [`std::collections::HashMap`] iteration anywhere in
//! the output path.

use std::collections::{BTreeMap, BTreeSet};

use crate::core::entity::{Classification, Entity};
use crate::core::relation::Relation;

/// Histogram of entities across the three [`Classification`] tiers.
///
/// Derived purely from [`Entity::classify`], so the split reflects effective
/// (cross-source) confidence, not the raw base
/// value. The three counts always sum to [`ScanMetrics::total_entities`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct TierCounts {
    /// Entities classified [`Classification::Verified`] (`C_eff ≥ 0.75`).
    pub verified: usize,
    /// Entities classified [`Classification::Probable`] (`0.40 ≤ C_eff < 0.75`).
    pub probable: usize,
    /// Entities classified [`Classification::Candidate`] (`C_eff < 0.40`).
    pub candidate: usize,
}

/// Objective, deterministic quality / telemetry measures for a single scan.
///
/// Produced by [`compute`] from a scan's entities and relations. Every field is
/// a count, a fraction in `[0, 1]`, or a deterministic statistic — there is no
/// hidden state, no clock, and no dependence on input order. See the
/// module-level documentation for what each measure signals and why.
///
/// Serialises in declaration order via `serde`; the two per-kind vectors are
/// sorted by kind name so the JSON is stable across runs.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct ScanMetrics {
    /// Total number of entities in the scan — raw discovery volume.
    pub total_entities: usize,
    /// Count of entities per [`EntityKind`](crate::core::entity::EntityKind),
    /// as `(kind_name, count)` pairs sorted ascending by kind name. A `Vec` of
    /// pairs (not a map) so the serialisation order is deterministic.
    pub entities_by_kind: Vec<(String, usize)>,
    /// Histogram of entities across the Verified / Probable / Candidate tiers.
    pub tier_counts: TierCounts,
    /// Arithmetic mean of every entity's
    /// [`c_effective`](crate::core::entity::Entity::c_effective). Defined as
    /// `0.0` for an empty scan. Computed over a sorted copy so it is
    /// order-independent.
    pub mean_confidence: f64,
    /// Median of every entity's
    /// [`c_effective`](crate::core::entity::Entity::c_effective) (mean of the
    /// two middle values for an even count). Defined as `0.0` for an empty scan.
    /// Kept alongside the mean because a long candidate tail pulls the mean down
    /// while the median reports the typical finding.
    pub median_confidence: f64,
    /// Fraction of entities corroborated by at least two distinct sources
    /// (`source_count() >= 2`). `0.0` for an empty scan. Multi-source agreement
    /// is the strongest cheap signal that a finding is real rather than noise.
    pub corroborated_fraction: f64,
    /// Total number of relations (typed edges) in the scan.
    pub total_relations: usize,
    /// Count of relations per
    /// [`RelationKind`](crate::core::relation::RelationKind), as
    /// `(kind_name, count)` pairs sorted ascending by kind name.
    pub relations_by_kind: Vec<(String, usize)>,
    /// Fraction of entities that are an endpoint (`from` or `to`) of at least
    /// one relation — graph connectivity. `0.0` for an empty scan. A scan whose
    /// findings link into a graph is more actionable than one of orphan nodes.
    pub linked_entity_fraction: f64,
    /// Undirected graph density: `total_relations / (n·(n−1)/2)` for `n`
    /// entities, clamped to `[0, 1]`. `0.0` when `n < 2` (no possible edges).
    /// Normalises edge count by scan size so a dense small graph and a sparse
    /// large one are comparable.
    pub graph_density: f64,
    /// Number of entities tagged as a cross-scan bridge — carrying any of
    /// `"cross-scan"`, `"cross-scan-cooccurrence"`, or `"cross-scan-relation"`.
    /// These are the historical-flywheel links: findings this scan shares with
    /// earlier ones.
    pub cross_scan_bridges: usize,
    /// Number of **distinct** `evidence.source` strings across all entities —
    /// the breadth of independent sourcing the scan drew on. Counts every
    /// distinct source label, including enrichment passes.
    pub distinct_evidence_sources: usize,
}

/// The tag values that mark an entity as a cross-scan bridge — a finding tying
/// this scan into the historical flywheel of earlier scans.
const CROSS_SCAN_TAGS: [&str; 3] = [
    "cross-scan",
    "cross-scan-cooccurrence",
    "cross-scan-relation",
];

/// Compute the [`ScanMetrics`] for a scan from its entities and relations.
///
/// **Pure, deterministic, read-only.** Borrows both slices and mutates nothing;
/// performs no I/O and reads no clock. The result is independent of the order
/// the entities and relations are supplied in — every aggregate either sorts its
/// inputs (the confidence statistics) or accumulates through an ordered map/set
/// (the per-kind counts, the endpoint and source sets) — so shuffling the inputs
/// yields a byte-identical [`ScanMetrics`]. Allocation is bounded by the input
/// size (one small map/set per aggregate, plus one `Vec<f64>` of confidences).
///
/// Edge cases are defined so the output is always finite and never `NaN`: for an
/// empty entity slice every count is `0`, every fraction and statistic is `0.0`,
/// and [`graph_density`](ScanMetrics::graph_density) is `0.0` whenever there are
/// fewer than two entities (no possible undirected edge).
///
/// ```
/// use huntsman_search_engine::core::metrics;
///
/// let m = metrics::compute(&[], &[]);
/// assert_eq!(m.total_entities, 0);
/// assert_eq!(m.mean_confidence, 0.0);
/// assert_eq!(m.graph_density, 0.0);
/// ```
#[must_use]
pub fn compute(entities: &[Entity], relations: &[Relation]) -> ScanMetrics {
    let total_entities = entities.len();
    let total_relations = relations.len();

    // ── Per-kind histograms (ordered map ⇒ sorted-by-name Vec) ──────────────
    let mut by_kind: BTreeMap<String, usize> = BTreeMap::new();
    for e in entities {
        *by_kind.entry(e.kind.to_string()).or_insert(0) += 1;
    }
    let entities_by_kind: Vec<(String, usize)> = by_kind.into_iter().collect();

    let mut rel_by_kind: BTreeMap<String, usize> = BTreeMap::new();
    for r in relations {
        *rel_by_kind.entry(r.kind.to_string()).or_insert(0) += 1;
    }
    let relations_by_kind: Vec<(String, usize)> = rel_by_kind.into_iter().collect();

    // ── Tier histogram + multi-source corroboration ─────────────────────────
    let mut tier_counts = TierCounts {
        verified: 0,
        probable: 0,
        candidate: 0,
    };
    let mut corroborated = 0usize;
    for e in entities {
        match e.classify() {
            Classification::Verified => tier_counts.verified += 1,
            Classification::Probable => tier_counts.probable += 1,
            Classification::Candidate => tier_counts.candidate += 1,
        }
        if e.source_count() >= 2 {
            corroborated += 1;
        }
    }

    // ── Confidence statistics over a SORTED copy (order-independent) ─────────
    let mut confidences: Vec<f64> = entities.iter().map(Entity::c_effective).collect();
    confidences.sort_by(f64::total_cmp);
    let mean_confidence = mean(&confidences);
    let median_confidence = median(&confidences);

    // ── Graph connectivity: endpoint set + density ──────────────────────────
    let mut endpoints: BTreeSet<&str> = BTreeSet::new();
    for r in relations {
        endpoints.insert(r.from_uid.as_str());
        endpoints.insert(r.to_uid.as_str());
    }
    let linked = entities
        .iter()
        .filter(|e| endpoints.contains(e.uid.as_str()))
        .count();
    let linked_entity_fraction = fraction(linked, total_entities);
    let graph_density = density(total_relations, total_entities);

    // ── Cross-scan bridges + distinct evidence sources ──────────────────────
    let cross_scan_bridges = entities
        .iter()
        .filter(|e| CROSS_SCAN_TAGS.iter().any(|t| e.has_tag(t)))
        .count();

    let mut sources: BTreeSet<&str> = BTreeSet::new();
    for e in entities {
        for ev in &e.evidence {
            sources.insert(ev.source.as_str());
        }
    }
    let distinct_evidence_sources = sources.len();

    ScanMetrics {
        total_entities,
        entities_by_kind,
        tier_counts,
        mean_confidence,
        median_confidence,
        corroborated_fraction: fraction(corroborated, total_entities),
        total_relations,
        relations_by_kind,
        linked_entity_fraction,
        graph_density,
        cross_scan_bridges,
        distinct_evidence_sources,
    }
}

/// Arithmetic mean of an already-sorted slice; `0.0` for an empty slice.
///
/// Summing the sorted copy (rather than the caller's arbitrary order) keeps the
/// result bit-identical under input shuffling. Defining the empty mean as `0.0`
/// avoids a `0/0` `NaN`.
fn mean(sorted: &[f64]) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let sum: f64 = sorted.iter().sum();
    sum / sorted.len() as f64
}

/// Median of an already-sorted slice; `0.0` for an empty slice. For an even
/// count it is the mean of the two central values.
fn median(sorted: &[f64]) -> f64 {
    let n = sorted.len();
    if n == 0 {
        return 0.0;
    }
    let mid = n / 2;
    if n % 2 == 1 {
        sorted[mid]
    } else {
        (sorted[mid - 1] + sorted[mid]) / 2.0
    }
}

/// `numerator / denominator` as a fraction in `[0, 1]`; `0.0` when the
/// denominator is `0` (an empty scan has no fraction to report).
fn fraction(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

/// Undirected graph density: `edges / (n·(n−1)/2)`, clamped to `[0, 1]`.
/// `0.0` for `n < 2`, where there is no possible undirected edge.
fn density(edges: usize, n: usize) -> f64 {
    if n < 2 {
        return 0.0;
    }
    // n·(n−1)/2 possible undirected edges. Compute in f64 (the counts are tiny
    // relative to the f64 mantissa for any realistic scan) and clamp so a
    // multigraph with parallel edges between the same pair can never exceed 1.0.
    let possible = (n as f64) * ((n - 1) as f64) / 2.0;
    (edges as f64 / possible).clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
