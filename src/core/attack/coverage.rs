//! Per-scan ATT&CK **Reconnaissance** coverage — the rollup + MITRE Navigator
//! layer the `/scans/{id}/attack` surface serialises. Split out of `attack/mod.rs`
//! (behaviour-preserving): the catalogue + lookups live in the parent, this is the
//! coverage-report OUTPUT layer built from the `attack:<id>` tags the engine stamps.

use serde::Serialize;

use super::{TACTIC_ID, TACTIC_NAME, Technique, reconnaissance, uncovered};

/// One exercised technique in a [`Coverage`] rollup: the catalogued technique
/// plus the number of scan entities collected via it.
#[derive(Debug, Clone, Serialize)]
pub struct CoveredTechnique {
    /// The catalogued technique (`id` + `name`), flattened into the object.
    #[serde(flatten)]
    pub technique: Technique,
    /// How many of the scan's entities carry this technique's `attack:<id>` tag.
    pub entity_count: usize,
}

/// One exercised technique broken down by entity type: how many entities of
/// each kind contributed to coverage of a single technique.
#[derive(Debug, Clone, Serialize)]
pub struct TechniqueByEntityType {
    /// The technique id + name.
    #[serde(flatten)]
    pub technique: Technique,
    /// Entity count per kind (e.g., `{ "Email": 5, "Username": 3 }`).
    pub by_entity_type: std::collections::BTreeMap<String, usize>,
}

/// A scan's MITRE ATT&CK **Reconnaissance** (TA0043) coverage: the techniques it
/// exercised (with entity counts) and the honest uncovered gaps, both in the
/// catalogue's sorted order. Built by [`coverage`] from the `attack:<id>` tags
/// the engine stamps on every admitted entity, and serialised straight to the
/// `/scans/{id}/attack` API surface.
#[derive(Debug, Clone, Serialize)]
pub struct Coverage {
    /// Always [`TACTIC_ID`] — the one Enterprise tactic HSE honestly performs.
    pub tactic_id: &'static str,
    /// Always [`TACTIC_NAME`].
    pub tactic_name: &'static str,
    /// Techniques the scan actually exercised, catalogue-sorted.
    pub covered: Vec<CoveredTechnique>,
    /// Catalogued TA0043 techniques the scan performed no collection for — the
    /// honest gaps, straight from [`uncovered`].
    pub uncovered: Vec<&'static Technique>,
    /// `covered.len() / reconnaissance().len()`, in `0.0..=1.0`.
    pub coverage_fraction: f64,
}

/// Roll a scan's exercised technique IDs (with per-technique entity counts —
/// typically the `attack:<id>` tags counted across the scan's entities) up into
/// a [`Coverage`]. Unknown IDs are ignored (the drift guard keeps them from ever
/// being emitted). Covered techniques and gaps come back catalogue-sorted, so
/// the rollup is deterministic regardless of entity iteration order.
#[must_use]
pub fn coverage(exercised: &std::collections::BTreeMap<String, usize>) -> Coverage {
    let recon = reconnaissance();
    let covered: Vec<CoveredTechnique> = recon
        .iter()
        .filter_map(|t| {
            exercised.get(t.id).map(|&entity_count| CoveredTechnique {
                technique: **t,
                entity_count,
            })
        })
        .collect();
    let gaps = uncovered(|id| exercised.contains_key(id));
    #[allow(clippy::cast_precision_loss)]
    let coverage_fraction = if recon.is_empty() {
        0.0
    } else {
        covered.len() as f64 / recon.len() as f64
    };
    Coverage {
        tactic_id: TACTIC_ID,
        tactic_name: TACTIC_NAME,
        covered,
        uncovered: gaps,
        coverage_fraction,
    }
}

/// Compute Reconnaissance technique coverage broken down by entity type.
/// This shows what kinds of entities carry each technique, enabling analysis
/// of collection depth across entity dimensions. For example, if a scan's
/// `T1589.002` (Email Addresses) technique is carried only by Breach entities
/// (not Search/Social collection), the gap is visible — operators can prioritize
/// module expansion accordingly.
///
/// Takes a list of (entity_kind, technique_id) pairs from the scan's entities
/// (each entity may contribute multiple technique IDs). Returns techniques in
/// catalogue order with per-type breakdowns (type-sorted within each technique).
#[must_use]
pub fn coverage_by_entity_type(
    entity_techniques: &[(String, String)],
) -> Vec<TechniqueByEntityType> {
    use std::collections::BTreeMap;

    // Aggregate: technique_id → kind → count
    let mut by_technique: BTreeMap<String, BTreeMap<String, usize>> = BTreeMap::new();
    for (kind, tech_id) in entity_techniques {
        by_technique
            .entry(tech_id.clone())
            .or_default()
            .entry(kind.clone())
            .and_modify(|c| *c += 1)
            .or_insert(1);
    }

    // Build result in catalogue order
    reconnaissance()
        .iter()
        .filter_map(|t| {
            by_technique
                .remove(t.id)
                .map(|by_entity_type| TechniqueByEntityType {
                    technique: **t,
                    by_entity_type,
                })
        })
        .collect()
}

/// Extract Reconnaissance technique IDs from a list of entities (typically the
/// correlated entities from a Correlation finding). Returns a sorted, deduplicated
/// set of technique IDs carried by the entities' `attack:<id>` tags.
///
/// This enables attribution tracing: "these entities were linked together by AU-123,
/// and they were discovered via these Reconnaissance techniques" — the full chain
/// from module → technique → entity → correlation.
#[must_use]
pub fn techniques_from_entities(entities: &[&crate::core::entity::Entity]) -> Vec<String> {
    use std::collections::BTreeSet;
    let mut techniques: BTreeSet<String> = BTreeSet::new();
    for e in entities {
        for tag in &e.tags {
            if let Some(tech_id) = tag.strip_prefix("attack:") {
                techniques.insert(tech_id.to_string());
            }
        }
    }
    techniques.into_iter().collect()
}

/// Serialise a [`Coverage`] as a MITRE ATT&CK **Navigator layer** — the standard
/// JSON the official [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
/// renders — so a scan's Reconnaissance coverage drops straight into MITRE's own
/// visualisation instead of living only in HSE's tags. Each exercised technique
/// carries a `score` equal to its entity count (the Navigator heat-map then shows
/// collection *intensity*); every uncovered TA0043 technique is emitted disabled
/// with `score: 0`, so the layer is an honest picture of exactly what HSE
/// collected and what it did not. `scan_label` names the source scan.
#[must_use]
pub fn navigator_layer(coverage: &Coverage, scan_label: &str) -> serde_json::Value {
    let max_score = coverage
        .covered
        .iter()
        .map(|c| c.entity_count)
        .max()
        .unwrap_or(0)
        .max(1);
    let mut techniques: Vec<serde_json::Value> = coverage
        .covered
        .iter()
        .map(|c| {
            serde_json::json!({
                "techniqueID": c.technique.id,
                "tactic": "reconnaissance",
                "score": c.entity_count,
                "enabled": true,
                "comment": c.technique.name,
            })
        })
        .collect();
    for t in &coverage.uncovered {
        techniques.push(serde_json::json!({
            "techniqueID": t.id,
            "tactic": "reconnaissance",
            "score": 0,
            "enabled": false,
            "comment": t.name,
        }));
    }
    serde_json::json!({
        "name": format!("HSE — {scan_label} (Reconnaissance coverage)"),
        "versions": { "attack": "16", "navigator": "5.1.0", "layer": "4.5" },
        "domain": "enterprise-attack",
        "description": "MITRE ATT&CK Reconnaissance (TA0043) coverage produced by \
                        Huntsman Search Engine. score = entities collected via each \
                        technique; disabled techniques are honest gaps (no collection \
                        performed). Scoped to TA0043 — a passive OSINT collector \
                        performs no post-compromise tactic.",
        "sorting": 3,
        "hideDisabled": false,
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffffff", "#66b1ff", "#0d4a90"],
            "minValue": 0,
            "maxValue": max_score
        },
        "legendItems": [],
    })
}
