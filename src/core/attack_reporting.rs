//! Hierarchy-aware reporting over raw MITRE ATT&CK Reconnaissance coverage.
//!
//! [`crate::core::attack::Coverage`] intentionally records the literal ATT&CK
//! objects HSE claims: parent techniques and sub-techniques alike. That is the
//! right representation for provenance and Navigator export, but it is the
//! wrong denominator for a human-facing percentage because a family with many
//! children would be counted once for its parent and again for every child.
//!
//! This module projects that raw object set into independent **leaf
//! capabilities**: every sub-technique is a leaf, while a parent technique is a
//! leaf only when ATT&CK gives it no sub-techniques in TA0043. Parents with
//! children are reported as roll-ups and never independently affect the score.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use super::attack::{Coverage, Technique, reconnaissance};

/// Machine-readable description of the denominator used by the public score.
pub const COVERAGE_BASIS: &str = "leaf-techniques";

/// Reconnaissance leaf capabilities HSE deliberately does not perform.
///
/// `T1598.*` requires active solicitation/social engineering. `T1681` is
/// threat-actor reconnaissance on threat-vendor reporting about one's own
/// campaign/activity (distinct from victim-targeting `T1597.001`). `T1682`
/// queries public AI services, which the runtime deliberately does not do.
const INTENTIONAL_EXCLUSIONS: &[&str] = &[
    "T1598.001",
    "T1598.002",
    "T1598.003",
    "T1598.004",
    "T1681",
    "T1682",
];

/// One parent technique whose sub-techniques are scored independently.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ParentRollup {
    /// Parent ATT&CK technique id.
    pub id: &'static str,
    /// Parent ATT&CK technique name.
    pub name: &'static str,
    /// Whether HSE also directly claims the parent object itself.
    pub directly_covered: bool,
    /// Number of covered child sub-techniques.
    pub covered_children: usize,
    /// Number of child sub-techniques in the current TA0043 catalogue.
    pub total_children: usize,
}

/// Human-facing, hierarchy-aware projection of raw Reconnaissance coverage.
#[derive(Debug, Clone, Serialize)]
pub struct HierarchyCoverage {
    /// Always [`COVERAGE_BASIS`].
    pub coverage_basis: &'static str,
    /// Independent leaf capabilities in TA0043.
    pub leaf_techniques_total: usize,
    /// Covered independent leaf capabilities.
    pub leaf_techniques_covered: usize,
    /// `leaf_techniques_covered / leaf_techniques_total`.
    pub coverage_fraction: f64,
    /// Literal ATT&CK objects (parents + sub-techniques) in TA0043.
    pub attack_objects_total: usize,
    /// Literal ATT&CK objects directly claimed by HSE.
    pub attack_objects_covered: usize,
    /// Covered leaf capabilities, catalogue-sorted.
    pub covered_leaves: Vec<&'static Technique>,
    /// Uncovered leaf capabilities, catalogue-sorted.
    pub uncovered_leaves: Vec<&'static Technique>,
    /// Uncovered leaves that represent material collection capability gaps.
    pub capability_gaps: Vec<&'static Technique>,
    /// Uncovered leaves deliberately outside HSE's collection contract.
    pub intentional_exclusions: Vec<&'static Technique>,
    /// Parent families with children, catalogue-sorted.
    pub parent_rollups: Vec<ParentRollup>,
}

/// Derive the hierarchy-aware reporting view from raw ATT&CK coverage.
#[must_use]
pub fn hierarchy_coverage(raw: &Coverage) -> HierarchyCoverage {
    let recon = reconnaissance();
    let covered_ids: BTreeSet<&str> = raw
        .covered
        .iter()
        .map(|covered| covered.technique.id)
        .collect();

    let mut children_by_parent: BTreeMap<&'static str, Vec<&'static Technique>> =
        BTreeMap::new();
    for technique in &recon {
        if !technique.is_subtechnique {
            continue;
        }
        if let Some((parent, _)) = technique.id.split_once('.') {
            children_by_parent.entry(parent).or_default().push(*technique);
        }
    }

    let leaves: Vec<&'static Technique> = recon
        .iter()
        .copied()
        .filter(|technique| {
            technique.is_subtechnique || !children_by_parent.contains_key(technique.id)
        })
        .collect();
    let (covered_leaves, uncovered_leaves): (Vec<_>, Vec<_>) = leaves
        .iter()
        .copied()
        .partition(|technique| covered_ids.contains(technique.id));

    let (intentional_exclusions, capability_gaps): (Vec<_>, Vec<_>) = uncovered_leaves
        .iter()
        .copied()
        .partition(|technique| INTENTIONAL_EXCLUSIONS.contains(&technique.id));

    let parent_rollups = recon
        .iter()
        .copied()
        .filter(|technique| !technique.is_subtechnique)
        .filter_map(|parent| {
            let children = children_by_parent.get(parent.id)?;
            Some(ParentRollup {
                id: parent.id,
                name: parent.name,
                directly_covered: covered_ids.contains(parent.id),
                covered_children: children
                    .iter()
                    .filter(|child| covered_ids.contains(child.id))
                    .count(),
                total_children: children.len(),
            })
        })
        .collect();

    #[allow(clippy::cast_precision_loss)]
    let coverage_fraction = if leaves.is_empty() {
        0.0
    } else {
        covered_leaves.len() as f64 / leaves.len() as f64
    };

    HierarchyCoverage {
        coverage_basis: COVERAGE_BASIS,
        leaf_techniques_total: leaves.len(),
        leaf_techniques_covered: covered_leaves.len(),
        coverage_fraction,
        attack_objects_total: raw.covered.len() + raw.uncovered.len(),
        attack_objects_covered: raw.covered.len(),
        covered_leaves,
        uncovered_leaves,
        capability_gaps,
        intentional_exclusions,
        parent_rollups,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::core::attack::coverage;

    #[test]
    fn v19_2_reconnaissance_hierarchy_has_37_independent_leaf_capabilities() {
        let raw = coverage(&BTreeMap::new());
        let report = hierarchy_coverage(&raw);

        assert_eq!(report.attack_objects_total, 46);
        assert_eq!(report.leaf_techniques_total, 37);
        assert_eq!(report.parent_rollups.len(), 9);
        assert_eq!(report.uncovered_leaves.len(), 37);
    }

    #[test]
    fn deliberate_exclusions_are_leaf_only_and_do_not_hide_actionable_gaps() {
        let raw = coverage(&BTreeMap::new());
        let report = hierarchy_coverage(&raw);
        let excluded: Vec<&str> = report
            .intentional_exclusions
            .iter()
            .map(|technique| technique.id)
            .collect();

        assert_eq!(excluded, INTENTIONAL_EXCLUSIONS);
        assert!(
            report
                .capability_gaps
                .iter()
                .any(|technique| technique.id == "T1590.003")
        );
    }
}
