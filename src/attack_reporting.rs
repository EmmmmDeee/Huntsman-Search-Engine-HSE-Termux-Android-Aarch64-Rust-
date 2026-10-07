//! Hierarchy-aware reporting over raw MITRE ATT&CK Reconnaissance coverage.
//!
//! `attack::Coverage` records literal ATT&CK objects, including both parents
//! and sub-techniques. That representation is correct for provenance and
//! Navigator export, but a human-facing percentage should not count a parent
//! and its children as independent capabilities. This module projects the raw
//! object set onto independent leaf capabilities while preserving the raw
//! counts and parent roll-ups separately.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::attack::{Coverage, Technique, reconnaissance};

pub const COVERAGE_BASIS: &str = "leaf_techniques";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ParentRollup {
    pub id: &'static str,
    pub name: &'static str,
    pub directly_covered: bool,
    pub covered_children: usize,
    pub total_children: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct HierarchyCoverage {
    pub coverage_basis: &'static str,
    pub leaf_techniques_total: usize,
    pub leaf_techniques_covered: usize,
    pub coverage_fraction: f64,
    pub attack_objects_total: usize,
    pub attack_objects_covered: usize,
    pub covered_leaves: Vec<&'static Technique>,
    pub uncovered_leaves: Vec<&'static Technique>,
    pub parent_rollups: Vec<ParentRollup>,
}

/// Derive a hierarchy-aware coverage view from the current ATT&CK catalogue.
///
/// Parent techniques that have sub-techniques remain visible as roll-ups but do
/// not contribute an additional scored unit. A parent with no children remains
/// a leaf capability.
///
/// This function is deliberately catalogue-driven: no ATT&CK version, count, or
/// technique identifier is hard-coded here.
///
/// # Panics
/// This function does not panic for a well-formed catalogue. The catalogue
/// structure itself is independently validated by `attack` module tests.
#[must_use]
pub fn hierarchy_coverage(raw: &Coverage) -> HierarchyCoverage {
    let recon = reconnaissance();
    let covered_ids: BTreeSet<&str> = raw
        .covered
        .iter()
        .map(|covered| covered.technique.id)
        .collect();

    let mut children_by_parent: BTreeMap<&'static str, Vec<&'static Technique>> = BTreeMap::new();
    for technique in &recon {
        if !technique.is_subtechnique {
            continue;
        }
        if let Some((parent, _)) = technique.id.split_once('.') {
            children_by_parent
                .entry(parent)
                .or_default()
                .push(*technique);
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
        .collect::<Vec<_>>();

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
        parent_rollups,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::attack::{coverage, reconnaissance};

    #[test]
    fn empty_coverage_partitions_current_catalogue_without_fixed_counts() {
        let raw = coverage(&BTreeMap::new());
        let report = hierarchy_coverage(&raw);

        assert_eq!(report.attack_objects_total, reconnaissance().len());
        assert_eq!(report.attack_objects_covered, 0);
        assert_eq!(report.leaf_techniques_covered, 0);
        assert_eq!(report.covered_leaves.len(), 0);
        assert_eq!(report.uncovered_leaves.len(), report.leaf_techniques_total);
        assert_eq!(
            report.leaf_techniques_total + report.parent_rollups.len(),
            report.attack_objects_total
        );
        assert!(report.coverage_fraction.abs() < f64::EPSILON);
    }

    #[test]
    fn covered_parent_is_rollup_not_second_scored_capability() {
        let raw = coverage(&BTreeMap::from([
            ("T1590".to_owned(), 1_usize),
            ("T1590.001".to_owned(), 1_usize),
        ]));
        let report = hierarchy_coverage(&raw);

        let parent = report
            .parent_rollups
            .iter()
            .find(|item| item.id == "T1590")
            .expect("T1590 roll-up");
        assert!(parent.directly_covered);
        assert_eq!(parent.covered_children, 1);
        assert!(
            report
                .covered_leaves
                .iter()
                .any(|item| item.id == "T1590.001")
        );
        assert!(!report.covered_leaves.iter().any(|item| item.id == "T1590"));
        assert_eq!(report.attack_objects_covered, 2);
        assert_eq!(report.leaf_techniques_covered, 1);
    }

    #[test]
    fn parent_without_children_remains_a_leaf() {
        let raw = coverage(&BTreeMap::from([("T1594".to_owned(), 3_usize)]));
        let report = hierarchy_coverage(&raw);
        assert!(report.covered_leaves.iter().any(|item| item.id == "T1594"));
        assert_eq!(report.leaf_techniques_covered, 1);
    }

    #[test]
    fn leaf_partition_and_fraction_are_self_consistent() {
        let raw = coverage(&BTreeMap::from([
            ("T1589.001".to_owned(), 1_usize),
            ("T1594".to_owned(), 1_usize),
            ("T1596.002".to_owned(), 1_usize),
        ]));
        let report = hierarchy_coverage(&raw);

        assert_eq!(
            report.covered_leaves.len() + report.uncovered_leaves.len(),
            report.leaf_techniques_total
        );
        #[allow(clippy::cast_precision_loss)]
        let expected = report.leaf_techniques_covered as f64 / report.leaf_techniques_total as f64;
        assert!((report.coverage_fraction - expected).abs() < f64::EPSILON);
    }
}
