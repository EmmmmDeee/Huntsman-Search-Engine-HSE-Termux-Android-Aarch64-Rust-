//! Reusable no-regression comparator for captured legacy oracle outputs.
//!
//! The harness is intentionally asymmetric: a reconstructed capability may add
//! results, but every legacy result must still be present, complete, and
//! attributed to the same source/dataset unless a reviewed intentional
//! difference explicitly allows that exact issue.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::entity::{Entity, EntityKind, Evidence};
use crate::sha256::{hex32, sha256};

const DATASET_KEYS: [&str; 6] = [
    "dbname",
    "breach",
    "source_db",
    "database_name",
    "dataset",
    "registry",
];

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DifferentialEntity {
    pub kind: EntityKind,
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dataset: Option<String>,
}

impl DifferentialEntity {
    #[must_use]
    pub fn new(kind: EntityKind, value: impl Into<String>) -> Self {
        Self {
            kind,
            value: value.into(),
            source: None,
            dataset: None,
        }
    }

    #[must_use]
    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.source = Some(source.into());
        self
    }

    #[must_use]
    pub fn with_dataset(mut self, dataset: impl Into<String>) -> Self {
        self.dataset = Some(dataset.into());
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DifferenceKind {
    Missing,
    Truncated,
    Misattributed,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Difference {
    pub kind: DifferenceKind,
    pub expected: DifferentialEntity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed: Option<DifferentialEntity>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowedDifference {
    pub kind: DifferenceKind,
    pub entity_kind: EntityKind,
    pub expected_value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_value: Option<String>,
    pub reason: String,
}

impl AllowedDifference {
    #[must_use]
    pub fn matches(&self, difference: &Difference) -> bool {
        if self.reason.trim().len() < 20
            || self.kind != difference.kind
            || self.entity_kind != difference.expected.kind
            || self.expected_value != difference.expected.value
        {
            return false;
        }
        match (&self.observed_value, &difference.observed) {
            (None, _) => true,
            (Some(want), Some(observed)) => *want == observed.value,
            (Some(_), None) => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DifferentialManifest {
    pub oracle_commit: String,
    pub capability: String,
    pub input_sha256: String,
    pub golden_sha256: String,
    #[serde(default)]
    pub allowed_differences: Vec<AllowedDifference>,
}

impl DifferentialManifest {
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        is_hex_sha256(&self.input_sha256)
            && is_hex_sha256(&self.golden_sha256)
            && self.oracle_commit.len() >= 7
            && !self.capability.trim().is_empty()
            && self
                .allowed_differences
                .iter()
                .all(|allowed| allowed.reason.trim().len() >= 20)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashMismatch {
    pub expected: String,
    pub actual: String,
}

pub fn verify_sha256(bytes: &[u8], expected: &str) -> Result<(), HashMismatch> {
    let actual = hex32(&sha256(bytes));
    if actual.eq_ignore_ascii_case(expected) {
        Ok(())
    } else {
        Err(HashMismatch {
            expected: expected.to_ascii_lowercase(),
            actual,
        })
    }
}

#[must_use]
pub fn snapshot_entities(entities: &[Entity]) -> Vec<DifferentialEntity> {
    let mut out = BTreeSet::new();
    for entity in entities {
        if entity.evidence.is_empty() {
            out.insert(DifferentialEntity::new(
                entity.kind.clone(),
                entity.value.clone(),
            ));
            continue;
        }
        for evidence in &entity.evidence {
            let mut snapshot =
                DifferentialEntity::new(entity.kind.clone(), entity.value.clone())
                    .with_source(evidence.provenance.source.clone());
            if let Some(dataset) = dataset_name(evidence) {
                snapshot = snapshot.with_dataset(dataset);
            }
            out.insert(snapshot);
        }
    }
    out.into_iter().collect()
}

/// Return only legacy regressions that are not explicitly allow-listed.
///
/// Extra reconstructed results are intentionally ignored: the restoration rule
/// prohibits drops/truncation/misattribution but does not prohibit improvements.
#[must_use]
pub fn compare_legacy(
    expected: &[DifferentialEntity],
    observed: &[DifferentialEntity],
    allowed: &[AllowedDifference],
) -> Vec<Difference> {
    let expected: BTreeSet<DifferentialEntity> = expected.iter().cloned().collect();
    let observed: BTreeSet<DifferentialEntity> = observed.iter().cloned().collect();
    let mut differences = Vec::new();

    for item in expected {
        if observed.iter().any(|candidate| exact_match(&item, candidate)) {
            continue;
        }

        let same_identity = observed
            .iter()
            .find(|candidate| candidate.kind == item.kind && candidate.value == item.value)
            .cloned();
        let difference = if let Some(candidate) = same_identity {
            Difference {
                kind: DifferenceKind::Misattributed,
                expected: item,
                observed: Some(candidate),
            }
        } else if let Some(candidate) = observed
            .iter()
            .find(|candidate| truncated_match(&item, candidate))
            .cloned()
        {
            Difference {
                kind: DifferenceKind::Truncated,
                expected: item,
                observed: Some(candidate),
            }
        } else {
            Difference {
                kind: DifferenceKind::Missing,
                expected: item,
                observed: None,
            }
        };

        if !allowed.iter().any(|entry| entry.matches(&difference)) {
            differences.push(difference);
        }
    }

    differences.sort();
    differences
}

fn exact_match(expected: &DifferentialEntity, observed: &DifferentialEntity) -> bool {
    expected.kind == observed.kind
        && expected.value == observed.value
        && optional_constraint_matches(expected.source.as_deref(), observed.source.as_deref())
        && optional_constraint_matches(expected.dataset.as_deref(), observed.dataset.as_deref())
}

fn optional_constraint_matches(expected: Option<&str>, observed: Option<&str>) -> bool {
    expected.is_none() || expected == observed
}

fn truncated_match(expected: &DifferentialEntity, observed: &DifferentialEntity) -> bool {
    expected.kind == observed.kind
        && observed.value.len() < expected.value.len()
        && expected.value.starts_with(&observed.value)
}

fn dataset_name(evidence: &Evidence) -> Option<String> {
    DATASET_KEYS.iter().find_map(|key| {
        evidence
            .attr_values(key)
            .next()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    })
}

fn is_hex_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::{Evidence, EvidenceProvenance};

    #[test]
    fn comparator_accepts_superset_without_dropping_legacy() {
        let expected = vec![
            DifferentialEntity::new(EntityKind::Email, "ada@example.org")
                .with_source("legacy")
                .with_dataset("Example"),
        ];
        let observed = vec![
            expected[0].clone(),
            DifferentialEntity::new(EntityKind::Domain, "example.org"),
        ];
        assert!(compare_legacy(&expected, &observed, &[]).is_empty());
    }

    #[test]
    fn comparator_distinguishes_missing_truncated_and_misattributed() {
        let expected = vec![
            DifferentialEntity::new(EntityKind::Email, "ada@example.org"),
            DifferentialEntity::new(EntityKind::Username, "adalovelace"),
            DifferentialEntity::new(EntityKind::Domain, "example.org")
                .with_source("legacy"),
        ];
        let observed = vec![
            DifferentialEntity::new(EntityKind::Username, "ada"),
            DifferentialEntity::new(EntityKind::Domain, "example.org")
                .with_source("other"),
        ];
        let differences = compare_legacy(&expected, &observed, &[]);
        assert_eq!(
            differences
                .iter()
                .map(|difference| difference.kind)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                DifferenceKind::Missing,
                DifferenceKind::Truncated,
                DifferenceKind::Misattributed,
            ])
        );
    }

    #[test]
    fn allow_list_requires_specific_issue_and_substantive_reason() {
        let expected = vec![DifferentialEntity::new(
            EntityKind::Username,
            "adalovelace",
        )];
        let observed = vec![DifferentialEntity::new(EntityKind::Username, "ada")];
        let weak = [AllowedDifference {
            kind: DifferenceKind::Truncated,
            entity_kind: EntityKind::Username,
            expected_value: "adalovelace".into(),
            observed_value: Some("ada".into()),
            reason: "intentional".into(),
        }];
        assert_eq!(compare_legacy(&expected, &observed, &weak).len(), 1);

        let reviewed = [AllowedDifference {
            reason: "legacy truncation is intentionally retained for this fixture".into(),
            ..weak[0].clone()
        }];
        assert!(compare_legacy(&expected, &observed, &reviewed).is_empty());
    }

    #[test]
    fn snapshots_preserve_source_and_dataset_attribution() {
        let mut entity = Entity::new(EntityKind::Email, "ADA@EXAMPLE.ORG", 0.8, "scan");
        entity.add_evidence(
            Evidence::new(EvidenceProvenance::for_scan("hibp", "scan"), "record")
                .with_attr("breach", "Example"),
        );
        assert_eq!(
            snapshot_entities(&[entity]),
            vec![
                DifferentialEntity::new(EntityKind::Email, "ada@example.org")
                    .with_source("hibp")
                    .with_dataset("Example")
            ]
        );
    }

    #[test]
    fn manifest_and_hash_checks_are_strict() {
        let abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert!(verify_sha256(b"abc", abc).is_ok());
        assert!(verify_sha256(b"abd", abc).is_err());

        let manifest = DifferentialManifest {
            oracle_commit: "7dca720b5bf51f20b4e27d5ca29cc570ec2f9a58".into(),
            capability: "fixture".into(),
            input_sha256: abc.into(),
            golden_sha256: abc.into(),
            allowed_differences: Vec::new(),
        };
        assert!(manifest.is_well_formed());
    }
}
