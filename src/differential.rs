//! Reusable no-regression comparator for captured legacy oracle outputs.
//!
//! The harness is intentionally asymmetric: a reconstructed capability may add
//! results, but every legacy result must still be present, complete, and
//! attributed to the same source/dataset unless a reviewed intentional
//! difference explicitly allows that exact issue.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::entity::{Entity, EntityKind, Evidence, normalise};
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
        let value = value.into();
        Self {
            value: normalise(&kind, &value),
            kind,
            source: None,
            dataset: None,
        }
    }

    #[must_use]
    fn canonicalized(mut self) -> Self {
        self.value = normalise(&self.kind, &self.value);
        self
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
    pub expected: DifferentialEntity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed: Option<DifferentialEntity>,
    pub reason: String,
}

impl AllowedDifference {
    #[must_use]
    fn canonicalized(mut self) -> Self {
        self.expected = self.expected.canonicalized();
        self.observed = self.observed.map(DifferentialEntity::canonicalized);
        self
    }

    #[must_use]
    pub fn matches(&self, difference: &Difference) -> bool {
        self.reason.trim().len() >= 20
            && self.kind == difference.kind
            && self.expected == difference.expected
            && self.observed == difference.observed
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
            && is_git_sha1(&self.oracle_commit)
            && !self.capability.trim().is_empty()
            && self
                .allowed_differences
                .iter()
                .all(|allowed| allowed.reason.trim().len() >= 20)
    }

    /// Validate the manifest against the approved oracle commit and the exact
    /// recorded input/golden byte streams.
    ///
    /// Shape-only validation is insufficient for a differential receipt:
    /// callers must prove both content digests and exact oracle identity.
    pub fn validate_artifacts(
        &self,
        approved_capability: &str,
        approved_oracle_commit: &str,
        input_bytes: &[u8],
        golden_bytes: &[u8],
    ) -> Result<(), ManifestValidationError> {
        if !self.is_well_formed()
            || approved_capability.trim().is_empty()
            || !is_git_sha1(approved_oracle_commit)
        {
            return Err(ManifestValidationError::MalformedManifest);
        }
        if self.capability != approved_capability {
            return Err(ManifestValidationError::CapabilityMismatch {
                expected: approved_capability.to_owned(),
                actual: self.capability.clone(),
            });
        }
        if self.oracle_commit != approved_oracle_commit {
            return Err(ManifestValidationError::OracleCommitMismatch {
                expected: approved_oracle_commit.to_owned(),
                actual: self.oracle_commit.clone(),
            });
        }
        verify_sha256(input_bytes, &self.input_sha256)
            .map_err(ManifestValidationError::InputHash)?;
        verify_sha256(golden_bytes, &self.golden_sha256)
            .map_err(ManifestValidationError::GoldenHash)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashMismatch {
    pub expected: String,
    pub actual: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestValidationError {
    MalformedManifest,
    CapabilityMismatch { expected: String, actual: String },
    OracleCommitMismatch { expected: String, actual: String },
    InputHash(HashMismatch),
    GoldenHash(HashMismatch),
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
            let base = DifferentialEntity::new(entity.kind.clone(), entity.value.clone())
                .with_source(evidence.provenance.source.clone());
            let datasets = dataset_names(evidence);
            if datasets.is_empty() {
                out.insert(base);
            } else {
                for dataset in datasets {
                    out.insert(base.clone().with_dataset(dataset));
                }
            }
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
    let expected: BTreeSet<DifferentialEntity> = expected
        .iter()
        .cloned()
        .map(DifferentialEntity::canonicalized)
        .collect();
    let observed: BTreeSet<DifferentialEntity> = observed
        .iter()
        .cloned()
        .map(DifferentialEntity::canonicalized)
        .collect();
    let allowed: Vec<AllowedDifference> = allowed
        .iter()
        .cloned()
        .map(AllowedDifference::canonicalized)
        .collect();
    let mut differences = Vec::new();

    for item in expected {
        if observed
            .iter()
            .any(|candidate| exact_match(&item, candidate))
        {
            continue;
        }

        let same_identity: Vec<DifferentialEntity> = observed
            .iter()
            .filter(|candidate| candidate.kind == item.kind && candidate.value == item.value)
            .cloned()
            .collect();
        if !same_identity.is_empty() {
            let candidates: Vec<Difference> = same_identity
                .into_iter()
                .map(|candidate| Difference {
                    kind: DifferenceKind::Misattributed,
                    expected: item.clone(),
                    observed: Some(candidate),
                })
                .collect();
            if candidates
                .iter()
                .any(|difference| allowed.iter().any(|entry| entry.matches(difference)))
            {
                continue;
            }
            if let Some(diagnostic) = candidates.into_iter().next() {
                differences.push(diagnostic);
            }
            continue;
        }

        let mut truncations: Vec<DifferentialEntity> = observed
            .iter()
            .filter(|candidate| truncated_match(&item, candidate))
            .cloned()
            .collect();
        if !truncations.is_empty() {
            truncations.sort_by(|left, right| {
                right
                    .value
                    .len()
                    .cmp(&left.value.len())
                    .then_with(|| left.cmp(right))
            });
            let candidates: Vec<Difference> = truncations
                .into_iter()
                .map(|candidate| Difference {
                    kind: DifferenceKind::Truncated,
                    expected: item.clone(),
                    observed: Some(candidate),
                })
                .collect();
            if candidates
                .iter()
                .any(|difference| allowed.iter().any(|entry| entry.matches(difference)))
            {
                continue;
            }
            if let Some(diagnostic) = candidates.into_iter().next() {
                differences.push(diagnostic);
            }
            continue;
        }

        let difference = Difference {
            kind: DifferenceKind::Missing,
            expected: item,
            observed: None,
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

fn dataset_names(evidence: &Evidence) -> BTreeSet<String> {
    DATASET_KEYS
        .iter()
        .flat_map(|key| evidence.attr_values(key))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect()
}

fn is_hex_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_git_sha1(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
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
        assert_eq!(compare_legacy(&expected, &observed, &[]), Vec::new());
    }

    #[test]
    fn comparator_distinguishes_missing_truncated_and_misattributed() {
        let expected = vec![
            DifferentialEntity::new(EntityKind::Email, "ada@example.org"),
            DifferentialEntity::new(EntityKind::Username, "adalovelace"),
            DifferentialEntity::new(EntityKind::Domain, "example.org").with_source("legacy"),
        ];
        let observed = vec![
            DifferentialEntity::new(EntityKind::Username, "ada"),
            DifferentialEntity::new(EntityKind::Domain, "example.org").with_source("other"),
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
        let expected = vec![DifferentialEntity::new(EntityKind::Username, "adalovelace")];
        let observed = vec![DifferentialEntity::new(EntityKind::Username, "ada")];
        let weak = [AllowedDifference {
            kind: DifferenceKind::Truncated,
            expected: expected[0].clone(),
            observed: Some(observed[0].clone()),
            reason: "intentional".into(),
        }];
        assert_eq!(compare_legacy(&expected, &observed, &weak).len(), 1);

        let reviewed = [AllowedDifference {
            reason: "legacy truncation is intentionally retained for this fixture".into(),
            ..weak[0].clone()
        }];
        assert_eq!(compare_legacy(&expected, &observed, &reviewed), Vec::new());
    }

    #[test]
    fn canonical_values_do_not_create_false_regressions() {
        let expected = [DifferentialEntity {
            kind: EntityKind::Email,
            value: "ADA@EXAMPLE.ORG".into(),
            source: None,
            dataset: None,
        }];
        let observed = [DifferentialEntity::new(EntityKind::Email, "ada@example.org")];
        assert_eq!(compare_legacy(&expected, &observed, &[]), Vec::new());
    }

    #[test]
    fn reviewed_misattribution_is_stable_when_extra_output_is_added() {
        let expected = [DifferentialEntity::new(EntityKind::Domain, "example.org")
            .with_source("legacy")];
        let reviewed_observed =
            DifferentialEntity::new(EntityKind::Domain, "example.org").with_source("z-source");
        let observed = [
            DifferentialEntity::new(EntityKind::Domain, "example.org").with_source("a-extra"),
            reviewed_observed.clone(),
        ];
        let allowed = [AllowedDifference {
            kind: DifferenceKind::Misattributed,
            expected: expected[0].clone(),
            observed: Some(reviewed_observed),
            reason: "reviewed source attribution difference for this legacy fixture".into(),
        }];
        assert_eq!(compare_legacy(&expected, &observed, &allowed), Vec::new());
    }

    #[test]
    fn reviewed_truncation_is_stable_when_extra_prefix_is_added() {
        let expected = [DifferentialEntity::new(EntityKind::Username, "adalovelace")];
        let reviewed_observed = DifferentialEntity::new(EntityKind::Username, "adalove");
        let observed = [
            DifferentialEntity::new(EntityKind::Username, "ada"),
            reviewed_observed.clone(),
        ];
        let allowed = [AllowedDifference {
            kind: DifferenceKind::Truncated,
            expected: expected[0].clone(),
            observed: Some(reviewed_observed),
            reason: "reviewed truncation difference for this legacy fixture output".into(),
        }];
        assert_eq!(compare_legacy(&expected, &observed, &allowed), Vec::new());
    }

    #[test]
    fn snapshots_preserve_every_source_and_dataset_attribution() {
        let mut entity = Entity::new(EntityKind::Email, "ADA@EXAMPLE.ORG", 0.8, "scan");
        entity.add_evidence(
            Evidence::new(EvidenceProvenance::for_scan("hibp", "scan"), "record")
                .with_attr("breach", "Example")
                .with_attr("breach", "Second")
                .with_attr("dataset", "Third"),
        );
        assert_eq!(
            snapshot_entities(&[entity]),
            vec![
                DifferentialEntity::new(EntityKind::Email, "ada@example.org")
                    .with_source("hibp")
                    .with_dataset("Example"),
                DifferentialEntity::new(EntityKind::Email, "ada@example.org")
                    .with_source("hibp")
                    .with_dataset("Second"),
                DifferentialEntity::new(EntityKind::Email, "ada@example.org")
                    .with_source("hibp")
                    .with_dataset("Third"),
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
        assert_eq!(
            manifest.validate_artifacts(
                "fixture",
                "7dca720b5bf51f20b4e27d5ca29cc570ec2f9a58",
                b"abc",
                b"abc",
            ),
            Ok(())
        );
        assert!(matches!(
            manifest.validate_artifacts(
                "wrong-capability",
                "7dca720b5bf51f20b4e27d5ca29cc570ec2f9a58",
                b"abc",
                b"abc",
            ),
            Err(ManifestValidationError::CapabilityMismatch { .. })
        ));
        assert!(matches!(
            manifest.validate_artifacts(
                "fixture",
                "0000000000000000000000000000000000000000",
                b"abc",
                b"abc",
            ),
            Err(ManifestValidationError::OracleCommitMismatch { .. })
        ));
        assert!(matches!(
            manifest.validate_artifacts(
                "fixture",
                "7dca720b5bf51f20b4e27d5ca29cc570ec2f9a58",
                b"abd",
                b"abc",
            ),
            Err(ManifestValidationError::InputHash(_))
        ));
        assert!(matches!(
            manifest.validate_artifacts(
                "fixture",
                "7dca720b5bf51f20b4e27d5ca29cc570ec2f9a58",
                b"abc",
                b"abd",
            ),
            Err(ManifestValidationError::GoldenHash(_))
        ));
    }
}
