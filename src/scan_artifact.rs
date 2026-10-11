//! Versioned, re-loadable scan results, so correlation can be rerun on a stored
//! scan without repeating its collection.
//!
//! An artifact is the entity set and relation set a scan produced, with a
//! format version. Writes are atomic: the bytes go to a temporary file that is
//! renamed into place, so a crash leaves either the old artifact or the new one,
//! never a truncated mix. Reads are strict: a file that does not parse, or that
//! carries a different format version, is an error. Nothing is migrated or
//! guessed.
//!
//! The central property is metamorphic: persisting an artifact and reading it
//! back must not change what the correlator reports. The tests check that.

use std::fs;
use std::io;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::collector::CollectionBatch;
use crate::correlator::{Correlation, evaluate_rules};
use crate::entity::Entity;
use crate::relation::Relation;

/// The only format this build reads and writes.
pub const FORMAT_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanArtifact {
    pub format_version: u32,
    pub scan_id: String,
    pub entities: Vec<Entity>,
    pub relations: Vec<Relation>,
}

impl ScanArtifact {
    #[must_use]
    pub fn new(
        scan_id: impl Into<String>,
        entities: Vec<Entity>,
        relations: Vec<Relation>,
    ) -> Self {
        Self {
            format_version: FORMAT_VERSION,
            scan_id: scan_id.into(),
            entities,
            relations,
        }
    }

    /// Build an artifact from one collector batch.
    ///
    /// Refuses a batch that carries relations. The artifact format stores
    /// `relation::Relation`, but collectors emit `graph::EntityRelation`, and
    /// converting between them silently would be a guess. Refusing is the
    /// honest answer until those two types are unified.
    ///
    /// # Errors
    /// [`ArtifactError::Unsupported`] when the batch carries any relation.
    pub fn from_batch(scan_id: &str, batch: &CollectionBatch) -> Result<Self, ArtifactError> {
        if !batch.relations.is_empty() {
            return Err(ArtifactError::Unsupported(format!(
                "batch carries {} relations, which this format does not store",
                batch.relations.len()
            )));
        }
        Ok(Self::new(scan_id, batch.entities.clone(), Vec::new()))
    }

    /// Rerun the correlation rules over this stored scan.
    #[must_use]
    pub fn correlate(&self) -> Vec<Correlation> {
        evaluate_rules(&self.entities, &self.relations, &self.scan_id)
    }
}

#[derive(Debug, Error)]
pub enum ArtifactError {
    #[error("scan artifact io: {0}")]
    Io(#[from] io::Error),
    #[error("scan artifact is malformed: {0}")]
    Malformed(String),
    #[error("scan artifact format {found} is not supported (this build reads {supported})")]
    UnsupportedVersion { found: u32, supported: u32 },
    #[error("scan artifact cannot represent this batch: {0}")]
    Unsupported(String),
}

/// Write `artifact` atomically: temporary file, then rename.
///
/// # Errors
/// [`ArtifactError::Io`] if the temporary file cannot be written or renamed.
pub fn write(path: &Path, artifact: &ScanArtifact) -> Result<(), ArtifactError> {
    let bytes = serde_json::to_vec_pretty(artifact)
        .map_err(|e| ArtifactError::Malformed(format!("could not encode: {e}")))?;
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, &bytes)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

/// Read and validate an artifact.
///
/// # Errors
/// [`ArtifactError::Io`] when the file cannot be read,
/// [`ArtifactError::Malformed`] when it does not decode, and
/// [`ArtifactError::UnsupportedVersion`] when its format differs from this build's.
pub fn read(path: &Path) -> Result<ScanArtifact, ArtifactError> {
    let bytes = fs::read(path)?;
    let artifact: ScanArtifact =
        serde_json::from_slice(&bytes).map_err(|e| ArtifactError::Malformed(e.to_string()))?;
    if artifact.format_version != FORMAT_VERSION {
        return Err(ArtifactError::UnsupportedVersion {
            found: artifact.format_version,
            supported: FORMAT_VERSION,
        });
    }
    Ok(artifact)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::{EntityKind, Evidence, EvidenceProvenance};

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("scan-artifact-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir.join("scan.json")
    }

    /// One email corroborated by three independent sources: enough for the
    /// high-corroboration rule to fire, so the round trip is tested on a
    /// non-empty result.
    fn corroborated() -> ScanArtifact {
        let mut email = Entity::new(EntityKind::Email, "a@example.com", 0.95, "scan-1");
        for source in ["hibp", "dehashed", "search_engines"] {
            let provenance = EvidenceProvenance::for_scan(source, "scan-1");
            email.add_evidence(Evidence::new(provenance, "seen"));
        }
        ScanArtifact::new("scan-1", vec![email], Vec::new())
    }

    #[test]
    fn round_trip_preserves_the_scan() {
        let path = scratch("roundtrip");
        let original = corroborated();
        write(&path, &original).unwrap();
        assert_eq!(read(&path).unwrap(), original);
    }

    #[test]
    fn metamorphic_persist_then_correlate_matches_correlating_in_memory() {
        let path = scratch("metamorphic");
        let original = corroborated();
        let in_memory = original.correlate();
        assert!(
            !in_memory.is_empty(),
            "fixture must trigger at least one rule"
        );
        write(&path, &original).unwrap();
        let reloaded = read(&path).unwrap();
        assert_eq!(reloaded.correlate(), in_memory);
    }

    #[test]
    fn a_different_format_version_is_refused() {
        let path = scratch("version");
        let mut artifact = corroborated();
        artifact.format_version = FORMAT_VERSION + 1;
        write(&path, &artifact).unwrap();
        match read(&path) {
            Err(ArtifactError::UnsupportedVersion { found, supported }) => {
                assert_eq!(found, FORMAT_VERSION + 1);
                assert_eq!(supported, FORMAT_VERSION);
            }
            other => panic!("expected UnsupportedVersion, got {other:?}"),
        }
    }

    #[test]
    fn a_malformed_file_is_a_named_error_not_an_empty_scan() {
        let path = scratch("malformed");
        fs::write(&path, b"{ not an artifact").unwrap();
        assert!(matches!(read(&path), Err(ArtifactError::Malformed(_))));
    }

    #[test]
    fn from_batch_refuses_relations_rather_than_dropping_them() {
        use crate::collector::{CollectionBatch, CollectionOutcome};
        use crate::graph::EntityRelation;
        let mut batch = CollectionBatch::empty("dehashed", "uid", CollectionOutcome::Success);
        batch.relations.push(EntityRelation::new(
            "a",
            "b",
            crate::graph::RelationKind::AliasOf,
            0.5,
        ));
        assert!(matches!(
            ScanArtifact::from_batch("scan-x", &batch),
            Err(ArtifactError::Unsupported(_))
        ));
    }

    #[test]
    fn from_batch_carries_entities_and_correlates() {
        use crate::collector::{CollectionBatch, CollectionOutcome};
        let mut batch = CollectionBatch::empty("dehashed", "uid", CollectionOutcome::Success);
        batch.entities = corroborated().entities;
        let artifact = ScanArtifact::from_batch("scan-1", &batch).unwrap();
        assert_eq!(artifact.entities, batch.entities);
        assert_eq!(artifact.correlate(), corroborated().correlate());
    }

    #[test]
    fn a_write_leaves_no_temporary_file_behind() {
        let path = scratch("atomic");
        write(&path, &corroborated()).unwrap();
        assert!(path.exists());
        assert!(!path.with_extension("tmp").exists());
    }
}
