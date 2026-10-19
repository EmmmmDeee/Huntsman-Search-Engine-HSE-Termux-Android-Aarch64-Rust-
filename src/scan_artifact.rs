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

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::collector::CollectionBatch;
use crate::correlator::{Correlation, evaluate_rules};
use crate::cross_scan::{
    CrossScanCategory, CrossScanOptions, CrossScanStore, category_from_entities,
};
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

    /// Rerun the correlation rules over this stored scan, exactly as the analysis behind `plan`
    /// correlates the same entities: the rules read the relations the entities imply, and the
    /// stored relations between confirmed entities.
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

/// Upper bound on an artifact, in bytes, for both writing and reading.
///
/// An artifact holds one scan's entity set: a `DeHashed` page or a collector
/// batch is a few hundred records, well under 1 MiB of JSON. 32 MiB leaves a
/// wide margin while keeping a hostile or runaway file from exhausting memory
/// on the Termux/Android target, matching the crate rule that every external
/// input is capped.
pub const MAX_ARTIFACT_BYTES: u64 = 32 * 1024 * 1024;

fn fsio_err(error: &crate::error::Error) -> ArtifactError {
    ArtifactError::Io(io::Error::other(error.to_string()))
}

/// Write `artifact` atomically and durably through the crate's hardened writer,
/// [`crate::fsio::write_atomic_private`].
///
/// An artifact can hold emails and usernames taken from breach records, so it
/// is created mode 600 on Unix before any bytes land, the same as the `DeHashed`
/// key file. The writer refuses a symlink at the target or its parent, opens a
/// fresh temporary file with `create_new` (never following or truncating an
/// existing one), flushes it, renames it over the target, and removes the
/// temporary file on error, and flushes the parent directory so the rename
/// survives a crash. The encoded artifact is capped at [`MAX_ARTIFACT_BYTES`].
///
/// # Errors
/// [`ArtifactError::Malformed`] if the artifact cannot be encoded, and
/// [`ArtifactError::Io`] on a symlink, an artifact over the cap, or a write,
/// flush, or rename failure.
pub fn write(path: &Path, artifact: &ScanArtifact) -> Result<(), ArtifactError> {
    let limit = usize::try_from(MAX_ARTIFACT_BYTES).unwrap_or(usize::MAX);
    let bytes = match crate::json::to_bounded_json(artifact, limit, true) {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(required_bytes)) => {
            return Err(ArtifactError::Io(io::Error::other(format!(
                "{}: exceeds {MAX_ARTIFACT_BYTES} bytes (needs {required_bytes})",
                path.display()
            ))));
        }
        Err(error) => {
            return Err(ArtifactError::Malformed(format!(
                "could not encode: {error}"
            )));
        }
    };
    crate::fsio::write_atomic_private(path, &bytes, MAX_ARTIFACT_BYTES).map_err(|e| fsio_err(&e))
}

/// Read and validate an artifact, through [`crate::fsio::read_bounded`] at
/// [`MAX_ARTIFACT_BYTES`].
///
/// # Errors
/// [`ArtifactError::Io`] when the file is missing, unreadable, not a regular
/// file, a symlink, or over the cap,
/// [`ArtifactError::Malformed`] when it does not decode, and
/// [`ArtifactError::UnsupportedVersion`] when its format differs from this build's.
pub fn read(path: &Path) -> Result<ScanArtifact, ArtifactError> {
    let bytes = crate::fsio::read_bounded(path, MAX_ARTIFACT_BYTES).map_err(|e| fsio_err(&e))?;
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

/// Most artifacts a history directory may hold. Matches the cross-scan
/// traversal's visited-scan budget: a larger history could not be walked anyway.
pub const MAX_HISTORY_ARTIFACTS: usize = 512;

/// Total bytes of artifacts a history directory may hold, so loading the index
/// stays bounded on the Termux/Android target.
pub const MAX_HISTORY_BYTES: u64 = 128 * 1024 * 1024;

/// Production [`CrossScanStore`] over a directory of saved scan artifacts.
///
/// Every regular `*.json` file directly inside the directory is read through
/// [`read`] and indexed by its artifact `scan_id`, so a prior scan that saw the
/// same entity becomes a cross-scan bridge. Reads are as strict as [`read`]: a
/// file that does not parse, or has another format version, fails the open with
/// its path named, rather than silently shrinking the history. Symlinks and
/// subdirectories are skipped, never followed. Artifacts that share a `scan_id`
/// (for example two pages of one `DeHashed` query) merge into one scan.
#[derive(Debug, Default)]
pub struct ArtifactHistory {
    by_scan: BTreeMap<String, Vec<Entity>>,
    by_uid: BTreeMap<String, BTreeSet<String>>,
}

impl ArtifactHistory {
    /// Load and index every artifact in `dir`.
    ///
    /// # Errors
    /// [`ArtifactError::Io`] when the directory cannot be listed, or holds more
    /// than [`MAX_HISTORY_ARTIFACTS`] artifacts or [`MAX_HISTORY_BYTES`] bytes;
    /// otherwise the first error [`read`] returns, prefixed with the file path.
    pub fn open(dir: &Path) -> Result<Self, ArtifactError> {
        let mut paths = Vec::new();
        let mut total = 0u64;
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let meta = fs::symlink_metadata(&path)?;
            if !meta.is_file() || path.extension().is_none_or(|ext| ext != "json") {
                continue;
            }
            total = total.saturating_add(meta.len());
            paths.push(path);
            if paths.len() > MAX_HISTORY_ARTIFACTS || total > MAX_HISTORY_BYTES {
                return Err(ArtifactError::Io(io::Error::other(format!(
                    "{}: history exceeds {MAX_HISTORY_ARTIFACTS} artifacts or {MAX_HISTORY_BYTES} bytes",
                    dir.display()
                ))));
            }
        }
        paths.sort();
        let mut history = Self::default();
        for path in paths {
            let artifact = read(&path).map_err(|error| named(&path, error))?;
            history.insert(artifact);
        }
        Ok(history)
    }

    fn insert(&mut self, artifact: ScanArtifact) {
        let scan = self.by_scan.entry(artifact.scan_id.clone()).or_default();
        for entity in artifact.entities {
            self.by_uid
                .entry(entity.uid.clone())
                .or_default()
                .insert(artifact.scan_id.clone());
            scan.push(entity);
        }
    }

    /// Number of distinct scans in the history.
    #[must_use]
    pub fn scan_count(&self) -> usize {
        self.by_scan.len()
    }
}

fn named(path: &Path, error: ArtifactError) -> ArtifactError {
    let at = path.display();
    match error {
        ArtifactError::Io(e) => ArtifactError::Io(io::Error::new(e.kind(), format!("{at}: {e}"))),
        ArtifactError::Malformed(m) => ArtifactError::Malformed(format!("{at}: {m}")),
        ArtifactError::Unsupported(m) => ArtifactError::Unsupported(format!("{at}: {m}")),
        other @ ArtifactError::UnsupportedVersion { .. } => {
            ArtifactError::Malformed(format!("{at}: {other}"))
        }
    }
}

impl CrossScanStore for ArtifactHistory {
    fn entities_for_scan(&self, scan_id: &str) -> Result<Vec<Entity>, crate::error::Error> {
        Ok(self.by_scan.get(scan_id).cloned().unwrap_or_default())
    }

    fn scan_ids_for_entity(&self, entity_uid: &str) -> Result<Vec<String>, crate::error::Error> {
        Ok(self
            .by_uid
            .get(entity_uid)
            .map(|scans| scans.iter().cloned().collect())
            .unwrap_or_default())
    }
}

impl ScanArtifact {
    /// Pivot this scan across every prior scan in `history`: entities it shares
    /// with earlier scans, and scans reachable through those shared entities.
    ///
    /// # Errors
    /// Propagates history lookup failures.
    pub fn cross_scan(
        &self,
        history: &ArtifactHistory,
        options: CrossScanOptions,
    ) -> Result<CrossScanCategory, crate::error::Error> {
        category_from_entities(history, &self.scan_id, &self.entities, options)
    }
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
        // Correlations are stamped with the scan's latest observation, which the artifact
        // stores, so the two runs agree exactly, `ts` included.
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
    fn reading_a_missing_path_is_io_not_malformed() {
        // correlate maps Io to exit 66 (unreadable input) and Malformed to 65
        // (bad data); a missing file must be Io so the exit code is right.
        let path = scratch("missing");
        let _ = fs::remove_file(&path);
        assert!(matches!(read(&path), Err(ArtifactError::Io(_))));
        // A directory is also unreadable-as-a-file, not malformed data.
        let dir = path.parent().unwrap();
        assert!(matches!(read(dir), Err(ArtifactError::Io(_))));
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
        // One fixture for both sides: each build stamps its entities with the clock, and a
        // correlation carries the latest stamp, so two builds a second apart never compare equal.
        let expected = corroborated();
        let mut batch = CollectionBatch::empty("dehashed", "uid", CollectionOutcome::Success);
        batch.entities.clone_from(&expected.entities);
        let artifact = ScanArtifact::from_batch("scan-1", &batch).unwrap();
        assert_eq!(artifact.entities, batch.entities);
        assert_eq!(artifact.correlate(), expected.correlate());
    }

    /// A saved scan correlates exactly as the analysis behind `plan` and the web UI correlates the
    /// same entities. An email, its local part as a handle and that handle's profile form an
    /// identity cluster (AU-060) of single-pathway links (AU-063), and two domains share a hosting
    /// address (AU-110). Before, `correlate` gave the rules only the relations stored in the
    /// artifact, and `dehashed --save-artifact`, the only writer, stores none, so no relation rule
    /// ever fired on a saved scan.
    #[test]
    fn a_saved_scan_correlates_as_the_analysis_of_its_entities() {
        use crate::analysis::analyze_snapshot;
        use crate::evidence_ancestry::EvidenceAncestryGraph;
        use crate::pipeline::AnalysisSnapshot;

        let hosted_on = |domain: &str| {
            let mut entity = Entity::new(EntityKind::Domain, domain, 0.9, "scan-1");
            entity.add_evidence(
                Evidence::new(EvidenceProvenance::for_scan("dns", "scan-1"), "A record")
                    .with_attr("ip", "192.0.2.10"),
            );
            entity
        };
        let entities = vec![
            Entity::new(EntityKind::Email, "ann@mail.example", 0.9, "scan-1"),
            Entity::new(EntityKind::Username, "ann", 0.9, "scan-1"),
            Entity::new(EntityKind::Url, "https://github.com/ann", 0.9, "scan-1"),
            hosted_on("alpha.example"),
            hosted_on("beta.example"),
            Entity::new(EntityKind::IpAddress, "192.0.2.10", 0.9, "scan-1"),
        ];
        let analysed = analyze_snapshot(&AnalysisSnapshot {
            entities: entities.clone(),
            relations: Vec::new(),
            coverage: Vec::new(),
            ancestry: EvidenceAncestryGraph::default(),
            truncated: false,
        })
        .correlations;
        let fired = analysed
            .iter()
            .map(|correlation| correlation.rule_id.as_str())
            .collect::<Vec<_>>();
        for rule in ["AU-060", "AU-063", "AU-110"] {
            assert!(fired.contains(&rule), "{rule} is missing from {fired:?}");
        }
        let saved = ScanArtifact::new("scan-1", entities, Vec::new());
        assert_eq!(saved.correlate(), analysed);
    }

    #[test]
    fn a_write_leaves_no_temporary_file_behind() {
        let path = scratch("atomic");
        write(&path, &corroborated()).unwrap();
        assert!(path.exists());
        // No temporary file of any name may remain in the directory.
        let dir = path.parent().unwrap();
        let leftovers: Vec<_> = fs::read_dir(dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "stray temp files: {leftovers:?}");
    }

    #[cfg(unix)]
    #[test]
    fn the_artifact_is_private_because_it_holds_breach_identifiers() {
        use std::os::unix::fs::PermissionsExt;
        let path = scratch("private");
        write(&path, &corroborated()).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "artifact mode was {mode:o}");
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_target_is_refused_and_its_destination_untouched() {
        let path = scratch("symlink");
        let victim = path.with_file_name("victim.txt");
        fs::write(&victim, b"keep me").unwrap();
        std::os::unix::fs::symlink(&victim, &path).unwrap();
        assert!(matches!(
            write(&path, &corroborated()),
            Err(ArtifactError::Io(_))
        ));
        assert_eq!(fs::read(&victim).unwrap(), b"keep me");
        assert!(matches!(read(&path), Err(ArtifactError::Io(_))));
    }

    #[test]
    fn an_artifact_over_the_cap_is_refused_on_read() {
        let path = scratch("oversize");
        let file = fs::File::create(&path).unwrap();
        file.set_len(MAX_ARTIFACT_BYTES + 1).unwrap();
        drop(file);
        assert!(matches!(read(&path), Err(ArtifactError::Io(_))));
    }

    fn history_dir(name: &str, artifacts: &[ScanArtifact]) -> std::path::PathBuf {
        let dir = scratch(name).parent().unwrap().join("history");
        fs::create_dir_all(&dir).unwrap();
        for (index, artifact) in artifacts.iter().enumerate() {
            write(&dir.join(format!("{index}.json")), artifact).unwrap();
        }
        dir
    }

    fn scan_of(scan_id: &str, entities: &[(EntityKind, &str)]) -> ScanArtifact {
        let entities = entities
            .iter()
            .map(|(kind, value)| Entity::new(kind.clone(), *value, 0.9, scan_id))
            .collect();
        ScanArtifact::new(scan_id, entities, Vec::new())
    }

    #[test]
    fn history_bridges_an_email_shared_with_an_earlier_saved_scan() {
        use crate::cross_scan::{CrossScanCategory, CrossScanOptions};
        let current = scan_of("scan-now", &[(EntityKind::Email, "ada@example.com")]);
        let dir = history_dir(
            "bridge",
            &[
                current.clone(),
                scan_of("scan-old", &[(EntityKind::Email, "ada@example.com")]),
                scan_of("scan-other", &[(EntityKind::Email, "bob@example.com")]),
            ],
        );
        let history = ArtifactHistory::open(&dir).unwrap();
        assert_eq!(history.scan_count(), 3);
        match current
            .cross_scan(&history, CrossScanOptions::default())
            .unwrap()
        {
            CrossScanCategory::Historical { matches } => {
                assert_eq!(matches.len(), 1);
                assert_eq!(matches[0].overlapping_scans, vec!["scan-old".to_string()]);
            }
            other => panic!("expected a historical bridge, got {other:?}"),
        }
    }

    #[test]
    fn history_walks_related_entities_transitively_across_files() {
        use crate::cross_scan::{CrossScanCategory, CrossScanOptions};
        let current = scan_of("scan-a", &[(EntityKind::IpAddress, "192.0.2.1")]);
        let dir = history_dir(
            "transitive",
            &[
                scan_of(
                    "scan-b",
                    &[
                        (EntityKind::IpAddress, "192.0.2.1"),
                        (EntityKind::IpAddress, "192.0.2.2"),
                    ],
                ),
                scan_of("scan-c", &[(EntityKind::IpAddress, "192.0.2.2")]),
            ],
        );
        let history = ArtifactHistory::open(&dir).unwrap();
        match current
            .cross_scan(&history, CrossScanOptions::default())
            .unwrap()
        {
            CrossScanCategory::Transitive { links } => {
                assert!(
                    links
                        .iter()
                        .any(|l| l.target_scan_id == "scan-b" && l.depth == 1)
                );
                assert!(
                    links
                        .iter()
                        .any(|l| l.target_scan_id == "scan-c" && l.depth == 2)
                );
            }
            other => panic!("expected a transitive walk, got {other:?}"),
        }
    }

    #[test]
    fn a_scan_alone_in_its_history_has_no_bridge_to_itself() {
        use crate::cross_scan::{CrossScanCategory, CrossScanOptions};
        let current = scan_of("scan-1", &[(EntityKind::Email, "ada@example.com")]);
        let dir = history_dir("self", std::slice::from_ref(&current));
        let history = ArtifactHistory::open(&dir).unwrap();
        assert_eq!(
            current
                .cross_scan(&history, CrossScanOptions::default())
                .unwrap(),
            CrossScanCategory::None
        );
    }

    #[test]
    fn pages_of_one_scan_merge_into_one_history_scan() {
        let dir = history_dir(
            "pages",
            &[
                scan_of("dehashed:q", &[(EntityKind::Email, "ada@example.com")]),
                scan_of("dehashed:q", &[(EntityKind::Email, "bob@example.com")]),
            ],
        );
        let history = ArtifactHistory::open(&dir).unwrap();
        assert_eq!(history.scan_count(), 1);
        assert_eq!(history.entities_for_scan("dehashed:q").unwrap().len(), 2);
    }

    #[test]
    fn a_malformed_history_file_fails_the_open_and_names_the_file() {
        let dir = history_dir("bad-history", &[corroborated()]);
        fs::write(dir.join("broken.json"), b"{ nope").unwrap();
        match ArtifactHistory::open(&dir) {
            Err(ArtifactError::Malformed(message)) => {
                assert!(message.contains("broken.json"), "{message}");
            }
            other => panic!("expected Malformed naming the file, got {other:?}"),
        }
    }

    #[test]
    fn history_ignores_non_json_files_and_a_missing_dir_is_io() {
        let dir = history_dir("non-json", &[corroborated()]);
        fs::write(dir.join("notes.txt"), b"not an artifact").unwrap();
        fs::create_dir_all(dir.join("nested.json")).unwrap();
        assert_eq!(ArtifactHistory::open(&dir).unwrap().scan_count(), 1);
        assert!(matches!(
            ArtifactHistory::open(&dir.join("absent")),
            Err(ArtifactError::Io(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn history_skips_symlinks_rather_than_following_them() {
        let dir = history_dir("history-symlink", &[]);
        let outside = dir.parent().unwrap().join("outside.json");
        write(&outside, &corroborated()).unwrap();
        std::os::unix::fs::symlink(&outside, dir.join("link.json")).unwrap();
        assert_eq!(ArtifactHistory::open(&dir).unwrap().scan_count(), 0);
    }

    #[test]
    fn bounded_artifact_write_preserves_existing_file_on_overflow() {
        let path = scratch("bounded-write-preserves");
        let stable = corroborated();
        write(&path, &stable).unwrap();
        let before = fs::read(&path).unwrap();
        let mut huge = stable.clone();
        huge.entities[0].raw_value = "x".repeat(usize::try_from(MAX_ARTIFACT_BYTES).unwrap());
        assert!(matches!(write(&path, &huge), Err(ArtifactError::Io(_))));
        assert_eq!(fs::read(&path).unwrap(), before);
        assert_eq!(read(&path).unwrap(), stable);
    }
}
