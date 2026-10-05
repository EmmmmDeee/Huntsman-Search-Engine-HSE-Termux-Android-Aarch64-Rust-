use std::fs;
use std::path::PathBuf;

const OPAQUE_ARCHIVE_SUFFIXES: &[&str] = &[
    ".zip", ".7z", ".rar", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".tar.zst",
];

#[test]
fn repository_root_contains_no_opaque_snapshot_archives() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();

    for entry in fs::read_dir(&root).expect("repository root") {
        let entry = entry.expect("repository entry");
        if !entry.file_type().expect("repository entry type").is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
        if OPAQUE_ARCHIVE_SUFFIXES
            .iter()
            .any(|suffix| name.ends_with(suffix))
        {
            offenders.push(name);
        }
    }

    offenders.sort();
    assert_eq!(
        offenders,
        Vec::<String>::new(),
        "opaque project snapshots belong in extracted, reviewable form; raw source archives remain recoverable from Git history"
    );
}

#[test]
fn archive_documentation_tracks_the_canonical_extracted_state() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let readme = fs::read_to_string(root.join("README.md")).expect("README.md");
    let architecture = fs::read_to_string(root.join("ARCHITECTURE.md")).expect("ARCHITECTURE.md");
    let dispositions =
        fs::read_to_string(root.join("docs/DISPOSITIONS.md")).expect("docs/DISPOSITIONS.md");
    let reconstruction = fs::read_to_string(root.join("docs/RECONSTRUCTION_2026-10-02.md"))
        .expect("docs/RECONSTRUCTION_2026-10-02.md");

    assert!(readme.contains("docs/ARCHIVE_PROVENANCE.md"));
    assert!(architecture.contains("docs/ARCHIVE_PROVENANCE.md"));
    assert!(dispositions.contains("ARCHIVE_PROVENANCE.md"));
    assert!(reconstruction.contains("ARCHIVE_PROVENANCE.md"));

    assert!(!readme.contains("`*.zip` (root)"));
    assert!(!architecture.contains("two root zip archives are pinned"));
    assert!(!dispositions.contains("two root zip archives"));
    assert!(!reconstruction.contains("legacy zip archives are back in the repository root"));
}
