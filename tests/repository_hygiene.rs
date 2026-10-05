use std::fs;
use std::path::PathBuf;

const OPAQUE_ARCHIVE_SUFFIXES: &[&str] = &[
    ".zip", ".7z", ".rar", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".tar.zst",
];

const PINNED_REFERENCE_ARCHIVES: &[(&str, &str)] = &[
    (
        "huntsman-hse-endtoend-refactor-overlay-feef60a.zip",
        "bba70abb0ac7f8c1f1ade818580273a78d169628c14b4b908ff6a5c08e90faf7",
    ),
    (
        "huntsman-search-engine-hse-termux-android-aarch64-rust--main (10).zip",
        "c3c7f843a1c495f443344a228ce2707b097d53edaa7aea2238347452b7495241",
    ),
];

#[test]
fn repository_root_contains_only_pinned_reference_archives() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();
    let mut found_pinned = Vec::new();

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
            if let Some((_, expected_hash)) = PINNED_REFERENCE_ARCHIVES
                .iter()
                .find(|(pinned_name, _)| *pinned_name == name)
            {
                let bytes = fs::read(entry.path()).expect("pinned archive");
                let actual_hash =
                    huntsman_recon::sha256::hex32(&huntsman_recon::sha256::sha256(&bytes));
                assert_eq!(
                    actual_hash, *expected_hash,
                    "pinned archive changed: {name}"
                );
                found_pinned.push(name);
            } else {
                offenders.push(name);
            }
        }
    }

    offenders.sort();
    found_pinned.sort();
    let mut required_pinned: Vec<String> = PINNED_REFERENCE_ARCHIVES
        .iter()
        .map(|(name, _)| (*name).to_owned())
        .collect();
    required_pinned.sort();
    assert_eq!(
        found_pinned, required_pinned,
        "both byte-pinned historical reference archives must remain at the repository root"
    );
    assert_eq!(
        offenders,
        Vec::<String>::new(),
        "only the two byte-pinned historical references are permitted as root archives"
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
