use std::fs;
use std::path::PathBuf;

const OPAQUE_ARCHIVE_SUFFIXES: &[&str] = &[
    ".zip", ".7z", ".rar", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".tar.zst",
];

#[test]
fn repository_root_contains_no_opaque_archives() {
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
        "opaque archive snapshots are forbidden at the repository root; preserve historical identity in docs/ARCHIVE_PROVENANCE.md and Git history"
    );
}

#[test]
fn archive_provenance_is_documented() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let provenance = fs::read_to_string(root.join("docs/ARCHIVE_PROVENANCE.md"))
        .expect("docs/ARCHIVE_PROVENANCE.md");
    assert!(provenance.contains("01089c7e756216a33573cdefdfd7068dfa4e5380"));
    assert!(provenance.contains("Historical Git tree"));
}
