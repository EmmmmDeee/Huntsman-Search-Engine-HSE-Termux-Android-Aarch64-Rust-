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
