//! Canonical Huntsman directive identity and repository mirror synchronization.
//!
//! This module deliberately operates only on an explicitly supplied repository
//! root. Installed binaries are not required to carry source-tree instruction
//! files, so ordinary runtime checks must not depend on these paths.

use std::path::Path;

use crate::error::Error;
use crate::fsio;

pub const EXPECTED_SHA256: &str =
    "3d02dd021502fd1c4eda70dd2b01cfe4bb19704f79452a890f1301053fac979d";
pub const CANONICAL: &str = "HUNTSMAN_CANONICAL_TEAM_DIRECTIVE.md";
const EMBEDDED_CANONICAL: &[u8] = include_bytes!("../HUNTSMAN_CANONICAL_TEAM_DIRECTIVE.md");
pub const MIRRORS: [&str; 6] = [
    "AGENTS.md",
    "CLAUDE.md",
    "GEMINI.md",
    "RULE.md",
    "CONTRIBUTING.md",
    ".github/copilot-instructions.md",
];

/// Upper bound on the canonical directive and on each mirror, for every read and write of them.
/// The canonical file is a few KiB; 1 MiB leaves it room to grow many times over and keeps a
/// mirror replaced by a huge file, or by a link to one, from being read whole into memory before
/// the comparison refuses it: every external input in the crate is capped.
pub const MAX_DIRECTIVE_BYTES: u64 = 1024 * 1024;

/// A file error as this module reports it. An `fsio` message already names the path it is about
/// (the file, its temp file or its parent directory), so it is passed through; any other error
/// gets the path.
fn describe(path: &Path, error: &Error) -> String {
    if let Error::Store(message) = error {
        message.clone()
    } else {
        format!("{}: {error}", path.display())
    }
}

/// Read the canonical file or a mirror through `fsio::read_bounded`: a symlink, a non-file or a
/// file over [`MAX_DIRECTIVE_BYTES`] is refused, naming the path.
fn read(path: &Path) -> Result<Vec<u8>, String> {
    fsio::read_bounded(path, MAX_DIRECTIVE_BYTES).map_err(|error| describe(path, &error))
}

/// Verify the canonical directive embedded into an installed binary at build time.
///
/// # Errors
/// Returns an error if the embedded bytes do not match the pinned canonical hash.
pub fn verify_embedded() -> Result<(), String> {
    let actual = crate::sha256::hex32(&crate::sha256::sha256(EMBEDDED_CANONICAL));
    if actual != EXPECTED_SHA256 {
        return Err(format!(
            "embedded canonical SHA-256 drift: expected {EXPECTED_SHA256}, got {actual}"
        ));
    }
    Ok(())
}

fn canonical_bytes(root: &Path) -> Result<Vec<u8>, String> {
    let path = root.join(CANONICAL);
    let bytes = read(&path)?;
    let actual = crate::sha256::hex32(&crate::sha256::sha256(&bytes));
    if actual != EXPECTED_SHA256 {
        return Err(format!(
            "{CANONICAL}: canonical SHA-256 drift: expected {EXPECTED_SHA256}, got {actual}"
        ));
    }
    Ok(bytes)
}

/// Verify the canonical directive and every repository instruction mirror.
///
/// # Errors
/// Returns a precise path-specific diagnostic when the canonical artifact is
/// missing/changed or any mirror is absent/different.
pub fn verify_at(root: &Path) -> Result<(), String> {
    let canonical = canonical_bytes(root)?;
    for mirror in MIRRORS {
        let path = root.join(mirror);
        let bytes = read(&path)?;
        if bytes != canonical {
            return Err(format!(
                "{mirror}: directive drift; run huntsman-recon directive sync from the repository root"
            ));
        }
    }
    Ok(())
}

/// Replace a mirror whole or not at all, through `fsio::write_atomic`: a mirror or a parent
/// directory that is a symlink is refused, a missing parent (`.github/`) is created, the temp
/// file is created exclusively under a fresh name, and the bytes and the directory entry are
/// flushed before the call returns.
fn replace_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    fsio::write_atomic(path, bytes, MAX_DIRECTIVE_BYTES).map_err(|error| describe(path, &error))
}

/// Rewrite every repository instruction mirror from the pinned canonical file.
///
/// The canonical file is validated before any mirror is changed. A corrupted
/// canonical source therefore cannot be propagated.
///
/// # Errors
/// Returns an error if canonical validation, any write, or final verification
/// fails.
pub fn sync_at(root: &Path) -> Result<(), String> {
    let canonical = canonical_bytes(root)?;
    for mirror in MIRRORS {
        replace_file(&root.join(mirror), &canonical)?;
    }
    verify_at(root)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use super::*;

    fn unique_root() -> PathBuf {
        std::env::temp_dir().join(format!(
            "huntsman-directive-lock-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ))
    }

    /// An empty root holding a copy of the repository's canonical file; its bytes.
    fn fresh_root_with_canonical() -> (PathBuf, Vec<u8>) {
        let root = unique_root();
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let canonical = fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join(CANONICAL)).unwrap();
        fs::write(root.join(CANONICAL), &canonical).unwrap();
        (root, canonical)
    }

    fn write_mirrors(root: &Path, bytes: &[u8]) {
        for mirror in MIRRORS {
            let path = root.join(mirror);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, bytes).unwrap();
        }
    }

    #[test]
    fn embedded_canonical_is_verified() {
        verify_embedded().unwrap();
    }

    #[test]
    fn repo_checkout_is_verified() {
        verify_at(Path::new(env!("CARGO_MANIFEST_DIR"))).unwrap();
    }

    #[test]
    fn sync_repairs_mirrors_without_mutating_canonical() {
        let (root, canonical) = fresh_root_with_canonical();
        write_mirrors(&root, b"drift");

        assert!(verify_at(&root).is_err());
        sync_at(&root).unwrap();
        verify_at(&root).unwrap();
        assert_eq!(fs::read(root.join(CANONICAL)).unwrap(), canonical);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn sync_creates_a_missing_mirror_directory() {
        let (root, canonical) = fresh_root_with_canonical();
        assert!(!root.join(".github").exists());
        sync_at(&root).unwrap();
        assert_eq!(
            fs::read(root.join(".github/copilot-instructions.md")).unwrap(),
            canonical
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_mirror_is_refused_by_verify_and_by_sync() {
        let (root, canonical) = fresh_root_with_canonical();
        write_mirrors(&root, &canonical);
        verify_at(&root).unwrap();

        // Replace one mirror with a link to a copy of the canonical text: a check that followed
        // the link would pass, and a sync that wrote through it would land in the link's target.
        let target = root.join("elsewhere.md");
        fs::write(&target, &canonical).unwrap();
        let link = root.join("CLAUDE.md");
        fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let shown = link.display().to_string();

        let error = verify_at(&root).expect_err("a symlinked mirror must be refused by verify");
        assert!(error.contains(&shown), "{error}");
        assert!(error.contains("refusing symlink"), "{error}");
        let error = sync_at(&root).expect_err("a symlinked mirror must be refused by sync");
        assert!(error.contains(&shown), "{error}");
        assert!(error.contains("refusing symlink"), "{error}");
        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink(),
            "sync must leave the link in place rather than replace it"
        );
        assert_eq!(
            fs::read(&target).unwrap(),
            canonical,
            "the link's target is untouched"
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_mirror_directory_is_refused_by_sync() {
        let (root, canonical) = fresh_root_with_canonical();
        let elsewhere = root.join("elsewhere");
        fs::create_dir_all(&elsewhere).unwrap();
        let linked_dir = root.join(".github");
        std::os::unix::fs::symlink(&elsewhere, &linked_dir).unwrap();

        let error = sync_at(&root).expect_err("a symlinked mirror directory must be refused");
        assert!(error.contains(&linked_dir.display().to_string()), "{error}");
        assert!(error.contains("refusing symlink"), "{error}");
        assert!(
            !elsewhere.join("copilot-instructions.md").exists(),
            "sync must not write through the linked directory"
        );
        assert_eq!(fs::read(root.join(CANONICAL)).unwrap(), canonical);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_mirror_over_the_cap_is_refused_naming_the_cap() {
        let (root, canonical) = fresh_root_with_canonical();
        write_mirrors(&root, &canonical);
        verify_at(&root).unwrap();

        let huge = root.join("RULE.md");
        let mut body = canonical;
        body.resize(usize::try_from(MAX_DIRECTIVE_BYTES).unwrap() + 1, b'#');
        fs::write(&huge, &body).unwrap();

        let error = verify_at(&root).expect_err("a mirror over the cap must be refused");
        assert!(error.contains(&huge.display().to_string()), "{error}");
        assert!(
            error.contains(&format!("exceeds {MAX_DIRECTIVE_BYTES} bytes")),
            "{error}"
        );

        fs::remove_dir_all(root).unwrap();
    }
}
