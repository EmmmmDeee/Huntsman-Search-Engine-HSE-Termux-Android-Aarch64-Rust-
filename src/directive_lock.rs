//! Canonical Huntsman directive identity and repository mirror synchronization.
//!
//! This module deliberately operates only on an explicitly supplied repository
//! root. Installed binaries are not required to carry source-tree instruction
//! files, so ordinary runtime checks must not depend on these paths.

use std::fs;
use std::path::Path;

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

fn read(path: &Path) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|error| format!("{}: {error}", path.display()))
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

/// A mirror is the canonical directive, which is a few KiB; a larger body is a bug.
const MIRROR_MAX_BYTES: u64 = 1_048_576;

/// Replace a mirror through the crate's one atomic writer, so it lands whole, is flushed with
/// its directory, and never writes through a symbolic link.
fn replace_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    crate::fsio::write_atomic(path, bytes, MIRROR_MAX_BYTES).map_err(|error| error.to_string())
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
    use super::*;
    use std::path::PathBuf;

    fn unique_root() -> PathBuf {
        std::env::temp_dir().join(format!(
            "huntsman-directive-lock-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ))
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
        let root = unique_root();
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();

        let canonical = fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join(CANONICAL)).unwrap();
        fs::write(root.join(CANONICAL), &canonical).unwrap();
        for mirror in MIRRORS {
            let path = root.join(mirror);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, b"drift").unwrap();
        }

        assert!(verify_at(&root).is_err());
        sync_at(&root).unwrap();
        verify_at(&root).unwrap();
        assert_eq!(fs::read(root.join(CANONICAL)).unwrap(), canonical);

        fs::remove_dir_all(root).unwrap();
    }
}
