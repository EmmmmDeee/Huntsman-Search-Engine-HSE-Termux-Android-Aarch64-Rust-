//! Canonical Huntsman directive identity and repository mirror synchronization.
//!
//! This module deliberately operates only on an explicitly supplied repository
//! root. Installed binaries are not required to carry source-tree instruction
//! files, so ordinary runtime checks must not depend on these paths.

use std::fs;
use std::path::{Path, PathBuf};

pub const EXPECTED_SHA256: &str =
    "5bdd9777d9a8046d2d4a6bf645ee6201b6e1d004b1a6a1fc7a99eb246a687584";
pub const CANONICAL: &str = "HUNTSMAN_CANONICAL_TEAM_DIRECTIVE.md";
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

fn ensure_parent(path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| format!("{}: {error}", parent.display()))?;
    }
    Ok(())
}

fn replacement_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map_or_else(|| "directive".into(), |name| name.to_os_string());
    name.push(format!(".tmp-{}", std::process::id()));
    path.with_file_name(name)
}

fn replace_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    ensure_parent(path)?;
    let tmp = replacement_path(path);
    fs::write(&tmp, bytes).map_err(|error| format!("{}: {error}", tmp.display()))?;
    match fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = fs::remove_file(&tmp);
            Err(format!("{}: {error}", path.display()))
        }
    }
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

    fn unique_root() -> PathBuf {
        std::env::temp_dir().join(format!(
            "huntsman-directive-lock-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ))
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

        let canonical =
            fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join(CANONICAL)).unwrap();
        fs::write(root.join(CANONICAL), &canonical).unwrap();
        for mirror in MIRRORS {
            let path = root.join(mirror);
            ensure_parent(&path).unwrap();
            fs::write(path, b"drift").unwrap();
        }

        assert!(verify_at(&root).is_err());
        sync_at(&root).unwrap();
        verify_at(&root).unwrap();
        assert_eq!(fs::read(root.join(CANONICAL)).unwrap(), canonical);

        fs::remove_dir_all(root).unwrap();
    }
}
