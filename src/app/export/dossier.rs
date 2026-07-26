//! Dossier directory helpers — path resolution and on-disk persistence.

use crate::core::error::{Error, Result};

/// Comma-join an iterator of strings, or `(none)` when empty — so an empty
/// provenance line is explicit rather than a confusing blank.
pub(super) fn join_or_dash<'a>(it: impl Iterator<Item = &'a String>) -> String {
    let joined = it.enumerate().fold(String::new(), |mut acc, (i, s)| {
        if i > 0 {
            acc.push_str(", ");
        }
        acc.push_str(s.as_str());
        acc
    });
    if joined.is_empty() {
        "(none)".to_string()
    } else {
        joined
    }
}

/// Default directory for auto-saved full dossiers: `$HOME/.huntsman/dossiers`.
pub(crate) fn dossier_dir() -> std::path::PathBuf {
    crate::util::paths::subdir("dossiers")
}

/// Render and persist the full dossier for `sid` to
/// `$HOME/.huntsman/dossiers/<sid>.txt`, returning the path. Called at the end
/// of every `hse scan` so the maximum-detail dossier — every entity, full
/// provenance, and every raw API response embedded — is guaranteed to exist for
/// EVERY search, without the operator running a separate `export`. Best-effort
/// for the caller: a write failure is returned as an error to log, never fatal.
pub(crate) fn write_full_dossier(
    store: &dyn crate::core::port::StoragePort,
    sid: &str,
) -> Result<std::path::PathBuf> {
    let body = super::renderers::render_full(store, sid)?;
    let dir = dossier_dir();
    // The auto-dossier embeds full PII + the raw API corpus (incl. any harvested
    // third-party keys), so keep the tree owner-only: 0700 dir + 0600 atomic write
    // (PROBLEM_TREE §7 S3), consistent with `.huntsman.env` / `key_pool.json`.
    crate::util::atomic_file::create_dir_private(&dir)
        .map_err(|e| Error::Other(format!("create {dir:?}: {e}")))?;
    let path = dir.join(format!("{sid}.txt"));
    crate::util::atomic_file::write(&path, body.as_bytes())
        .map_err(|e| Error::Other(format!("write {path:?}: {e}")))?;
    Ok(path)
}
