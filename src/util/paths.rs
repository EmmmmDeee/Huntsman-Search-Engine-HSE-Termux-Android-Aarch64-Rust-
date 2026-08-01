//! Single source of truth for HSE's on-disk layout.
//!
//! Every persisted file — the scan DB, key pool, key vault, settings, raw
//! archive, dossiers, diagnostics ledger, cell-tower DB — lives under one base
//! directory, `$HOME/.huntsman`. Before this module that base path was
//! reconstructed independently in a dozen call sites with **inconsistent**
//! behaviour: some (`map_or_else`) scattered bare files into the CWD when `$HOME`
//! was unset (`./cell_towers.db`) while others (`unwrap_or_else(".")`) kept the
//! layout together (`./.huntsman/…`); and some created the directory `0700`
//! (owner-only), some at the default umask, some not at all. Consolidating here
//! makes the layout — and its permissions — consistent by construction.

use std::path::PathBuf;

/// The base `$HOME/.huntsman` data directory, created **`0700` (owner-only)** if
/// absent, and returned.
///
/// `~/.huntsman` holds secrets (the key pool / vault, harvested credentials) and
/// intelligence data, so it is always owner-only to stop another local user on a
/// shared host enumerating it (PROBLEM_TREE §7 S3). Directory creation is
/// best-effort — a caller that only reads still gets the correct path back even
/// if creation fails.
///
/// When `$HOME` is unset — which never happens on Termux, where it is always set
/// (typically `/data/data/com.termux/files/home`) — this falls back to
/// `.huntsman` under the current directory, keeping the whole layout together
/// rather than scattering bare files.
///
/// Under `cfg(test)` this is rooted under the OS temp directory instead of the
/// real `$HOME` — several tests exercise code paths that persist real state
/// here (e.g. a 401/403/429 response through `keyed_cascade` triggers
/// `ModuleContext::report_key_exhausted`, which unconditionally saves the
/// whole key pool). `std::env::set_var("HOME", …)` would be the obvious
/// per-test fix, but is an `unsafe fn` this crate's `#![forbid(unsafe_code)]`
/// rules out entirely (see `curl_client::resolve_doh`'s doc comment for the
/// same constraint elsewhere) — `cfg(test)` is a compile-time switch, not a
/// runtime env mutation, so it needs no unsafe code and can't race a
/// fire-and-forget `spawn_blocking` persist that outlives the test function.
/// Shared across the whole test process (not a fresh directory per call), so
/// every call site agrees on one location, matching a real `$HOME`'s
/// single-location semantics — and still ends in `.huntsman`, so this is
/// invisible to callers and to this module's own path-shape tests below.
#[must_use]
pub fn huntsman_dir() -> PathBuf {
    let dir = if cfg!(test) {
        std::env::temp_dir()
            .join("huntsman-test-home")
            .join(".huntsman")
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        PathBuf::from(home).join(".huntsman")
    };
    // 0700 owner-only; best-effort so a read path still resolves on failure.
    // `create_dir_private` also RE-TIGHTENS a pre-existing dir (an older install's
    // `~/.huntsman` made 0755 by a plain `create_dir_all`), so the key pool /
    // vault / intelligence DB beneath it stay unreadable to other local UIDs on
    // the upgrade path — this centralises the unconditional 0700 the
    // pre-consolidation `vault_path` used to run on every call.
    let _ = crate::util::atomic_file::create_dir_private(&dir);
    dir
}

/// `$HOME/.huntsman/<name>` — a file directly under the base data directory,
/// created (0700) on demand. The one-liner every per-file path accessor is built
/// from (`data_file("key_pool.json")`, `data_file("settings.json")`, …).
#[must_use]
pub fn data_file(name: &str) -> PathBuf {
    huntsman_dir().join(name)
}

/// `$HOME/.huntsman/<sub>` — a SUB-directory under the base, created (0700) so
/// callers can immediately write files into it (`subdir("raw")`,
/// `subdir("dossiers")`).
#[must_use]
pub fn subdir(sub: &str) -> PathBuf {
    let dir = huntsman_dir().join(sub);
    let _ = crate::util::atomic_file::create_dir_private(&dir);
    dir
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_file_is_under_the_base_dir() {
        let f = data_file("key_pool.json");
        assert!(f.ends_with(".huntsman/key_pool.json"), "{f:?}");
        // The parent is exactly the base dir.
        assert_eq!(f.parent().expect("should succeed"), huntsman_dir());
    }

    #[test]
    fn subdir_is_a_child_of_the_base_dir() {
        let d = subdir("raw");
        assert!(d.ends_with(".huntsman/raw"), "{d:?}");
        assert_eq!(d.parent().expect("should succeed"), huntsman_dir());
    }

    #[test]
    fn base_dir_ends_in_dot_huntsman() {
        assert!(huntsman_dir().ends_with(".huntsman"));
    }
}
