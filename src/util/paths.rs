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
///
/// That `cfg(test)` switch covers the library's OWN unit tests only. An
/// integration crate under `tests/` links the ordinary non-test build of the
/// library, where `cfg!(test)` is `false` — so those crates use
/// [`isolate_for_tests`] (via `tests/common`) to get the same redirection at
/// runtime, without `unsafe` and without touching the process environment.
#[must_use]
pub fn huntsman_dir() -> PathBuf {
    let dir = huntsman_dir_path();
    // 0700 owner-only; best-effort so a read path still resolves on failure.
    // `create_dir_private` also RE-TIGHTENS a pre-existing dir (an older install's
    // `~/.huntsman` made 0755 by a plain `create_dir_all`), so the key pool /
    // vault / intelligence DB beneath it stay unreadable to other local UIDs on
    // the upgrade path — this centralises the unconditional 0700 the
    // pre-consolidation `vault_path` used to run on every call.
    let _ = crate::util::atomic_file::create_dir_private(&dir);
    dir
}

/// The `$HOME/.huntsman` base path **without** creating or re-tightening it —
/// the pure path computation only, with none of [`huntsman_dir`]'s directory
/// side effects.
///
/// For a read-only / measurement caller that must not mutate the on-disk layout
/// (e.g. `hse tidy --dry-run`, whose contract is that nothing on disk changes).
/// Every path that will be *written* must go through [`huntsman_dir`] /
/// [`data_file`] / [`subdir`] instead, so the base dir is created and re-tightened
/// `0700` before anything lands under it. Shares [`huntsman_dir`]'s `cfg(test)`
/// redirection so the two never disagree on where the base is.
#[must_use]
pub fn huntsman_dir_path() -> PathBuf {
    if cfg!(test) {
        return std::env::temp_dir()
            .join("huntsman-test-home")
            .join(".huntsman");
    }
    if let Some(dir) = TEST_BASE_DIR.get() {
        return dir.clone();
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".huntsman")
}

/// Set once by [`isolate_for_tests`]; consulted by [`huntsman_dir_path`], the
/// single computation every accessor in this module derives from.
static TEST_BASE_DIR: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/// Route **every** accessor in this module at an isolated, per-process
/// directory under the OS temp dir for the rest of the process, and return it.
/// The integration-test harness's (`tests/common`) counterpart of the
/// `cfg(test)` switch in [`huntsman_dir`].
///
/// Why it exists: `cfg!(test)` is `false` in the library as linked by a crate
/// under `tests/`, so before this every `tests/api.rs` scan that completed
/// wrote its synthetic `module_stats.json` into the developer's **real**
/// `~/.huntsman` (observed: a real ledger carrying 102 fixture "seed" scans,
/// feeding `hse scan --adaptive`), one test overwrote the real `settings.json`,
/// and the smoke suite's key-chaining fixture banked a fake `shodan` key into
/// the real `key_pool.json` — a labelled test fixture escaping the harness,
/// exactly what RULE 1 forbids.
///
/// Why this shape: `std::env::set_var("HOME", …)` is `unsafe` and this crate
/// is `#![forbid(unsafe_code)]`; a `OnceLock` is safe, needs no env mutation,
/// and `get_or_init` blocks concurrent callers until the first has set it, so
/// parallel test threads that all go through the harness see one location.
/// Idempotent: the first call fixes the location for the process; later calls
/// return the same path. Per-process (`huntsman-test-home-<pid>`) so the api,
/// smoke and halting binaries `cargo test` runs concurrently never share a
/// settings/ledger file.
///
/// This is deliberately **not** the env-var escape hatch [`data_file`]'s doc
/// rules out: it changes only the base-path computation, so [`huntsman_dir`]'s
/// `0700` creation still runs and [`data_file`]/[`subdir`] still derive from the
/// one base. `production_code_never_redirects_the_data_dir`
/// (tests/architecture_parts) pins that nothing under `src/` calls it.
#[must_use]
pub fn isolate_for_tests() -> PathBuf {
    TEST_BASE_DIR
        .get_or_init(|| {
            std::env::temp_dir()
                .join(format!("huntsman-test-home-{}", std::process::id()))
                .join(".huntsman")
        })
        .clone()
}

/// `$HOME/.huntsman/<name>` — a file directly under the base data directory,
/// created (0700) on demand. The one-liner every per-file path accessor is built
/// from (`data_file("key_pool.json")`, `data_file("settings.json")`, …).
///
/// Deliberately has **no env-var escape hatch**. An override that returned early
/// would skip [`huntsman_dir`]'s `create_dir_private` — the sole mechanism that
/// creates, and re-tightens, the base directory `0700` — so the key pool and key
/// vault would land under the ambient umask (the exact exposure this module
/// exists to close, see above). It would also desynchronise this accessor from
/// [`subdir`]: `huntsman.db` would move while the `raw/` archive it indexes
/// stayed behind. Tests get their isolation from the `cfg(test)` switch in
/// [`huntsman_dir`] (unit tests) or [`isolate_for_tests`] (integration crates)
/// instead — both only move the base every accessor shares, so the `0700`
/// creation and the single-base derivation hold uniformly.
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

/// `$HOME/.huntsman/<sub>` **without** creating it — the pure path only, the
/// non-creating counterpart to [`subdir`]. For a read-only / measurement caller
/// (e.g. `hse tidy --dry-run`) that must not mutate the on-disk layout: [`subdir`]
/// would create and re-tighten both the child and the base directory as a side
/// effect, which a dry run must not do. Every write path must use [`subdir`].
#[must_use]
pub fn subdir_path(sub: &str) -> PathBuf {
    huntsman_dir_path().join(sub)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subdir_path_is_pure_while_subdir_creates() {
        // The dry-run contract depends on `subdir_path` computing the path with
        // NO filesystem side effect, unlike `subdir` which creates 0700. Use a
        // unique child name so this is independent of any other test's state in
        // the process-shared cfg(test) home.
        let unique = format!("measure-only-{}", std::process::id());
        let pure = subdir_path(&unique);
        assert!(
            !pure.exists(),
            "subdir_path must not create the directory: {pure:?}"
        );
        assert_eq!(pure, huntsman_dir_path().join(&unique));

        // The creating counterpart does make it exist.
        let created = subdir(&unique);
        assert_eq!(created, pure, "both must resolve to the same path");
        assert!(created.exists(), "subdir must create the directory");
        // Clean up so the assertion holds on a re-run in the shared test home.
        let _ = std::fs::remove_dir(&created);
    }

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
