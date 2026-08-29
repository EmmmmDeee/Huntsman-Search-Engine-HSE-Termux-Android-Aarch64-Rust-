//! Topology: architectural layers, in strict dependency order.
//!
//! Lower rank == earlier == fewer dependencies. The ordering is the
//! linearisation of the dependency DAG enforced by `tests/architecture.rs`:
//! util (leaf) -> core (uses util, defines ports) -> storage (impl ports)
//! -> modules (use core types + util; never engine/storage) -> api -> cli
//! -> audit/selftest -> crate roots (declare everything) -> tests/benches
//! -> tooling/docs appendix.

/// `(rank, label, human description)` — matched in order by [`classify_layer`].
pub const LAYER_RANKS: &[(u32, &str, &str)] = &[
    (
        0,
        "build",
        "Build & dependency foundation (manifest, lockfile, build script, lints)",
    ),
    (
        1,
        "util",
        "src/util — leaf utilities; no intra-crate deps above this layer",
    ),
    (
        2,
        "core",
        "src/core — engine, entities, correlation; uses util, defines ports",
    ),
    (
        3,
        "storage",
        "src/storage — persistence implementing core's StoragePort",
    ),
    (
        4,
        "modules",
        "src/modules — OSINT collectors; use core+util, never engine/storage",
    ),
    (
        5,
        "api",
        "src/api — HTTP/axum surface over core (via ports, not storage)",
    ),
    (
        6,
        "cli",
        "src/cli — command-line orchestration wiring all layers",
    ),
    (7, "audit", "src/audit — cross-cutting audit trail"),
    (8, "selftest", "src/selftest — built-in self-test harness"),
    (
        9,
        "crate-root",
        "Crate roots — lib.rs/main.rs declare & depend on every module above",
    ),
    (
        10,
        "web",
        "src/web — static SPA assets served by the api layer",
    ),
    (
        11,
        "src-other",
        "src/* — remaining source not otherwise classified",
    ),
    (
        12,
        "tests",
        "tests/ — integration & architecture tests (depend on whole crate)",
    ),
    (13, "benches", "benches/ — performance benchmarks"),
    (14, "scripts", "scripts/ — developer & CI shell tooling"),
    (15, "ci", ".github/ — CI/CD workflow definitions"),
    (
        16,
        "proptest",
        "proptest-regressions/ — recorded property-test seeds",
    ),
    (17, "meta", ".claude/ — agent & tooling configuration"),
    (
        18,
        "docs",
        "docs/ & root prose — design docs, READMEs, analyses, license",
    ),
];

/// A few foundation files get an explicit head-of-file order; everything
/// else is ordered structurally (see [`module_token_key`]).
const EXPLICIT_ORDER: &[(&str, u32)] = &[
    ("Cargo.toml", 0),
    ("Cargo.lock", 1),
    ("build.rs", 2),
    ("rust-toolchain.toml", 3),
    ("rust-toolchain", 3),
    ("deny.toml", 4),
    (".cargo/config.toml", 5),
    (".gitignore", 9),
];

fn explicit_order(path: &str) -> Option<u32> {
    EXPLICIT_ORDER
        .iter()
        .find(|(p, _)| *p == path)
        .map(|(_, o)| *o)
}

/// Return `(rank, label)` for `path`'s architectural layer.
///
/// Only the crate-root build files are "foundation". A per-module `build.rs`
/// (e.g. `src/modules/photon/build.rs`) belongs WITH its module and is left
/// to fall through to the `modules` layer, so a module stays contiguous.
pub fn classify_layer(path: &str) -> (u32, &'static str) {
    if explicit_order(path).is_some() || path.starts_with(".cargo/") {
        return (0, "build");
    }
    if path.starts_with("src/util/") {
        return (1, "util");
    }
    if path.starts_with("src/core/") {
        return (2, "core");
    }
    if path.starts_with("src/storage/") {
        return (3, "storage");
    }
    if path.starts_with("src/modules/") {
        return (4, "modules");
    }
    if path.starts_with("src/api/") {
        return (5, "api");
    }
    if path.starts_with("src/cli/") {
        return (6, "cli");
    }
    if path.starts_with("src/audit/") {
        return (7, "audit");
    }
    if path.starts_with("src/selftest/") {
        return (8, "selftest");
    }
    if matches!(
        path,
        "src/lib.rs" | "src/lib_tests.rs" | "src/main.rs" | "src/main_tests.rs"
    ) {
        return (9, "crate-root");
    }
    if path.starts_with("src/web/") {
        return (10, "web");
    }
    if path.starts_with("src/") {
        return (11, "src-other");
    }
    if path.starts_with("tests/") {
        return (12, "tests");
    }
    if path.starts_with("benches/") {
        return (13, "benches");
    }
    if path.starts_with("scripts/") {
        return (14, "scripts");
    }
    if path.starts_with(".github/") {
        return (15, "ci");
    }
    if path.starts_with("proptest-regressions/") {
        return (16, "proptest");
    }
    if path.starts_with(".claude/") {
        return (17, "meta");
    }
    (18, "docs")
}

/// One path component's place in [`module_token_key`]'s ordering: a file
/// (`File`) always sorts before a directory-continuation (`Dir`) at the same
/// depth — declaration order here IS the comparison order via `derive(Ord)`,
/// mirroring the Python original's `(0, ...)` / `(1, ...)` tuple-marker
/// trick without relying on comparing differently-shaped tuples.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum PathToken {
    /// `(0 for "mod.rs", 1 otherwise, filename)`.
    File(u8, String),
    Dir(String),
}

/// Structural sort key so a directory's own files (`mod.rs` first) sort
/// before its sub-directories — i.e. parent module before child modules.
pub fn module_token_key(path: &str) -> Vec<PathToken> {
    let parts: Vec<&str> = path.split('/').collect();
    let mut key: Vec<PathToken> = Vec::with_capacity(parts.len());
    for d in &parts[..parts.len() - 1] {
        key.push(PathToken::Dir((*d).to_string()));
    }
    let fname = parts[parts.len() - 1];
    let marker = u8::from(fname != "mod.rs");
    key.push(PathToken::File(marker, fname.to_string()));
    key
}

pub type SortKey = (u32, u32, Vec<PathToken>);

pub fn sort_key(path: &str) -> SortKey {
    let (rank, _label) = classify_layer(path);
    (
        rank,
        explicit_order(path).unwrap_or(10_000),
        module_token_key(path),
    )
}

/// Provenance hint so the agent knows non-authored / generated files.
pub fn category_note(path: &str) -> &'static str {
    if path.starts_with("src/web/vendor/") {
        return "vendored third-party asset (not HSE-authored)";
    }
    if path == "Cargo.lock" {
        return "generated dependency lockfile";
    }
    if path.starts_with("proptest-regressions/") {
        return "generated property-test regression seeds";
    }
    if path.ends_with(".der") {
        return "binary test fixture (DER certificate)";
    }
    if path.starts_with("src/web/") && !path.starts_with("src/web/vendor/") {
        return "hand-rolled SPA front-end asset";
    }
    ""
}

#[cfg(test)]
mod tests {
    include!("topology_tests.rs");
}
