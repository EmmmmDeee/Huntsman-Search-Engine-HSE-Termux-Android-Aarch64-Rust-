//! Pure parsing of the subset of `Cargo.lock` this tool needs: name, version,
//! and whether a package came from the public crates.io registry (as opposed
//! to a path, git, or alternate-registry dependency — a cooldown on crates.io
//! publish dates has nothing to check for those, so they're filtered out
//! here rather than left for the caller to notice).
//!
//! No network, no filesystem — the caller reads the file, this just parses
//! the string, so the parse itself is exercised directly in tests.

use serde::Deserialize;

/// The crates.io source marker Cargo writes into every `[[package]]` entry
/// resolved from the public index. A literal string to match exactly, not a
/// URL to parse or compare loosely — this is what's actually on disk.
const CRATES_IO_SOURCE: &str = "registry+https://github.com/rust-lang/crates.io-index";

#[derive(Debug, Deserialize)]
struct RawLockfile {
    #[serde(rename = "package", default)]
    packages: Vec<RawPackage>,
}

#[derive(Debug, Deserialize)]
struct RawPackage {
    name: String,
    version: String,
    #[serde(default)]
    source: Option<String>,
}

/// One crates.io-sourced dependency, as recorded in `Cargo.lock`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryPackage {
    pub name: String,
    pub version: String,
}

/// Parse `Cargo.lock` and return every dependency sourced from the public
/// crates.io registry, in file order. A package with no `source` (this
/// crate's own `[[package]]` entry, or any path dependency) or a non-crates.io
/// source (git, an alternate registry) is skipped, not reported as an error —
/// it is simply out of scope for a crates.io publish-date cooldown.
pub fn crates_io_packages(raw: &str) -> Result<Vec<RegistryPackage>, toml::de::Error> {
    let parsed: RawLockfile = toml::from_str(raw)?;
    Ok(parsed
        .packages
        .into_iter()
        .filter(|p| p.source.as_deref() == Some(CRATES_IO_SOURCE))
        .map(|p| RegistryPackage {
            name: p.name,
            version: p.version,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    include!("lockfile_tests.rs");
}
