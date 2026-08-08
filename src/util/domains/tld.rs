//! The IANA delegated top-level-domain set — the canonical answer to "is this
//! last label a real TLD?".
//!
//! # Why this exists
//!
//! Every domain locator in this crate was purely STRUCTURAL: `core::classifier`'s
//! `DOMAIN_RE` matches `label(.label)+.alpha{2,}`, and
//! [`super::looks_like_domain`] additionally required only that the last label be
//! ≥2 chars with an alphabetic character in it. Neither asked whether the TLD
//! exists, so anything shaped like a dotted name became a `Domain` entity.
//! Measured against the real extractor, from a nine-line input:
//!
//! ```text
//! john.smith      → domain 0.75     report.pdf     → domain 0.75
//! mr.smith        → domain 0.75     image.png      → domain 0.75
//! version.number  → domain 0.75     script.js      → domain 0.75
//!                                   config.yaml    → domain 0.75
//! ```
//!
//! Seven of nine inputs were false positives: a person's name, a name with a
//! title, ordinary prose, and four filenames. Each became a first-class entity
//! that later scans would try to resolve, enrich and correlate as a host.
//! `firstname.lastname` is not an unusual string in this problem domain — it is
//! the single most common shape of a username in a breach dump.
//!
//! # Why a snapshot rather than a live query
//!
//! The target platform is offline-capable Termux with no root: a DNS or HTTP
//! check per candidate would be unbounded, non-deterministic, network-dependent,
//! and would leak the operator's extraction inputs to a resolver. The IANA list
//! is 9.5 KB and changes a few times a year, so it is embedded verbatim.
//!
//! The file is the authoritative artefact, unmodified — including its version
//! header — so it can be diffed against the source and refreshed by replacing it:
//!
//! ```text
//! curl -o src/util/domains/tlds-alpha-by-domain.txt \
//!      https://data.iana.org/TLD/tlds-alpha-by-domain.txt
//! ```
//!
//! [`snapshot_version`] surfaces which revision is compiled in, and a test pins
//! the parsed entry count so a truncated or corrupted replacement fails the build
//! rather than silently shrinking the accepted set.

use std::collections::HashSet;
use std::sync::LazyLock;

/// The IANA list verbatim, uppercase, one TLD per line, `#`-comment header.
const RAW: &str = include_str!("tlds-alpha-by-domain.txt");

/// Lowercased delegated TLDs. Built once; ~1.4k short strings, well under 64 KB.
static TLDS: LazyLock<HashSet<String>> = LazyLock::new(|| {
    RAW.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_ascii_lowercase)
        .collect()
});

/// The `Version NNNNNNNNNN` field from the embedded file's header, or `"unknown"`
/// if the header is not in the expected shape. Reported by `hse diagnostics` so
/// an operator can see how old the compiled-in set is.
#[must_use]
pub fn snapshot_version() -> &'static str {
    RAW.lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(2))
        .map_or("unknown", |v| v.trim_end_matches(','))
}

/// True when `tld` is an IANA-delegated top-level domain.
///
/// Case-insensitive. Accepts a bare label (`"com"`), with or without a leading
/// dot (`".com"`). Punycode IDN TLDs (`xn--…`) are included, as IANA lists them.
#[must_use]
pub fn is_known_tld(tld: &str) -> bool {
    let t = tld.trim().trim_start_matches('.');
    if t.is_empty() {
        return false;
    }
    // The common case — already lowercase, as every caller here works from an
    // already-lowercased value — costs no allocation.
    if TLDS.contains(t) {
        return true;
    }
    if t.bytes().any(|b| b.is_ascii_uppercase()) {
        return TLDS.contains(&t.to_ascii_lowercase());
    }
    false
}

/// True when `host`'s LAST label is a delegated TLD — the domain-level form of
/// [`is_known_tld`]. `false` for a single label with no dot at all, which names
/// no registrable domain.
#[must_use]
pub fn has_known_tld(host: &str) -> bool {
    let h = host.trim().trim_end_matches('.');
    match h.rsplit_once('.') {
        Some((_, tld)) => is_known_tld(tld),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact false positives measured against the real extractor, which is
    /// what motivated embedding the list.
    #[test]
    fn the_observed_false_positives_are_all_rejected() {
        for host in [
            "john.smith",
            "mr.smith",
            "report.pdf",
            "image.png",
            "script.js",
            "config.yaml",
            "version.number",
        ] {
            assert!(
                !has_known_tld(host),
                "{host} must not read as a domain — its last label is not a delegated TLD"
            );
        }
    }

    /// The other half, and the one that matters more: real domains must survive.
    /// A filter that rejected everything would pass the test above.
    #[test]
    fn real_domains_survive() {
        for host in [
            "example.com",
            "bbc.co.uk",
            "sub.example.org",
            "a-zfastfitcentre.co.uk",
            "some.thing.gov.au",
            // Newer gTLDs are exactly the case a hand-maintained "common TLDs"
            // list gets wrong, and `.app`/`.dev` are genuinely delegated — a
            // file named `foo.app` is ambiguous by nature and must NOT be
            // rejected on a guess.
            "myproject.app",
            "tooling.dev",
            "shop.xyz",
        ] {
            assert!(has_known_tld(host), "{host} is a real domain and must pass");
        }
    }

    #[test]
    fn is_known_tld_is_case_and_dot_insensitive() {
        for t in ["com", "COM", "Com", ".com", ".COM", "  com  "] {
            assert!(is_known_tld(t), "{t:?} must be recognised");
        }
        assert!(!is_known_tld(""));
        assert!(!is_known_tld("."));
        assert!(!is_known_tld("smith"));
    }

    /// IDN TLDs are delegated and must be accepted in their punycode form.
    #[test]
    fn punycode_idn_tlds_are_included() {
        assert!(
            TLDS.iter().any(|t| t.starts_with("xn--")),
            "the snapshot must contain the IDN TLDs"
        );
    }

    /// A single label names no registrable domain.
    #[test]
    fn a_bare_label_is_not_a_domain() {
        assert!(!has_known_tld("localhost"));
        assert!(!has_known_tld("com"));
        assert!(!has_known_tld(""));
    }

    /// Pins the snapshot so a truncated or corrupted replacement fails the build
    /// instead of silently shrinking the accepted set — which would show up as
    /// real domains being dropped, the least visible failure mode this has.
    #[test]
    fn the_snapshot_parses_to_a_plausible_tld_count() {
        let n = TLDS.len();
        assert!(
            (1_000..=2_000).contains(&n),
            "IANA has published between 1000 and 2000 TLDs for years; got {n} — \
             the embedded file is probably truncated or the wrong format"
        );
        assert!(TLDS.contains("com") && TLDS.contains("au") && TLDS.contains("uk"));
        assert_ne!(
            snapshot_version(),
            "unknown",
            "the version header must parse"
        );
    }
}
