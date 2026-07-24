//! Redaction of proprietary breach/intel **source identities** from the
//! shareable scan exports (CSV, `report.json`, GEXF, `events.log`).
//!
//! The operator pays for and relies on a private set of breach / leak / stealer
//! and paid-OSINT data providers (SeekNow, OathNet, DeHashed, …). A scan result
//! handed to a *customer* must not reveal WHICH providers produced a finding —
//! that provider set is the operator's tradecraft. Every finding's evidence and
//! every scan event names its producing module, so those names are genericised
//! on the way out of the four *download* endpoints.
//!
//! Scope: this genericises only the *provider identity*, never the finding
//! itself — the datum, its confidence, and its provenance TYPE (that it came
//! from a breach source) are preserved, so the export stays fully useful. The
//! operator's own full-detail views are deliberately UNAFFECTED: the live web-UI
//! panels (served by the `/entities`, `/network`, … JSON endpoints), the
//! loopback-only debug bundle, and `hse export` in the shell all keep the real
//! source names.

use crate::core::module::ModuleCategory;
use regex::Regex;
use std::collections::BTreeSet;
use std::sync::LazyLock;

/// The label a redacted provider name is replaced with. Preserves that the
/// datum came from a breach/leak source without naming which one, and is itself
/// never a sensitive name (so redaction is idempotent).
pub const REDACTED_LABEL: &str = "breach-source";

/// Paid/proprietary breach-intel provider source labels the category sweep in
/// [`SENSITIVE`] does NOT catch, in EVERY string form they appear as:
///   - `oathnet_pro` is `People`-categorised (not `Breach`), so the sweep skips
///     it entirely; and
///   - the `breach_rich` rich-pass and the stealer path stamp their source as
///     the HYPHENATED provider label (`see-know` / `oathnet-pro`) or the bare
///     `oathnet`, distinct from the underscore module `name()` the sweep sees.
///
/// The operator named OathNet and Seek-Know specifically, so every spelling of
/// both is listed. Add any other paid provider here as it is integrated; the
/// `every_breach_category_source_is_redacted` test guards the `Breach`-category
/// set automatically.
const EXTRA_SENSITIVE: &[&str] = &[
    "oathnet_pro",
    "oathnet-pro",
    "oathnet",
    "see_know",
    "see-know",
    "seeknow",
];

/// The set of source names to genericise, resolved ONCE: every `Breach`-category
/// module's source name (authoritative and self-maintaining — a newly added
/// breach module is covered without editing this file) plus [`EXTRA_SENSITIVE`].
static SENSITIVE: LazyLock<BTreeSet<String>> = LazyLock::new(|| {
    let mut set: BTreeSet<String> = crate::modules::registry()
        .iter()
        .filter(|m| m.category() == ModuleCategory::Breach)
        .map(|m| m.name().to_string())
        .collect();
    for &e in EXTRA_SENSITIVE {
        set.insert(e.to_string());
    }
    set
});

/// One whole-token alternation regex over [`SENSITIVE`], compiled once. `\b`
/// anchors both ends so a coincidental substring (a subject value that merely
/// *contains* a provider name) is never touched.
static SENSITIVE_RE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    if SENSITIVE.is_empty() {
        return None;
    }
    // Longest-first, so a longer provider label (`oathnet-pro`) is matched whole
    // before a shorter label it contains (`oathnet`), independent of the regex
    // engine's alternation-ordering semantics.
    let mut names: Vec<&String> = SENSITIVE.iter().collect();
    names.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
    let alt = names
        .iter()
        .map(|s| regex::escape(s))
        .collect::<Vec<_>>()
        .join("|");
    Regex::new(&format!(r"\b(?:{alt})\b")).ok()
});

/// Replace every proprietary breach/intel provider name in `body` with
/// [`REDACTED_LABEL`], leaving the finding itself intact. Whole-token match, so a
/// coincidental substring is never redacted. Idempotent.
#[must_use]
pub fn redact_sensitive_sources(body: &str) -> String {
    match &*SENSITIVE_RE {
        Some(re) => re.replace_all(body, REDACTED_LABEL).into_owned(),
        None => body.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_named_paid_provider_but_keeps_public_sources() {
        // `oathnet_pro` is the paid provider the operator named; it is
        // `People`-categorised, so it is covered via EXTRA_SENSITIVE.
        assert!(!redact_sensitive_sources("source: oathnet_pro").contains("oathnet_pro"));
        assert!(redact_sensitive_sources("via oathnet_pro").contains(REDACTED_LABEL));
        // Public, non-secret sources are preserved — they are not tradecraft.
        let out = redact_sensitive_sources("source: whois\nsource: github_user\n");
        assert!(out.contains("whois") && out.contains("github_user"));
    }

    #[test]
    fn covers_every_spelling_of_the_named_providers() {
        // `breach_rich` stamps the HYPHENATED source label ("see-know" /
        // "oathnet-pro") and the stealer path stamps bare "oathnet" — distinct
        // from the underscore module name()s. Every spelling the operator named
        // must be redacted whole (not partially, leaving a recognisable stub).
        for tag in [
            "see_know",
            "see-know",
            "seeknow",
            "oathnet_pro",
            "oathnet-pro",
            "oathnet",
        ] {
            let out = redact_sensitive_sources(&format!(r#"{{"source":"{tag}"}}"#));
            assert!(
                !out.contains(tag),
                "source tag {tag:?} leaked through redaction: {out}"
            );
            assert!(out.contains(REDACTED_LABEL), "expected label for {tag:?}");
        }
    }

    #[test]
    fn every_breach_category_source_is_redacted() {
        // Drift guard: the sensitive set is registry-derived, so a NEW
        // breach-category module is hidden automatically. This asserts it.
        let breach: Vec<String> = crate::modules::registry()
            .iter()
            .filter(|m| m.category() == ModuleCategory::Breach)
            .map(|m| m.name().to_string())
            .collect();
        assert!(!breach.is_empty(), "expected some breach-category modules");
        for name in &breach {
            assert!(
                !redact_sensitive_sources(&format!("source: {name}")).contains(name.as_str()),
                "breach-category source {name} leaked through redaction"
            );
        }
    }

    #[test]
    fn whole_token_match_leaves_longer_tokens_intact() {
        // A longer alphanumeric token that merely CONTAINS a source name (no word
        // boundary) must survive untouched — only the bare provider token is hit.
        let name = crate::modules::registry()
            .iter()
            .find(|m| m.category() == ModuleCategory::Breach)
            .map(|m| m.name().to_string())
            .expect("a breach-category module");
        let longer = format!("{name}xyz");
        assert!(
            redact_sensitive_sources(&format!("value={longer}")).contains(&longer),
            "a longer token containing a source name must not be partially redacted"
        );
    }

    #[test]
    fn idempotent() {
        let once = redact_sensitive_sources("source: oathnet_pro");
        assert_eq!(redact_sensitive_sources(&once), once);
    }
}
