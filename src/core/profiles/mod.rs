//! Named scan profiles — preset ScanOptions bundles for common use cases.
//!
//! SpiderFoot has "footprint", "investigate", "passive" presets. This module
//! provides equivalent named configurations that operators can select via
//! CLI (`--profile passive`) or API (`"profile": "passive"`).

use crate::core::module::ModuleCategory;
use crate::core::scan::ScanOptions;

/// The functional categories a skip-trace (debtor-location) scan runs. Person
/// identity, contact (phone/email), physical location (geo), social/web
/// accounts, corporate/asset records, open-web search, and breach corpora —
/// everything that helps fix *where a person is and how to reach/recover from
/// them*. Deliberately excludes the categories that are pure noise for locating
/// a human: DNS/cert lookups, network infrastructure, threat intel, and the
/// operator's own local sensors. Shared with the focus guard test.
pub const SKIPTRACE_CATEGORIES: &[ModuleCategory] = &[
    ModuleCategory::People,
    ModuleCategory::Phone,
    ModuleCategory::Geo,
    ModuleCategory::Email,
    ModuleCategory::Social,
    ModuleCategory::Corporate,
    ModuleCategory::Search,
    ModuleCategory::Breach,
];

/// Resolve a named scan profile to its [`ScanOptions`] preset, or `None` for an
/// unknown name. The profile is the operator's one-word intent (`passive`,
/// `footprint`, `investigate`, `skiptrace`, …); `recommended`/`default` and
/// `skiptrace`/`locate` are aliases. The single lookup the CLI and API both use,
/// so a `--profile` flag and a `?profile=` query resolve identically.
#[must_use]
pub fn resolve_profile(name: &str) -> Option<ScanOptions> {
    match name {
        // `default` is an alias for `recommended` so callers can ask for either.
        "recommended" | "default" => Some(recommended()),
        "passive" => Some(passive()),
        "footprint" => Some(footprint()),
        "investigate" => Some(investigate()),
        "fast" => Some(fast()),
        // `locate` is an alias for the skip-trace (debtor-location) profile.
        "skiptrace" | "locate" => Some(skiptrace()),
        _ => None,
    }
}

/// Overlay a resolved profile's TUNING fields onto `base`, leaving every
/// orthogonal field (module selection/exclusion, throttle, per-module
/// timeout, min_confidence, tags/notes, webhook, max_roi/convex_budget,
/// min_marginal_yield, seeknow_scan_cap, expand_all_identities,
/// gate_speculative, …) from `base` untouched.
///
/// This is the SINGLE field-by-field merge policy shared by the CLI
/// (`--profile`) and the API (`"profile": "…"` in the request body), so a
/// profile means the same thing everywhere — matching this function's own
/// name and the field's own doc ("overrides individual option fields with
/// the profile's values"), not a wholesale replace. Previously the CLI
/// overlaid an incomplete field list (missing `expansion_strategy` /
/// `regional_search` — dormant only because `ScanOptions::default()`
/// happens to coincide with every current profile's values for those two
/// fields) and the API did `opts = profile_opts`, a full replace that
/// silently discarded every client-supplied option — `{"profile":
/// "skiptrace", "modules": ["hunter_io"]}` lost `modules` entirely.
///
/// The field list here is exactly the set every `resolve_profile` preset
/// function (`recommended`/`passive`/`footprint`/`investigate`/`fast`/
/// `skiptrace`) explicitly sets before falling through to
/// `..Default::default()` — i.e. every field a profile can meaningfully
/// tune. Add a field here whenever a new profile starts tuning it.
#[must_use]
pub fn apply_profile_overlay(base: ScanOptions, profile: ScanOptions) -> ScanOptions {
    ScanOptions {
        free_only: profile.free_only,
        passive_only: profile.passive_only,
        depth: profile.depth,
        min_expand_confidence: profile.min_expand_confidence,
        max_concurrent: profile.max_concurrent,
        max_entities: profile.max_entities,
        max_wall_time_secs: profile.max_wall_time_secs,
        category_focus: profile.category_focus,
        expansion_strategy: profile.expansion_strategy,
        regional_search: profile.regional_search,
        ..base
    }
}

/// Every selectable profile as `(name, one-line description)` — the catalogue the
/// CLI `--help` and the API/SPA profile picker render. Aliases are omitted (each
/// profile is listed once under its canonical name).
#[must_use]
pub fn list_profiles() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "recommended",
            "Zero-setup optimal: free/keyless sources, one expansion round for \
             cross-service correlation, phone-safe budgets — works out of the box",
        ),
        (
            "passive",
            "No active probing — breach lookups, DNS, WHOIS, public APIs only",
        ),
        ("footprint", "Full depth-3 expansion with all free modules"),
        (
            "investigate",
            "Maximum depth with paid APIs, aggressive expansion",
        ),
        (
            "fast",
            "Depth-0, free-only, 8 concurrent — quick surface scan",
        ),
        (
            "skiptrace",
            "Debtor / person location: focuses person, contact, geo, social, \
             corporate-asset, search and breach modules; geo-converging \
             expansion to fix current address, phone, employer and associates \
             (alias: locate)",
        ),
    ]
}

/// The recommended zero-configuration profile — the out-of-the-box default for a
/// fresh Termux install that has entered no API keys.
///
/// Tuned so the system delivers genuine cross-referenced correlation with NO
/// manual setup:
///   * `free_only` — only keyless public APIs and the build's embedded
///     zero-config keys run, so it never silently needs a paid key;
///   * `depth: 1` — exactly one expansion round, so a discovered identifier is
///     re-scanned across the independent providers (GitHub, Hacker News, Wikidata,
///     breach/DNS/geo, …). Depth 0 finds entities but never *links* them; one
///     round is what lets the cross-service rules (notably AU-045 multi-service
///     identity confirmation) actually fire — the whole point of "out-of-box
///     correlation" — while staying far cheaper than the deep `footprint`/
///     `investigate` profiles;
///   * bounded `max_entities`/`max_wall_time_secs` and modest concurrency so a
///     low-RAM phone on mobile data stays responsive and predictable.
fn recommended() -> ScanOptions {
    ScanOptions {
        free_only: true,
        depth: 1,
        min_expand_confidence: 0.50,
        max_concurrent: 4,
        max_entities: Some(300),
        max_wall_time_secs: Some(180),
        ..Default::default()
    }
}

fn passive() -> ScanOptions {
    ScanOptions {
        passive_only: true,
        free_only: true,
        depth: 1,
        max_concurrent: 4,
        ..Default::default()
    }
}

fn footprint() -> ScanOptions {
    ScanOptions {
        depth: 3,
        min_expand_confidence: 0.45,
        max_concurrent: 4,
        max_entities: Some(500),
        ..Default::default()
    }
}

fn investigate() -> ScanOptions {
    ScanOptions {
        depth: 5,
        min_expand_confidence: 0.40,
        max_concurrent: 8,
        max_entities: Some(2000),
        max_wall_time_secs: Some(600),
        ..Default::default()
    }
}

fn fast() -> ScanOptions {
    ScanOptions {
        depth: 0,
        free_only: true,
        max_concurrent: 8,
        ..Default::default()
    }
}

/// Skip-trace / debtor-location profile — find *where a person is and how to
/// reach or recover from them*.
///
/// The objective differs from a security investigation: the prize is the
/// subject's **current address, phone, employer, assets and associates**, not
/// their infrastructure. So this profile:
///   * **Focuses** dispatch on the person-locating categories
///     ([`SKIPTRACE_CATEGORIES`]) — person/contact/geo/social/corporate/search/
///     breach — and skips DNS, network-infrastructure, threat-intel and local
///     sensor modules that contribute nothing to locating a human. The focus is
///     by category, so it can't drift as modules are renamed and picks up new
///     in-category sources automatically.
///   * **Expands geo-convergently** ([`crate::core::scan::ExpansionStrategy::GeoConverge`]): each
///     round prioritises the candidates one hop from an Address/Coordinates, so
///     the scan converges on the residence rather than fanning out — exactly the
///     skip-tracer's "tighten the net around where they live" instinct.
///   * Runs **depth 3** at a slightly relaxed `min_expand_confidence` (0.45) so
///     softer-but-on-topic leads — an alias, a relative sharing a surname, a
///     prior address — are still chased, then re-scanned for *their* contacts.
///   * Leaves `free_only` off so keyed people-search / breach providers run when
///     a key is present and degrade gracefully when not, and keeps
///     `regional_search` on (AU directories like the white pages are prime
///     skip-trace sources). Entity/wall-time caps stay phone-safe for Termux.
fn skiptrace() -> ScanOptions {
    use crate::core::scan::ExpansionStrategy;
    ScanOptions {
        category_focus: SKIPTRACE_CATEGORIES.to_vec(),
        depth: 3,
        min_expand_confidence: 0.45,
        max_concurrent: 4,
        max_entities: Some(800),
        max_wall_time_secs: Some(420),
        expansion_strategy: ExpansionStrategy::GeoConverge,
        regional_search: true,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
