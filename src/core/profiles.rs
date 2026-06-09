//! Named scan profiles — preset ScanOptions bundles for common use cases.
//!
//! SpiderFoot has "footprint", "investigate", "passive" presets. This module
//! provides equivalent named configurations that operators can select via
//! CLI (`--profile passive`) or API (`"profile": "passive"`).

use crate::core::scan::ScanOptions;

pub fn resolve_profile(name: &str) -> Option<ScanOptions> {
    match name {
        // `default` is an alias for `recommended` so callers can ask for either.
        "recommended" | "default" => Some(recommended()),
        "passive" => Some(passive()),
        "footprint" => Some(footprint()),
        "investigate" => Some(investigate()),
        "fast" => Some(fast()),
        _ => None,
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_known_profiles() {
        assert!(resolve_profile("passive").is_some());
        assert!(resolve_profile("footprint").is_some());
        assert!(resolve_profile("investigate").is_some());
        assert!(resolve_profile("fast").is_some());
    }

    #[test]
    fn resolve_unknown_returns_none() {
        assert!(resolve_profile("nonexistent").is_none());
    }

    #[test]
    fn passive_profile_is_passive_and_free() {
        let opts = resolve_profile("passive").unwrap();
        assert!(opts.passive_only);
        assert!(opts.free_only);
    }

    #[test]
    fn investigate_profile_has_max_depth() {
        let opts = resolve_profile("investigate").unwrap();
        assert_eq!(opts.depth, 5);
        assert!(opts.max_entities.is_some());
    }

    #[test]
    fn fast_profile_is_depth_zero() {
        let opts = resolve_profile("fast").unwrap();
        assert_eq!(opts.depth, 0);
        assert!(opts.free_only);
    }

    #[test]
    fn list_profiles_returns_all() {
        let profiles = list_profiles();
        assert_eq!(profiles.len(), 5);
        assert!(profiles.iter().any(|(n, _)| *n == "recommended"));
        assert!(profiles.iter().any(|(n, _)| *n == "passive"));
        assert!(profiles.iter().any(|(n, _)| *n == "footprint"));
    }

    #[test]
    fn recommended_is_zero_setup_and_correlation_ready() {
        // The out-of-box default: needs no keys (free-only), and expands exactly
        // one round so the cross-service correlation rules can actually fire —
        // depth 0 would find entities but never link them. `default` is an alias.
        let opts = resolve_profile("recommended").unwrap();
        assert!(opts.free_only, "must need no manual key setup");
        assert_eq!(
            opts.depth, 1,
            "one expansion round enables cross-service links"
        );
        assert!(opts.max_entities.is_some(), "phone-safe bound");
        assert!(
            opts.max_wall_time_secs.is_some(),
            "phone-safe wall-time bound"
        );
        // The `default` alias resolves to the same options.
        let aliased = resolve_profile("default").unwrap();
        assert_eq!(aliased.depth, opts.depth);
        assert_eq!(aliased.free_only, opts.free_only);
    }
}
