//! Named scan profiles — preset ScanOptions bundles for common use cases.
//!
//! SpiderFoot has "footprint", "investigate", "passive" presets. This module
//! provides equivalent named configurations that operators can select via
//! CLI (`--profile passive`) or API (`"profile": "passive"`).

use crate::core::scan::ScanOptions;

pub fn resolve_profile(name: &str) -> Option<ScanOptions> {
    match name {
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
        assert_eq!(profiles.len(), 4);
        assert!(profiles.iter().any(|(n, _)| *n == "passive"));
        assert!(profiles.iter().any(|(n, _)| *n == "footprint"));
    }
}
