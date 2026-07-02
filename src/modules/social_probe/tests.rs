use super::*;

#[test]
fn high_risk_platforms_have_negative_patterns_and_standard_platforms_do_not() {
    // F2.4 regression guard: the 6 high-risk platforms must have patterns so the
    // body-capture path fires for them; standard platforms must keep &[] so the
    // fast (-o /dev/null) path is preserved and no overhead is introduced.
    let high_risk = [
        "livejasmin",
        "imlive",
        "mydirtyhobby",
        "sextpanther",
        "stripchat",
        "loyalfans",
    ];
    let standard = ["github", "reddit", "twitter", "twitch", "steam"];
    for name in high_risk {
        let p = USERNAME_PLATFORMS
            .iter()
            .find(|p| p.name == name)
            .unwrap_or_else(|| panic!("{name} missing from USERNAME_PLATFORMS"));
        assert!(
            !p.negative_patterns.is_empty(),
            "{name} must have at least one negative pattern (body capture enabled)"
        );
    }
    for name in standard {
        let p = USERNAME_PLATFORMS
            .iter()
            .find(|p| p.name == name)
            .unwrap_or_else(|| panic!("{name} missing from USERNAME_PLATFORMS"));
        assert!(
            p.negative_patterns.is_empty(),
            "{name} must have no negative patterns (fast path, no body capture)"
        );
    }
}

#[test]
fn negative_patterns_field_compiles_and_defaults_empty() {
    // Every platform in the standard set must have the field; for most it is &[].
    for p in USERNAME_PLATFORMS {
        // Platforms with no negative patterns always let the status code decide.
        // Platforms with patterns must have at least one non-empty pattern string.
        for pat in p.negative_patterns {
            assert!(
                !pat.is_empty(),
                "platform {} has an empty negative pattern",
                p.name
            );
        }
    }
    // The 6 high-risk platforms must have at least one negative pattern each.
    let high_risk = [
        "livejasmin",
        "imlive",
        "mydirtyhobby",
        "sextpanther",
        "stripchat",
        "loyalfans",
    ];
    for name in high_risk {
        let p = USERNAME_PLATFORMS
            .iter()
            .find(|p| p.name == name)
            .unwrap_or_else(|| panic!("{name} not found in USERNAME_PLATFORMS"));
        assert!(
            !p.negative_patterns.is_empty(),
            "{name} must have at least one negative pattern"
        );
    }
}

#[test]
fn accepts_username_and_fullname() {
    let m = SocialProbe;
    assert!(m.accepts(&Target::new(TargetKind::Username, "test")));
    assert!(m.accepts(&Target::new(TargetKind::FullName, "Test User")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y")));
    assert!(!m.accepts(&Target::new(TargetKind::Domain, "x.com")));
}

#[test]
fn platform_count() {
    assert!(USERNAME_PLATFORMS.len() >= 34);
    assert!(NAME_PLATFORMS.len() >= 2);
}

#[test]
fn probe_with_no_hits_does_not_echo_the_seed() {
    // A run that checked platforms but confirmed nothing must NOT vouch for
    // the target — otherwise it counts as an independent corroborating
    // source and inflates the seed to VERIFIED on phantom evidence.
    assert!(!should_echo_target(0));
    let t = Target::new(TargetKind::Username, "haigenb");
    assert!(build_target_summary(&t, 0, 28, &[], "scan").is_none());
}

#[test]
fn probe_with_a_hit_echoes_the_seed_as_corroboration() {
    assert!(should_echo_target(1));
    let t = Target::new(TargetKind::Username, "haigenb");
    let summary = build_target_summary(&t, 1, 28, &["github"], "scan")
        .expect("a confirmed profile must echo the seed");
    assert_eq!(summary.value, "haigenb");
    assert!(summary.has_tag("social-probed"));
    assert!(!summary.has_tag("multi-platform"));
    // Three or more confirmed profiles flags the multi-platform footprint.
    let multi =
        build_target_summary(&t, 3, 28, &["github", "reddit", "twitch"], "scan").expect("entity");
    assert!(multi.has_tag("multi-platform"));
}

#[test]
fn module_metadata() {
    let m = SocialProbe;
    assert_eq!(m.name(), "social_probe");
    assert!(!m.description().is_empty());
    assert_eq!(m.priority(), 108);
    assert!(!m.is_passive());
    assert!(!m.attack_techniques().is_empty());
}

#[test]
fn build_target_summary_evidence_lists_confirmed_platforms() {
    let t = Target::new(TargetKind::Username, "testuser");
    let confirmed = &["github", "reddit"];
    let e = build_target_summary(&t, 2, 30, confirmed, "scan").unwrap();
    let attr = e.evidence[0]
        .attributes
        .get("platforms")
        .map(String::as_str);
    assert!(attr.is_some(), "platforms attribute must be present");
    let platforms = attr.unwrap();
    assert!(platforms.contains("github") && platforms.contains("reddit"));
}

#[test]
fn build_target_summary_stamps_platforms_count_for_au011() {
    // AU-011 (cross-platform username footprint) counts how many platforms ONE
    // module confirmed a handle on by reading the `platforms_count` evidence
    // attribute — the same attribute the sibling aggregate probes
    // (`username_search`, `streaming_probe`) stamp, and `social_probe` is not on
    // AU-011's PLATFORM_SOURCES fallback list. `social_probe` previously wrote
    // only `found`/`platforms`, so AU-011 read a count of 0 and a handle
    // confirmed here on ≥3 platforms silently never fired the finding. The
    // canonical count attribute must now be present and equal the number of
    // confirmed platforms.
    let t = Target::new(TargetKind::Username, "testuser");
    let e = build_target_summary(&t, 3, 30, &["github", "reddit", "twitch"], "scan").unwrap();
    assert_eq!(
        e.evidence[0]
            .attributes
            .get("platforms_count")
            .map(String::as_str),
        Some("3"),
        "platforms_count must equal the confirmed-platform count so AU-011 can count it"
    );
}
