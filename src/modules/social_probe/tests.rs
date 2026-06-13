use super::*;

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
    assert!(USERNAME_PLATFORMS.len() >= 28);
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
    let multi = build_target_summary(&t, 3, 28, &["github", "reddit", "twitch"], "scan")
        .expect("entity");
    assert!(multi.has_tag("multi-platform"));
}
