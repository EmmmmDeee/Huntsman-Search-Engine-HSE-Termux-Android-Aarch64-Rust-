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
fn detection_strength_matches_negative_pattern_presence() {
    // No negative pattern → bare status-code guess → weak/unverified.
    let weak = Platform {
        name: "x",
        url_pattern: "https://x.com/{}",
        exists_codes: &[200],
        negative_patterns: &[],
    };
    assert_eq!(detection_strength(&weak), (0.74, false));

    // A negative pattern means the body was actually inspected → verified.
    let strong = Platform {
        name: "y",
        url_pattern: "https://y.com/{}",
        exists_codes: &[200],
        negative_patterns: &["user not found"],
    };
    assert_eq!(detection_strength(&strong), (0.92, true));
}

#[test]
fn every_standard_platform_is_weak_and_every_high_risk_platform_is_verified() {
    // Cross-check against the F2.4 high-risk/standard split: every platform
    // without a negative pattern must be classified weak (matching the
    // "fast path, no body capture" intent), and every one with a pattern
    // must be classified verified.
    for p in USERNAME_PLATFORMS {
        let (_, verified) = detection_strength(p);
        assert_eq!(
            verified,
            !p.negative_patterns.is_empty(),
            "platform {} detection_strength disagrees with its negative_patterns",
            p.name
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
    assert!(build_target_summary(&t, 0, 0, 28, &[], &[], &[], 0, "scan").is_none());
}

#[test]
fn blocked_zero_hit_sweep_is_inconclusive_not_a_confirmed_absence() {
    // M6: a zero-hit run is only a confirmed absence when the probes actually
    // answered. When at least half returned no definitive answer (curl code 0 —
    // blocked / unreachable / no egress), the sweep is inconclusive and must be
    // surfaced as an error, never as a silent empty "not on any platform".
    let msg = inconclusive_sweep(0, 28, 0, 28).expect("all-blocked zero-hit run is inconclusive");
    assert!(
        msg.contains("28 of 28") && msg.contains("not a confirmed absence"),
        "message must quantify the blocked probes and disclaim absence: {msg}"
    );
    // An indiscriminate platform (present for the control handle too) is
    // neither an answer nor a failure: the verdict is over the platforms that
    // can tell, and the message says how many could not.
    assert!(
        inconclusive_sweep(0, 3, 20, 28).is_none(),
        "3 of 8 telling platforms blocked is a genuine absence"
    );
    let msg = inconclusive_sweep(0, 3, 24, 28).expect("3 of 4 telling platforms blocked");
    assert!(
        msg.contains("3 of 4") && msg.contains("24 platforms answer"),
        "{msg}"
    );
    assert!(
        inconclusive_sweep(0, 14, 0, 28).is_some(),
        "exactly half blocked is still inconclusive"
    );

    // A run whose probes mostly ANSWERED (definitive not-founds) with only a few
    // blocked IS a genuine absence — not inconclusive.
    assert!(
        inconclusive_sweep(0, 3, 0, 28).is_none(),
        "mostly-definitive not-founds are a real absence, not inconclusive"
    );
    // Any confirmed hit means the sweep reached the network — never inconclusive,
    // even if other probes were blocked.
    assert!(
        inconclusive_sweep(2, 26, 0, 28).is_none(),
        "any hit proves reachability, so the run is never inconclusive"
    );
    // A fully cancelled/empty sweep (nothing attempted) is not inconclusive.
    assert!(
        inconclusive_sweep(0, 0, 0, 0).is_none(),
        "no probes attempted is not an inconclusive absence claim"
    );
}

#[test]
fn probe_with_a_hit_echoes_the_seed_as_corroboration() {
    assert!(should_echo_target(1));
    let t = Target::new(TargetKind::Username, "haigenb");
    let summary = build_target_summary(&t, 1, 1, 28, &["github"], &[], &[], 0, "scan")
        .expect("a confirmed profile must echo the seed");
    assert_eq!(summary.value, "haigenb");
    assert!(summary.has_tag("social-probed"));
    assert!(!summary.has_tag("multi-platform"));
    // Three or more confirmed profiles flags the multi-platform footprint.
    let multi = build_target_summary(
        &t,
        3,
        3,
        28,
        &["github", "reddit", "twitch"],
        &[],
        &[],
        0,
        "scan",
    )
    .expect("entity");
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
    let e =
        build_target_summary(&t, 2, 2, 30, confirmed, &[], &[], 0, "scan").expect("should succeed");
    let attr = e.evidence[0]
        .attributes
        .get("platforms")
        .map(String::as_str);
    assert!(attr.is_some(), "platforms attribute must be present");
    let platforms = attr.expect("should succeed");
    assert!(platforms.contains("github") && platforms.contains("reddit"));
}

#[test]
fn build_target_summary_stamps_hits_verified_and_status_only() {
    // OD-17: AU-035/AU-077's is_verified_discovery reads `hits_verified` on
    // THIS aggregate evidence record (the per-platform verified/weak split
    // lives on separate Url entities the rule never scans). An absent
    // attribute reads as vacuously verified, so an all-status-only sweep
    // could fabricate a "prediction confirmed" bridge. Must mirror
    // `username_search`/`streaming_probe`'s existing hits_verified shape.
    let t = Target::new(TargetKind::Username, "testuser");

    // All hits status-only (weak-detection): 0 verified of 2 found.
    let weak = build_target_summary(&t, 2, 0, 30, &["reddit", "tumblr"], &[], &[], 0, "scan")
        .expect("should succeed");
    assert_eq!(
        weak.evidence[0]
            .attributes
            .get("hits_verified")
            .map(String::as_str),
        Some("0")
    );
    assert_eq!(
        weak.evidence[0]
            .attributes
            .get("hits_status_only")
            .map(String::as_str),
        Some("2")
    );

    // A mixed sweep: 1 body-verified + 2 status-only of 3 found.
    let mixed = build_target_summary(
        &t,
        3,
        1,
        30,
        &["github", "reddit", "tumblr"],
        &[],
        &[],
        0,
        "scan",
    )
    .expect("should succeed");
    assert_eq!(
        mixed.evidence[0]
            .attributes
            .get("hits_verified")
            .map(String::as_str),
        Some("1")
    );
    assert_eq!(
        mixed.evidence[0]
            .attributes
            .get("hits_status_only")
            .map(String::as_str),
        Some("2")
    );
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
    let e = build_target_summary(
        &t,
        3,
        3,
        30,
        &["github", "reddit", "twitch"],
        &[],
        &[],
        0,
        "scan",
    )
    .expect("should succeed");
    assert_eq!(
        e.evidence[0]
            .attributes
            .get("platforms_count")
            .map(String::as_str),
        Some("3"),
        "platforms_count must equal the confirmed-platform count so AU-011 can count it"
    );
}

// ── Backlog #38: a body curl never delivered is not a marker-free body ─────────

const PROBE_URL: &str = "https://example.invalid/some-handle";

fn a_negative_marker_platform() -> &'static Platform {
    USERNAME_PLATFORMS
        .iter()
        .chain(NAME_PLATFORMS.iter())
        .find(|p| !p.negative_patterns.is_empty())
        .expect("the table has negative-marker platforms")
}

fn a_status_only_platform() -> &'static Platform {
    USERNAME_PLATFORMS
        .iter()
        .find(|p| p.negative_patterns.is_empty() && p.exists_codes.contains(&200))
        .expect("the table has status-only platforms answering 200")
}

#[test]
fn a_presence_status_whose_body_curl_refused_or_cut_is_inconclusive_not_a_verified_hit() {
    // Reproduced at the transport (`util::curl` tests; and by hand with the
    // production curl arguments): with `--max-filesize`, curl answers a
    // not-found page whose Content-Length exceeds the cap with status 200, an
    // EMPTY body and exit 63, and a chunked one with the first bytes only. The
    // old loop ran the negative-marker check over that body, found nothing —
    // there was nothing to find — and minted the 0.92 `verified-detection` /
    // `body-marker` profile: for every negative-marker (adult / cam) platform,
    // for any handle whose not-found page is bigger than the cap.
    let p = a_negative_marker_platform();
    let refused = StatusProbe {
        status: 200,
        body: String::new(),
        truncated: true,
    };
    assert_eq!(
        classify_probe(p, PROBE_URL, &refused),
        ProbeResult::Error,
        "an empty body curl refused to download is no evidence of a profile on {}",
        p.name
    );
    let cut_before_the_marker = StatusProbe {
        status: 200,
        body: "<html><head><script>/* 256 KiB of application shell */</script>".into(),
        truncated: true,
    };
    assert_eq!(
        classify_probe(p, PROBE_URL, &cut_before_the_marker),
        ProbeResult::Error,
        "a marker-free PREFIX of the page proves nothing about the rest of it"
    );
}

#[test]
fn hackernews_soft_404_is_not_a_profile() {
    // REQ-PROBE-003: news.ycombinator.com/user?id=<nobody> answers 200 "No such
    // user." for every handle, so the old status-only rule (negative_patterns
    // &[]) minted a weak-detection profile for a handle nobody holds — the
    // runner's known-negative control caught it 2026-09-16. The body marker
    // discriminates: a nonce is a definitive NotFound, a real profile a
    // body-verified Found.
    let hn = USERNAME_PLATFORMS
        .iter()
        .find(|p| p.name == "hackernews")
        .expect("hackernews platform");
    assert_eq!(
        hn.negative_patterns,
        &["No such user."],
        "the soft-404 marker must gate the presence claim"
    );
    let absent = StatusProbe {
        status: 200,
        body: "No such user.".into(),
        truncated: false,
    };
    assert_eq!(
        classify_probe(hn, PROBE_URL, &absent),
        ProbeResult::NotFound,
        "200 \"No such user.\" is an absence, not a profile"
    );
    let present = StatusProbe {
        status: 200,
        body: "<html><body>user: pg<br>created: 6000 days ago<br>karma: 155000</body></html>"
            .into(),
        truncated: false,
    };
    match classify_probe(hn, PROBE_URL, &present) {
        ProbeResult::Found { verified, .. } => {
            assert!(verified, "a real HN profile is body-verified");
        }
        other => panic!("a real HN profile must be Found, got {other:?}"),
    }
}

#[test]
fn a_negative_marker_seen_in_a_partial_body_is_still_a_definitive_not_found() {
    let p = a_negative_marker_platform();
    let marker = p.negative_patterns[0];
    let cut_after_the_marker = StatusProbe {
        status: 200,
        body: format!("<html><head><title>{marker}</title><script>"),
        truncated: true,
    };
    assert_eq!(
        classify_probe(p, PROBE_URL, &cut_after_the_marker),
        ProbeResult::NotFound,
        "the marker was seen — the cut came after it"
    );
}

#[test]
fn a_whole_marker_free_body_on_a_presence_status_is_the_verified_hit() {
    let p = a_negative_marker_platform();
    let whole = StatusProbe {
        status: 200,
        body: "<html><head><title>@some-handle — live now</title></head></html>".into(),
        truncated: false,
    };
    match classify_probe(p, PROBE_URL, &whole) {
        ProbeResult::Found {
            url,
            confidence,
            verified,
            ..
        } => {
            assert_eq!(url, PROBE_URL);
            assert!(
                verified,
                "the whole page was inspected and carries no marker"
            );
            assert!((confidence - 0.92).abs() < 1e-9, "{confidence}");
        }
        other => panic!(
            "a complete marker-free page on a presence status is the verified hit, got {other:?}"
        ),
    }
}

#[test]
fn a_status_only_platform_is_a_weak_hit_whatever_the_body() {
    // No marker to check, so the body — delivered or not — is irrelevant; the
    // hit rests on the status alone and says so (0.74, unverified).
    let p = a_status_only_platform();
    for truncated in [false, true] {
        let answer = StatusProbe {
            status: 200,
            body: String::new(),
            truncated,
        };
        match classify_probe(p, PROBE_URL, &answer) {
            ProbeResult::Found {
                confidence,
                verified,
                ..
            } => {
                assert!(!verified, "{}: status-only is never verified", p.name);
                assert!((confidence - 0.74).abs() < 1e-9, "{confidence}");
            }
            other => panic!("{}: a presence status is a weak hit, got {other:?}", p.name),
        }
    }
}

#[test]
fn refusals_are_inconclusive_and_absence_statuses_are_definitive() {
    let p = a_negative_marker_platform();
    for refusal in [0u16, 403, 429, 503] {
        let answer = StatusProbe {
            status: refusal,
            ..StatusProbe::default()
        };
        assert_eq!(
            classify_probe(p, PROBE_URL, &answer),
            ProbeResult::Error,
            "status {refusal} is a refusal, not an answer"
        );
    }
    for absent in [404u16, 410] {
        let answer = StatusProbe {
            status: absent,
            ..StatusProbe::default()
        };
        assert_eq!(
            classify_probe(p, PROBE_URL, &answer),
            ProbeResult::NotFound,
            "status {absent} is the platform saying no such handle"
        );
    }
}

/// The reading of the control judgement, pure: an indiscriminate platform is
/// never a profile and is named in the summary; a presence says whether the
/// platform denied the control handle.
#[test]
fn an_indiscriminate_platform_is_never_a_profile_and_the_summary_names_it() {
    let by_name = |name: &str| {
        USERNAME_PLATFORMS
            .iter()
            .find(|p| p.name == name)
            .unwrap_or_else(|| panic!("{name} is a platform"))
    };
    let judged: Vec<((&'static Platform, u16), ProbeResult)> = vec![
        (
            (by_name("github"), 200),
            ProbeResult::Found {
                url: "https://github.com/alice".to_string(),
                confidence: 0.92,
                verified: true,
                controlled: true,
            },
        ),
        (
            (by_name("instagram"), 200),
            ProbeResult::Indiscriminate {
                url: "https://www.instagram.com/alice".to_string(),
            },
        ),
        (
            (by_name("tiktok"), 200),
            ProbeResult::Found {
                url: "https://www.tiktok.com/@alice".to_string(),
                confidence: 0.74,
                verified: false,
                controlled: false,
            },
        ),
    ];
    let (result, tally) = emit_judged(&judged, "scan-ctl");
    assert!(
        result
            .entities
            .iter()
            .all(|e| e.value != "https://www.instagram.com/alice"),
        "an indiscriminate platform is never a profile"
    );
    assert_eq!(tally.found, 2);
    assert_eq!(tally.verified, 1);
    assert_eq!(tally.uncontrolled, 1);
    assert_eq!(tally.found_platforms, vec!["github", "tiktok"]);
    assert_eq!(tally.indiscriminate_platforms, vec!["instagram"]);
    let attr = |value: &str, key: &str| -> Option<String> {
        result
            .entities
            .iter()
            .find(|e| e.value == value)
            .and_then(|e| e.evidence.first())
            .and_then(|ev| ev.attributes.get(key).cloned())
    };
    assert_eq!(
        attr("https://github.com/alice", "control").as_deref(),
        Some("absent")
    );
    assert_eq!(
        attr("https://www.tiktok.com/@alice", "control").as_deref(),
        Some("unavailable")
    );
    assert_eq!(
        attr("https://github.com/alice", "http_status").as_deref(),
        Some("200")
    );

    let t = Target::new(TargetKind::Username, "alice");
    let summary = build_target_summary(
        &t,
        tally.found,
        tally.verified,
        3,
        &tally.found_platforms,
        &tally.indiscriminate_platforms,
        &tally.uncontrolled_platforms,
        tally.uncontrolled,
        "scan-ctl",
    )
    .expect("a summary for a run with hits");
    let ev = summary.evidence.first().expect("evidence");
    assert_eq!(
        ev.attributes
            .get("sites_indiscriminate")
            .map(String::as_str),
        Some("1")
    );
    assert_eq!(
        ev.attributes
            .get("indiscriminate_platforms")
            .map(String::as_str),
        Some("instagram")
    );
    assert_eq!(
        ev.attributes.get("hits_uncontrolled").map(String::as_str),
        Some("1")
    );
}
