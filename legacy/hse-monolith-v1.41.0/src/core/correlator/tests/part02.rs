#[test]
fn au036_fires_when_two_addresses_converge() {
    let e = canonical_email(
        "jdoe@gmail.com",
        &["j.doe@gmail.com", "jdoe+news@gmail.com"],
    );
    let r = rule_au_036_email_alias_convergence(&RuleContext::new(&[e]), "scan-test", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-036");
    assert!(r[0].description.contains("jdoe@gmail.com"));
    assert!(r[0].description.contains("j.doe@gmail.com"));
    assert!(r[0].description.contains("jdoe+news@gmail.com"));
}

#[test]
fn au036_no_fire_on_single_alias() {
    // Only one address folded in → nothing converged, no finding.
    let e = canonical_email("jdoe@gmail.com", &["j.doe@gmail.com"]);
    assert!(
        rule_au_036_email_alias_convergence(&RuleContext::new(&[e]), "scan-test", 0).is_empty()
    );
}

#[test]
fn au036_ignores_non_canonical_evidence() {
    // Two evidence records, but not from email_canonical → not alias
    // convergence (could be two breach sources for one address).
    let e = email("jdoe@gmail.com", &["hibp", "hudsonrock"]);
    assert!(
        rule_au_036_email_alias_convergence(&RuleContext::new(&[e]), "scan-test", 0).is_empty()
    );
}

fn tagged(kind: EntityKind, value: &str, tags: &[&str]) -> Entity {
    let mut e = Entity::new(kind, value, 0.9, "scan-test");
    for t in tags {
        e.tag(*t);
    }
    e
}

fn username_summary(value: &str, count: u64, platforms: &str) -> Entity {
    let mut e = Entity::new(EntityKind::Username, value, 0.95, "scan-test");
    e.tag("multi-platform");
    e.add_evidence(
        Evidence::new("username_search", "summary")
            .with_attr("platforms_count", count.to_string())
            .with_attr("platforms", platforms),
    );
    e
}

// ── AU-001 ──────────────────────────────────────────────────────────

#[test]
fn au001_fires_at_two_breach_sources() {
    let e = email("x@y.com", &["hudsonrock", "breach_directory"]);
    let r = rule_au_001_multi_breach(&RuleContext::new(&[e]), "s1", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-001");
    assert_eq!(r[0].severity, Severity::Critical);
}

#[test]
fn au001_no_fire_at_one_source() {
    let e = email("x@y.com", &["hudsonrock"]);
    assert!(rule_au_001_multi_breach(&RuleContext::new(&[e]), "s1", 0).is_empty());
}

#[test]
fn au001_ignores_non_breach_sources() {
    let e = email("x@y.com", &["crtsh", "dns_resolver"]);
    assert!(rule_au_001_multi_breach(&RuleContext::new(&[e]), "s1", 0).is_empty());
}

#[test]
fn au001_does_not_count_generic_search_as_a_breach_source() {
    // A web-search hit alongside ONE real breach source is a single breach
    // source — `search_engines` must never count toward the Critical multi-breach
    // finding (guards against re-adding it to BREACH_SOURCES).
    let one = email("x@y.com", &["hibp", "search_engines"]);
    assert!(rule_au_001_multi_breach(&RuleContext::new(&[one]), "s1", 0).is_empty());
    // Two genuine breach sources still fire.
    let two = email("x@y.com", &["hibp", "dehashed"]);
    assert_eq!(
        rule_au_001_multi_breach(&RuleContext::new(&[two]), "s1", 0).len(),
        1
    );
}

#[test]
fn au001_recognises_real_breach_modules_the_allow_list_had_missed() {
    // BREACH_SOURCES was a hand-maintained allow-list that never grew to cover
    // several real breach-category modules -- confirmed against
    // source_family_covers_every_breach_category_module (rules/tests.rs),
    // which pins all of them as family "breach". Two of the previously-missed
    // modules together must still fire AU-001, exactly as two listed ones do.
    let e = email("x@y.com", &["intelx", "psbdmp"]);
    let r = rule_au_001_multi_breach(&RuleContext::new(&[e]), "s1", 0);
    assert_eq!(
        r.len(),
        1,
        "intelx + psbdmp is two genuinely independent breach corpora: {r:?}"
    );
    assert_eq!(r[0].severity, Severity::Critical);
}

#[test]
fn au001_does_not_raise_critical_on_a_role_mailbox() {
    // Live person-scan false positive: `abuse@godaddy.com` (a registrar desk) is in
    // HIBP + XposedOrNot as a matter of course — that is NOT the subject's breach
    // exposure and must not fire a Critical.
    let role = email("abuse@godaddy.com", &["hibp", "xposed_or_not"]);
    assert!(rule_au_001_multi_breach(&RuleContext::new(&[role]), "s1", 0).is_empty());
    // A genuine personal mailbox in the same two sources still fires.
    let real = email("matthew@example.com", &["hibp", "xposed_or_not"]);
    assert_eq!(
        rule_au_001_multi_breach(&RuleContext::new(&[real]), "s1", 0).len(),
        1
    );
}

// ── AU-002 ──────────────────────────────────────────────────────────

#[test]
fn au002_fires_with_all_three_kinds() {
    let entities = vec![
        Entity::new(EntityKind::Email, "x@y.com", 0.9, "s"),
        Entity::new(EntityKind::Username, "xuser", 0.8, "s"),
        Entity::new(EntityKind::Phone, "+61400000000", 0.8, "s"),
    ];
    let r = rule_au_002_identity_cluster(&RuleContext::new(&entities), "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-002");
    assert_eq!(r[0].entity_uids.len(), 3);
}

#[test]
fn au002_no_fire_missing_kind() {
    let entities = vec![
        Entity::new(EntityKind::Email, "x@y.com", 0.9, "s"),
        Entity::new(EntityKind::Username, "xuser", 0.8, "s"),
    ];
    assert!(rule_au_002_identity_cluster(&RuleContext::new(&entities), "s", 0).is_empty());
}

// ── AU-003 ──────────────────────────────────────────────────────────

#[test]
fn au003_fires_at_kind_specific_thresholds() {
    // Thresholds are now on DISTINCT sources: identity (email) >= 2,
    // infra (domain) >= 3. These fixtures set corroboration with no
    // evidence, so source_count() falls back to the field value.
    let mut email = Entity::new(EntityKind::Email, "x@y.com", 0.9, "s");
    email.corroboration = 2;
    let r = rule_au_003_high_corroboration(&RuleContext::new(&[email]), "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-003");
    assert!(
        r[0].description.contains("2 independent source"),
        "description must report the true distinct-source count: {}",
        r[0].description
    );

    let mut domain = Entity::new(EntityKind::Domain, "x.com", 0.9, "s");
    domain.corroboration = 3;
    let r = rule_au_003_high_corroboration(&RuleContext::new(&[domain]), "s", 0);
    assert_eq!(r.len(), 1);
}

#[test]
fn au003_no_fire_below_threshold() {
    // Email below 2 distinct sources, domain below 3 → no fire.
    let mut e = Entity::new(EntityKind::Email, "x@y.com", 0.9, "s");
    e.corroboration = 1;
    assert!(rule_au_003_high_corroboration(&RuleContext::new(&[e]), "s", 0).is_empty());

    let mut d = Entity::new(EntityKind::Domain, "x.com", 0.9, "s");
    d.corroboration = 2;
    assert!(rule_au_003_high_corroboration(&RuleContext::new(&[d]), "s", 0).is_empty());
}

#[test]
fn au003_uses_distinct_sources_not_summed_corroboration() {
    // THE FIX in correlator terms: an email with summed corroboration=8
    // but only 1 distinct evidence source must NOT fire AU-003 (it is not
    // cross-corroborated), and an email with 2 distinct sources must fire
    // regardless of the summed field.
    let mut single = Entity::new(EntityKind::Email, "a@b.com", 0.9, "s");
    single.corroboration = 8;
    single.add_evidence(crate::core::entity::Evidence::new("oathnet_pro", "8 rows"));
    assert!(
        rule_au_003_high_corroboration(&RuleContext::new(&[single]), "s", 0).is_empty(),
        "single-source entity must not fire AU-003 despite inflated corroboration"
    );

    let mut multi = Entity::new(EntityKind::Email, "a@b.com", 0.9, "s");
    multi.corroboration = 2;
    multi.add_evidence(crate::core::entity::Evidence::new("hibp", "breach"));
    multi.add_evidence(crate::core::entity::Evidence::new("dehashed", "breach"));
    assert_eq!(
        rule_au_003_high_corroboration(&RuleContext::new(&[multi]), "s", 0).len(),
        1,
        "two distinct sources must fire AU-003"
    );
}

#[test]
fn au003_excludes_weak_detection_only_entities() {
    // Regression: a real scan against a guessed username handle showed a
    // `Url` entity (a guessed profile page) reach `source_count() = 6` and a
    // reported `C_eff=1.000` purely from status-only guesses (username_search,
    // streaming_probe) plus `webserver_banner`'s domain-root check
    // mis-attributed to the guessed path (fixed separately) — "high
    // cross-source corroboration" for a handle that was never confirmed to
    // exist. An entity tagged `weak-detection` with no accompanying
    // `verified-detection` must not fire AU-003 no matter how many distinct
    // modules ran the same shallow check.
    let mut weak = Entity::new(
        EntityKind::Url,
        "https://onlyfans.com/rob_dorito",
        0.74,
        "s",
    );
    weak.tag("weak-detection");
    weak.add_evidence(crate::core::entity::Evidence::new(
        "username_search",
        "status 200",
    ));
    weak.add_evidence(crate::core::entity::Evidence::new(
        "streaming_probe",
        "status 200",
    ));
    weak.add_evidence(crate::core::entity::Evidence::new("web_crawler", "linked"));
    assert!(
        rule_au_003_high_corroboration(&RuleContext::new(&[weak]), "s", 0).is_empty(),
        "weak-detection-only entity must not fire AU-003 regardless of distinct-source count"
    );

    // A `verified-detection` tag (a real body-marker confirmation) alongside
    // the same evidence chain means genuine corroboration is present, so the
    // rule still fires.
    let mut verified = Entity::new(EntityKind::Url, "https://github.com/rob_dorito", 0.92, "s");
    verified.tag("weak-detection"); // some sources were still weak…
    verified.tag("verified-detection"); // …but at least one was confirmed
    verified.add_evidence(crate::core::entity::Evidence::new(
        "username_search",
        "body match",
    ));
    verified.add_evidence(crate::core::entity::Evidence::new(
        "streaming_probe",
        "status 200",
    ));
    verified.add_evidence(crate::core::entity::Evidence::new("web_crawler", "linked"));
    assert_eq!(
        rule_au_003_high_corroboration(&RuleContext::new(&[verified]), "s", 0).len(),
        1,
        "a genuinely verified-detection entity must still fire AU-003"
    );
}

// ── AU-004 ──────────────────────────────────────────────────────────

#[test]
fn au004_fires_on_malicious_domain() {
    // Requires two independent sources to reach CRITICAL — shared infra appears
    // in single blocklists without being subject-owned.
    let mut e = tagged(
        EntityKind::Domain,
        "evil.example",
        &[crate::core::tags::MALICIOUS],
    );
    e.add_evidence(Evidence::new(
        "ip_reputation",
        "flagged malicious".to_string(),
    ));
    e.add_evidence(Evidence::new("threatfox", "c2 domain".to_string()));
    let r = rule_au_004_malicious_infrastructure(&RuleContext::new(&[e]), "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].severity, Severity::Critical);
}

#[test]
fn au004_no_fire_single_source() {
    // Single-source malicious tag must NOT produce a CRITICAL — insufficient
    // corroboration to distinguish CDN/ESP blocklist noise from real malice.
    let mut e = tagged(
        EntityKind::Domain,
        "evil.example",
        &[crate::core::tags::MALICIOUS],
    );
    e.add_evidence(Evidence::new(
        "ip_reputation",
        "flagged malicious".to_string(),
    ));
    assert!(rule_au_004_malicious_infrastructure(&RuleContext::new(&[e]), "s", 0).is_empty());
}

#[test]
fn au004_no_fire_without_tag() {
    let e = tagged(EntityKind::Domain, "ok.example", &[]);
    assert!(rule_au_004_malicious_infrastructure(&RuleContext::new(&[e]), "s", 0).is_empty());
}

#[test]
fn au004_no_fire_on_single_threat_source_plus_enrichment() {
    // Regression: the ≥2 bar must count THREAT sources, not every corroborating
    // source. `ip_geo` is geolocation enrichment — it is NOT in
    // ENRICHMENT_ONLY_SOURCES, so it counts toward `Entity::source_count`, yet it
    // asserts nothing about maliciousness. One blocklist hit (`ip_reputation`)
    // plus a routine `ip_geo` record previously reached source_count == 2 and
    // fired a CRITICAL "malicious" finding on a shared-edge IP. Only one threat
    // source actually flagged it, so AU-004 must stay silent (AU-015 still
    // reports the single-source hit at its own severity).
    let mut e = tagged(
        EntityKind::IpAddress,
        "45.79.10.20",
        &[crate::core::tags::MALICIOUS],
    );
    e.add_evidence(Evidence::new(
        "ip_reputation",
        "flagged malicious".to_string(),
    ));
    e.add_evidence(Evidence::new("ip_geo", "Sydney, AU".to_string()));
    assert!(
        rule_au_004_malicious_infrastructure(&RuleContext::new(&[e]), "s", 0).is_empty(),
        "one threat source + geolocation enrichment is not two agreeing threat verdicts"
    );
}

// ── AU-005 ──────────────────────────────────────────────────────────

#[test]
fn au005_fires_on_tor_exit() {
    let e = tagged(EntityKind::IpAddress, "1.1.1.1", &["tor-exit"]);
    let r = rule_au_005_anonymous_network(&RuleContext::new(&[e]), "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].severity, Severity::High);
}

// ── AU-006 ──────────────────────────────────────────────────────────

#[test]
fn au006_fires_on_vpn_but_not_tor() {
    let vpn_ip = tagged(EntityKind::IpAddress, "2.2.2.2", &["vpn"]);
    let tor_ip = tagged(EntityKind::IpAddress, "3.3.3.3", &["tor-exit", "vpn"]);
    let r = rule_au_006_proxy_vpn(&RuleContext::new(&[vpn_ip, tor_ip]), "s", 0);
    assert_eq!(r.len(), 1);
    assert!(r[0].description.contains("2.2.2.2"));
}

#[test]
fn au006_excludes_all_anon_tags_not_just_tor_exit() {
    let tor_short = tagged(EntityKind::IpAddress, "4.4.4.4", &["tor", "vpn"]);
    let anon_net = tagged(
        EntityKind::IpAddress,
        "5.5.5.5",
        &["anonymous-network", "vpn"],
    );
    let anon_vpn = tagged(EntityKind::IpAddress, "6.6.6.6", &["anonymous-vpn", "vpn"]);
    assert!(rule_au_006_proxy_vpn(&RuleContext::new(&[tor_short]), "s", 0).is_empty());
    assert!(rule_au_006_proxy_vpn(&RuleContext::new(&[anon_net]), "s", 0).is_empty());
    assert!(rule_au_006_proxy_vpn(&RuleContext::new(&[anon_vpn]), "s", 0).is_empty());
}

// ── AU-007 ──────────────────────────────────────────────────────────

#[test]
fn au007_fires_on_high_risk() {
    let e = tagged(EntityKind::IpAddress, "4.4.4.4", &["high-risk", "scanner"]);
    let r = rule_au_007_high_risk_reputation(&RuleContext::new(&[e]), "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].severity, Severity::High);
}

// ── AU-008 ──────────────────────────────────────────────────────────

#[test]
fn au008_fires_on_vulnerable_tag() {
    let e = tagged(
        EntityKind::Domain,
        "vuln.example",
        &[crate::core::tags::VULNERABLE],
    );
    let r = rule_au_008_exposed_service(&RuleContext::new(&[e]), "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-008");
}

#[test]
fn au008_benign_infra_verdict_vetoes_exposed_service() {
    // The user's real false positive: a Cloudflare edge IP tagged
    // `vulnerable` by a shared-edge CVE scan but catalogued benign by
    // GreyNoise must not be reported as an exposed service.
    let e = tagged(
        EntityKind::IpAddress,
        "104.20.37.187",
        &[crate::core::tags::VULNERABLE, "greynoise-benign"],
    );
    assert!(rule_au_008_exposed_service(&RuleContext::new(&[e]), "s", 0).is_empty());
}

// ── AU-009 ──────────────────────────────────────────────────────────

#[test]
fn au009_fires_on_stealer_log() {
    let e = tagged(EntityKind::Email, "x@y.com", &["stealer-log"]);
    let r = rule_au_009_stealer_log(&RuleContext::new(&[e]), "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].severity, Severity::High);
}

#[test]
fn au009_fires_on_the_oathnet_pro_and_see_know_stealer_tag() {
    // oathnet_pro::stealer::push_stealer_entity and push_oathnet_entity (the
    // two richest stealer-log extraction paths in this codebase) tag their
    // entities "stealer", not "stealer-log" -- confirmed against
    // src/modules/oathnet_pro/stealer.rs and breach.rs. see_know's stealer
    // extraction does the same (src/modules/see_know/extract/mod.rs). AU-009
    // must recognise both literals, or a subject whose credentials were
    // captured live by malware and surfaced via OathNet/SeeKnow gets no
    // "Stealer-log compromise" finding at all.
    let oathnet = tagged(
        EntityKind::Email,
        "a@b.com",
        &["breach", "oathnet-pro", "stealer"],
    );
    let see_know = tagged(EntityKind::Email, "c@d.com", &["see-know", "stealer"]);
    let r = rule_au_009_stealer_log(&RuleContext::new(&[oathnet, see_know]), "s", 0);
    assert_eq!(
        r.len(),
        2,
        "both the OathNet Pro and SeeKnow stealer-tagged emails must fire AU-009: {r:?}"
    );
}

// ── AU-037 ──────────────────────────────────────────────────────────

#[test]
fn au037_fires_critical_on_plaintext_credentials() {
    let pw1 = Entity::new(EntityKind::Password, "hunter2", 0.9, "s");
    let pw2 = Entity::new(EntityKind::Password, "letmein", 0.9, "s");
    let cred = Entity::new(EntityKind::Credential, "user:pass", 0.9, "s");
    let email = Entity::new(EntityKind::Email, "x@y.com", 0.9, "s");
    let r = rule_au_037_credential_exposure(
        &RuleContext::new(&[pw1, pw2, cred, email.clone()]),
        "s",
        0,
    );
    assert_eq!(r.len(), 1, "one aggregate alert");
    assert_eq!(r[0].severity, Severity::Critical);
    assert!(r[0].description.contains("2 plaintext passwords"));
    assert!(r[0].description.contains("1 credential record"));
    // The raw secret value must NEVER appear in the alert text.
    assert!(
        !r[0].description.contains("hunter2") && !r[0].description.contains("letmein"),
        "secret values must not leak into correlation text"
    );
    // Links the secret entities plus the affected identity (the email).
    assert!(r[0].entity_uids.contains(&email.uid));

    // No secret entities → no firing.
    assert!(rule_au_037_credential_exposure(&RuleContext::new(&[email]), "s", 0).is_empty());
}

#[test]
fn au037_does_not_fire_on_a_published_public_key() {
    // github_user (fetch.rs) and pgp (mod.rs) both mint EntityKind::Credential
    // for a PUBLISHED public key -- an SSH/PGP key fingerprint the subject
    // themselves posted on GitHub or a keyserver, tagged "ssh-key"/"pgp-key",
    // used only to feed AU-048's cross-account key-sharing link. A public
    // key's private half is definitionally not "directly recoverable"; AU-037
    // must not treat one as breach/stealer credential exposure.
    let mut ssh_key = Entity::new(EntityKind::Credential, "SHA256:abc123", 0.9, "s");
    ssh_key.tag("ssh-key");
    ssh_key.tag("public-key");
    ssh_key.tag("github");
    let mut pgp_key = Entity::new(EntityKind::Credential, "0xDEADBEEF", 0.9, "s");
    pgp_key.tag("pgp-key");
    assert!(
        rule_au_037_credential_exposure(&RuleContext::new(&[ssh_key, pgp_key]), "s", 0).is_empty(),
        "a published SSH/PGP public key must not fire AU-037"
    );
}

#[test]
fn au037_entity_uids_are_deterministic_under_input_order() {
    // Determinism fix (the AU-039 take(N) family): the secret/identity samples are
    // sorted-then-capped, so the persisted entity_uids SET is independent of the
    // randomized HashMap input order — preventing duplicate AU-037 rows across the
    // live and finalise passes. Use >cap (20) secrets so truncation engages.
    use std::collections::BTreeSet;
    let mut ents: Vec<Entity> = (0..25)
        .map(|i| Entity::new(EntityKind::Password, format!("pw{i:02}"), 0.9, "s"))
        .collect();
    ents.push(Entity::new(
        EntityKind::Email,
        "subject@example.com",
        0.9,
        "s",
    ));

    let forward = rule_au_037_credential_exposure(&RuleContext::new(&ents), "s", 0);
    let mut reversed = ents.clone();
    reversed.reverse();
    let backward = rule_au_037_credential_exposure(&RuleContext::new(&reversed), "s", 0);

    assert_eq!(forward.len(), 1);
    assert_eq!(backward.len(), 1);
    let f: BTreeSet<&String> = forward[0].entity_uids.iter().collect();
    let b: BTreeSet<&String> = backward[0].entity_uids.iter().collect();
    assert_eq!(
        f, b,
        "entity_uids must be order-independent (sorted-then-capped)"
    );
    // The 20-cap on secrets is honoured (+ the one identity).
    assert!(forward[0].entity_uids.len() <= 21);
}

// ── AU-038 ──────────────────────────────────────────────────────────

#[test]
fn au038_fires_on_confirmed_profiles_across_platforms() {
    let mk = |url: &str| {
        let mut e = Entity::new(EntityKind::Url, url, 0.85, "s");
        e.tag("confirmed-profile");
        e
    };
    // Confirmed profiles on TWO distinct hosts → fires Medium, names both.
    let r = rule_au_038_verified_cross_platform_identity(
        &RuleContext::new(&[
            mk("https://x.com/kylo4kylo"),
            mk("https://github.com/kylo4kylo"),
        ]),
        "s",
        0,
    );
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].severity, Severity::Medium);
    assert!(r[0].description.contains("2 distinct platforms"));
    assert!(r[0].description.contains("x.com") && r[0].description.contains("github.com"));

    // Same host twice → only one distinct platform → no firing.
    assert!(
        rule_au_038_verified_cross_platform_identity(
            &RuleContext::new(&[
                mk("https://www.x.com/kylo4kylo"),
                mk("https://x.com/kylo4kylo")
            ]),
            "s",
            0
        )
        .is_empty()
    );
    // A non-confirmed URL is ignored.
    let plain = Entity::new(EntityKind::Url, "https://x.com/kylo4kylo", 0.5, "s");
    assert!(
        rule_au_038_verified_cross_platform_identity(&RuleContext::new(&[plain]), "s", 0)
            .is_empty()
    );
}

#[test]
fn au038_fires_on_social_probe_profiles() {
    // `social_probe` tags direct-enumeration profiles `social-profile` (not
    // `confirmed-profile`); AU-038 must treat that probe signal as verified.
    let mk = |url: &str| {
        let mut e = Entity::new(EntityKind::Url, url, 0.9, "s");
        e.tag("social-profile");
        e
    };
    let r = rule_au_038_verified_cross_platform_identity(
        &RuleContext::new(&[
            mk("https://steamcommunity.com/id/kylo4kylo"),
            mk("https://www.tiktok.com/@kylo4kylo"),
            mk("https://bsky.app/profile/kylo4kylo.bsky.social"),
        ]),
        "s",
        0,
    );
    assert_eq!(r.len(), 1);
    assert!(r[0].description.contains("3 distinct platforms"));

    // Mixed provenance (one probe + one search-confirmed) still aggregates.
    let mut probe = Entity::new(EntityKind::Url, "https://twitch.tv/kylo4kylo", 0.9, "s");
    probe.tag("social-profile");
    let mut searched = Entity::new(EntityKind::Url, "https://twitter.com/kylo4kylo", 0.85, "s");
    searched.tag("confirmed-profile");
    let r =
        rule_au_038_verified_cross_platform_identity(&RuleContext::new(&[probe, searched]), "s", 0);
    assert_eq!(r.len(), 1);
    assert!(r[0].description.contains("2 distinct platforms"));
}

#[test]
fn au038_excludes_weak_detection_status_only_guesses() {
    // Same regression as AU-055: `social-profile` is tagged on a bare
    // status-code guess just as readily as on a body-marker-confirmed hit,
    // and this rule's OWN NAME promises "verified" — a claim only the latter
    // earns. `weak-detection`-tagged hits, even across several platforms,
    // must not fire this rule.
    let mk_weak = |url: &str| {
        let mut e = Entity::new(EntityKind::Url, url, 0.74, "s");
        e.tag("social-profile");
        e.tag("weak-detection");
        e
    };
    let r = rule_au_038_verified_cross_platform_identity(
        &RuleContext::new(&[
            mk_weak("https://onlyfans.com/rob_dorito"),
            mk_weak("https://twitch.tv/rob_dorito"),
            mk_weak("https://tiktok.com/@rob_dorito"),
        ]),
        "s",
        0,
    );
    assert!(
        r.is_empty(),
        "weak-detection hits must not fire a rule named 'Verified cross-platform identity'"
    );

    // A verified-detection hit alongside a weak one still needs a SECOND
    // distinct platform (the rule's own ≥2 contract) — one strong platform
    // alone doesn't fire AU-038 (that's AU-055's job).
    let mut strong1 = Entity::new(EntityKind::Url, "https://github.com/rob_dorito", 0.92, "s");
    strong1.tag("social-profile");
    strong1.tag("verified-detection");
    let mut strong2 = Entity::new(
        EntityKind::Url,
        "https://reddit.com/user/rob_dorito",
        0.92,
        "s",
    );
    strong2.tag("social-profile");
    strong2.tag("verified-detection");
    let r = rule_au_038_verified_cross_platform_identity(
        &RuleContext::new(&[strong1, strong2, mk_weak("https://onlyfans.com/rob_dorito")]),
        "s",
        0,
    );
    assert_eq!(r.len(), 1);
    assert!(r[0].description.contains("2 distinct platforms"));
    assert!(!r[0].description.contains("onlyfans"));
}

// ── AU-010 ──────────────────────────────────────────────────────────

#[test]
fn au010_fires_at_three_sources_on_domain() {
    let e = domain("x.com", &["crtsh", "dns_resolver", "hudsonrock"]);
    let r = rule_au_010_infra_consensus(&RuleContext::new(&[e]), "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-010");
}

#[test]
fn au010_no_fire_at_two_sources() {
    let e = domain("x.com", &["crtsh", "dns_resolver"]);
    assert!(rule_au_010_infra_consensus(&RuleContext::new(&[e]), "s", 0).is_empty());
}

#[test]
fn au010_ignores_non_infrastructure_kinds() {
    let e = email("x@y.com", &["a", "b", "c"]);
    assert!(rule_au_010_infra_consensus(&RuleContext::new(&[e]), "s", 0).is_empty());
}

#[test]
fn au010_recall_replay_does_not_manufacture_consensus() {
    // Live person-scan flaw: a CDN edge IP "confirmed by dns_intel, doh_resolver,
    // recall" fired AU-010 265× — but `recall` is a replay of the same prior
    // observation, not an independent source, so `corroborating_sources` drops it
    // below the 3-source bar and the infrastructure noise no longer fires.
    let mk = |sources: &[&str]| {
        let mut e = Entity::new(EntityKind::IpAddress, "104.26.7.243", 0.9, "scan-test");
        for s in sources {
            e.add_evidence(Evidence::new(*s, "test"));
        }
        e
    };
    assert!(
        rule_au_010_infra_consensus(
            &RuleContext::new(&[mk(&["dns_intel", "doh_resolver", "recall"])]),
            "s",
            0
        )
        .is_empty(),
        "two resolvers + a recall replay is not a 3-source consensus"
    );
    // Three INDEPENDENT infrastructure sources still fire.
    assert_eq!(
        rule_au_010_infra_consensus(
            &RuleContext::new(&[mk(&["dns_intel", "doh_resolver", "crtsh"])]),
            "s",
            0
        )
        .len(),
        1
    );
}

// ── AU-011 ──────────────────────────────────────────────────────────

#[test]
fn au011_fires_on_three_platforms() {
    let e = username_summary("alice", 3, "github, reddit, twitter");
    let r = rule_au_011_cross_platform_username(&RuleContext::new(&[e]), "s", 0);
    assert_eq!(r.len(), 1);
    assert!(r[0].description.contains("3 platforms"));
    assert!(r[0].description.contains("github"));
}

#[test]
fn au011_no_fire_on_two_platforms() {
    let e = username_summary("alice", 2, "github, reddit");
    assert!(rule_au_011_cross_platform_username(&RuleContext::new(&[e]), "s", 0).is_empty());
}

#[test]
fn au011_discounts_status_only_hits_when_hits_verified_present() {
    // platforms_count=4 (raw, includes status-only guesses) but hits_verified=1:
    // AU-011 must trust the verified count, not the inflated raw one, so this
    // must NOT fire despite 4 >= 3.
    let mut e = Entity::new(EntityKind::Username, "alice", 0.9, "scan-test");
    e.add_evidence(
        Evidence::new("username_search", "summary")
            .with_attr("platforms_count", "4")
            .with_attr("platforms", "a, b, c, d")
            .with_attr("hits_verified", "1")
            .with_attr("hits_status_only", "3"),
    );
    assert!(
        rule_au_011_cross_platform_username(&RuleContext::new(&[e]), "s", 0).is_empty(),
        "an inflated raw count with only 1 verified hit must not fire"
    );
}

#[test]
fn au011_fires_on_genuinely_verified_hits() {
    let mut e = Entity::new(EntityKind::Username, "alice", 0.9, "scan-test");
    e.add_evidence(
        Evidence::new("username_search", "summary")
            .with_attr("platforms_count", "3")
            .with_attr("platforms", "github, reddit, twitter")
            .with_attr("hits_verified", "3")
            .with_attr("hits_status_only", "0"),
    );
    let r = rule_au_011_cross_platform_username(&RuleContext::new(&[e]), "s", 0);
    assert_eq!(r.len(), 1);
    assert!(r[0].description.contains("3 platforms"));
}

// ── AU-012 ──────────────────────────────────────────────────────────

#[test]
fn au012_fires_when_username_and_personal_site_url_present() {
    let entities = vec![
        tagged(EntityKind::Username, "alice", &[]),
        tagged(
            EntityKind::Url,
            "https://alice.example/",
            &["personal-site"],
        ),
    ];
    let r = rule_au_012_identity_linked_domain(&RuleContext::new(&entities), "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].entity_uids.len(), 2);
    assert!(r[0].description.contains("co-occurs"));
}

#[test]
fn au012_also_fires_on_personal_site_domain() {
    let entities = vec![
        tagged(EntityKind::Username, "alice", &[]),
        tagged(EntityKind::Domain, "alice.example", &["personal-site"]),
    ];
    let r = rule_au_012_identity_linked_domain(&RuleContext::new(&entities), "s", 0);
    assert_eq!(r.len(), 1);
}

#[test]
fn au012_no_fire_without_username() {
    let entities = vec![tagged(
        EntityKind::Url,
        "https://alice.example/",
        &["personal-site"],
    )];
    assert!(rule_au_012_identity_linked_domain(&RuleContext::new(&entities), "s", 0).is_empty());
}

// ── AU-013 ──────────────────────────────────────────────────────────

#[test]
fn au013_fires_on_two_lan_entities() {
    let entities = vec![
        tagged(
            EntityKind::IpAddress,
            "192.168.1.1",
            &[crate::core::tags::LOCAL_ARP],
        ),
        tagged(
            EntityKind::MacAddress,
            "aa:bb:cc:dd:ee:ff",
            &[crate::core::tags::LOCAL_ARP],
        ),
    ];
    let r = rule_au_013_local_network_discovery(&RuleContext::new(&entities), "s", 0);
    assert_eq!(r.len(), 1);
}
