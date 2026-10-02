#[test]
fn au_043_fires_on_paste_exposure() {
    let ents = vec![
        mk_tagged(
            EntityKind::Url,
            "https://pastebin.com/abc",
            "psbdmp",
            &[crate::core::tags::PASTE_EXPOSED],
        ),
        mk_tagged(EntityKind::Url, "https://example.com", "web_crawler", &[]),
    ];
    let out = rule_au_043_paste_exposure(&RuleContext::new(&ents), "scan", 0);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].entity_uids.len(), 1, "only the paste url");
    assert!(out[0].description.contains("1 public paste"));
}

#[test]
fn shared_tracking_id_fires_only_across_multiple_sites() {
    // A TrackingId carrying source_domain evidence for two distinct sites is the
    // affiliate signal: same analytics id ⇒ common ownership.
    let mut shared = Entity::new(EntityKind::TrackingId, "UA-123456-1", 0.80, "scan");
    shared.add_evidence(
        Evidence::new("web_crawler", "ga id on a.com".to_string())
            .with_attr("source_domain", "a.com"),
    );
    shared.add_evidence(
        Evidence::new("web_crawler", "ga id on b.com".to_string())
            .with_attr("source_domain", "b.com"),
    );

    let out =
        rule_au_044_shared_tracking_id(&RuleContext::new(std::slice::from_ref(&shared)), "scan", 0);
    assert_eq!(out.len(), 1, "shared id across 2 sites must fire");
    assert_eq!(out[0].rule_id, "AU-044");
    assert!(out[0].description.contains("a.com") && out[0].description.contains("b.com"));

    // A tracking id on a single site is not a correlation.
    let mut single = Entity::new(EntityKind::TrackingId, "G-ABCDE12345", 0.80, "scan");
    single.add_evidence(
        Evidence::new("web_crawler", "ga4 on a.com".to_string())
            .with_attr("source_domain", "a.com"),
    );
    assert!(
        rule_au_044_shared_tracking_id(&RuleContext::new(std::slice::from_ref(&single)), "scan", 0)
            .is_empty(),
        "single-site id must not fire"
    );
}

#[test]
fn au045_multi_service_identity_requires_cross_family_agreement() {
    use super::rules::source_family;
    // Classifier maps real module names to the expected families. Code-hosting,
    // forums and social media are distinct independent families.
    assert_eq!(source_family("github_user"), "code");
    assert_eq!(source_family("reddit_user"), "forum");
    assert_eq!(source_family("hacker_news"), "forum");
    assert_eq!(source_family("social_probe"), "social");
    assert_eq!(source_family("hibp"), "breach");
    assert_eq!(source_family("username_search"), "presence");
    assert_eq!(source_family("dns_intel"), "infra");
    assert_eq!(source_family("totally_unknown_src"), "other");

    // The payoff: an alias confirmed on GitHub (code) + Reddit (forum) — two
    // independent provider families — now fires AU-045, where before the three
    // social modules were one family and never did.
    let mut handle = Entity::new(EntityKind::Username, "kylo4kylo", 0.6, "scan");
    for s in ["github_user", "reddit_user"] {
        handle.add_evidence(Evidence::new(s, "confirmed"));
    }
    assert_eq!(
        super::rules::rule_au_045_multi_service_identity(&RuleContext::new(&[handle]), "scan", 0)
            .len(),
        1,
        "code + forum are independent families and must fire AU-045"
    );

    // A username confirmed by breach + social + presence → 3 families → fires.
    let mut u = Entity::new(EntityKind::Username, "kylo4kylo", 0.6, "scan");
    for s in ["hibp", "github_user", "username_search"] {
        u.add_evidence(Evidence::new(s, "found"));
    }
    let hits = super::rules::rule_au_045_multi_service_identity(&RuleContext::new(&[u]), "scan", 0);
    assert_eq!(hits.len(), 1, "cross-family identity must fire AU-045");
    assert_eq!(hits[0].rule_id, "AU-045");
    assert_eq!(hits[0].severity, super::Severity::High);
    assert!(
        hits[0].description.contains("3 service families"),
        "got: {}",
        hits[0].description
    );

    // Same family only (two breach DBs) → not independent → must NOT fire.
    let mut e = Entity::new(EntityKind::Email, "x@y.com", 0.6, "scan");
    for s in ["hibp", "dehashed"] {
        e.add_evidence(Evidence::new(s, "found"));
    }
    assert!(
        super::rules::rule_au_045_multi_service_identity(&RuleContext::new(&[e]), "scan", 0)
            .is_empty(),
        "same-family corroboration must not count as multi-service"
    );

    // An unclassified source can't fabricate diversity on its own.
    let mut p = Entity::new(EntityKind::Person, "Kylo Ren", 0.6, "scan");
    for s in ["hibp", "totally_unknown_src"] {
        p.add_evidence(Evidence::new(s, "x"));
    }
    assert!(
        super::rules::rule_au_045_multi_service_identity(&RuleContext::new(&[p]), "scan", 0)
            .is_empty(),
        "the 'other' bucket is excluded from family diversity"
    );

    // Non-identity kinds are ignored even when cross-family.
    let mut d = Entity::new(EntityKind::Domain, "acme.com", 0.6, "scan");
    for s in ["dns_intel", "github_user"] {
        d.add_evidence(Evidence::new(s, "x"));
    }
    assert!(
        super::rules::rule_au_045_multi_service_identity(&RuleContext::new(&[d]), "scan", 0)
            .is_empty(),
        "AU-045 binds identity kinds only"
    );
}

#[test]
fn au045_excludes_status_only_hits_even_across_distinct_families() {
    // Regression: a real scan against a guessed handle showed `username_search`
    // (family "presence") and `social_probe` (family "social") both hit the
    // SAME unverified handle via a bare status-code check — and because they
    // classify into two DIFFERENT families purely by platform category, not
    // by detection rigour, that satisfied AU-045's "two distinct service
    // families" bar despite neither one being an actual confirmation. A
    // status-only hit must not contribute its family to the diversity count.
    let mut weak = Entity::new(EntityKind::Username, "rob_dorito", 0.6, "scan");
    weak.add_evidence(
        Evidence::new("username_search", "status 200").with_attr("detection", "status-only"),
    );
    weak.add_evidence(
        Evidence::new("social_probe", "status 200").with_attr("detection", "status-only"),
    );
    assert!(
        super::rules::rule_au_045_multi_service_identity(&RuleContext::new(&[weak]), "scan", 0)
            .is_empty(),
        "two status-only hits in different families must not satisfy the cross-family bar"
    );

    // The same two sources, but at least one with a real body-marker
    // confirmation, DOES count — the fix discounts the *hit*, not the module.
    let mut strong = Entity::new(EntityKind::Username, "rob_dorito", 0.6, "scan");
    strong.add_evidence(
        Evidence::new("username_search", "body match").with_attr("detection", "body-marker"),
    );
    strong.add_evidence(
        Evidence::new("social_probe", "status 200").with_attr("detection", "status-only"),
    );
    assert_eq!(
        super::rules::rule_au_045_multi_service_identity(&RuleContext::new(&[strong]), "scan", 0)
            .len(),
        0,
        "one verified source alone is still only ONE family (presence) — needs a second"
    );

    // Two genuinely verified sources in distinct families fire normally.
    let mut both_strong = Entity::new(EntityKind::Username, "rob_dorito", 0.6, "scan");
    both_strong.add_evidence(
        Evidence::new("username_search", "body match").with_attr("detection", "body-marker"),
    );
    both_strong.add_evidence(Evidence::new("hibp", "breach row"));
    assert_eq!(
        super::rules::rule_au_045_multi_service_identity(
            &RuleContext::new(&[both_strong]),
            "scan",
            0
        )
        .len(),
        1,
        "a verified presence hit + a breach hit are two real independent families"
    );
}

#[test]
fn au011_counts_independent_platform_module_confirmations() {
    // Three independent username-keyed modules (github_user + reddit_user +
    // hacker_news) confirming one handle is a 3-platform footprint even though no
    // single module reported a `platforms_count` — the cross-service signal the
    // keyless social modules produce must light up AU-011.
    let mut u = Entity::new(EntityKind::Username, "kylo4kylo", 0.6, "scan");
    for s in ["github_user", "reddit_user", "hacker_news"] {
        u.add_evidence(Evidence::new(s, "confirmed account"));
    }
    let hits =
        super::rules::rule_au_011_cross_platform_username(&RuleContext::new(&[u]), "scan", 0);
    assert_eq!(
        hits.len(),
        1,
        "3 independent platform modules must fire AU-011"
    );
    assert_eq!(hits[0].rule_id, "AU-011");
    assert!(
        hits[0].description.contains("3 platforms"),
        "got: {}",
        hits[0].description
    );

    // Two platform modules is below the threshold.
    let mut u2 = Entity::new(EntityKind::Username, "lonely", 0.6, "scan");
    for s in ["github_user", "reddit_user"] {
        u2.add_evidence(Evidence::new(s, "x"));
    }
    assert!(
        super::rules::rule_au_011_cross_platform_username(&RuleContext::new(&[u2]), "scan", 0)
            .is_empty(),
        "two platforms must not fire"
    );
}

#[test]
fn au072_payid_surface_fires_on_multiple_payids_and_links_them() {
    // Two PayID handles (email + phone) → the consolidated payment-identity
    // surface fires, lists both channels, and links both uids in sorted order.
    let mut email = Entity::new(EntityKind::Email, "a@contoso.com", 0.8, "s");
    email.tag("payid");
    email.tag("payid:email");
    let mut phone = Entity::new(EntityKind::Phone, "+61410959140", 0.8, "s");
    phone.tag("payid");
    phone.tag("payid:phone");

    // Deliberately unsorted input to exercise the determinism of entity_uids.
    let r = super::rules::rule_au_072_payid_payment_surface(
        &RuleContext::new(&[phone.clone(), email.clone()]),
        "s",
        0,
    );
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-072");
    assert_eq!(
        r[0].severity,
        Severity::Medium,
        "no register-resolvable ABN → Medium"
    );
    assert!(r[0].description.contains("2 PayID"));
    assert!(r[0].description.contains("email") && r[0].description.contains("phone"));
    let mut expect = vec![email.uid.clone(), phone.uid.clone()];
    expect.sort();
    assert_eq!(r[0].entity_uids, expect, "full member set, sorted");

    // A single PayID handle is not a surface.
    assert!(
        super::rules::rule_au_072_payid_payment_surface(&RuleContext::new(&[email]), "s", 0)
            .is_empty()
    );
}

#[test]
fn au072_register_resolvable_abn_raises_severity() {
    let mut email = Entity::new(EntityKind::Email, "a@contoso.com", 0.8, "s");
    email.tag("payid");
    email.tag("payid:email");
    let mut abn = Entity::new(EntityKind::AbnAcn, "51824753556", 0.9, "s");
    abn.tag("payid");
    abn.tag("payid:abn");
    abn.tag("payid:registry-resolvable");

    let r =
        super::rules::rule_au_072_payid_payment_surface(&RuleContext::new(&[email, abn]), "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(
        r[0].severity,
        Severity::High,
        "a register-resolvable ABN PayID lifts the severity"
    );
    assert!(r[0].description.contains("public register"));
}

#[test]
fn au072_does_not_fire_on_uncorroborated_name_permutation_guesses() {
    // Two purely-speculative name_intel email permutations, each merely
    // annotated by the enrichment-only `payid` module (no independent
    // corroboration either belongs to the subject), must not fabricate a
    // consolidated payment-identity surface — under default settings
    // (`--gate-speculative` off) these guesses expand and reach every
    // enrichment-only module exactly like a real identifier would.
    let mut guess1 = Entity::new(EntityKind::Email, "j.smith@gmail.com", 0.4, "s");
    guess1.tag("name-derived");
    guess1.tag("payid");
    guess1.tag("payid:email");
    guess1.add_evidence(Evidence::new(
        "name_intel",
        "Speculative email permuted from name",
    ));
    guess1.add_evidence(Evidence::new("payid", "PayID-eligible email"));

    let mut guess2 = Entity::new(EntityKind::Email, "jsmith@outlook.com", 0.35, "s");
    guess2.tag("name-derived");
    guess2.tag("payid");
    guess2.tag("payid:email");
    guess2.add_evidence(Evidence::new(
        "name_intel",
        "Speculative email permuted from name",
    ));
    guess2.add_evidence(Evidence::new("payid", "PayID-eligible email"));

    assert!(
        super::rules::rule_au_072_payid_payment_surface(
            &RuleContext::new(&[guess1, guess2]),
            "s",
            0
        )
        .is_empty(),
        "two uncorroborated name-permutation guesses must not fabricate a PayID surface"
    );
}

#[test]
fn au072_counts_a_name_permutation_guess_once_a_reliable_source_confirms_it() {
    // Same speculative guess as above, but this one is independently confirmed
    // by a real corpus hit — it is no longer "uncorroborated" and legitimately
    // combines with a genuine, unrelated PayID to fire.
    let mut confirmed_guess = Entity::new(EntityKind::Email, "j.smith@gmail.com", 0.4, "s");
    confirmed_guess.tag("name-derived");
    confirmed_guess.tag("payid");
    confirmed_guess.tag("payid:email");
    confirmed_guess.add_evidence(Evidence::new(
        "name_intel",
        "Speculative email permuted from name",
    ));
    confirmed_guess.add_evidence(Evidence::new("hibp", "Found in a breach corpus"));

    let mut real_phone = Entity::new(EntityKind::Phone, "+61410959140", 0.8, "s");
    real_phone.tag("payid");
    real_phone.tag("payid:phone");

    let r = super::rules::rule_au_072_payid_payment_surface(
        &RuleContext::new(&[confirmed_guess, real_phone]),
        "s",
        0,
    );
    assert_eq!(
        r.len(),
        1,
        "a corroborated former-guess plus a real PayID should still fire"
    );
}

#[test]
fn au073_dob_corroborated_across_sources_disambiguates_namesakes() {
    // Two independent sources assert the same DOB (one as an ISO datetime that
    // must normalise) → High. A namesake's DOB from a single source is a
    // separate Medium finding — visible, not silently merged.
    let mut p = Entity::new(EntityKind::Person, "Cindy Haynes", 0.9, "s");
    p.add_evidence(
        Evidence::new("oathnet_pro", "breach").with_attr("date_of_birth", "1980-11-08T00:00:00"),
    );
    let mut e = Entity::new(EntityKind::Email, "c@contoso.com", 0.9, "s");
    e.add_evidence(Evidence::new("see_know", "breach").with_attr("dob", "1980-11-08"));
    let mut ns = Entity::new(EntityKind::Email, "d@contoso.com", 0.9, "s");
    ns.add_evidence(Evidence::new("hibp", "breach").with_attr("date_of_birth", "1975-01-01"));

    let r = super::rules::rule_au_073_subject_date_of_birth(&RuleContext::new(&[p, e, ns]), "s", 0);
    let main = r
        .iter()
        .find(|c| c.description.contains("1980-11-08"))
        .expect("the corroborated DOB fires");
    assert_eq!(main.rule_id, "AU-073");
    assert_eq!(main.severity, Severity::High, "two agreeing sources → High");
    let minor = r
        .iter()
        .find(|c| c.description.contains("1975-01-01"))
        .expect("the namesake DOB is surfaced separately");
    assert_eq!(minor.severity, Severity::Medium, "single source → Medium");
}

#[test]
fn au073_counts_two_see_know_corpora_as_independent_not_one_source() {
    // Regression: `see_know`/`oathnet_pro` stamp ONE constant module `source`
    // across rows from DIFFERENT breach corpora (real `source_db`/`dbname`
    // values per row) — the exact bug AU-105 already fixed for itself
    // (`au105_reads_the_see_know_source_db_breach_name`). Two genuinely
    // distinct corpora (LinkedIn, Adobe) both asserting the same DOB is
    // 2-corpora corroboration and must be High, not Medium from a collapsed
    // "1 source (see_know)".
    let mut e = Entity::new(EntityKind::Email, "c@contoso.com", 0.9, "s");
    e.add_evidence(
        Evidence::new("see_know", "breach")
            .with_attr("dob", "1985-03-02")
            .with_attr("source_db", "linkedin.com"),
    );
    e.add_evidence(
        Evidence::new("see_know", "breach")
            .with_attr("dob", "1985-03-02")
            .with_attr("source_db", "adobe.com"),
    );
    let r = super::rules::rule_au_073_subject_date_of_birth(&RuleContext::new(&[e]), "s", 0);
    let main = r
        .iter()
        .find(|c| c.description.contains("1985-03-02"))
        .expect("the DOB fires");
    assert_eq!(
        main.severity,
        Severity::High,
        "two distinct see_know corpora must count as 2 independent sources, not 1: {r:?}"
    );
}

#[test]
fn au073_derives_subject_age_from_dob() {
    // ts = 2026-01-01 00:00 UTC; DOB 1992-07-01 → age 33 (July birthday not yet
    // passed). Also exercises the new `date_birth` key (OathNet's field).
    const TS_2026_01_01: u64 = 1_767_225_600;
    let mut p = Entity::new(EntityKind::Person, "Jerome Despal", 0.9, "s");
    p.add_evidence(Evidence::new("oathnet_pro", "breach").with_attr("date_birth", "1992-07-01"));
    let mut e = Entity::new(EntityKind::Email, "j@x.com", 0.9, "s");
    e.add_evidence(Evidence::new("see_know", "breach").with_attr("dob", "1992-07-01"));

    let r = super::rules::rule_au_073_subject_date_of_birth(
        &RuleContext::new(&[p, e]),
        "s",
        TS_2026_01_01,
    );
    let f = r
        .iter()
        .find(|c| c.description.contains("1992-07-01"))
        .expect("the DOB fires (incl. via the date_birth key)");
    assert_eq!(f.severity, Severity::High, "date_birth + dob = two sources");
    assert!(
        f.description.contains("age 33"),
        "derived age present: {}",
        f.description
    );
}

#[test]
fn au073_tolerates_a_multibyte_dob_without_panicking() {
    // Regression: a breach DOB whose first 8 bytes look ISO ("YYYY-MM-", with
    // ASCII dashes at indices 4 and 7) but whose 9th byte begins a MULTIBYTE
    // UTF-8 char (here `€`, three bytes at indices 8..11) passed `normalise_dob`
    // verbatim via its non-ISO else-branch and then reached `age_from_dob`, whose
    // guard only checked the two dashes and the length — so `dob[8..10]` sliced
    // through the middle of the `€` and panicked. The correlator runs OUTSIDE the
    // engine's per-module `catch_unwind`, so that panic crashed the whole scan on
    // adversarial breach input. It must degrade to "no derived age", never panic.
    const TS: u64 = 1_767_225_600; // 2026-01-01
    let mut p = Entity::new(EntityKind::Person, "Jerome Despal", 0.9, "s");
    p.add_evidence(Evidence::new("oathnet_pro", "breach").with_attr("dob", "1980-11-€X"));
    let mut e = Entity::new(EntityKind::Email, "j@x.com", 0.9, "s");
    e.add_evidence(Evidence::new("see_know", "breach").with_attr("dob", "1980-11-€X"));
    let r = super::rules::rule_au_073_subject_date_of_birth(&RuleContext::new(&[p, e]), "s", TS);
    let f = r
        .iter()
        .find(|c| c.description.contains("1980-11-€X"))
        .expect("the non-ISO DOB still fires as a (no-age) correlation");
    assert!(
        !f.description.contains("age "),
        "no age is derived from a non-ISO DOB: {}",
        f.description
    );
}

#[test]
fn au073_never_panics_on_a_multibyte_dob_at_any_byte_position() {
    // Generalises the regression above: slide a 3-byte char (`€`) through every
    // byte position of an otherwise-ISO date so it straddles each of the
    // `dob[0..4]`/`dob[5..7]`/`dob[8..10]` slice boundaries in turn, then add a
    // 4-byte emoji, all-multibyte, control, short and empty forms. The rule must
    // tolerate every one (no panic) — proving the byte-slice DOB parser is
    // boundary-safe on arbitrary breach input, not just the one captured shrink.
    const TS: u64 = 1_767_225_600;
    let base = "1980-11-08";
    let mut inputs: Vec<String> = (0..=base.len())
        .map(|i| format!("{}€{}", &base[..i], &base[i..]))
        .collect();
    for s in [
        "",
        "€",
        "--------",
        "1980-11-",
        "1980-€1-08",
        "1980-11-0😀",
        "😀😀😀😀-11-08",
        "19\u{0}0-11-08",
    ] {
        inputs.push(s.to_string());
    }
    for dob in inputs {
        let mut p = Entity::new(EntityKind::Person, "X Y", 0.9, "s");
        p.add_evidence(Evidence::new("oathnet_pro", "breach").with_attr("dob", dob.as_str()));
        // The assertion is simply that this returns without panicking.
        let _ = super::rules::rule_au_073_subject_date_of_birth(&RuleContext::new(&[p]), "s", TS);
    }
}

#[test]
fn au073_age_advances_after_the_birthday() {
    // Same DOB, ts = 2026-12-01 (after the July birthday) → age 34.
    const TS_2026_12_01: u64 = 1_796_083_200;
    let mut p = Entity::new(EntityKind::Person, "Jerome Despal", 0.9, "s");
    p.add_evidence(Evidence::new("oathnet_pro", "breach").with_attr("dob", "1992-07-01"));
    let r = super::rules::rule_au_073_subject_date_of_birth(
        &RuleContext::new(&[p]),
        "s",
        TS_2026_12_01,
    );
    let f = r
        .iter()
        .find(|c| c.description.contains("1992-07-01"))
        .expect("should succeed");
    assert!(f.description.contains("age 34"), "{}", f.description);
}

#[test]
fn au073_omits_age_for_a_non_iso_dob() {
    // A non-ISO DOB is surfaced verbatim but yields no (mis-parsed) age.
    let mut p = Entity::new(EntityKind::Person, "Jane Citizen", 0.9, "s");
    p.add_evidence(Evidence::new("oathnet_pro", "breach").with_attr("dob", "08/11/1980"));
    let r = super::rules::rule_au_073_subject_date_of_birth(
        &RuleContext::new(&[p]),
        "s",
        1_767_225_600,
    );
    let f = r
        .iter()
        .find(|c| c.description.contains("08/11/1980"))
        .expect("should succeed");
    assert!(
        !f.description.contains("age "),
        "no age for a non-ISO DOB: {}",
        f.description
    );
}

#[test]
fn au074_government_id_exposure_validates_checksum_and_masks() {
    // A checksum-valid TFN (ATO example 123456782) + a valid Medicare under their
    // breach keys → CRITICAL, value masked. A bad-checksum TFN is rejected.
    let mut e = Entity::new(EntityKind::Credential, "leak", 0.9, "s");
    e.add_evidence(
        Evidence::new("dehashed", "breach")
            .with_attr("tfn", "123456782")
            .with_attr("medicare", "2123456701"),
    );
    let mut bad = Entity::new(EntityKind::Credential, "leak2", 0.9, "s");
    bad.add_evidence(Evidence::new("dehashed", "breach").with_attr("tfn", "123456789"));

    let r =
        super::rules::rule_au_074_au_government_id_exposure(&RuleContext::new(&[e, bad]), "s", 0);
    assert!(!r.is_empty(), "a valid gov-ID exposure must fire");
    let crit = r
        .iter()
        .find(|c| c.rule_id == "AU-074")
        .expect("AU-074 fires");
    assert_eq!(crit.rule_id, "AU-074");
    assert_eq!(crit.severity, Severity::Critical);
    assert!(r.iter().any(|c| c.description.contains("Tax File Number")));
    assert!(r.iter().any(|c| c.description.contains("Medicare")));
    assert!(
        r.iter().all(|c| !c.description.contains("123456782")),
        "the raw value must be masked, never shown in the finding"
    );
    assert_eq!(
        r.iter()
            .filter(|c| c.description.contains("Tax File Number"))
            .count(),
        1,
        "the bad-checksum TFN produced no finding"
    );
}

#[test]
fn au075_named_associate_from_breach_record() {
    let mut e = Entity::new(EntityKind::Person, "Cindy Haynes", 0.9, "s");
    e.add_evidence(
        Evidence::new("see_know", "breach")
            .with_attr("spouse", "Thomas Haynes")
            .with_attr("emergency_contact", "self"),
    );
    let r = super::rules::rule_au_075_named_associate(&RuleContext::new(&[e]), "s", 0);
    let hit = r
        .iter()
        .find(|c| c.description.contains("Thomas Haynes"))
        .expect("the named spouse is surfaced");
    assert_eq!(hit.rule_id, "AU-075");
    assert!(hit.description.contains("spouse"));
    assert!(
        r.iter()
            .all(|c| !c.description.contains("emergency contact")),
        "a placeholder 'self' contact must be filtered out"
    );
}

#[test]
fn au075_non_breach_parent_is_not_a_named_associate() {
    // A live phone scan mislabeled a search/crawl "parent" DOMAIN relationship
    // ("parent" = wikipedia.org) as a breached relative. A non-breach source
    // must never produce a named-associate finding.
    let mut e = Entity::new(EntityKind::Person, "Jo Citizen", 0.9, "s");
    e.add_evidence(Evidence::new("search_engines", "serp").with_attr("parent", "wikipedia.org"));
    assert!(
        super::rules::rule_au_075_named_associate(&RuleContext::new(&[e]), "s", 0).is_empty(),
        "a search-sourced domain 'parent' is not a breach-record associate"
    );
}

#[test]
fn au075_does_not_report_a_see_know_relationship_label_as_a_name() {
    // `see_know`'s associate extractor stores the associate's real name as the
    // entity's own `.value` and uses `relationship` for the CATEGORY label
    // ("relative"/"household"/"associate"/"neighbor"), never a name. A prior
    // `("relationship", "relation")` entry in ASSOCIATE_KEYS read that label as
    // if it were a person's name, reporting the literal word "relative" as a
    // named associate on any SeekNow relative/household hit.
    let mut e = Entity::new(EntityKind::Person, "Jane Smith", 0.9, "s");
    e.add_evidence(
        Evidence::new("see_know", "SeekNow relative of Cindy Haynes")
            .with_attr("relationship", "relative")
            .with_attr("related_to", "Cindy Haynes"),
    );
    let r = super::rules::rule_au_075_named_associate(&RuleContext::new(&[e]), "s", 0);
    assert!(
        r.iter().all(|c| !c.description.contains("'relative'")),
        "the relationship category label must never be reported as an associate's name: {r:?}"
    );
}

#[test]
fn au090_jurisdiction_two_sources_agree_is_high() {
    let mut e = Entity::new(EntityKind::Person, "Cindy Haynes", 0.9, "s");
    e.add_evidence(Evidence::new("oathnet_pro", "breach").with_attr("state", "QLD"));
    e.add_evidence(Evidence::new("see_know", "breach").with_attr("address_state", "Queensland"));
    let r = super::rules::rule_au_090_au_jurisdiction(&RuleContext::new(&[e]), "s", 0);
    assert_eq!(r.len(), 1, "QLD and Queensland resolve to one jurisdiction");
    assert_eq!(r[0].rule_id, "AU-090");
    assert_eq!(r[0].severity, super::Severity::High);
    assert!(r[0].description.contains("QLD"));
    assert!(r[0].description.contains("2 breach record source"));
}

#[test]
fn au090_single_source_is_medium() {
    let mut e = Entity::new(EntityKind::Person, "Jo Citizen", 0.9, "s");
    e.add_evidence(Evidence::new("see_know", "breach").with_attr("licence_state", "VIC"));
    let r = super::rules::rule_au_090_au_jurisdiction(&RuleContext::new(&[e]), "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].severity, super::Severity::Medium);
    assert!(r[0].description.contains("VIC"));
}

#[test]
fn au090_conflicting_states_each_surface_with_move_note() {
    let mut e = Entity::new(EntityKind::Person, "Jo Citizen", 0.9, "s");
    e.add_evidence(Evidence::new("see_know", "breach").with_attr("state", "NSW"));
    e.add_evidence(Evidence::new("oathnet_pro", "breach").with_attr("licence_state", "VIC"));
    let r = super::rules::rule_au_090_au_jurisdiction(&RuleContext::new(&[e]), "s", 0);
    assert_eq!(r.len(), 2, "each distinct state surfaces independently");
    assert!(r.iter().all(|c| c.rule_id == "AU-090"));
    assert!(r.iter().any(|c| c.description.contains("NSW")));
    assert!(r.iter().any(|c| c.description.contains("VIC")));
    assert!(
        r.iter().all(|c| c.description.contains("interstate move")),
        "multiple state claims must carry the move/namesake note"
    );
}

#[test]
fn au090_non_au_or_missing_state_yields_nothing() {
    let mut e = Entity::new(EntityKind::Person, "John Doe", 0.9, "s");
    // A US state and a status-style value — neither resolves to an AU jurisdiction.
    e.add_evidence(Evidence::new("dehashed", "breach").with_attr("state", "California"));
    e.add_evidence(Evidence::new("dehashed", "breach").with_attr("state", "active"));
    assert!(super::rules::rule_au_090_au_jurisdiction(&RuleContext::new(&[e]), "s", 0).is_empty());
}

#[test]
fn au091_postcode_resolves_to_state_and_offline_coord() {
    let mut e = Entity::new(EntityKind::Person, "Cindy Haynes", 0.9, "s");
    e.add_evidence(Evidence::new("oathnet_pro", "breach").with_attr("postcode", "4000"));
    e.add_evidence(Evidence::new("see_know", "breach").with_attr("post_code", "4000"));
    let r = super::rules::rule_au_091_au_postcode_locality(&RuleContext::new(&[e]), "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-091");
    assert_eq!(r[0].severity, super::Severity::High); // two independent sources
    assert!(r[0].description.contains("4000"));
    assert!(
        r[0].description.contains("QLD"),
        "4000 is a Brisbane (QLD) postcode"
    );
    assert!(
        r[0].description.contains("offline"),
        "an offline coordinate is attached"
    );
}

#[test]
fn au091_single_source_is_medium_and_handles_leading_zero() {
    // NT postcode 0800 (Darwin) — 4-digit with a leading zero must still resolve.
    let mut e = Entity::new(EntityKind::Person, "Jo Citizen", 0.9, "s");
    e.add_evidence(Evidence::new("see_know", "breach").with_attr("postal_code", "0800"));
    let r = super::rules::rule_au_091_au_postcode_locality(&RuleContext::new(&[e]), "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].severity, super::Severity::Medium);
    assert!(r[0].description.contains("0800"));
    assert!(r[0].description.contains("NT"));
}

#[test]
fn au091_two_postcodes_surface_separately_with_note() {
    let mut e = Entity::new(EntityKind::Person, "Jo Citizen", 0.9, "s");
    e.add_evidence(Evidence::new("see_know", "breach").with_attr("postcode", "4000")); // QLD
    e.add_evidence(Evidence::new("oathnet_pro", "breach").with_attr("postcode", "3000")); // VIC
    let r = super::rules::rule_au_091_au_postcode_locality(&RuleContext::new(&[e]), "s", 0);
    assert_eq!(r.len(), 2);
    assert!(r.iter().all(|c| c.rule_id == "AU-091"));
    assert!(
        r.iter()
            .any(|c| c.description.contains("4000") && c.description.contains("QLD"))
    );
    assert!(
        r.iter()
            .any(|c| c.description.contains("3000") && c.description.contains("VIC"))
    );
    assert!(r.iter().all(|c| c.description.contains("second residence")));
}

#[test]
fn au091_non_au_and_noise_yield_nothing() {
    let mut e = Entity::new(EntityKind::Person, "John Doe", 0.9, "s");
    // A US 5-digit zip in a postal_code field, and a non-postcode 4-digit (year).
    e.add_evidence(Evidence::new("dehashed", "breach").with_attr("postal_code", "90210"));
    e.add_evidence(Evidence::new("dehashed", "breach").with_attr("postcode", "0001")); // unassigned
    assert!(
        super::rules::rule_au_091_au_postcode_locality(&RuleContext::new(&[e]), "s", 0).is_empty()
    );
}

#[test]
fn au092_breach_state_agrees_with_geocoded_footprint() {
    // Breach says QLD; an independent Brisbane coordinate also resolves to QLD.
    let mut p = Entity::new(EntityKind::Person, "Cindy Haynes", 0.9, "s");
    p.add_evidence(Evidence::new("oathnet_pro", "breach").with_attr("state", "QLD"));
    let mut coord = Entity::new(EntityKind::Coordinates, "-27.4705,153.0260", 0.6, "s"); // Brisbane
    coord.add_evidence(Evidence::new("geocode", "geocoded subject fix")); // person-anchored, not infra
    let r = super::rules::rule_au_092_breach_locality_footprint_crosscheck(
        &RuleContext::new(&[p, coord]),
        "s",
        0,
    );
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-092");
    assert_eq!(r[0].severity, super::Severity::High);
    assert!(r[0].rule_name.contains("corroborated"));
    assert!(r[0].description.contains("QLD"));
}

#[test]
fn au092_breach_postcode_conflicts_with_footprint() {
    // Breach postcode 3000 (VIC) vs a Brisbane (QLD) coordinate → conflict.
    let mut p = Entity::new(EntityKind::Person, "Jo Citizen", 0.9, "s");
    p.add_evidence(Evidence::new("see_know", "breach").with_attr("postcode", "3000"));
    let mut coord = Entity::new(EntityKind::Coordinates, "-27.4705,153.0260", 0.6, "s");
    coord.add_evidence(Evidence::new("geocode", "geocoded subject fix")); // person-anchored, not infra
    let r = super::rules::rule_au_092_breach_locality_footprint_crosscheck(
        &RuleContext::new(&[p, coord]),
        "s",
        0,
    );
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].severity, super::Severity::Medium);
    assert!(r[0].rule_name.contains("conflict"));
    assert!(r[0].description.contains("VIC") && r[0].description.contains("QLD"));
}

#[test]
fn au092_agrees_with_address_entity_footprint() {
    // Footprint can also come from a confident Address entity, not just a coord.
    let mut p = Entity::new(EntityKind::Person, "Jo Citizen", 0.9, "s");
    p.add_evidence(Evidence::new("see_know", "breach").with_attr("state", "New South Wales"));
    let addr = Entity::new(EntityKind::Address, "Sydney NSW 2000", 0.7, "s");
    let r = super::rules::rule_au_092_breach_locality_footprint_crosscheck(
        &RuleContext::new(&[p, addr]),
        "s",
        0,
    );
    assert_eq!(r.len(), 1);
    assert!(r[0].rule_name.contains("corroborated"));
    assert!(r[0].description.contains("NSW"));
}
