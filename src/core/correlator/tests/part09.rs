#[test]
fn au050_excludes_shared_business_and_service_lines() {
    // A shared AU business/service line — freephone (1800) or local-rate
    // (13/1300) — is an organisational desk many unrelated people legitimately
    // reach, not evidence they are associates. It must NOT fire AU-050.
    for service in ["1800 123 456", "1300 975 707"] {
        let ents = vec![
            person_with_phone("Jordan Meyers", service),
            person_with_phone("Casey Lin", service),
        ];
        let hits =
            super::rules::rule_au_050_shared_phone_association(&RuleContext::new(&ents), "s", 0);
        assert!(
            hits.is_empty(),
            "shared business/service line {service} must not link unrelated people: {hits:?}"
        );
    }

    // A shared PERSONAL line (a mobile) still links the two people — no false
    // negative — even across formatting variants that collapse to one key.
    let mobile = vec![
        person_with_phone("Jordan Meyers", "0412 345 678"),
        person_with_phone("Casey Lin", "(0412) 345-678"),
    ];
    let hits =
        super::rules::rule_au_050_shared_phone_association(&RuleContext::new(&mobile), "s", 0);
    assert_eq!(
        hits.len(),
        1,
        "a shared personal mobile still links: {hits:?}"
    );
    assert_eq!(hits[0].rule_id, "AU-050");
}

#[test]
fn au050_vetoes_au_business_line_in_plus61_international_form() {
    // Regression (OD-14): an AU freephone/local-rate line stored in +61
    // international form reaches the veto as a `+`-stripped digits key
    // ("+61 1800 123 456" → key "611800123456") that au_phone_line_type can't see
    // as domestic 1800. It must still be vetoed as a shared business desk, not fire
    // a false associate cluster.
    for service in ["+61 1800 123 456", "+61 1300 975 707"] {
        let ents = vec![
            person_with_phone("Jordan Meyers", service),
            person_with_phone("Casey Lin", service),
        ];
        assert!(
            super::rules::rule_au_050_shared_phone_association(&RuleContext::new(&ents), "s", 0)
                .is_empty(),
            "a +61-international-form AU business line must not link unrelated people: {service}"
        );
    }
    // A personal AU mobile in +61 form is not a business line and still links.
    let mobile = vec![
        person_with_phone("Jordan Meyers", "+61 412 345 678"),
        person_with_phone("Casey Lin", "61 412 345 678"),
    ];
    let hits =
        super::rules::rule_au_050_shared_phone_association(&RuleContext::new(&mobile), "s", 0);
    assert_eq!(hits.len(), 1, "a shared +61 mobile still links: {hits:?}");
    assert_eq!(hits[0].rule_id, "AU-050");
}

#[test]
fn au050_links_nanp_number_colliding_with_au_service_prefix() {
    // Regression (phone line-type false negative): a shared US number whose digits
    // collide with an AU service prefix must still link two people. `+1 909 555
    // 0142` (San Bernardino) normalises to the key `19095550142`, which the
    // line-type classifier used to read as AU premium `190x` and veto as a
    // "business/service line" — silently dropping the real association. It is 11
    // digits (NANP `1` + area code), not a 10-digit AU service number, so it is a
    // personal line and AU-050 must fire.
    let ents = vec![
        person_with_phone("Jordan Meyers", "+1 909 555 0142"),
        person_with_phone("Casey Lin", "1 (909) 555-0142"),
    ];
    let hits = super::rules::rule_au_050_shared_phone_association(&RuleContext::new(&ents), "s", 0);
    assert_eq!(
        hits.len(),
        1,
        "a shared NANP line colliding with AU 190x must still link: {hits:?}"
    );
    assert_eq!(hits[0].rule_id, "AU-050");
}

#[test]
fn au051_shared_surname_at_residence_is_kin() {
    let ents = vec![
        person_at("Jordan Meyers", "123 Main St, Springfield"),
        person_at("Dana Meyers", "123 Main St, Springfield"),
    ];
    let hits = super::rules::rule_au_051_shared_surname_kin(&RuleContext::new(&ents), "s", 0);
    assert_eq!(hits.len(), 1, "shared surname + residence = kin");
    assert_eq!(hits[0].rule_id, "AU-051");
    assert_eq!(hits[0].severity, super::Severity::Critical);
    assert!(hits[0].description.contains("meyers"));
}

#[test]
fn au051_requires_shared_residence_and_distinguishes_roommates() {
    // Same surname, different homes: two unrelated people must NOT link.
    let apart = vec![
        person_at("Jordan Meyers", "123 Main St, Springfield"),
        person_at("Dana Meyers", "987 Oak Ave, Portland"),
    ];
    assert!(
        super::rules::rule_au_051_shared_surname_kin(&RuleContext::new(&apart), "s", 0).is_empty()
    );

    // Same residence, different families: AU-049 fires (household) but AU-051
    // (kin) does not.
    let roommates = vec![
        person_at("Jordan Meyers", "123 Main St, Springfield"),
        person_at("Casey Lin", "123 Main St, Springfield"),
    ];
    assert_eq!(
        super::rules::rule_au_049_shared_address_association(&RuleContext::new(&roommates), "s", 0)
            .len(),
        1
    );
    assert!(
        super::rules::rule_au_051_shared_surname_kin(&RuleContext::new(&roommates), "s", 0)
            .is_empty()
    );
}

#[test]
fn au051_common_surname_is_a_high_lead_not_critical_kin() {
    // Two "Smith"s sharing one building address (unit numbers absent from the
    // data) must NOT be asserted as Critical "likely relatives" — a common surname
    // makes the shared-residence a coincidence risk (an apartment tower collapses
    // unrelated co-residents onto one key). It still fires, but as a High LEAD to
    // verify; a distinctive surname (Meyers, above) stays Critical.
    let ents = vec![
        person_at("Jordan Smith", "123 Main St, Springfield"),
        person_at("Dana Smith", "123 Main St, Springfield"),
    ];
    let hits = super::rules::rule_au_051_shared_surname_kin(&RuleContext::new(&ents), "s", 0);
    assert_eq!(hits.len(), 1, "still fires — it is a lead, not silence");
    assert_eq!(hits[0].rule_id, "AU-051");
    assert_eq!(
        hits[0].severity,
        super::Severity::High,
        "a common surname is a High lead, not a Critical kin assertion"
    );
    assert!(hits[0].description.contains("common surname"));
}

// ─── Shared organisational email domain (AU-087) ─────────────────────────────

#[cfg(test)]
fn org_email_ent(addr: &str) -> Entity {
    Entity::new(EntityKind::Email, addr, 0.72, "s")
}

#[test]
fn au087_fires_on_two_addresses_at_one_org_domain() {
    // Two distinct addresses at a specific (non-freemail) organisational domain
    // form an employer / institution affiliation surface.
    let e1 = org_email_ent("john.smith@acme.com.au");
    let e2 = org_email_ent("jane.doe@acme.com.au");
    let (u1, u2) = (e1.uid.clone(), e2.uid.clone());
    let hits =
        super::rules::rule_au_087_shared_org_email_domain(&RuleContext::new(&[e1, e2]), "s", 0);
    assert_eq!(hits.len(), 1, "one org-domain affiliation cluster");
    let c = &hits[0];
    assert_eq!(c.rule_id, "AU-087");
    assert_eq!(c.severity, super::Severity::Medium);
    assert!(c.description.contains("acme.com.au"));
    assert!(c.entity_uids.contains(&u1) && c.entity_uids.contains(&u2));
}

#[test]
fn au087_excludes_freemail_and_isp_webmail() {
    // Freemail (gmail) and ISP webmail (bigpond) are millions-strong shared
    // services, not an organisation — two addresses on either never fire.
    let gmail = vec![
        org_email_ent("alice@gmail.com"),
        org_email_ent("bob@gmail.com"),
    ];
    assert!(
        super::rules::rule_au_087_shared_org_email_domain(&RuleContext::new(&gmail), "s", 0)
            .is_empty()
    );
    let isp = vec![
        org_email_ent("a@bigpond.com"),
        org_email_ent("b@bigpond.com"),
    ];
    assert!(
        super::rules::rule_au_087_shared_org_email_domain(&RuleContext::new(&isp), "s", 0)
            .is_empty()
    );
    // Regression: consumer webmail OUTSIDE the `is_noncentral_domain` damping list
    // must be excluded too. `gmail.com`/`bigpond.com` above happen to sit in
    // `MEGA_DOMAINS`, so `is_noncentral_domain` alone caught them — but the ~40
    // other freemail domains (Yahoo/Hotmail country variants, Chinese providers,
    // legacy Yahoo brands) do not, and previously slipped through to fire a false
    // employer/institution affiliation between strangers. The canonical
    // `is_freemail` guard now closes that gap. Every domain below is in FREEMAIL
    // yet absent from `MEGA_DOMAINS`/`INFRA_DOMAINS`.
    for freemail in ["qq.com", "163.com", "rocketmail.com", "yahoo.co.uk"] {
        let pair = vec![
            org_email_ent(&format!("john.smith@{freemail}")),
            org_email_ent(&format!("jane.doe@{freemail}")),
        ];
        assert!(
            super::rules::rule_au_087_shared_org_email_domain(&RuleContext::new(&pair), "s", 0)
                .is_empty(),
            "{freemail} is consumer webmail, not an organisational affiliation surface"
        );
    }
}

#[test]
fn au087_needs_two_distinct_addresses() {
    // A single address at an org domain is not a shared surface.
    let one = vec![org_email_ent("solo@acme.com.au")];
    assert!(
        super::rules::rule_au_087_shared_org_email_domain(&RuleContext::new(&one), "s", 0)
            .is_empty()
    );
    // The same address in different case (recalled + re-discovered) is ONE
    // distinct address after normalisation, not a cluster of two.
    let dup = vec![
        org_email_ent("solo@acme.com.au"),
        org_email_ent("SOLO@acme.com.au"),
    ];
    assert!(
        super::rules::rule_au_087_shared_org_email_domain(&RuleContext::new(&dup), "s", 0)
            .is_empty()
    );
}

#[test]
fn au087_rides_along_named_person_and_covers_edu_domains() {
    // A university (.edu.au) domain fires, and a Person whose name derives one of
    // the local-parts is linked — the affiliation names a real person.
    let e1 = org_email_ent("j.citizen@uq.edu.au");
    let e2 = org_email_ent("m.lee@uq.edu.au");
    let mut person = Entity::new(EntityKind::Person, "Jane Citizen", 0.62, "s");
    person.tag("au");
    let puid = person.uid.clone();
    let hits = super::rules::rule_au_087_shared_org_email_domain(
        &RuleContext::new(&[e1, e2, person]),
        "s",
        0,
    );
    assert_eq!(hits.len(), 1);
    assert!(hits[0].description.contains("uq.edu.au"));
    assert!(
        hits[0].entity_uids.contains(&puid),
        "the named affiliate rides along in the firing"
    );
}

// ─── Authoritative AU register confirmation (AU-088) ─────────────────────────────

#[cfg(test)]
fn ent_from_source(kind: EntityKind, value: &str, source: &str) -> Entity {
    let mut e = Entity::new(kind, value, 0.70, "s");
    e.add_evidence(Evidence::new(source, "register record"));
    e
}

#[test]
fn au088_single_register_is_high_confirmation() {
    // One authoritative register returning subject data is a High confirmation.
    let p = ent_from_source(EntityKind::Person, "Jane Citizen", "ahpra");
    let hits = super::rules::rule_au_088_authoritative_register_confirmation(
        &RuleContext::new(&[p]),
        "s",
        0,
    );
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].rule_id, "AU-088");
    assert_eq!(hits[0].severity, super::Severity::High);
    assert!(hits[0].description.contains("AHPRA"));
    assert!(hits[0].description.contains("1 authoritative"));
}

#[test]
fn au088_two_distinct_registers_is_critical() {
    // Two DIFFERENT authorities agreeing is the strongest identity signal → Critical.
    let p = ent_from_source(EntityKind::Person, "Jane Citizen", "ahpra");
    let o = ent_from_source(EntityKind::Person, "Jane Citizen", "au_electoral");
    let hits = super::rules::rule_au_088_authoritative_register_confirmation(
        &RuleContext::new(&[p, o]),
        "s",
        0,
    );
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].severity, super::Severity::Critical);
    assert!(hits[0].description.contains("2 authoritative"));
    assert!(hits[0].description.contains("AHPRA") && hits[0].description.contains("electoral"));
}

#[test]
fn au088_asic_subfeeds_collapse_to_one_authority() {
    // Three ASIC feeds are ONE issuing authority — High, not Critical.
    let a = ent_from_source(EntityKind::Person, "Jo Director", "asic_persons");
    let b = ent_from_source(EntityKind::Organisation, "Acme Pty Ltd", "asic_director");
    let c = ent_from_source(EntityKind::Person, "Jo Director", "asic_banned_orgs");
    let hits = super::rules::rule_au_088_authoritative_register_confirmation(
        &RuleContext::new(&[a, b, c]),
        "s",
        0,
    );
    assert_eq!(hits.len(), 1);
    assert_eq!(
        hits[0].severity,
        super::Severity::High,
        "3 ASIC feeds collapse to a single authority"
    );
    assert!(hits[0].description.contains("1 authoritative"));
}

#[test]
fn au088_non_register_sources_do_not_fire() {
    // Search-engine / name-derivation hits are not authoritative registers.
    let p = ent_from_source(EntityKind::Person, "Jane Citizen", "search_engines");
    let e = ent_from_source(EntityKind::Email, "jane@gmail.com", "name_intel");
    assert!(
        super::rules::rule_au_088_authoritative_register_confirmation(
            &RuleContext::new(&[p, e]),
            "s",
            0
        )
        .is_empty()
    );
}

// ─── Australian corporate network (AU-089) ───────────────────────────────────────────

#[test]
fn au089_two_distinct_companies_fire_medium() {
    // ACN 004085616 and the company ABN 53004085616 are the SAME company → must
    // collapse to one; add a second, distinct company (ACN 000000019) to fire.
    let a = Entity::new(EntityKind::AbnAcn, "53004085616", 0.80, "s"); // company ABN
    let b = Entity::new(EntityKind::AbnAcn, "004085616", 0.80, "s"); // its ACN (same co.)
    let c = Entity::new(EntityKind::AbnAcn, "000000019", 0.80, "s"); // a 2nd company
    let hits = super::rules::rule_au_089_corporate_network(&RuleContext::new(&[a, b, c]), "s", 0);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].rule_id, "AU-089");
    assert_eq!(hits[0].severity, super::Severity::Medium);
    // Exactly two distinct companies, ABN+ACN of the first deduped to one.
    assert!(hits[0].description.contains("2 distinct"));
    assert!(hits[0].description.contains("004 085 616"));
    assert!(hits[0].description.contains("000 000 019"));
}

#[test]
fn au089_single_company_does_not_fire() {
    // A company seen as both its ABN and its derived ACN is still ONE company.
    let a = Entity::new(EntityKind::AbnAcn, "53004085616", 0.80, "s");
    let b = Entity::new(EntityKind::AbnAcn, "004085616", 0.80, "s");
    assert!(
        super::rules::rule_au_089_corporate_network(&RuleContext::new(&[a, b]), "s", 0).is_empty()
    );
}

#[test]
fn au089_three_companies_escalate_to_high() {
    let a = Entity::new(EntityKind::AbnAcn, "004085616", 0.80, "s");
    let b = Entity::new(EntityKind::AbnAcn, "000000019", 0.80, "s");
    // A third distinct, checksum-valid ACN (prefix 01000000 → check digit 3).
    let c = Entity::new(EntityKind::AbnAcn, "010000003", 0.80, "s");
    let hits = super::rules::rule_au_089_corporate_network(&RuleContext::new(&[a, b, c]), "s", 0);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].severity, super::Severity::High);
    assert!(hits[0].description.contains("3 distinct"));
}

#[test]
fn au089_non_company_abn_is_excluded() {
    // 51824753556 is a valid ABN but NOT a company (no embedded ACN), so it is
    // not a corporate vehicle — one real company alongside it must not fire.
    let sole = Entity::new(EntityKind::AbnAcn, "51824753556", 0.80, "s");
    let company = Entity::new(EntityKind::AbnAcn, "004085616", 0.80, "s");
    assert!(
        super::rules::rule_au_089_corporate_network(&RuleContext::new(&[sole, company]), "s", 0)
            .is_empty()
    );
}

#[cfg(test)]
fn api_key_ent(value: &str, service: &str, criticality: &str, detection: &str) -> Entity {
    let mut e = Entity::new(EntityKind::ApiKey, value, 0.80, "s");
    e.tag("api-key");
    e.tag(format!("service:{service}"));
    e.tag(format!("key-criticality:{criticality}"));
    e.tag(format!("detection:{detection}"));
    if matches!(criticality, "critical" | "high") {
        e.tag("high-value");
    }
    e
}

#[test]
fn au095_ranks_portfolio_critical_first() {
    let aws = api_key_ent("AKIA_aws_secret", "aws", "critical", "proven");
    let analytics = api_key_ent("ph_low_token", "posthog", "low", "probable");
    let r = super::rules::rule_au_095_exposed_key_portfolio(
        &RuleContext::new(&[analytics, aws]),
        "s",
        0,
    );
    assert_eq!(r.len(), 1, "one portfolio summary");
    assert_eq!(r[0].rule_id, "AU-095");
    assert_eq!(r[0].severity, super::Severity::Critical); // a high-value key present
    assert!(r[0].description.contains("2 exposed API key"));
    assert!(r[0].description.contains("2 provider"));
    assert!(r[0].description.contains("1 high-criticality"));
    // The critical AWS key must lead the revoke-first list, before the low one.
    let aws_pos = r[0].description.find("aws").expect("aws listed");
    let ph_pos = r[0].description.find("posthog").expect("posthog listed");
    assert!(
        aws_pos < ph_pos,
        "critical key ranked before low-criticality key"
    );
    assert!(
        r[0].description.contains("not reused"),
        "states the no-reuse policy"
    );
}

#[test]
fn au095_flags_exploitable_and_handles_unrated() {
    let mut jwt = api_key_ent("eyJ.none.token", "jwt_token", "low", "potential");
    jwt.tag(crate::core::tags::VULNERABLE); // e.g. alg:none
    // A found_keys-path key with no criticality tag → counts, ranks unrated.
    let mut bare = Entity::new(EntityKind::ApiKey, "foreignkey123", 0.7, "s");
    bare.tag("api-key");
    bare.tag("foreign-key");
    let r =
        super::rules::rule_au_095_exposed_key_portfolio(&RuleContext::new(&[jwt, bare]), "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].severity, super::Severity::High); // no high-criticality key
    assert!(r[0].description.contains("outright exploitable"));
    assert!(
        r[0].description.contains("unrated"),
        "untagged key ranks unrated"
    );
}

#[test]
fn au095_discloses_when_the_priority_list_is_truncated() {
    // The revoke-first list is capped at 5, but the description must never
    // read as complete when it isn't — the same "(+N more)" disclosure
    // AU-047/AU-048/AU-106 already carry via join_capped.
    let keys: Vec<Entity> = (0..7)
        .map(|i| api_key_ent(&format!("key-{i}"), &format!("svc{i}"), "high", "proven"))
        .collect();
    let r = super::rules::rule_au_095_exposed_key_portfolio(&RuleContext::new(&keys), "s", 0);
    assert_eq!(r.len(), 1);
    assert!(
        r[0].description.contains("7 exposed API key"),
        "the true total must still be stated: {}",
        r[0].description
    );
    assert!(
        r[0].description.contains("(+2 more)"),
        "the capped (top-5) priority list must disclose the 2 it omitted: {}",
        r[0].description
    );
}

#[test]
fn au095_no_keys_no_finding() {
    let p = Entity::new(EntityKind::Person, "Jo Citizen", 0.9, "s");
    assert!(
        super::rules::rule_au_095_exposed_key_portfolio(&RuleContext::new(&[p]), "s", 0).is_empty()
    );
}

#[cfg(test)]
fn osint_key_ent(value: &str, service: &str, category: &str) -> Entity {
    let mut e = Entity::new(EntityKind::ApiKey, value, 0.80, "s");
    e.tag("api-key");
    e.tag(format!("service:{service}"));
    e.tag("osint-practitioner");
    e.tag(format!("osint-category:{category}"));
    e
}

#[test]
fn au096_flags_osint_practitioner_with_tradecraft() {
    let shodan = osint_key_ent(
        "shodankey32xxxxxxxxxxxxxxxxxxxxxx",
        "shodan",
        "attack-surface",
    );
    let dehashed = osint_key_ent("dehashedkey", "dehashed", "breach-leak");
    let r = super::rules::rule_au_096_osint_practitioner(
        &RuleContext::new(&[shodan, dehashed]),
        "s",
        0,
    );
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-096");
    assert_eq!(r[0].severity, super::Severity::High);
    assert!(
        r[0].description
            .contains("2 OSINT/recon-provider credential")
    );
    assert!(r[0].description.contains("shodan") && r[0].description.contains("dehashed"));
    assert!(
        r[0].description.contains("attack-surface") && r[0].description.contains("breach-leak")
    );
}

#[cfg(test)]
fn osint_cred_ent(value: &str, service: &str, category: &str) -> Entity {
    // The leaked-login path (`store_api_credential`) mints a Credential — not an
    // ApiKey — but carries the same OSINT-practitioner pivot tags.
    let mut e = Entity::new(EntityKind::Credential, value, 0.65, "s");
    e.tag("stealer-credential");
    e.tag(format!("service:{service}"));
    e.tag("osint-practitioner");
    e.tag(format!("osint-category:{category}"));
    e
}

#[test]
fn au096_counts_leaked_provider_logins_not_just_api_keys() {
    // A harvested Shodan API key and a leaked Maltego account login are equal
    // practitioner evidence: AU-096 must fold both provider-access kinds into one
    // attribution, spanning both tradecraft categories.
    let shodan = osint_key_ent(
        "shodankey32xxxxxxxxxxxxxxxxxxxxxx",
        "shodan",
        "attack-surface",
    );
    let maltego = osint_cred_ent("maltego-account-pw", "maltego", "social-link-analysis");
    let r =
        super::rules::rule_au_096_osint_practitioner(&RuleContext::new(&[shodan, maltego]), "s", 0);
    assert_eq!(r.len(), 1, "one practitioner finding folding both kinds");
    assert_eq!(r[0].rule_id, "AU-096");
    assert!(
        r[0].description
            .contains("2 OSINT/recon-provider credential")
    );
    assert!(r[0].description.contains("shodan") && r[0].description.contains("maltego"));
    assert!(
        r[0].description.contains("attack-surface")
            && r[0].description.contains("social-link-analysis"),
        "both tradecraft categories surface: {}",
        r[0].description
    );
    assert_eq!(
        r[0].entity_uids.len(),
        2,
        "both artifacts cited as evidence"
    );
}

#[test]
fn au097_consumer_isp_is_medium_residency_signal() {
    // An IP whose `isp` evidence names an Australian consumer ISP.
    let mut ip = Entity::new(EntityKind::IpAddress, "1.2.3.4", 0.8, "s");
    ip.add_evidence(
        Evidence::new("ip_geo", "geo")
            .with_attr("isp", "Telstra")
            .with_attr("as", "AS1221 Telstra"),
    );
    let r = super::rules::rule_au_097_au_isp_network(&RuleContext::new(&[ip]), "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-097");
    assert_eq!(r[0].severity, super::Severity::Medium);
    assert!(r[0].description.contains("Telstra"));
    assert!(r[0].description.contains("consumer ISP"));
}

#[test]
fn au097_aarnet_is_high_academic_affiliation() {
    // An ASN entity valued with AARNet → academic/research network.
    let asn = Entity::new(EntityKind::Asn, "AS7575 AARNet", 0.8, "s");
    let r = super::rules::rule_au_097_au_isp_network(&RuleContext::new(&[asn]), "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].severity, super::Severity::High);
    assert!(r[0].description.contains("AARNet"));
    assert!(r[0].description.contains("academic"));
}

#[test]
fn au097_ignores_foreign_and_non_network_entities() {
    // A foreign ISP must not fire; a non-IP/ASN entity is ignored.
    let mut foreign = Entity::new(EntityKind::IpAddress, "8.8.8.8", 0.8, "s");
    foreign.add_evidence(Evidence::new("ip_geo", "geo").with_attr("isp", "Google LLC"));
    let person = Entity::new(EntityKind::Person, "Telstra Smith", 0.8, "s"); // name, not a network
    assert!(
        super::rules::rule_au_097_au_isp_network(&RuleContext::new(&[foreign, person]), "s", 0)
            .is_empty()
    );
}

#[test]
fn au097_does_not_attribute_belong_isp_from_descr_prose() {
    // Regression (OD-13): `belong` is a real AU ISP AND a common verb. A RIPE
    // `descr` naming the verb ("…used to belong to LegacyCorp") must NOT fabricate
    // a Belong residency attribution; only a structured isp/org field naming the
    // operator should.
    let mut prose = Entity::new(EntityKind::IpAddress, "1.2.3.4", 0.8, "s");
    prose.add_evidence(Evidence::new("ripestat", "asn").with_attr(
        "descr",
        "address space that used to belong to LegacyCorp Pty Ltd",
    ));
    assert!(
        super::rules::rule_au_097_au_isp_network(&RuleContext::new(&[prose]), "s", 0).is_empty(),
        "`belong` as a verb in descr prose must not attribute the Belong ISP"
    );
    // A genuine Belong customer IP (structured isp field) still fires.
    let mut genuine = Entity::new(EntityKind::IpAddress, "1.2.3.5", 0.8, "s");
    genuine.add_evidence(Evidence::new("ip_geo", "geo").with_attr("isp", "Belong"));
    let r = super::rules::rule_au_097_au_isp_network(&RuleContext::new(&[genuine]), "s", 0);
    assert_eq!(
        r.len(),
        1,
        "a structured Belong isp field is a real attribution"
    );
    assert_eq!(r[0].rule_id, "AU-097");
}

#[test]
fn au097_short_token_needs_word_boundary() {
    // "tpg" must not match inside a longer word (no false AU attribution).
    let mut ip = Entity::new(EntityKind::IpAddress, "1.2.3.4", 0.8, "s");
    ip.add_evidence(Evidence::new("ripestat", "asn").with_attr("descr", "ACMETPGENETICS LIMITED"));
    assert!(super::rules::rule_au_097_au_isp_network(&RuleContext::new(&[ip]), "s", 0).is_empty());
}

#[test]
fn au097_skips_hosting_and_platform_infra_entities() {
    // Regression: a hosting/datacentre IP that resolves to an AU network operator
    // is a SERVER (mail host, CDN edge, the box a linked page resolves to), not
    // the subject's access connection — attributing AU residency/affiliation to it
    // fabricates a network-layer signal from pure infrastructure. Same Telstra IP
    // as the Medium-residency test, but tagged `hosting` → must stay silent.
    let mut host = Entity::new(EntityKind::IpAddress, "1.2.3.4", 0.8, "s");
    host.add_evidence(
        Evidence::new("ip_geo", "geo")
            .with_attr("isp", "Telstra")
            .with_attr("as", "AS1221 Telstra"),
    );
    host.tag(crate::core::tags::HOSTING);
    assert!(
        super::rules::rule_au_097_au_isp_network(&RuleContext::new(&[host]), "s", 0).is_empty(),
        "a hosting-tagged server IP is not the subject's AU access connection"
    );
    // A platform-infra-tagged ASN (e.g. an AARNet-hosted cloud range) is likewise
    // not the subject's institutional affiliation.
    let mut asn = Entity::new(EntityKind::Asn, "AS7575 AARNet", 0.8, "s");
    asn.tag(crate::core::tags::PLATFORM_INFRA);
    assert!(
        super::rules::rule_au_097_au_isp_network(&RuleContext::new(&[asn]), "s", 0).is_empty(),
        "a platform-infra-tagged ASN is not the subject's institutional affiliation"
    );
}

#[test]
fn au096_ignores_non_osint_keys() {
    // A plain infra key (no osint-practitioner tag) must not trigger AU-096.
    let mut aws = Entity::new(EntityKind::ApiKey, "AKIAxxxx", 0.8, "s");
    aws.tag("api-key");
    aws.tag("service:aws");
    assert!(
        super::rules::rule_au_096_osint_practitioner(&RuleContext::new(&[aws]), "s", 0).is_empty()
    );
}

#[test]
fn au094_non_company_abn_is_a_sole_trader_signal() {
    // 51824753556 — valid ABN, no embedded ACN → a non-company (sole trader/trust).
    let sole = Entity::new(EntityKind::AbnAcn, "51 824 753 556", 0.80, "s");
    let r = super::rules::rule_au_094_sole_trader_abn(&RuleContext::new(&[sole]), "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-094");
    assert_eq!(r[0].severity, super::Severity::Medium);
    assert!(
        r[0].description.contains("51 824 753 556"),
        "ABN shown grouped"
    );
    assert!(r[0].description.contains("sole-trader"));
}

#[test]
fn au094_excludes_companies_and_acns() {
    // A company ABN (53004085616) and a bare ACN are companies — AU-089's domain,
    // not AU-094's. Neither must fire the sole-trader rule.
    let company_abn = Entity::new(EntityKind::AbnAcn, "53004085616", 0.80, "s");
    let acn = Entity::new(EntityKind::AbnAcn, "004085616", 0.80, "s");
    assert!(
        super::rules::rule_au_094_sole_trader_abn(&RuleContext::new(&[company_abn, acn]), "s", 0)
            .is_empty()
    );
}

#[test]
fn au094_dedups_and_counts_distinct_non_company_abns() {
    // Same ABN in two formats collapses; a second distinct non-company ABN counts.
    let a1 = Entity::new(EntityKind::AbnAcn, "51824753556", 0.80, "s");
    let a1_spaced = Entity::new(EntityKind::AbnAcn, "51 824 753 556", 0.80, "s");
    // 18123456789 — a second valid ABN whose trailing nine (123456789) fail the
    // ACN check, so it is genuinely non-company.
    let a2 = Entity::new(EntityKind::AbnAcn, "18123456789", 0.80, "s");
    let r =
        super::rules::rule_au_094_sole_trader_abn(&RuleContext::new(&[a1, a1_spaced, a2]), "s", 0);
    assert_eq!(r.len(), 1);
    assert!(r[0].description.contains("2 non-company"));
}

#[test]
fn au100_work_email_surfaces_employer_affiliation() {
    // A .com.au work email → commercial employer; a .gov.au → government.
    let e1 = Entity::new(EntityKind::Email, "j.citizen@acme-widgets.com.au", 0.7, "s");
    let e2 = Entity::new(EntityKind::Email, "officer@health.nsw.gov.au", 0.7, "s");
    let r = super::rules::rule_au_100_au_employer_affiliation(&RuleContext::new(&[e1, e2]), "s", 0);
    assert_eq!(r.len(), 2);
    assert!(r.iter().all(|c| c.rule_id == "AU-100"));
    let commercial = r
        .iter()
        .find(|c| c.description.contains("acme-widgets.com.au"))
        .expect("should succeed");
    assert!(commercial.description.contains("commercial"));
    assert!(commercial.description.contains("ABN/ACN"));
    let gov = r
        .iter()
        .find(|c| c.description.contains("health.nsw.gov.au"))
        .expect("should succeed");
    assert!(gov.description.contains("government"));
}

#[test]
fn au100_excludes_freemail_personal_and_foreign() {
    // Freemail, a personal .id.au domain, and a foreign .com must NOT fire.
    let gmail = Entity::new(EntityKind::Email, "subject@gmail.com", 0.8, "s");
    let personal = Entity::new(EntityKind::Email, "me@haigen.id.au", 0.8, "s");
    let foreign = Entity::new(EntityKind::Email, "x@example.com", 0.8, "s");
    assert!(
        super::rules::rule_au_100_au_employer_affiliation(
            &RuleContext::new(&[gmail, personal, foreign]),
            "s",
            0
        )
        .is_empty()
    );
}

#[test]
fn au100_dedups_multiple_emails_on_one_domain() {
    let e1 = Entity::new(EntityKind::Email, "a@acme.com.au", 0.7, "s");
    let e2 = Entity::new(EntityKind::Email, "b@acme.com.au", 0.7, "s");
    let r = super::rules::rule_au_100_au_employer_affiliation(&RuleContext::new(&[e1, e2]), "s", 0);
    assert_eq!(r.len(), 1);
    assert!(r[0].description.contains("2 email(s)"));
}

// ─── Geo convex footprint (AU-052) ───────────────────────────────────────────────────

#[cfg(test)]
fn coord_from(value: &str, source: &str) -> Entity {
    let mut e = Entity::new(EntityKind::Coordinates, value, 0.70, "s");
    e.add_evidence(Evidence::new(source, "geo sighting"));
    e
}

/// A coordinate tagged `hosting` (a CDN/datacenter edge) — infrastructure, not a
/// person, even if it carries several sources.
#[cfg(test)]
fn hosting_coord(value: &str, source: &str) -> Entity {
    let mut e = coord_from(value, source);
    e.tag(crate::core::tags::HOSTING);
    e
}

/// An Overpass map-POI coordinate: a camera / cell tower scraped near a
/// geolocated point, tagged `infra:*` and sourced only from `overpass`. Not a
/// sighting of the person.
#[cfg(test)]
fn overpass_poi(value: &str, infra_tag: &str) -> Entity {
    let mut e = Entity::new(EntityKind::Coordinates, value, 0.55, "s");
    e.add_evidence(Evidence::new("overpass", "nearby map feature"));
    e.tag(infra_tag);
    e
}
