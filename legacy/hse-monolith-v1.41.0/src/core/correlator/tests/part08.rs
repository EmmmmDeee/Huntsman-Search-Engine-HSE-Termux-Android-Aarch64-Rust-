#[test]
fn au047_links_on_password_entity_and_credits_unique_sources() {
    // The breach/stealer modules emit a leaked plaintext password as a
    // first-class `Password` entity (not the `username@host` `Credential`
    // string). AU-047 must link identities on a reused high-entropy `Password`
    // in its own right, and CREDIT cross-source spread: the same password seen
    // across ≥2 independent breach datasets is more individuating than one seen
    // inside a single dump, so it rises from High to Critical.
    let pw_entity = |sources: &[&str], emails: &[&str]| {
        let mut c = Entity::new(EntityKind::Password, "Tr0ub4dor&3xK9!q", 0.6, "scan");
        c.tag("credential");
        // One evidence record per (source, email): the importer stamps `source`
        // (See-Know) or `dbname` (OathNet) provenance onto each.
        for (i, em) in emails.iter().enumerate() {
            let src = sources.get(i).copied().unwrap_or("unknown");
            c.add_evidence(
                Evidence::new("see-know", "breach record")
                    .with_attr("email", *em)
                    .with_attr("source", src),
            );
        }
        c
    };
    let a = Entity::new(EntityKind::Email, "burner1@proton.me", 0.6, "scan");
    let b = Entity::new(EntityKind::Email, "real.name@gmail.com", 0.6, "scan");

    // Reused `Password` across 2 accounts but only ONE distinct source → High.
    let single_src = pw_entity(&["collection1", "collection1"], &[&a.value, &b.value]);
    let hits = super::rules::rule_au_047_reused_secret_identity(
        &RuleContext::new(&[single_src, a.clone(), b.clone()]),
        "scan",
        0,
    );
    assert_eq!(hits.len(), 1, "reused Password entity must link accounts");
    assert_eq!(
        hits[0].severity,
        super::Severity::High,
        "single-source reuse stays High"
    );

    // Same reused `Password` spread across TWO distinct sources → Critical, and
    // the description names the unique-source count.
    let cross_src = pw_entity(&["collection1", "antipublic"], &[&a.value, &b.value]);
    let hits = super::rules::rule_au_047_reused_secret_identity(
        &RuleContext::new(&[cross_src, a.clone(), b.clone()]),
        "scan",
        0,
    );
    assert_eq!(hits.len(), 1);
    assert_eq!(
        hits[0].severity,
        super::Severity::Critical,
        "cross-source reuse (≥2 independent datasets) is a near-certain controller link"
    );
    assert!(
        hits[0].description.contains("2 sources"),
        "description must surface the unique-source count, got: {}",
        hits[0].description
    );

    // A reused `Password` whose value is a salted hash is labelled a hash and
    // stays Critical (construction-unique), never demoted to the plaintext tier.
    let mut hashed = Entity::new(
        EntityKind::Password,
        "$2b$12$abcdefghijklmnopqrstuv",
        0.6,
        "scan",
    );
    hashed.tag("password-hash");
    for em in [&a.value, &b.value] {
        hashed.add_evidence(Evidence::new("oathnet", "breach").with_attr("email", em));
    }
    let hits = super::rules::rule_au_047_reused_secret_identity(
        &RuleContext::new(&[hashed, a, b]),
        "scan",
        0,
    );
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].severity, super::Severity::Critical);
    assert!(hits[0].description.contains("password hash"));
}

#[test]
fn au047_fires_on_two_accounts_combined_through_the_production_merge_path() {
    // The sibling test below hand-builds its fixture with two `add_evidence`
    // calls, which merely PUSH — so it holds two evidence records sharing one
    // `(source, summary)`. Production never reaches that shape: two rows of one
    // corpus mint two same-UID Password entities that `dispatch` folds with
    // `Entity::merge`, and `absorb` deduplicates evidence by `(source, summary)`,
    // collapsing them into ONE record whose colliding `username` values are
    // concatenated by `merge_evidence_attrs` into `"ghost_91; nightcrawler"`.
    //
    // AU-047 then reads that attribute WHOLE, so the two accounts fold to a
    // single canonical handle and the >=2-distinct-handle firing gate can never
    // be met — the Critical reused-secret link is dropped silently.
    let mk = |user: &str| {
        let mut e = Entity::new(
            EntityKind::Password,
            "$2b$12$usernamekeyedreuse00",
            0.6,
            "scan",
        );
        e.tag("password-hash");
        e.add_evidence(Evidence::new("oathnet", "Breach on ForumX").with_attr("username", user));
        e
    };
    let mut secret = mk("ghost_91");
    secret.merge(mk("nightcrawler"));

    // Pin the mechanism, so a future change to `absorb` retargets this test
    // rather than silently making it vacuous.
    assert_eq!(
        secret.evidence.len(),
        1,
        "absorb collapses same-(source, summary) records"
    );
    assert_eq!(
        secret.evidence[0].attributes.get("username").unwrap(),
        "ghost_91; nightcrawler",
        "colliding attribute values accumulate in the `a; b` form"
    );

    let u1 = Entity::new(EntityKind::Username, "ghost_91", 0.6, "scan");
    let u2 = Entity::new(EntityKind::Username, "nightcrawler", 0.6, "scan");
    let hits = super::rules::rule_au_047_reused_secret_identity(
        &RuleContext::new(&[secret.clone(), u1.clone(), u2.clone()]),
        "scan",
        0,
    );
    assert_eq!(
        hits.len(),
        1,
        "a unique hash shared by two accounts in ONE corpus must still link them"
    );
    assert!(
        hits[0].entity_uids.contains(&u1.uid) && hits[0].entity_uids.contains(&u2.uid),
        "both identities must be linked into the controller cluster"
    );
}

#[test]
fn au047_links_username_keyed_accounts_and_resists_single_record_self_link() {
    // Potentiation: a breach footprint keyed by USERNAME (username + hash, no
    // email — a very common dump shape) must link its accounts on a shared unique
    // secret exactly as an email-keyed one does, so reverse-searching a handle is
    // not a dead end. Previously AU-047 counted only distinct EMAILS to fire, so a
    // unique hash shared across two usernames went unlinked despite the rule's own
    // documented intent to link on "email/username".
    let mut by_username = Entity::new(
        EntityKind::Password,
        "$2b$12$usernamekeyedreuse00",
        0.6,
        "scan",
    );
    by_username.tag("password-hash");
    // Two DISTINCT usernames (no email anywhere) carry the identical salted hash.
    for u in ["ghost_91", "nightcrawler"] {
        by_username.add_evidence(Evidence::new("oathnet", "breach").with_attr("username", u));
    }
    let u1 = Entity::new(EntityKind::Username, "ghost_91", 0.6, "scan");
    let u2 = Entity::new(EntityKind::Username, "nightcrawler", 0.6, "scan");
    let hits = super::rules::rule_au_047_reused_secret_identity(
        &RuleContext::new(&[by_username.clone(), u1.clone(), u2.clone()]),
        "scan",
        0,
    );
    assert_eq!(
        hits.len(),
        1,
        "a unique hash across 2 distinct usernames must link them (username-keyed reverse search)"
    );
    assert_eq!(hits[0].severity, super::Severity::Critical);
    assert!(
        hits[0].entity_uids.contains(&u1.uid) && hits[0].entity_uids.contains(&u2.uid),
        "both username identities must be linked into the controller cluster"
    );

    // SAME-RECORD SAFETY: one record carrying an email and its MATCHING username
    // is ONE account — the handles collapse to a single canonical handle, so no
    // phantom "2 accounts" link is manufactured from a single record.
    let mut one_account = Entity::new(
        EntityKind::Password,
        "$2b$12$oneaccounttwoids0000",
        0.6,
        "scan",
    );
    one_account.tag("password-hash");
    one_account.add_evidence(
        Evidence::new("oathnet", "breach")
            .with_attr("email", "alice@example.com")
            .with_attr("username", "alice"),
    );
    let em = Entity::new(EntityKind::Email, "alice@example.com", 0.6, "scan");
    let un = Entity::new(EntityKind::Username, "alice", 0.6, "scan");
    assert!(
        super::rules::rule_au_047_reused_secret_identity(
            &RuleContext::new(&[one_account, em, un]),
            "scan",
            0
        )
        .is_empty(),
        "an email and its matching username from one record are one account, not a link"
    );

    // A unique hash shared across an email and a GENUINELY DIFFERENT username
    // (distinct handles) still links — the cross-representation reverse pivot.
    let mut cross = Entity::new(
        EntityKind::Password,
        "$2b$12$crossrepresentation0",
        0.6,
        "scan",
    );
    cross.tag("password-hash");
    cross.add_evidence(Evidence::new("oathnet", "breach").with_attr("email", "burner@proton.me"));
    cross.add_evidence(Evidence::new("oathnet", "breach").with_attr("username", "bob_work"));
    let e3 = Entity::new(EntityKind::Email, "burner@proton.me", 0.6, "scan");
    let u3 = Entity::new(EntityKind::Username, "bob_work", 0.6, "scan");
    let hits = super::rules::rule_au_047_reused_secret_identity(
        &RuleContext::new(&[cross, e3.clone(), u3.clone()]),
        "scan",
        0,
    );
    assert_eq!(
        hits.len(),
        1,
        "a unique hash across an email and a different-handle username must link them"
    );
    assert!(hits[0].entity_uids.contains(&e3.uid) && hits[0].entity_uids.contains(&u3.uid));
}

#[test]
fn au018_includes_full_member_set_so_finalize_supersedes_live() {
    use super::rules::rule_au_018_email_address_colocation;
    // Regression: a live "Haigen Bamford" scan persisted AU-018 twice
    // ("co-located with 6" and "with 9"). The rule sampled take(5) of a growing
    // address set, so the live and finalize rows had DISJOINT 5-address samples
    // that storage's superset-supersede dedup couldn't fold. The member set must
    // be the FULL set, so the (monotonically growing) finalize set is a superset
    // of the live set and supersedes it.
    let mut email = Entity::new(EntityKind::Email, "haigen@visionhomesqld.com.au", 0.70, "s");
    email.add_evidence(Evidence::new("see_know", "x"));
    let mut ents = vec![email];
    for i in 0..7 {
        let mut a = Entity::new(EntityKind::Address, format!("Suburb {i}, QLD"), 0.60, "s");
        a.tag("geoint");
        ents.push(a);
    }
    let out = rule_au_018_email_address_colocation(&RuleContext::new(&ents), "s", 0);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].rule_id, "AU-018");
    // 1 email + all 7 addresses — not capped at take(5) — so a later superset
    // (more addresses) strictly contains this set and supersedes it in storage.
    assert_eq!(
        out[0].entity_uids.len(),
        8,
        "full member set, not a take(5) sample: {:?}",
        out[0].entity_uids
    );
}

#[test]
fn au018_excludes_role_mailboxes_from_the_identity_location_link() {
    use super::rules::rule_au_018_email_address_colocation;
    // A role/provider mailbox (a shared registrar/abuse desk) is not the
    // subject's identity, so co-locating it with the subject's address forges a
    // false identity↔location linkage — the same false positive AU-001 was
    // patched for (`abuse@godaddy.com`). AU-018 must exclude it, exactly as
    // AU-001/AU-045/AU-002 already do.
    let mut addr = Entity::new(EntityKind::Address, "Booroobin, QLD", 0.80, "s");
    addr.tag("geoint");

    // Role mailbox alone with the address must NOT fire — even at high confidence.
    let role = Entity::new(EntityKind::Email, "abuse@godaddy.com", 0.90, "s");
    let only_role = vec![role, addr.clone()];
    let out = rule_au_018_email_address_colocation(&RuleContext::new(&only_role), "s", 0);
    assert!(
        out.is_empty(),
        "a role mailbox must not co-locate to a person's address: {out:?}"
    );

    // A genuine personal email in the same scene still fires (no false negative).
    let person = Entity::new(EntityKind::Email, "haigen.bamford@gmail.com", 0.90, "s");
    let with_person = vec![
        person,
        Entity::new(EntityKind::Email, "abuse@godaddy.com", 0.90, "s"),
        addr,
    ];
    let out = rule_au_018_email_address_colocation(&RuleContext::new(&with_person), "s", 0);
    assert_eq!(out.len(), 1, "the personal email still links: {out:?}");
    assert_eq!(out[0].rule_id, "AU-018");
    // The role mailbox is excluded from the member set, so exactly 1 email + 1
    // address are linked, not 2 emails.
    assert_eq!(
        out[0].entity_uids.len(),
        2,
        "only the personal email + the address, role mailbox dropped: {:?}",
        out[0].entity_uids
    );
}

#[test]
fn au027_chains_only_the_dominant_coherent_location() {
    use super::rules::rule_au_027_address_coordinates_chain;
    // Regression from a deep "Haigen Bamford" scan: a Brisbane subject also
    // picked up a Cairns coordinate ~1700 km away, and AU-027 fused all of them
    // into one continent-spanning "validated chain". It must anchor on the
    // dominant coherent cluster (Brisbane) and exclude the far Cairns point.
    let coord = |v: &str| {
        let mut e = Entity::new(EntityKind::Coordinates, v, 0.75, "scan");
        e.tag("geocoded");
        // Anchoring source (reverse-geocoded from the address) so the coordinate
        // is person-anchored, not infrastructure geo.
        e.add_evidence(Evidence::new("geocode", "reverse-geocoded"));
        e
    };
    let mut brisbane_addr = Entity::new(EntityKind::Address, "Brisbane, QLD", 0.80, "scan");
    brisbane_addr.tag("geoint");
    let cairns_uid = coord("-16.9186,145.7781").uid;
    let ents = vec![
        brisbane_addr,
        coord("-27.4698,153.0251"), // Brisbane CBD
        coord("-27.4690,153.0235"), // Brisbane CBD (~0.2 km away)
        coord("-16.9186,145.7781"), // Cairns, ~1700 km north
    ];
    let out = rule_au_027_address_coordinates_chain(&RuleContext::new(&ents), "scan", 0);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].rule_id, "AU-027");
    // Dominant cluster = Brisbane's 2 coords, anchored near Brisbane; Cairns out.
    assert!(
        out[0].description.contains("2 coordinate set(s)"),
        "dominant cluster only: {}",
        out[0].description
    );
    assert!(
        out[0].description.contains("-27.4"),
        "anchored near Brisbane: {}",
        out[0].description
    );
    assert!(
        !out[0].entity_uids.contains(&cairns_uid),
        "the far Cairns coordinate must not be in the chain"
    );
}

#[test]
fn au027_never_anchors_on_the_radar_sentinel() {
    use super::rules::rule_au_027_address_coordinates_chain;
    // `hse radar` seeds every sweep with a sentinel Coordinates entity at (0,0),
    // minted with `seed, subject` tags and no `geocoded`/`geoint` tag of its own.
    // If it were the ONLY cluster it would win "dominant" by default (max_by on
    // a single-element cluster list) and anchor a bogus AU-027 chain at null
    // island instead of correctly finding no coherent chain at all.
    let mut addr = Entity::new(EntityKind::Address, "Brisbane, QLD", 0.80, "scan");
    addr.tag("geoint");
    let mut sentinel = Entity::new(
        EntityKind::Coordinates,
        crate::core::scan::RADAR_SENTINEL_COORD_RAW,
        0.90,
        "scan",
    );
    sentinel.tag("seed");
    sentinel.tag("subject");
    let ents = vec![addr, sentinel];
    let out = rule_au_027_address_coordinates_chain(&RuleContext::new(&ents), "scan", 0);
    assert!(
        out.is_empty(),
        "the radar sentinel must never anchor an AU-027 chain: {out:?}"
    );
}

#[test]
fn au027_excludes_infrastructure_coordinates() {
    use super::rules::rule_au_027_address_coordinates_chain;
    // The geo-tag gate is an OR the ADDRESS satisfies alone, so datacentre
    // coordinates could ride in and anchor the chain, fusing the host's location
    // with the subject's real address. Hosting/IP-geo coordinates must be
    // excluded; person-anchored coordinates at real spots still chain (control).
    let mut addr = Entity::new(EntityKind::Address, "Brisbane, QLD", 0.80, "scan");
    addr.tag("geoint");

    let hosting = |v: &str| {
        let mut e = Entity::new(EntityKind::Coordinates, v, 0.80, "scan");
        e.tag("geocoded");
        e.tag(crate::core::tags::HOSTING);
        e
    };
    let out = rule_au_027_address_coordinates_chain(
        &RuleContext::new(&[
            addr.clone(),
            hosting("-33.8688,151.2093"),
            hosting("-33.8690,151.2100"),
        ]),
        "scan",
        0,
    );
    assert!(
        out.is_empty(),
        "hosting datacentre coordinates must not anchor an AU-027 chain: {out:?}"
    );

    // Control: person-anchored (geocoded) coordinates DO chain with the address.
    let anchored = |v: &str| {
        let mut e = Entity::new(EntityKind::Coordinates, v, 0.80, "scan");
        e.tag("geocoded");
        e.add_evidence(Evidence::new("geocode", "reverse-geocoded"));
        e
    };
    let out2 = rule_au_027_address_coordinates_chain(
        &RuleContext::new(&[
            addr,
            anchored("-27.4698,153.0251"),
            anchored("-27.4690,153.0235"),
        ]),
        "scan",
        0,
    );
    assert_eq!(
        out2.len(),
        1,
        "anchored coordinates still chain with the address"
    );
    assert_eq!(out2[0].rule_id, "AU-027");
}

#[test]
fn au027_excludes_infrastructure_addresses() {
    use super::rules::rule_au_027_address_coordinates_chain;
    // Mirrors au027_excludes_infrastructure_coordinates, but for the ADDRESS
    // side: unlike `coords` (filtered on `!is_infrastructure_geo` above), the
    // `addresses` collection has no such filter, so a WHOIS-registrant address
    // — a company's filing/privacy address, not the subject's home — rides
    // into `entity_uids` unfiltered. The registrant address here has no
    // `geoint`/`reverse-geocoded`/`validated` tag of its own and no
    // geographic relationship to the coordinates (a different city
    // entirely); only the coordinates' `geocoded` tag satisfies the rule's
    // geo-tag gate, so a purely-infrastructure address with zero real
    // grounding still gets asserted as part of a "validated geolocation
    // chain".
    let mut registrant_addr = Entity::new(
        EntityKind::Address,
        "123 Corporate Ave, Melbourne, VIC",
        0.60,
        "scan",
    );
    registrant_addr.tag(crate::core::tags::REGISTRANT);
    let registrant_uid = registrant_addr.uid.clone();

    let anchored = |v: &str| {
        let mut e = Entity::new(EntityKind::Coordinates, v, 0.80, "scan");
        e.tag("geocoded");
        e.add_evidence(Evidence::new("geocode", "reverse-geocoded"));
        e
    };

    let out = rule_au_027_address_coordinates_chain(
        &RuleContext::new(&[
            registrant_addr,
            anchored("-27.4698,153.0251"), // Brisbane — unrelated to the Melbourne registrant address
            anchored("-27.4690,153.0235"),
        ]),
        "scan",
        0,
    );
    assert!(
        out.is_empty() || !out[0].entity_uids.contains(&registrant_uid),
        "a WHOIS-registrant address must not be fused into an AU-027 chain: {out:?}"
    );
}

#[test]
fn au048_links_accounts_sharing_a_public_key() {
    // A public key published by two accounts → cryptographic proof of one
    // controller (same private key). Single account → no link.
    let key = |fp: &str, logins: &[&str]| {
        let mut e = Entity::new(EntityKind::Credential, fp, 0.85, "scan");
        e.tag("ssh-key");
        for l in logins {
            e.add_evidence(
                Evidence::new("github_user", format!("SSH key published by @{l}"))
                    .with_attr("github_login", *l),
            );
        }
        e
    };
    let a = Entity::new(EntityKind::Username, "ghost91", 0.6, "scan");
    let b = Entity::new(EntityKind::Username, "jsmith_work", 0.6, "scan");

    let shared = key("ssh:deadbeefcafef00d", &["ghost91", "jsmith_work"]);
    let hits = super::rules::rule_au_048_shared_public_key(
        &RuleContext::new(&[shared.clone(), a.clone(), b.clone()]),
        "scan",
        0,
    );
    assert_eq!(hits.len(), 1, "a key on two accounts must link them");
    assert_eq!(hits[0].rule_id, "AU-048");
    assert_eq!(hits[0].severity, super::Severity::Critical);
    assert!(hits[0].entity_uids.contains(&a.uid) && hits[0].entity_uids.contains(&b.uid));

    // A key on a single account is not a link; a non-key Credential is ignored.
    let solo = key("ssh:only0neacct", &["ghost91"]);
    assert!(
        super::rules::rule_au_048_shared_public_key(
            &RuleContext::new(&[solo, a.clone()]),
            "scan",
            0
        )
        .is_empty()
    );
    let mut pw = Entity::new(EntityKind::Credential, "$2a$10$x", 0.6, "scan");
    pw.add_evidence(Evidence::new("import", "x").with_attr("github_login", "a"));
    pw.add_evidence(Evidence::new("import", "y").with_attr("github_login", "b"));
    assert!(
        super::rules::rule_au_048_shared_public_key(&RuleContext::new(&[pw]), "scan", 0).is_empty(),
        "AU-048 only fires on key-tagged credentials"
    );

    // ONE account whose key evidence carries both its login and its email is
    // two identifier strings but a single controller — it must NOT fire a
    // Critical "controls 2 accounts". The canonical-handle fold collapses
    // "alice" and "alice@x.com" to one handle.
    let mut same_acct = Entity::new(EntityKind::Credential, "ssh:1acct2attrs", 0.85, "scan");
    same_acct.tag("ssh-key");
    same_acct.add_evidence(
        Evidence::new("github_user", "SSH key published by @alice")
            .with_attr("github_login", "alice")
            .with_attr("email", "alice@x.com"),
    );
    assert!(
        super::rules::rule_au_048_shared_public_key(&RuleContext::new(&[same_acct]), "scan", 0)
            .is_empty(),
        "login + email of ONE account must not count as two accounts"
    );

    // A genuine cross-identifier link (a login and a DIFFERENT person-handle
    // email sharing one key) still fires.
    let mut cross = Entity::new(EntityKind::Credential, "ssh:2realaccts", 0.85, "scan");
    cross.tag("pgp-key");
    cross.add_evidence(
        Evidence::new("github_user", "key published by @alice").with_attr("github_login", "alice"),
    );
    cross.add_evidence(
        Evidence::new("pgp", "key bound to bob@x.com").with_attr("email", "bob@x.com"),
    );
    let hits = super::rules::rule_au_048_shared_public_key(&RuleContext::new(&[cross]), "scan", 0);
    assert_eq!(hits.len(), 1, "distinct handles sharing a key must link");
}

#[test]
fn au048_reports_distinct_controllers_not_identifier_spellings() {
    // A key whose evidence names alice under BOTH her login and her email, PLUS a
    // second owner bob = 3 identifier spellings but only 2 distinct account owners
    // (alice, bob). The finding must report "controls 2 accounts", not 3 — the
    // count is the distinct-controller measure the guard already uses (which treats
    // "alice" + "alice@x.com" as ONE account), so reporting the spelling count
    // over-states control by the rule's own definition.
    let mut key = Entity::new(EntityKind::Credential, "ssh:count-check", 0.9, "scan");
    key.tag("ssh-key");
    key.add_evidence(
        Evidence::new("github_user", "SSH key published by @alice")
            .with_attr("github_login", "alice")
            .with_attr("email", "alice@x.com"),
    );
    key.add_evidence(
        Evidence::new("github_user", "same key published by @bob").with_attr("github_login", "bob"),
    );
    let hits = super::rules::rule_au_048_shared_public_key(&RuleContext::new(&[key]), "scan", 0);
    assert_eq!(hits.len(), 1, "two distinct owners sharing a key must link");
    assert!(
        hits[0].description.contains("controls 2 accounts"),
        "must report 2 distinct account owners, not 3 identifier spellings: {}",
        hits[0].description
    );
}

#[test]
fn au048_discloses_when_the_account_list_is_truncated() {
    // The description enumerates at most 6 accounts, but a key genuinely
    // shared across MANY accounts (a stolen/reused keypair pushed to several
    // profiles) must say so — not silently cut the list with no indication,
    // the same "(+N more)" convention AU-076 already uses via join_capped.
    let mut key = Entity::new(EntityKind::Credential, "ssh:widelyshared", 0.85, "scan");
    key.tag("ssh-key");
    for i in 0..9 {
        key.add_evidence(
            Evidence::new("github_user", format!("SSH key published by @acct{i}"))
                .with_attr("github_login", format!("acct{i}")),
        );
    }
    let hits = super::rules::rule_au_048_shared_public_key(&RuleContext::new(&[key]), "scan", 0);
    assert_eq!(hits.len(), 1);
    assert!(
        hits[0].description.contains("9 accounts"),
        "the true total must still be stated: {}",
        hits[0].description
    );
    assert!(
        hits[0].description.contains("(+3 more)"),
        "the enumerated (top-6) list must disclose the 3 it omitted: {}",
        hits[0].description
    );
}

// ─── Associates / household family (AU-049 … AU-051) ─────────────────────────

#[cfg(test)]
fn person_at(name: &str, addr: &str) -> Entity {
    let mut e = Entity::new(EntityKind::Person, name, 0.62, "s");
    e.add_evidence(Evidence::new("import:dossier", "breach entry").with_attr("address", addr));
    e
}

#[cfg(test)]
fn person_with_phone(name: &str, phone: &str) -> Entity {
    let mut e = Entity::new(EntityKind::Person, name, 0.62, "s");
    e.add_evidence(Evidence::new("import:dossier", "breach entry").with_attr("phone", phone));
    e
}

#[test]
fn au049_fires_on_two_people_one_residence() {
    // Two distinct people whose breach records carry the same specific residence
    // (in inconsistent formatting) form one household cluster.
    let ents = vec![
        person_at("Jordan Meyers", "123 Main St, Springfield, IL"),
        person_at("Dana Meyers", "123 Main St Springfield IL"),
    ];
    let hits =
        super::rules::rule_au_049_shared_address_association(&RuleContext::new(&ents), "s", 0);
    assert_eq!(hits.len(), 1, "one household cluster expected");
    assert_eq!(hits[0].rule_id, "AU-049");
    assert!(hits[0].description.contains("2 people"));
}

#[test]
fn au049_unit_address_and_street_number_are_not_one_household() {
    // Regression (address unit separator): `1/2 Oak Street` (unit 1 of number 2)
    // and `12 Oak Street` (number 12) are DIFFERENT dwellings. Deleting `/` in
    // normalisation collapsed them onto one key and fired AU-049 — a fabricated
    // household between strangers. They must not group.
    let strangers = vec![
        person_at("Jordan Meyers", "1/2 Oak Street, Sydney NSW 2000"),
        person_at("Dana Lin", "12 Oak Street, Sydney NSW 2000"),
    ];
    assert!(
        super::rules::rule_au_049_shared_address_association(&RuleContext::new(&strangers), "s", 0)
            .is_empty(),
        "a unit address and a street number are not one household"
    );
    // Control: two people genuinely at the SAME unit still form one household —
    // the folded unit form remains a valid, groupable residence key.
    let cohabitants = vec![
        person_at("Jordan Meyers", "1/2 Oak Street, Sydney NSW 2000"),
        person_at("Dana Meyers", "1/2 oak street sydney nsw 2000"),
    ];
    let hits = super::rules::rule_au_049_shared_address_association(
        &RuleContext::new(&cohabitants),
        "s",
        0,
    );
    assert_eq!(hits.len(), 1, "same unit is one household");
    assert_eq!(hits[0].rule_id, "AU-049");
}

#[test]
fn au049_single_person_and_region_only_do_not_fire() {
    let one = vec![person_at("Jordan Meyers", "123 Main St, Springfield, IL")];
    assert!(
        super::rules::rule_au_049_shared_address_association(&RuleContext::new(&one), "s", 0)
            .is_empty()
    );
    // A bare region shared by strangers must never fuse a household.
    let region = vec![
        person_at("Jordan Meyers", "California"),
        person_at("Unrelated Stranger", "California"),
    ];
    assert!(
        super::rules::rule_au_049_shared_address_association(&RuleContext::new(&region), "s", 0)
            .is_empty()
    );
}

#[test]
fn au049_one_persons_two_emails_is_not_a_household() {
    // Two emails + one named person at an address is the SAME person's handles,
    // not an association — must not fire.
    let mut e1 = Entity::new(EntityKind::Email, "jordan@gmail.com", 0.72, "s");
    e1.add_evidence(
        Evidence::new("import:dossier", "e").with_attr("address", "123 Main St, Springfield"),
    );
    let mut e2 = Entity::new(EntityKind::Email, "j.meyers@work.com", 0.72, "s");
    e2.add_evidence(
        Evidence::new("import:dossier", "e").with_attr("address", "123 Main St, Springfield"),
    );
    let ents = vec![
        person_at("Jordan Meyers", "123 Main St, Springfield"),
        e1,
        e2,
    ];
    assert!(
        super::rules::rule_au_049_shared_address_association(&RuleContext::new(&ents), "s", 0)
            .is_empty()
    );
}

#[test]
fn au049_references_address_node_and_reachable_handles() {
    let mut email = Entity::new(EntityKind::Email, "dana@gmail.com", 0.72, "s");
    email.add_evidence(
        Evidence::new("import:dossier", "e").with_attr("address", "123 Main St, Springfield"),
    );
    let addr = Entity::new(EntityKind::Address, "123 Main St, Springfield", 0.58, "s");
    let addr_uid = addr.uid.clone();
    let email_uid = email.uid.clone();
    let ents = vec![
        person_at("Jordan Meyers", "123 Main St, Springfield"),
        person_at("Dana Meyers", "123 Main St, Springfield"),
        email,
        addr,
    ];
    let hits =
        super::rules::rule_au_049_shared_address_association(&RuleContext::new(&ents), "s", 0);
    assert_eq!(hits.len(), 1);
    assert!(
        hits[0].entity_uids.contains(&addr_uid),
        "address node referenced"
    );
    assert!(
        hits[0].entity_uids.contains(&email_uid),
        "reachable handle referenced"
    );
}

#[test]
fn au049_references_every_reachable_handle_not_a_capped_eight() {
    // Full-fidelity: a large household / share-house can have more than 8 associated
    // email/phone handles at one residence; the correlation's entity_uids (the actual
    // linkage it asserts) must reference EVERY reachable handle, not a silent
    // bounded-8 subset. Fail-before: capped at 8.
    let addr = "123 Main St, Springfield";
    let mut ents = vec![
        person_at("Jordan Meyers", addr),
        person_at("Dana Meyers", addr),
        Entity::new(EntityKind::Address, addr, 0.58, "s"),
    ];
    let mut handle_uids: Vec<String> = Vec::new();
    for i in 0..10 {
        let mut email = Entity::new(
            EntityKind::Email,
            format!("user{i:02}@example.com"),
            0.72,
            "s",
        );
        email.add_evidence(Evidence::new("import:dossier", "e").with_attr("address", addr));
        handle_uids.push(email.uid.clone());
        ents.push(email);
    }
    let hits =
        super::rules::rule_au_049_shared_address_association(&RuleContext::new(&ents), "s", 0);
    assert_eq!(hits.len(), 1);
    let referenced = handle_uids
        .iter()
        .filter(|u| hits[0].entity_uids.contains(u))
        .count();
    assert_eq!(
        referenced, 10,
        "every reachable handle must be referenced, not capped at 8; got {referenced}"
    );
}

#[test]
fn au050_shared_phone_links_two_people_and_rejects_placeholders() {
    // Formatting variants of the same line collapse to one association.
    let ents = vec![
        person_with_phone("Jordan Meyers", "+1 (415) 555-0100"),
        person_with_phone("Casey Lin", "14155550100"),
    ];
    let hits = super::rules::rule_au_050_shared_phone_association(&RuleContext::new(&ents), "s", 0);
    assert_eq!(
        hits.len(),
        1,
        "formatting variants must collapse to one line"
    );
    assert_eq!(hits[0].rule_id, "AU-050");
    assert!(hits[0].description.contains("0100"), "masked tail shown");

    // All-same-digit placeholder is not a subscriber line.
    let placeholder = vec![
        person_with_phone("Jordan Meyers", "+00000000000"),
        person_with_phone("Casey Lin", "+00000000000"),
    ];
    assert!(
        super::rules::rule_au_050_shared_phone_association(&RuleContext::new(&placeholder), "s", 0)
            .is_empty()
    );
}
