use super::*;

    #[test]
    fn split_uid_variants() {
        assert_eq!(
            split_uid("Jordan Avery <matt@example.com>"),
            (Some("Jordan Avery"), Some("matt@example.com"))
        );
        assert_eq!(
            split_uid("<only@example.com>"),
            (None, Some("only@example.com"))
        );
        assert_eq!(
            split_uid("bare@example.com"),
            (None, Some("bare@example.com"))
        );
        assert_eq!(
            split_uid("No Address Here"),
            (Some("No Address Here"), None)
        );
    }

    #[test]
    fn extract_pulls_name_and_alternate_emails() {
        // Realistic HKP machine-readable index: one key, two UIDs (the queried
        // address + an alternate), URL-encoded as keyservers return them.
        let body = "info:1:1\n\
            pub:ABCDEF0123456789ABCDEF0123456789ABCDEF01:1:4096:1500000000::\n\
            uid:Jordan%20Avery%20%3Cmatt%40example.com%3E:1500000000::\n\
            uid:Jordan%20Avery%20%3Cm.avery%40work.com%3E:1500000000::\n";
        let mut r = ModuleResult::new();
        extract(body, "matt@example.com", "scan", &mut r);

        let has = |k: EntityKind, v: &str| r.entities.iter().any(|e| e.kind == k && e.value == v);
        // Owner name surfaced once (deduped across both UIDs); it rides the
        // query-matching UID, so it stays first-class.
        assert!(has(EntityKind::Person, "Jordan Avery"));
        assert_eq!(
            r.entities
                .iter()
                .filter(|e| e.kind == EntityKind::Person)
                .count(),
            1
        );
        // The ALTERNATE email is surfaced as a lead; the queried one is not
        // re-emitted. REQ-PGP-001: the alternate is a keyserver-unverified
        // self-assertion, so it is down-tiered and tagged `pgp-unverified-uid`,
        // never the `pgp-linked` tier AU-042 fuses into a proven same-owner.
        let alt = r
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Email && e.value == "m.avery@work.com")
            .expect("alternate address surfaced as a lead");
        assert!(alt.confidence <= confidence::TENTATIVE);
        assert!(alt.has_tag("pgp-unverified-uid") && !alt.has_tag("pgp-linked"));
        assert!(!has(EntityKind::Email, "matt@example.com"));
        // Evidence carries the key fingerprint.
        assert!(r.entities.iter().all(|e| {
            e.evidence
                .iter()
                .any(|ev| ev.attributes.contains_key("key_fingerprint"))
        }));
    }

    #[test]
    fn extract_mints_correlatable_pgp_key_credential() {
        // The key fingerprint becomes a Credential `pgp:<fp>` tagged `pgp-key`,
        // the artifact AU-048 links across accounts (the PGP analogue of
        // github_user's ssh-key). REQ-PGP-001: only the QUERY-MATCHED email is
        // bound as a controller — a co-resident UID's other address is a
        // keyserver-unverified self-assertion and must not enter the AU-048
        // "proof of control" set. Genuine cross-account linkage instead comes
        // from a SEPARATE seed independently matching this same key, which the
        // fingerprinted value dedups together.
        let body = "info:1:1\n\
            pub:ABCDEF0123456789ABCDEF0123456789ABCDEF01:1:4096:1500000000::\n\
            uid:Jordan%20Avery%20%3Cmatt%40example.com%3E:1500000000::\n\
            uid:Jordan%20Avery%20%3Cm.avery%40work.com%3E:1500000000::\n";
        let mut r = ModuleResult::new();
        extract(body, "matt@example.com", "scan", &mut r);

        let cred = r
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Credential)
            .expect("PGP key minted as a Credential");
        // Stable, lowercased value so the same key dedups across scans.
        assert_eq!(cred.value, "pgp:abcdef0123456789abcdef0123456789abcdef01");
        assert!(cred.has_tag("pgp-key") && cred.has_tag("public-key") && cred.has_tag("pgp"));
        let emails: std::collections::BTreeSet<&str> = cred
            .evidence
            .iter()
            .filter_map(|ev| ev.attributes.get("email").map(String::as_str))
            .collect();
        // The queried email is bound (the key matched it)...
        assert!(emails.contains("matt@example.com"));
        // ...but the unverified co-resident UID email is NOT — that binding was
        // exactly the single-scan AU-048 fabrication REQ-PGP-001 removed.
        assert!(
            !emails.contains("m.avery@work.com"),
            "an unverified co-resident UID email must not be an AU-048 controller: {emails:?}"
        );
    }

    #[test]
    fn extract_is_quiet_on_no_keys() {
        let mut r = ModuleResult::new();
        extract("info:1:0\n", "x@y.com", "scan", &mut r);
        assert!(r.entities.is_empty());
    }

    #[test]
    fn module_metadata() {
        let m = Pgp;
        assert_eq!(m.name(), "pgp");
        assert!(!m.description().is_empty());
        assert!(m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "y.com")));
        assert!(!m.attack_techniques().is_empty());
    }

    #[test]
    fn extract_deduplicates_person_across_uids() {
        // Two UIDs carry the same name — Person must be emitted exactly once.
        let body = "info:1:1\n\
            pub:ABCDEF0123456789ABCDEF0123456789ABCDEF01:1:4096:1500000000::\n\
            uid:Jordan%20Avery%20%3Ca%40example.com%3E:1500000000::\n\
            uid:Jordan%20Avery%20%3Cb%40example.com%3E:1500000000::\n";
        let mut r = ModuleResult::new();
        extract(body, "a@example.com", "scan", &mut r);
        assert_eq!(
            r.entities.iter().filter(|e| e.kind == EntityKind::Person).count(),
            1,
            "duplicate name across UIDs must be emitted once"
        );
    }

    #[test]
    fn extract_ignores_a_second_key_whose_uids_never_name_the_queried_email() {
        // Regression: an HKP index response can carry more than one `pub:`
        // block. If a keyserver ever returns an unrelated key alongside the
        // real match (fuzzy fallback despite `exact=on`, keyserver bug), NONE
        // of that second key's own UIDs name the queried address — its name
        // and alternate email must not be misattributed to this query.
        let body = "info:1:2\n\
            pub:ABCDEF0123456789ABCDEF0123456789ABCDEF01:1:4096:1500000000::\n\
            uid:Jordan%20Avery%20%3Cmatt%40example.com%3E:1500000000::\n\
            pub:1111111111111111111111111111111111111111:1:4096:1500000000::\n\
            uid:Someone%20Else%20%3Cstranger%40other.com%3E:1500000000::\n";
        let mut r = ModuleResult::new();
        extract(body, "matt@example.com", "scan", &mut r);

        assert!(
            r.entities
                .iter()
                .any(|e| e.kind == EntityKind::Person && e.value == "Jordan Avery"),
            "the actually-matching key's owner must still surface"
        );
        assert!(
            !r.entities
                .iter()
                .any(|e| e.value.contains("Someone Else") || e.value.contains("stranger")),
            "an unrelated key's name/email must not be attributed to this query: {:?}",
            r.entities
        );
        assert!(
            r.entities
                .iter()
                .all(|e| e.kind != EntityKind::Credential
                    || e.value == "pgp:abcdef0123456789abcdef0123456789abcdef01"),
            "the unrelated key must not be minted as a Credential either: {:?}",
            r.entities
        );
    }

#[test]
fn a_forged_co_resident_uid_never_produces_corroborated_identity() {
    // REQ-PGP-001 (CRITICAL): keyserver.ubuntu.com does not verify that a UID's
    // email is owned by the key holder — anyone can self-certify ANY UID onto
    // their own key with zero proof. So a key that (legitimately) names the
    // queried address in one UID, but carries a SECOND UID naming a different,
    // attacker-chosen identity, must NOT turn that second UID into first-class,
    // correlator-feeding evidence about the query. Before this fix the second
    // UID minted a `confidence::HIGH` Person, a `HIGH_PLUS` `pgp-linked` Email,
    // and — worst — its address was bound into the `pgp:<fp>` Credential's
    // `email` evidence, which AU-048 reads to fabricate a Critical
    // "cryptographic proof of control" between the victim and an identity the
    // attacker invented from nothing.
    let body = "info:1:1\n\
        pub:ABCDEF0123456789ABCDEF0123456789ABCDEF01:1:4096:1500000000::\n\
        uid:Real%20Owner%20%3Cvictim%40example.com%3E:1500000000::\n\
        uid:Attacker%20Alias%20%3Calt%40attacker.tld%3E:1500000000::\n";
    let mut r = ModuleResult::new();
    extract(body, "victim@example.com", "scan", &mut r);

    // The queried UID's owner name is still recovered at full confidence — the
    // module's legitimate purpose is untouched.
    let owner = r
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Person && e.value == "Real Owner")
        .expect("the queried UID's owner name stays first-class");
    assert!(owner.confidence >= confidence::HIGH);
    assert!(!owner.has_tag("pgp-unverified-uid"));

    // The attacker's co-resident UID name is NOT first-class: if surfaced at all
    // it is a clearly-labelled, down-tiered lead, never HIGH and never able to
    // masquerade as the verified owner.
    if let Some(alias) = r
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Person && e.value == "Attacker Alias")
    {
        assert!(
            alias.confidence <= confidence::TENTATIVE,
            "an unverified co-resident UID name must be down-tiered, got {}",
            alias.confidence
        );
        assert!(alias.has_tag("pgp-unverified-uid"));
    }

    // The attacker's alternate address is likewise a down-tiered, unverified
    // lead — never the HIGH_PLUS `pgp-linked` entity AU-042 fuses into a
    // "proven same owner".
    if let Some(alt) = r
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Email && e.value == "alt@attacker.tld")
    {
        assert!(
            alt.confidence <= confidence::TENTATIVE,
            "an unverified co-resident UID email must be down-tiered, got {}",
            alt.confidence
        );
        assert!(alt.has_tag("pgp-unverified-uid"));
        assert!(
            !alt.has_tag("pgp-linked"),
            "must not carry the `pgp-linked` tag AU-042 reads as verified same-owner evidence"
        );
    }

    // The decisive lock: the Credential AU-048 reads must bind ONLY the queried
    // email. An unverified co-resident UID email in this controller set is
    // exactly the fabricated "cryptographic proof of control" this fix prevents.
    let cred = r
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Credential)
        .expect("the key is still minted as a correlatable Credential");
    let bound: std::collections::BTreeSet<&str> = cred
        .evidence
        .iter()
        .filter_map(|ev| ev.attributes.get("email").map(String::as_str))
        .collect();
    assert!(
        bound.contains("victim@example.com"),
        "the queried email is bound (the key matched it): {bound:?}"
    );
    assert!(
        !bound.contains("alt@attacker.tld"),
        "an unverified co-resident UID email must NOT be bound as an AU-048 \
         controller — that is the fabricated cryptographic proof of control: {bound:?}"
    );
}
