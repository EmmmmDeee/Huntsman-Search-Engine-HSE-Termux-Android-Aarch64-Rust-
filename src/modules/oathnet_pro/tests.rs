use super::*;

    #[test]
    fn extract_breach_entities_characterization() {
        use serde_json::json;
        let item = json!({
            "email": "jordan.meyer@example.com",
            "username": "jmeyer",
            "phone_number": "15551234567",
            "ip": "8.8.8.8",
            "country": "US",
            "discordid": "123456789012345678",
            "email_domain": "example.com",
            "password_hash": "0123456789abcdef0123456789abcdef",
            "source": "TestDB"
        });
        let mut seen = HashSet::new();
        let mut result = ModuleResult::new();
        // Target matches the email -> is_target_row = true (no "candidate" tags).
        extract_breach_entities(
            &item,
            "jordan.meyer@example.com",
            "scan",
            "oathnet.org:test",
            &mut seen,
            &mut result,
        );

        // Exact, ordered tag vectors — locks byte-stable serialization across
        // the refactor (a reordered tag would fail here).
        let tags_of = |k: EntityKind, needle: &str| -> Vec<String> {
            result
                .entities
                .iter()
                .find(|e| e.kind == k && e.value.contains(needle))
                .map(|e| e.tags.clone())
                .unwrap_or_default()
        };
        assert_eq!(
            tags_of(EntityKind::Email, "jordan.meyer"),
            ["breach", "oathnet-pro"]
        );
        assert_eq!(
            tags_of(EntityKind::Username, "jmeyer"),
            ["breach", "oathnet-pro"]
        );
        assert_eq!(
            tags_of(EntityKind::Phone, "15551234567"),
            ["breach", "oathnet-pro"]
        );
        assert_eq!(
            tags_of(EntityKind::IpAddress, "8.8.8.8"),
            ["breach", "oathnet-pro", "geolocation-lead"]
        );
        assert_eq!(
            tags_of(EntityKind::Username, "discord:"),
            ["breach", "oathnet-pro", "discord"]
        );
        assert_eq!(
            tags_of(EntityKind::Domain, "example.com"),
            ["breach", "oathnet-pro", "email-domain"]
        );
        assert_eq!(
            tags_of(EntityKind::Password, "0123456789"),
            ["breach", "oathnet-pro", "password-hash"]
        );
    }

    #[test]
    fn extract_stealer_entities_characterization() {
        use serde_json::json;
        let item = json!({
            "email": ["victim@example.com"],
            "username": "loginuser@example.com",
            "domain": ["testsite.com"],
            "url": "https://login.site",
            "password": "secret"
        });
        let mut seen = HashSet::new();
        let mut result = ModuleResult::new();
        extract_stealer_entities(&item, "scan", "oathnet.org:test", &mut seen, &mut result);

        let tags_of = |k: EntityKind, needle: &str| -> Vec<String> {
            result
                .entities
                .iter()
                .find(|e| e.kind == k && e.value.contains(needle))
                .map(|e| e.tags.clone())
                .unwrap_or_default()
        };
        // The email-array kind carries `breach`; the login-email/domain/credential
        // kinds do NOT (they are credential context, not leaked PII). Exact order.
        assert_eq!(
            tags_of(EntityKind::Email, "victim@example.com"),
            ["breach", "oathnet-pro", "stealer"]
        );
        assert_eq!(
            tags_of(EntityKind::Email, "loginuser@example.com"),
            ["oathnet-pro", "stealer", "stealer-login"]
        );
        assert_eq!(
            tags_of(EntityKind::Domain, "testsite.com"),
            ["oathnet-pro", "stealer"]
        );
        assert_eq!(
            tags_of(EntityKind::Credential, "loginuser@example.com@"),
            ["oathnet-pro", "stealer"]
        );
    }

    #[test]
    fn extract_breach_entities_non_target_row_tags_candidate() {
        use serde_json::json;
        // A row whose fields do NOT match the target: phone/person/country are
        // preserved at candidate confidence with a `candidate` tag (order:
        // breach, oathnet-pro, candidate).
        let item = json!({ "phone_number": "19998887777", "source": "TestDB" });
        let mut seen = HashSet::new();
        let mut result = ModuleResult::new();
        extract_breach_entities(
            &item,
            "unrelated-target-xyz",
            "scan",
            "oathnet.org:test",
            &mut seen,
            &mut result,
        );
        let phone = result
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Phone)
            .unwrap();
        assert_eq!(phone.tags, ["breach", "oathnet-pro", "candidate"]);
        assert!(
            (phone.confidence - 0.25).abs() < 1e-9,
            "non-target conf is 0.25"
        );
    }

    #[test]
    fn non_target_email_and_domain_are_quarantined_as_candidates() {
        use serde_json::json;
        // The exact junk pattern from the "Jordan Avery" name scan: a breach
        // row for a stranger (a bank employee) returned by the broad search. The
        // email AND its domain must be demoted to candidate — previously they
        // were emitted at full 0.70/0.55 confidence with no `candidate` tag,
        // which is what flooded the result with 88% junk.
        let item = json!({
            "email": "hlaura@blackhawkbank.com",
            "email_domain": "blackhawkbank.com",
            "source": "AbrigoBreach"
        });
        let mut seen = HashSet::new();
        let mut result = ModuleResult::new();
        extract_breach_entities(
            &item,
            "Jordan Avery",
            "scan",
            "oathnet.org:test",
            &mut seen,
            &mut result,
        );

        let email = result
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Email)
            .expect("email entity");
        assert!(
            email.has_tag("candidate"),
            "stranger email must be a candidate"
        );
        assert!(email.confidence <= 0.25 + 1e-9, "demoted to candidate conf");

        let domain = result
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Domain)
            .expect("domain entity");
        assert!(
            domain.has_tag("candidate"),
            "stranger domain must be a candidate"
        );
    }

    #[test]
    fn full_name_matcher_requires_all_terms_not_just_one() {
        use serde_json::json;
        // "Jordan Parker" shares only the first name with the target — it must
        // NOT count as the target row (the old any-term match treated every
        // "Jordan …" as a hit, the dominant false-positive on name scans).
        let parker = json!({ "full_name": "Jordan Parker", "source": "X" });
        let mut seen = HashSet::new();
        let mut result = ModuleResult::new();
        extract_breach_entities(
            &parker,
            "Jordan Avery",
            "scan",
            "oathnet.org:test",
            &mut seen,
            &mut result,
        );
        let p = result
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Person)
            .expect("person entity");
        assert!(
            p.has_tag("candidate"),
            "partial-name match must be a candidate, got tags {:?}",
            p.tags
        );

        // The real person — both terms present — is a confirmed target row.
        let avery = json!({ "full_name": "Jordan Avery", "source": "X" });
        let (mut seen2, mut r2) = (HashSet::new(), ModuleResult::new());
        extract_breach_entities(
            &avery,
            "Jordan Avery",
            "scan",
            "oathnet.org:test",
            &mut seen2,
            &mut r2,
        );
        let d = r2
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Person)
            .expect("person entity");
        assert!(
            !d.has_tag("candidate"),
            "exact name is the target, not a candidate"
        );
        assert!(
            (d.confidence - 0.70).abs() < 1e-9,
            "target person at full conf"
        );
    }

    #[test]
    fn accepts_identity_and_infra_kinds() {
        let m = OathnetPro;
        for k in [
            TargetKind::Email,
            TargetKind::Username,
            TargetKind::Phone,
            TargetKind::IpAddress,
            TargetKind::Domain,
            TargetKind::FullName,
        ] {
            assert!(m.accepts(&Target::new(k, "x")));
        }
    }

    #[test]
    fn cost_is_paid() {
        assert!(matches!(OathnetPro.cost(), ModuleCost::Paid));
    }

    #[test]
    fn attack_techniques_reflect_breach_pool_not_role_identification() {
        use crate::core::attack;
        let t = OathnetPro.attack_techniques();
        // Each claimed technique is backed by a concrete extractor: credentials,
        // emails, employee names, network IPs, and physical-location addresses.
        for id in [
            "T1589.001",
            "T1589.002",
            "T1589.003",
            "T1590.005",
            "T1591.001",
        ] {
            assert!(t.contains(&id), "oathnet_pro must claim {id}, got {t:?}");
            assert!(attack::technique(id).is_some(), "{id} must be catalogued");
        }
        // The People-category default's "Identify Roles" (T1591.004) is
        // deliberately NOT claimed — oathnet_pro extracts no job-title/role field.
        assert!(
            !t.contains(&"T1591.004"),
            "oathnet_pro identifies no roles; must not claim T1591.004"
        );
    }

    #[test]
    fn timeout_exceeds_default() {
        assert!(OathnetPro.max_timeout_ms() > crate::MODULE_TIMEOUT_MS);
    }

    #[test]
    fn val_str_or_fallback() {
        let item = serde_json::json!({"full_name": "Jerome Despal"});
        assert_eq!(
            val_str_or(&item, &["display_name", "full_name"]).as_deref(),
            Some("Jerome Despal")
        );
    }

    #[test]
    fn private_ips_are_detected() {
        assert!(is_private_ip("192.168.1.1"));
        assert!(is_private_ip("10.0.0.1"));
        assert!(is_private_ip("172.16.0.1"));
        assert!(is_private_ip("127.0.0.1"));
        assert!(is_private_ip("169.254.1.1"));
        assert!(is_private_ip("100.64.0.1"));
        assert!(is_private_ip("::1"));
        assert!(is_private_ip("fe80::1"));
        assert!(is_private_ip("fd00::1"));
        assert!(is_private_ip("224.0.0.251"));
        assert!(is_private_ip("239.255.255.250"));
        assert!(is_private_ip("ff02::fb"));
    }

    #[test]
    fn public_ips_are_not_private() {
        assert!(!is_private_ip("8.8.8.8"));
        assert!(!is_private_ip("1.1.1.1"));
        assert!(!is_private_ip("203.0.113.5"));
        assert!(!is_private_ip("2606:4700::1111"));
    }

    #[test]
    fn local_domains_are_detected() {
        assert!(is_local_domain("localhost"));
        assert!(is_local_domain("router.local"));
        assert!(is_local_domain("mypc.lan"));
        assert!(is_local_domain("host.internal"));
        assert!(is_local_domain("gateway.home"));
        assert!(is_local_domain("1.168.192.in-addr.arpa"));
        assert!(is_local_domain("router.local."));
    }

    #[test]
    fn real_domains_are_not_local() {
        assert!(!is_local_domain("example.com"));
        assert!(!is_local_domain("oathnet.org"));
        assert!(!is_local_domain("google.com.au"));
    }

    #[test]
    fn placeholder_usernames_detected() {
        for u in [
            "anonymous",
            "anon",
            "user",
            "admin",
            "test",
            "demo",
            "guest",
            "root",
            "username",
            "default",
            "example",
            "null",
            "undefined",
            "Anonymous",
            "ADMIN",
            "Test", // case insensitive
        ] {
            assert!(is_placeholder_username(u), "should skip: {u}");
        }
    }

    #[test]
    fn real_usernames_not_placeholders() {
        for u in ["alice", "bob_smith", "matrix_neo", "trinity99", "jdoe2024"] {
            assert!(!is_placeholder_username(u), "should NOT skip: {u}");
        }
    }

    #[test]
    fn should_skip_preflight_gates_each_kind_as_before() {
        use crate::core::scan::TargetKind;
        // Junk that must be skipped (one per kind), matching the per-kind gates
        // the dispatcher used to inline.
        assert!(should_skip_preflight(TargetKind::Email, "x@example.test"));
        assert!(should_skip_preflight(TargetKind::Username, "ab")); // < 4 chars
        assert!(should_skip_preflight(TargetKind::Username, "12345")); // all digits
        assert!(should_skip_preflight(TargetKind::Username, "admin")); // placeholder
        assert!(should_skip_preflight(TargetKind::Phone, "12345")); // < 6 digits
        assert!(should_skip_preflight(TargetKind::Phone, "000 000 000")); // all zeros
        assert!(should_skip_preflight(TargetKind::FullName, "Cher")); // single word
        assert!(should_skip_preflight(TargetKind::IpAddress, "192.168.1.1"));
        assert!(should_skip_preflight(TargetKind::Domain, "facebook.com"));
        assert!(should_skip_preflight(TargetKind::Domain, "x.local"));
        // A kind OathNet doesn't index is skipped too.
        assert!(should_skip_preflight(TargetKind::Url, "https://x.com"));

        // Real inputs that must pass through to a query.
        assert!(!should_skip_preflight(
            TargetKind::Email,
            "jane.doe@example.com"
        ));
        assert!(!should_skip_preflight(TargetKind::Username, "bob_smith"));
        assert!(!should_skip_preflight(TargetKind::Phone, "+61412345678"));
        assert!(!should_skip_preflight(TargetKind::FullName, "John Doe"));
        assert!(!should_skip_preflight(TargetKind::IpAddress, "8.8.8.8"));
        assert!(!should_skip_preflight(TargetKind::Domain, "acme.io"));
    }

    #[test]
    fn field_validators_are_objective() {
        // IBAN mod-97 (ISO 7064): canonical valid accounts pass; a flipped check
        // digit and a redacted sentinel fail.
        assert!(iban_is_valid("GB82 WEST 1234 5698 7654 32"));
        assert!(iban_is_valid("DE89370400440532013000"));
        assert!(iban_is_valid("FR1420041010050500013M02606"));
        assert!(!iban_is_valid("GB82WEST12345698765431")); // flipped last digit
        assert!(!iban_is_valid("UPGRADE_TO_SEE"));
        assert!(!iban_is_valid("1234567890123456"));

        // Public-IP gate: routable IPs pass; private / non-IP junk are rejected.
        assert!(is_public_ip("8.8.8.8"));
        assert!(is_public_ip("2606:4700::1111"));
        assert!(!is_public_ip("192.168.1.1")); // private
        assert!(!is_public_ip("1234567")); // not an IP at all
        assert!(!is_public_ip("UPGRADE_TO_SEE"));

        // Digit gate, email structure, redaction sentinel.
        assert!(has_min_digits("15551234567", 7));
        assert!(!has_min_digits("UPGRADE_TO_SEE", 7));
        assert!(looks_like_email("jane.doe@example.com"));
        assert!(!looks_like_email("UPGRADE_TO_SEE@x"));
        assert!(!looks_like_email("nobody"));
        assert!(is_redacted_sentinel("UPGRADE_TO_SEE_FULL"));
        assert!(!is_redacted_sentinel("realhandle"));
    }

    #[test]
    fn breach_extraction_validates_and_enriches() {
        use serde_json::json;
        let item = json!({
            "email": "subject@example.com",
            "ip": "1234567",                  // junk — not a real IP
            "phone_number": "UPGRADE_TO_SEE", // redacted sentinel
            "iban": "GB82 WEST 1234 5698 7654 32",
            "telegram": "@subject_tg",
            "github": "subjectdev",
            "snapchat": "UPGRADE_TO_SEE",     // redacted — must be skipped
            "source": "TestDB"
        });
        let mut seen = HashSet::new();
        let mut result = ModuleResult::new();
        extract_breach_entities(
            &item,
            "subject@example.com",
            "scan",
            "oathnet.org:test",
            &mut seen,
            &mut result,
        );

        let has = |k: EntityKind, needle: &str| {
            result
                .entities
                .iter()
                .any(|e| e.kind == k && e.value.contains(needle))
        };

        // Objective gates drop the junk IP and the redacted phone.
        assert!(
            !has(EntityKind::IpAddress, "1234567"),
            "junk IP must be dropped"
        );
        assert!(
            !result.entities.iter().any(|e| e.kind == EntityKind::Phone),
            "redacted phone must be dropped"
        );

        // A mod-97-valid IBAN is emitted as an Other(\"iban\") financial entity.
        let iban = result
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Other("iban".to_string()))
            .expect("validated IBAN entity");
        assert!(iban.has_tag("financial") && iban.has_tag("iban"));

        // New social handles become Username pivots (the `@` is stripped);
        // redacted ones are skipped.
        assert!(has(EntityKind::Username, "subject_tg"), "telegram handle");
        assert!(has(EntityKind::Username, "subjectdev"), "github handle");
        assert!(
            !result
                .entities
                .iter()
                .any(|e| e.kind == EntityKind::Username && e.has_tag("snapchat")),
            "redacted snapchat handle must be skipped"
        );
    }

    #[test]
    fn breach_bio_is_mined_for_contact_identifiers() {
        use serde_json::json;
        let item = json!({
            "email": "subject@example.com",
            "bio": "Reach me at alt.contact@proton.me or +14155550123 — DMs open",
            "source": "TestDB"
        });
        let mut seen = HashSet::new();
        let mut result = ModuleResult::new();
        extract_breach_entities(
            &item,
            "subject@example.com",
            "scan",
            "oathnet.org:test",
            &mut seen,
            &mut result,
        );
        // Alternate contact email mined from the free-text bio, tagged bio-mined.
        let mined = result
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Email && e.value.contains("alt.contact@proton.me"))
            .expect("bio-mined email");
        assert!(mined.has_tag("bio-mined"));
        // Phone mined from the bio (E.164 normalised by the shared extractor).
        assert!(
            result
                .entities
                .iter()
                .any(|e| e.kind == EntityKind::Phone && e.has_tag("bio-mined")),
            "bio-mined phone"
        );
    }

    #[test]
    fn stealer_url_becomes_url_and_domain_pivots() {
        use serde_json::json;
        let item = json!({
            "username": "victim@example.com",
            "url": "https://portal.acmebank.com/login",
            "password": "secret"
        });
        let mut seen = HashSet::new();
        let mut result = ModuleResult::new();
        extract_stealer_entities(&item, "scan", "oathnet.org:test", &mut seen, &mut result);

        // The login URL is now a first-class Url pivot (was evidence-only).
        let url = result
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Url && e.value.contains("portal.acmebank.com/login"))
            .expect("stealer Url entity");
        assert!(url.has_tag("credential-url"));
        // Its host is emitted as a Domain pivot.
        assert!(
            result
                .entities
                .iter()
                .any(|e| e.kind == EntityKind::Domain && e.value == "portal.acmebank.com"),
            "stealer url host Domain"
        );
    }
