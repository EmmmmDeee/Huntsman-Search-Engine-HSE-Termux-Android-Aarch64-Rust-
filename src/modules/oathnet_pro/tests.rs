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
            [
                "breach",
                "oathnet-pro",
                "password-hash",
                "hash:md5",
                "crackable:fast"
            ]
        );
    }

    #[test]
    fn numeric_fields_coerced_and_household_attrs_stamped() {
        use serde_json::json;
        // Breach row encoding IDs/codes as JSON NUMBERS (a common real shape) — the
        // string-only reader silently dropped the phone lead, the Discord pivot and
        // the postcode. Also exercises the household/associate grouping attrs the
        // live correlators (AU-049/050/051) read off a Person's evidence.
        let item = json!({
            "full_name": "Dana Whitlock",
            "email": "dana.whitlock@example.com",
            "phone_number": 61412345678_u64,
            "discordid": 123456789012345678_u64,
            "address_street": "12 Wattle St",
            "city": "Logan",
            "state": "QLD",
            "postal_code": 4114,
            "source": "TestDB"
        });
        let mut seen = HashSet::new();
        let mut result = ModuleResult::new();
        extract_breach_entities(
            &item,
            "dana.whitlock@example.com",
            "scan",
            "oathnet.org:test",
            &mut seen,
            &mut result,
        );

        // Numeric phone & discordid are now recovered (previously dropped entirely).
        assert!(
            result
                .entities
                .iter()
                .any(|e| e.kind == EntityKind::Phone && e.value == "61412345678"),
            "numeric phone_number must coerce into a Phone entity"
        );
        assert!(
            result
                .entities
                .iter()
                .any(|e| e.kind == EntityKind::Username
                    && e.value == "discord:123456789012345678"),
            "numeric discordid must coerce into a Discord username entity"
        );

        // The Person's evidence now carries the `phone` and street-anchored
        // `address` attrs AU-050 (shared phone) and AU-049/051 (household/kin)
        // cluster on — the gap that left those rules dead on live scans.
        let person = result
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Person && e.value == "Dana Whitlock")
            .expect("Person minted from full_name");
        let ev = person.evidence.first().expect("breach evidence present");
        assert_eq!(ev.attributes.get("phone").map(String::as_str), Some("61412345678"));
        assert_eq!(
            ev.attributes.get("address").map(String::as_str),
            Some("12 Wattle St, Logan, QLD, 4114"),
            "street-anchored residence stamped for household clustering"
        );
        // The numeric postcode is captured as its own evidence attr too.
        assert_eq!(ev.attributes.get("postal_code").map(String::as_str), Some("4114"));
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
    fn stealer_never_emits_a_captured_password_verbatim() {
        use serde_json::json;
        // A real captured password must NEVER be persisted verbatim in any emitted
        // entity's evidence — only a redacted hint + length + marker. This is an
        // evidentiary tool; storing a victim's plaintext credential is exactly the
        // leak it must not create.
        let item = json!({
            "email": ["victim@example.com"],
            "url": "https://login.site",
            "password": "SuperSecret123"
        });
        let mut seen = HashSet::new();
        let mut result = ModuleResult::new();
        extract_stealer_entities(&item, "scan", "oathnet.org:test", &mut seen, &mut result);

        for e in &result.entities {
            for ev in &e.evidence {
                assert!(
                    !ev.attributes.values().any(|v| v.contains("SuperSecret123")),
                    "captured password leaked verbatim into evidence of {:?}",
                    e.value
                );
            }
        }
        let attr_is = |key: &str, want: &str| {
            result.entities.iter().any(|e| {
                e.evidence
                    .iter()
                    .any(|ev| ev.attributes.get(key).map(String::as_str) == Some(want))
            })
        };
        assert!(
            attr_is("password_redacted", "true"),
            "a redaction marker must be surfaced"
        );
        assert!(
            attr_is("password_hint_first", "S") && attr_is("password_hint_last", "3"),
            "first/last-char hints must be surfaced"
        );
    }

    #[test]
    fn stealer_paywall_sentinel_is_not_emitted_verbatim() {
        use serde_json::json;
        let item = json!({
            "email": ["victim@example.com"],
            "password": "UPGRADE_TO_SEE_FULL_DATA"
        });
        let mut seen = HashSet::new();
        let mut result = ModuleResult::new();
        extract_stealer_entities(&item, "scan", "oathnet.org:test", &mut seen, &mut result);
        for e in &result.entities {
            for ev in &e.evidence {
                assert!(
                    !ev.attributes.values().any(|v| v.contains("UPGRADE_TO_SEE")),
                    "paywall sentinel leaked verbatim"
                );
            }
        }
        assert!(
            result.entities.iter().any(|e| e
                .evidence
                .iter()
                .any(|ev| ev.attributes.get("password_paywalled").map(String::as_str) == Some("true"))),
            "the paywall sentinel is recorded as password_paywalled"
        );
    }

    #[test]
    fn stealer_row_surfaces_device_fingerprints_and_long_tail() {
        use serde_json::json;
        // The defining payload of an infostealer log — machine fingerprints and
        // the verbose detail tail — must now surface as pivotable entities
        // (shared `breach_rich` pass), not stay locked in evidence.
        let item = json!({
            "username": "victim@example.com",
            "url": "https://accounts.example.com/login",
            "hwid": "9F8E7D6C5B4A3210",
            "hostname": "DESKTOP-VICTIM",
            "country": "US",
            "ip_country_code": "us",
            "gender": "M",
        });
        let mut seen = HashSet::new();
        let mut result = ModuleResult::new();
        extract_stealer_entities(&item, "scan", "oathnet.org:test", &mut seen, &mut result);

        let find = |k: EntityKind, v: &str| {
            result.entities.iter().find(|e| e.kind == k && e.value == v)
        };
        // Device fingerprints → DeviceId, tagged context (provider + device),
        // NOT `breach` (infrastructure, not leaked PII).
        let dev = find(EntityKind::DeviceId, "9F8E7D6C5B4A3210").expect("hwid → DeviceId");
        assert!(dev.tags.iter().any(|t| t == "oathnet-pro"));
        assert!(dev.tags.iter().any(|t| t == "device"));
        assert!(!dev.tags.iter().any(|t| t == "breach"));
        assert!(find(EntityKind::DeviceId, "DESKTOP-VICTIM").is_some());
        // Long-tail scalar → Other(field) raw-data node.
        assert!(find(EntityKind::Other("gender".into()), "M").is_some());
        // The primary stealer leads are still present and un-duplicated.
        assert_eq!(
            result
                .entities
                .iter()
                .filter(|e| e.kind == EntityKind::Url && e.value.contains("accounts.example.com"))
                .count(),
            1
        );
    }

    #[test]
    fn stealer_deviceid_evidence_carries_the_login_email_join_key() {
        use serde_json::json;
        // The DeviceId/MacAddress nodes a stealer row mints (via breach_rich) must
        // carry BOTH the username and the login email on their evidence, so AU-106
        // (shared-device identity) can fold the email handle into its distinct-
        // handle count — matching the breach/dehashed/see_know sibling paths.
        let item = json!({
            "username": "ghost_91",
            "email": ["victim@example.com"],
            "hwid": "9F8E7D6C5B4A3210FEDC",
            "url": "https://accounts.example.com/login",
        });
        let mut seen = HashSet::new();
        let mut result = ModuleResult::new();
        extract_stealer_entities(&item, "scan", "oathnet.org:test", &mut seen, &mut result);
        let dev = result
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::DeviceId && e.value == "9F8E7D6C5B4A3210FEDC")
            .expect("hwid → DeviceId");
        let attrs = &dev.evidence[0].attributes;
        assert_eq!(
            attrs.get("email").map(String::as_str),
            Some("victim@example.com"),
            "stealer DeviceId evidence must carry the login email (AU-106 join key)"
        );
        assert_eq!(attrs.get("username").map(String::as_str), Some("ghost_91"));
    }

    #[test]
    fn stealer_android_app_package_is_not_minted_as_domain() {
        use serde_json::json;
        // Real shape from a live oathnet stealer-search row (Android credential):
        // the `domain` field is the reverse-DNS app PACKAGE, and the `url` is an
        // `android://` scheme. Neither must become a `Domain` entity — a bogus
        // `com.facebook.katana` domain previously expanded into a wasted
        // HudsonRock `search-by-domain` call that pulled in strangers' records.
        let item = json!({
            "username": "alikareem",
            "domain": ["com.facebook.katana"],
            "url": "android://zQxb6hXv1MJiC1Yy==@com.facebook.katana/",
            "password": "secret"
        });
        let mut seen = HashSet::new();
        let mut result = ModuleResult::new();
        extract_stealer_entities(&item, "scan", "oathnet.org:test", &mut seen, &mut result);

        assert!(
            !result
                .entities
                .iter()
                .any(|e| e.kind == EntityKind::Domain),
            "an Android app package must not be minted as a Domain entity"
        );
        // The credential itself (username@url) is still captured — the app
        // context is preserved as a Credential, just not as a fake domain.
        assert!(
            result
                .entities
                .iter()
                .any(|e| e.kind == EntityKind::Credential),
            "the credential pivot is still emitted"
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
    fn candidate_flood_is_capped_but_target_rows_always_survive() {
        use serde_json::json;
        // The exact "Ali Kareem" failure mode: a broad `full_name` search
        // returned 100 pureincubation.com rows, NONE of them Ali. Each stranger
        // row mints several quarantined `candidate` entities, which flooded a
        // memory-constrained device with low-value noise. `extract_breach_page`
        // SAMPLES the non-matching rows (cap = MAX_CANDIDATE_ROWS) instead of
        // emitting every one — but a genuinely matching row is ALWAYS extracted
        // in full, even when it lands after the cap is already exhausted.
        let mut items: Vec<serde_json::Value> = (0..100)
            .map(|i| {
                json!({
                    "email": format!("stranger{i}@pureincubation.com"),
                    "username": format!("stranger{i}"),
                    "source": "pureincubation.com"
                })
            })
            .collect();
        // The real target lands LAST, long after the candidate cap is spent.
        items.push(json!({
            "email": "ali.kareem.real@example.com",
            "full_name": "Ali Kareem",
            "source": "RealLeak"
        }));

        let mut seen = HashSet::new();
        let mut result = ModuleResult::new();
        let match_ctx = TargetMatch::new("Ali Kareem");
        let row_matches: Vec<bool> = items.iter().map(|i| match_ctx.matches(i)).collect();
        extract_breach_page(
            &items,
            &row_matches,
            "scan",
            "oathnet.org:test",
            &mut seen,
            &mut result,
        );

        // The candidate flood is bounded: one candidate email per SAMPLED
        // stranger row, never more than the cap (and far below the unbounded
        // 100 the page would otherwise emit).
        let candidate_emails = result
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Email && e.has_tag("candidate"))
            .count();
        assert!(
            candidate_emails <= MAX_CANDIDATE_ROWS,
            "candidate emails ({candidate_emails}) must not exceed the cap ({MAX_CANDIDATE_ROWS})"
        );
        assert!(
            candidate_emails < 100,
            "the stranger flood must be capped, not passed through"
        );

        // The genuine target row SURVIVES at full confidence with no candidate
        // tag, despite arriving after the cap was exhausted.
        let target = result
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Person && e.value == "Ali Kareem")
            .expect("the matching target row must always be extracted");
        assert!(
            !target.has_tag("candidate"),
            "the target row must not be quarantined"
        );
        assert!(
            target.confidence > crate::core::entity::CANDIDATE_CONF,
            "the target row keeps full confidence, not candidate strength"
        );
    }

    #[test]
    fn breach_parent_is_honest_about_whether_the_subject_appears() {
        use serde_json::json;
        // A `full_name` page of pure strangers must NOT mint a 0.85
        // breach-tagged subject node: the engine pre-seeds a subject anchor, so
        // that parent would merge a false "breach hit" — plus a 50-stranger
        // name/country dump — onto it. Zero matching rows => None.
        let strangers: Vec<serde_json::Value> = (0..50)
            .map(|i| {
                json!({
                    "full_name": format!("Stranger {i}"),
                    "country": "ZZ",
                    "source": "pureincubation.com"
                })
            })
            .collect();
        let target = Target::new(TargetKind::FullName, "Ali Kareem");
        let mc = TargetMatch::new("Ali Kareem");
        let none_matching: Vec<serde_json::Value> =
            strangers.iter().filter(|i| mc.matches(i)).cloned().collect();
        assert!(none_matching.is_empty(), "no stranger should match the subject");
        assert!(
            breach_parent_entity(&target, "scan", &none_matching, strangers.len()).is_none(),
            "a zero-match page must not produce a breach parent"
        );

        // When the subject genuinely appears, the parent aggregates over the
        // MATCHING rows only — its own country (AU), never the strangers' ZZ.
        let mut page = strangers.clone();
        page.push(json!({
            "full_name": "Ali Kareem",
            "country": "AU",
            "gender": "M",
            "source": "RealLeak"
        }));
        let matching: Vec<serde_json::Value> =
            page.iter().filter(|i| mc.matches(i)).cloned().collect();
        assert_eq!(matching.len(), 1, "exactly the subject's own row matches");
        let parent = breach_parent_entity(&target, "scan", &matching, page.len())
            .expect("subject present => parent emitted");
        assert_eq!(parent.value, "Ali Kareem");
        assert!((parent.confidence - 0.85).abs() < 1e-9);
        assert!(parent.has_tag("breach") && parent.has_tag("oathnet-pro"));
        let ev = parent.evidence.first().expect("parent evidence");
        assert_eq!(ev.attributes.get("hits").map(String::as_str), Some("1"));
        assert_eq!(
            ev.attributes.get("records_returned").map(String::as_str),
            Some("51")
        );
        assert_eq!(
            ev.attributes.get("countries").map(String::as_str),
            Some("AU"),
            "aggregates the subject's matching rows only, not the strangers' ZZ"
        );
        assert_eq!(
            ev.attributes.get("names").map(String::as_str),
            Some("Ali Kareem")
        );
    }

    #[test]
    fn lastip_login_ip_is_extracted_as_geolocation_lead() {
        use serde_json::json;
        // snusbase-style records carry the login IP in `lastip` (no `ip` field).
        // Reading `ip` alone dropped the subject's geolocation; a PUBLIC lastip
        // must surface as an IpAddress geo lead.
        let item = json!({
            "username": "ali.kareem",
            "lastip": "142.204.244.67",
            "source": "snusbase"
        });
        let mut seen = HashSet::new();
        let mut result = ModuleResult::new();
        extract_breach_entities(
            &item,
            "ali.kareem",
            "scan",
            "oathnet.org:test",
            &mut seen,
            &mut result,
        );
        let ip = result
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::IpAddress)
            .expect("lastip extracted as IpAddress");
        assert_eq!(ip.value, "142.204.244.67");
        assert!(ip.has_tag("geolocation-lead"));

        // A PRIVATE last-login IP can't geolocate — dropped, never minted.
        let private = json!({ "username": "ali.kareem", "lastip": "192.168.1.5", "source": "x" });
        let mut seen = HashSet::new();
        let mut result = ModuleResult::new();
        extract_breach_entities(&private, "ali.kareem", "scan", "k", &mut seen, &mut result);
        assert!(
            result.entities.iter().all(|e| e.kind != EntityKind::IpAddress),
            "private lastip must not become a geo lead"
        );
    }

    #[test]
    fn composed_address_includes_postal_code_for_geocodability() {
        use serde_json::json;
        // A postcode-qualified address geocodes to the ZIP centroid, not the
        // whole city. The breach record carries `postal_code`, so it belongs in
        // the composed Address value, not only the evidence. A whitespace-only
        // `address_street` (which `val_str` admits) must be trimmed away rather
        // than leaving a leading `", "` gap in the composed value.
        let item = json!({
            "full_name": "Ali Kareem",
            "address_street": "   ",
            "city": "HAMPTON",
            "state": "VA",
            "postal_code": "23666",
            "source": "TestDB"
        });
        let mut seen = HashSet::new();
        let mut result = ModuleResult::new();
        extract_breach_entities(
            &item,
            "Ali Kareem",
            "scan",
            "oathnet.org:test",
            &mut seen,
            &mut result,
        );
        let addr = result
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Address && e.value.contains("HAMPTON"))
            .expect("composed address entity");
        assert_eq!(addr.value, "HAMPTON, VA, 23666");
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
    fn produces_declares_harvested_key_and_crypto_kinds() {
        // The shared key_harvest path (extract_api_keys_from_item) emits ApiKey
        // and CryptoAddress; produces() must declare them so the producer graph
        // matches the actual emissions.
        let kinds = OathnetPro.produces();
        assert!(kinds.contains(&EntityKind::ApiKey));
        assert!(kinds.contains(&EntityKind::CryptoAddress));
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
    fn stealer_url_becomes_url_pivot_but_host_is_not_a_domain() {
        use serde_json::json;
        let item = json!({
            "username": "victim@example.com",
            "url": "https://portal.acmebank.com/login",
            "password": "secret"
        });
        let mut seen = HashSet::new();
        let mut result = ModuleResult::new();
        extract_stealer_entities(&item, "scan", "oathnet.org:test", &mut seen, &mut result);

        // The login URL is a first-class Url pivot (was evidence-only).
        let url = result
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Url && e.value.contains("portal.acmebank.com/login"))
            .expect("stealer Url entity");
        assert!(url.has_tag("credential-url"));
        // Its host is a third-party service the subject merely uses — it must NOT
        // become a Domain entity (that minted subdomain noise + misdirected
        // dns/cert/wayback expansion of the platform's own infrastructure).
        assert!(
            !result
                .entities
                .iter()
                .any(|e| e.kind == EntityKind::Domain && e.value == "portal.acmebank.com"),
            "stealer url host must not be minted as a Domain"
        );
    }

    #[test]
    fn identify_password_hash_classifies_common_formats() {
        // Fast, unsalted digests by hex width.
        assert_eq!(identify_password_hash(&"a".repeat(32)), Some(("md5", true)));
        assert_eq!(identify_password_hash(&"a".repeat(40)), Some(("sha1", true)));
        assert_eq!(
            identify_password_hash(&"a".repeat(64)),
            Some(("sha256", true))
        );
        assert_eq!(
            identify_password_hash(&"a".repeat(128)),
            Some(("sha512", true))
        );
        assert_eq!(
            identify_password_hash(&format!("*{}", "A".repeat(40))),
            Some(("mysql", true))
        );
        // Slow, adaptive / salted KDFs by prefix.
        assert_eq!(
            identify_password_hash("$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9PgBkqquzi.Ss7KIUgO2t0jWMUW"),
            Some(("bcrypt", false))
        );
        assert_eq!(
            identify_password_hash("$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaGhhc2g"),
            Some(("argon2", false))
        );
        assert_eq!(
            identify_password_hash("$6$rounds=5000$salt$hashhashhashhashhash"),
            Some(("sha512crypt", false))
        );
        // Non-hashes.
        assert_eq!(identify_password_hash("not-a-hash"), None);
        assert_eq!(identify_password_hash(&"a".repeat(33)), None); // odd width
    }

    #[test]
    fn identify_password_hash_reads_digest_with_appended_salt() {
        // OathNet packs the salt onto the digest (real values from the Ali.kareem
        // scan): space-separated, and behind a `,:` marker. Both must still be
        // recognised as a fast, crackable MD5 — the strongest exposure signal,
        // which the whole-string hex check used to miss entirely.
        assert_eq!(
            identify_password_hash("2f4370b7f7000f4f2a7cf96ec45f2858 _:=j[gpxgh[e<b!+k?2h(n0b'9pn=w"),
            Some(("md5", true))
        );
        assert_eq!(
            identify_password_hash("b3dd5393fc5e7f44fd4fd4c85490b414,:xpay"),
            Some(("md5", true))
        );
        // A leading SHA-256 with an appended salt classifies by the 64-hex run.
        assert_eq!(
            identify_password_hash(&format!("{}:somesalt", "a".repeat(64))),
            Some(("sha256", true))
        );
        // The remainder must begin at a separator: a token that merely starts with
        // hex but runs straight into non-hex is not a digest.
        assert_eq!(
            identify_password_hash("2f4370b7f7000f4f2a7cf96ec45f2858XYZ"),
            None
        );
    }

    #[test]
    fn password_hash_entity_carries_hash_intel() {
        use serde_json::json;
        // A bcrypt digest with a salt → classified slow + salted.
        let item = json!({
            "email": "subject@example.com",
            "password_hash": "$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9PgBkqquzi.Ss7KIUgO2t0jWMUW",
            "salt": "abc123",
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
        let pw = result
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Password)
            .expect("password entity");
        assert!(pw.has_tag("hash:bcrypt"), "tags: {:?}", pw.tags);
        assert!(pw.has_tag("crackable:slow"));
        assert!(pw.has_tag("salted"));
    }

    #[test]
    fn password_hash_intel_handles_oathnet_appended_salt() {
        use serde_json::json;
        // OathNet's real format from the Ali.kareem scan (jefit row): the MD5 digest
        // with the salt appended and no separate `salt` field. The appended salt
        // used to leave the hash entirely unclassified; it must now read as a fast,
        // crackable, salted MD5.
        let item = json!({
            "email": "ali.kareem95@gmail.com",
            "password_hash": "2f4370b7f7000f4f2a7cf96ec45f2858 _:=j[gpxgh[e<b!+k?2h(n0b'9pn=w",
            "source": "jefit.com"
        });
        let mut seen = HashSet::new();
        let mut result = ModuleResult::new();
        extract_breach_entities(
            &item,
            "ali.kareem95@gmail.com",
            "scan",
            "oathnet.org:test",
            &mut seen,
            &mut result,
        );
        let pw = result
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Password)
            .expect("password entity");
        assert!(pw.has_tag("hash:md5"), "tags: {:?}", pw.tags);
        assert!(pw.has_tag("crackable:fast"));
        assert!(pw.has_tag("salted"), "appended salt must set the salted tag");
    }

    #[test]
    fn breach_evidence_carries_account_join_keys() {
        use serde_json::json;
        // AU-047 (reused-secret identity link) reads `email`/`username` off a
        // leaked secret's evidence; the breach extractor must stamp them so the
        // correlator can tie the accounts that share a secret to one controller.
        let item = json!({
            "email": "subject@example.com",
            "username": "subj99",
            "password_hash": "$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9PgBkqquzi.Ss7KIUgO2t0jWMUW",
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
        let pw = result
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Password)
            .expect("password entity");
        let ev = pw.evidence.first().expect("evidence");
        assert_eq!(
            ev.attributes.get("email").map(String::as_str),
            Some("subject@example.com")
        );
        assert_eq!(
            ev.attributes.get("username").map(String::as_str),
            Some("subj99")
        );
    }

    #[test]
    fn plaintext_password_emitted_as_entity() {
        use serde_json::json;
        // A real plaintext password becomes the canonical Password secret that
        // AU-037 / AU-047 operate on.
        let item = json!({
            "email": "subject@example.com",
            "password": "Xy7$kq2Lm9wz",
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
        let pw = result
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Password && e.value == "Xy7$kq2Lm9wz")
            .expect("plaintext password entity");
        assert!(pw.has_tag("plaintext-password"));

        // Redacted sentinels and trivial values are skipped.
        for junk in ["UPGRADE_TO_SEE_FULL", "aaaaaa", "ab"] {
            let item = json!({ "email": "x@example.com", "password": junk, "source": "T" });
            let (mut s, mut r) = (HashSet::new(), ModuleResult::new());
            extract_breach_entities(&item, "x@example.com", "scan", "k", &mut s, &mut r);
            assert!(
                !r.entities.iter().any(|e| e.kind == EntityKind::Password),
                "junk password '{junk}' must not be emitted"
            );
        }
    }

    #[test]
    fn plaintext_password_drops_sentinel_and_recovers_email() {
        use serde_json::json;
        // A capture sentinel in the password slot must not become a Password.
        let item = json!({"email": "subject@example.com", "password": "[fail]", "source": "DB"});
        let mut seen = HashSet::new();
        let mut r = ModuleResult::new();
        extract_breach_entities(&item, "subject@example.com", "scan", "oathnet.org:t", &mut seen, &mut r);
        assert!(
            !r.entities.iter().any(|e| e.kind == EntityKind::Password && e.value == "[fail]"),
            "a [fail] sentinel must not be minted as a Password"
        );

        // An email mis-stored in the password slot is recovered as an Email lead,
        // never as a Password (which would forge a reused-secret link).
        let item = json!({"username": "ali", "password": "ayilmazer486@gmail.com", "source": "Stealer"});
        let mut seen = HashSet::new();
        let mut r = ModuleResult::new();
        extract_breach_entities(&item, "ali", "scan", "oathnet.org:t", &mut seen, &mut r);
        let recovered = r.entities.iter()
            .find(|e| e.value == "ayilmazer486@gmail.com")
            .expect("email recovered from the password field");
        assert_eq!(recovered.kind, EntityKind::Email);
        assert!(recovered.has_tag("recovered-from-password"), "tags: {:?}", recovered.tags);
        assert!(
            !r.entities.iter().any(|e| e.kind == EntityKind::Password && e.value.contains('@')),
            "an email must not also be minted as a Password"
        );
    }
