use super::*;
use crate::core::entity::Entity;

    #[test]
    fn module_timeout_exceeds_seeknow_curl_outer_budget() {
        // Regression: the engine aborts a module at max_timeout_ms. see_know's
        // name/auto search legitimately takes ~55s (server cap) and the curl
        // client's outer timeout is 78s; the module budget must exceed that so
        // the engine doesn't kill see_know before the upstream responds. Was
        // 45s — below the cap — which guaranteed truncation on name seeds.
        assert!(
            SeekNow.max_timeout_ms() >= 78_000,
            "see_know max_timeout_ms {} must be >= 78_000 (curl-client outer timeout)",
            SeekNow.max_timeout_ms()
        );
    }

    #[test]
    fn is_exempt_from_the_termux_timeout_cap() {
        // The 45s Termux module cap is BELOW see_know's ~55s server cap, so
        // without an exemption every phone scan would time it out with zero data
        // — silently wasting the operator's highest-priority paid source on the
        // platform HSE targets. see_know must opt out so its budget survives the
        // clamp, and that budget must still clear the curl outer timeout.
        assert!(
            SeekNow.termux_timeout_cap_exempt(),
            "see_know must be exempt from the 45s Termux cap (server cap is ~55s)"
        );
        assert!(
            SeekNow.termux_timeout_ms() >= 78_000,
            "exempt budget {} must still exceed the 78s curl outer timeout",
            SeekNow.termux_timeout_ms()
        );
    }

    #[test]
    fn should_skip_seed_matches_preflight_policy() {
        // Skipped (junk) seeds.
        assert!(should_skip_seed(TargetKind::Email, "x@localhost"));
        assert!(should_skip_seed(TargetKind::Username, "abc")); // < 4
        assert!(should_skip_seed(TargetKind::Username, "12345")); // all digits
        assert!(should_skip_seed(TargetKind::Phone, "12345")); // < 6 digits
        assert!(should_skip_seed(TargetKind::FullName, "Jordan")); // no space
        assert!(should_skip_seed(TargetKind::IpAddress, "192.168.1.1"));
        assert!(should_skip_seed(TargetKind::Coordinates, "0,0")); // unsupported kind
        // Accepted (real) seeds.
        assert!(!should_skip_seed(
            TargetKind::Email,
            "jordan.meyer@wartburg.edu"
        ));
        assert!(!should_skip_seed(TargetKind::Username, "jmeyer82291"));
        assert!(!should_skip_seed(TargetKind::Phone, "+15551234567"));
        assert!(!should_skip_seed(TargetKind::FullName, "Jordan Meyer"));
        assert!(!should_skip_seed(TargetKind::IpAddress, "8.8.8.8"));
        assert!(!should_skip_seed(TargetKind::Domain, "example.com"));
    }

    #[test]
    fn search_subject_present_gates_on_a_real_match() {
        use serde_json::json;
        // T2.36-pattern regression: a broad `full_name` `/search` page of pure
        // term-sharing strangers must not read as "subject present" — the
        // caller would otherwise mint a confidence::HIGH_PLUSPLUS_PLUS BREACH parent that merges (via
        // `absorb`, GREATEST semantics) straight onto the pre-seeded subject
        // anchor regardless of whether any row actually concerns them.
        let strangers: Vec<serde_json::Value> = (0..5)
            .map(|i| {
                json!({
                    "full_name": format!("Stranger {i}"),
                    "country": "ZZ",
                })
            })
            .collect();
        assert!(
            !search_subject_present("Ali Kareem", &strangers),
            "a page of strangers must not read as subject-present"
        );

        // When the subject's own row is present, the gate opens.
        let mut page = strangers.clone();
        page.push(json!({"full_name": "Ali Kareem", "country": "AU"}));
        assert!(
            search_subject_present("Ali Kareem", &page),
            "the subject's own row must open the gate"
        );

        // Exact-selector kinds (email/phone/domain/IP) trivially match their
        // own record — the parent must still fire for those.
        let email_hit = vec![json!({"email": "jordan.meyer@wartburg.edu"})];
        assert!(search_subject_present(
            "jordan.meyer@wartburg.edu",
            &email_hit
        ));

        // Empty results never read as subject-present.
        assert!(!search_subject_present("Ali Kareem", &[]));
    }

    #[test]
    fn extract_entities_characterization() {
        use serde_json::json;
        let item = json!({
            "dbname": "TestBreach",
            "email": "Jordan.Meyer@Example.com",
            "username": "jmeyer",
            "phone": "15551234567",
            "full_name": "Jordan Meyer",
            "ip": "8.8.8.8",
            "country": "US",
            "discord_id": "123456789012345678",
            "steam_id": "76561198000000000",
            "domain": "example.com"
        });
        let mut seen = HashSet::new();
        let mut result = ModuleResult::new();
        extract_entities(
            &item,
            "15551234567",
            "scan",
            "search",
            "see-know.eu:test",
            &mut seen,
            &mut result,
        );

        // One entity per recognised field.
        assert_eq!(
            result.entities.len(),
            9,
            "kinds: {:?}",
            result
                .entities
                .iter()
                .map(|e| (e.kind.to_string(), e.value.clone()))
                .collect::<Vec<_>>()
        );
        // Every entity carries `see-know`; all but the Domain carry `breach`.
        for e in &result.entities {
            assert!(e.has_tag("see-know"), "{} missing see-know", e.value);
            assert_eq!(
                e.has_tag("breach"),
                e.kind != EntityKind::Domain,
                "breach tag policy wrong for {} ({})",
                e.value,
                e.kind
            );
        }
        // Kind-specific values + endpoint-specific tags.
        let has =
            |k: EntityKind, v: &str| result.entities.iter().any(|e| e.kind == k && e.value == v);
        assert!(has(EntityKind::Email, "jordan.meyer@example.com"));
        assert!(has(EntityKind::Username, "jmeyer"));
        assert!(has(EntityKind::Phone, "15551234567"));
        assert!(has(EntityKind::Person, "Jordan Meyer"));
        assert!(has(EntityKind::Address, "US"));
        assert!(has(EntityKind::Domain, "example.com"));
        assert!(
            result
                .entities
                .iter()
                .any(|e| e.kind == EntityKind::IpAddress && e.has_tag("geolocation-lead"))
        );
        assert!(
            result
                .entities
                .iter()
                .any(|e| e.value == "discord:123456789012345678" && e.has_tag("discord"))
        );
        assert!(
            result
                .entities
                .iter()
                .any(|e| e.value == "steam:76561198000000000" && e.has_tag("steam"))
        );
    }

    #[test]
    fn lastip_login_ip_is_extracted_and_private_is_rejected() {
        use serde_json::json;
        // snusbase records carry the subject's login IP ONLY in `lastip`; the
        // extractor previously read `ip` alone and dropped it. A public lastip
        // surfaces as a geolocation lead; a private one is rejected as noise
        // (tightening the old `len >= 7` gate to a publicly-routable check).
        let item = json!({ "username": "ali.kareem", "lastip": "37.236.187.22", "source": "snusbase" });
        let mut seen = HashSet::new();
        let mut result = ModuleResult::new();
        extract_entities(
            &item,
            "ali.kareem",
            "scan",
            "search",
            "see-know.eu:test",
            &mut seen,
            &mut result,
        );
        let ip = result
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::IpAddress)
            .expect("lastip extracted as IpAddress");
        assert_eq!(ip.value, "37.236.187.22");
        assert!(ip.has_tag("geolocation-lead"));

        let private = json!({ "username": "x", "lastip": "10.0.0.4", "source": "x" });
        let mut seen = HashSet::new();
        let mut result = ModuleResult::new();
        extract_entities(
            &private,
            "x",
            "scan",
            "search",
            "see-know.eu:test",
            &mut seen,
            &mut result,
        );
        assert!(
            result.entities.iter().all(|e| e.kind != EntityKind::IpAddress),
            "private lastip must not become a geo lead"
        );
    }

    #[test]
    fn person_carries_normalized_identity_demographics() {
        use serde_json::json;
        // The subject node should surface DOB/gender/age as first-class tags,
        // normalized across provider key spellings (birthdate vs date_birth;
        // "Male" -> M), so the dossier headline reads the demographics directly
        // instead of leaving them buried in the raw-record evidence.
        let item = json!({
            "full_name": "Ali Kareem",
            "birthdate": "1990-05-12",
            "gender": "Male",
            "age": 34,
            "source": "snusbase"
        });
        let mut seen = HashSet::new();
        let mut result = ModuleResult::new();
        extract_entities(
            &item,
            "Ali Kareem",
            "scan",
            "search",
            "see-know.eu:test",
            &mut seen,
            &mut result,
        );
        let person = result
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Person)
            .expect("person entity");
        assert!(person.has_tag("dob:1990-05-12"), "tags: {:?}", person.tags);
        assert!(person.has_tag("gender:M"), "\"Male\" normalizes to M");
        assert!(person.has_tag("age:34"));

        // A record with no demographics adds no identity tags (and never panics).
        let bare = json!({ "full_name": "Bare Name", "source": "x" });
        let mut seen = HashSet::new();
        let mut result = ModuleResult::new();
        extract_entities(&bare, "Bare Name", "scan", "search", "k", &mut seen, &mut result);
        let p2 = result
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Person)
            .expect("person entity");
        assert!(
            !p2.tags
                .iter()
                .any(|t| t.starts_with("dob:") || t.starts_with("gender:") || t.starts_with("age:")),
            "no demographics => no identity tags; got {:?}",
            p2.tags
        );
    }

    #[test]
    fn provider_internal_record_ids_are_not_minted_as_entities() {
        use serde_json::json;
        // snusbase/see_know stamp `uid` + `migration_id` on every row (their own
        // database keys, not the subject's); they must not leak as Other() junk.
        let item = json!({
            "full_name": "Ali Kareem",
            "uid": "9e15bceb60c0",
            "migration_id": "48217",
            "source": "snusbase"
        });
        let mut seen = HashSet::new();
        let mut result = ModuleResult::new();
        extract_entities(
            &item,
            "Ali Kareem",
            "scan",
            "search",
            "see-know.eu:test",
            &mut seen,
            &mut result,
        );
        assert!(
            !result.entities.iter().any(
                |e| matches!(&e.kind, EntityKind::Other(k) if k == "uid" || k == "migration_id")
            ),
            "provider-internal IDs must not become entities; got {:?}",
            result
                .entities
                .iter()
                .map(|e| (e.kind.to_string(), e.value.clone()))
                .collect::<Vec<_>>()
        );
        // The real field (the person) is still extracted.
        assert!(
            result
                .entities
                .iter()
                .any(|e| e.kind == EntityKind::Person && e.value == "Ali Kareem"),
            "the subject person is still surfaced"
        );
    }

    /// Same real failure mode as `oathnet_pro` (they share this breach schema):
    /// a breach DB stores `full_name = "{username} {username}"` when no real
    /// name is available. Minting `Person("rhino-ryno23 rhino-ryno23")` maps to
    /// `TargetKind::FullName` and spawns a spurious, noise-dominated child scan.
    #[test]
    fn doubled_username_full_name_is_rejected_not_minted_as_person() {
        use serde_json::json;
        let item = json!({
            "full_name": "rhino-ryno23 rhino-ryno23",
            "username": "rhino-ryno23",
            "source": "snusbase"
        });
        let mut seen = HashSet::new();
        let mut result = ModuleResult::new();
        extract_entities(
            &item,
            "rhino-ryno23",
            "scan",
            "search",
            "see-know.eu:test",
            &mut seen,
            &mut result,
        );
        assert!(
            !result.entities.iter().any(|e| e.kind == EntityKind::Person),
            "a username doubled into the full_name field must never mint a Person: {:?}",
            result
                .entities
                .iter()
                .map(|e| (e.kind.to_string(), e.value.clone()))
                .collect::<Vec<_>>()
        );

        // A real name must still be admitted (no false positive from the guard).
        let item2 = json!({ "full_name": "Jordan Avery", "source": "snusbase" });
        let mut seen2 = HashSet::new();
        let mut result2 = ModuleResult::new();
        extract_entities(
            &item2,
            "Jordan Avery",
            "scan",
            "search",
            "see-know.eu:test",
            &mut seen2,
            &mut result2,
        );
        assert!(
            result2
                .entities
                .iter()
                .any(|e| e.kind == EntityKind::Person && e.value == "Jordan Avery"),
            "a real name must still be admitted: {:?}",
            result2.entities
        );
    }

    #[test]
    fn non_matching_record_is_quarantined_as_candidate() {
        use crate::core::entity::CANDIDATE_CONF;
        use serde_json::json;
        // A broad see_know NAME search can return same-name strangers; their PII
        // must be demoted to quarantined `candidate` leads (mirroring
        // oathnet_pro), never minted as the subject at full confidence.
        let stranger =
            json!({ "email": "bob.smith@example.com", "full_name": "Bob Smith", "source": "snusbase" });
        let mut seen = HashSet::new();
        let mut result = ModuleResult::new();
        extract_entities(
            &stranger,
            "Ali Kareem",
            "scan",
            "search",
            "see-know.eu:test",
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
            "stranger email must be quarantined; tags: {:?}",
            email.tags
        );
        assert!(
            email.confidence <= CANDIDATE_CONF + 1e-9,
            "stranger email demoted to candidate confidence"
        );

        // The subject's OWN record stays at full confidence, no candidate tag.
        let subject = json!({
            "email": "ali.kareem@example.com",
            "full_name": "Ali Kareem",
            "source": "snusbase"
        });
        let mut seen = HashSet::new();
        let mut result = ModuleResult::new();
        extract_entities(
            &subject,
            "Ali Kareem",
            "scan",
            "search",
            "see-know.eu:test",
            &mut seen,
            &mut result,
        );
        let email = result
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Email)
            .expect("email entity");
        assert!(!email.has_tag("candidate"), "subject email not quarantined");
        assert!(
            email.confidence > CANDIDATE_CONF,
            "subject email keeps full confidence"
        );
    }

    #[test]
    fn extract_entities_spiders_stealer_url_into_pivots() {
        use serde_json::json;
        // A stealer-log row: a saved credential for a login URL. The URL is the
        // highest-value pivot and must spider into Url + Credential (NOT a Domain —
        // the host is a third-party service the subject uses, not one they own),
        // none tagged `breach` (credential context / infrastructure, not PII).
        let item = json!({
            "dbname": "RedlineStealer",
            "username": "victim_login",
            "password": "hunter2",
            "url": "https://accounts.example.com/login?ref=1",
        });
        let mut seen = HashSet::new();
        let mut result = ModuleResult::new();
        extract_entities(
            &item,
            "victim_login",
            "scan",
            "stealer",
            "see-know.eu:test",
            &mut seen,
            &mut result,
        );

        let find = |k: EntityKind, pred: &dyn Fn(&Entity) -> bool| {
            result.entities.iter().find(|e| e.kind == k && pred(e))
        };
        // Url entity for the captured login surface.
        let url = find(EntityKind::Url, &|e| {
            e.value.contains("accounts.example.com")
        })
        .expect("stealer URL must surface as a Url entity");
        assert!(url.has_tag("stealer") && url.has_tag("see-know"));
        assert!(
            !url.has_tag("breach"),
            "stealer URL must NOT be tagged breach"
        );
        // The URL host must NOT be minted as a Domain: it is a third-party login
        // surface the subject merely uses, and minting it spawned subdomain noise
        // + misdirected crt.sh/DNS/whois expansion of the platform's own infra.
        assert!(
            find(EntityKind::Domain, &|e| e.value == "accounts.example.com").is_none(),
            "stealer URL host must not become a Domain entity"
        );
        // username@url Credential binding.
        assert!(
            find(EntityKind::Credential, &|e| {
                e.value == "victim_login@https://accounts.example.com/login?ref=1"
            })
            .is_some(),
            "login↔surface must surface as a Credential entity"
        );
    }

    #[test]
    fn extract_entities_rejects_non_web_stealer_url_but_keeps_the_credential() {
        use serde_json::json;
        // A stealer row whose `url` is a native-app URI, not a web login surface.
        // It must NOT mint a `Url` entity (the sibling oathnet_pro parser rejects
        // the same value with its scheme+dot gate) — but the login↔surface
        // Credential is still captured (a login for a native surface is real).
        let item = json!({
            "dbname": "RedlineStealer",
            "username": "victim_login",
            "password": "hunter2",
            "url": "android://com.example.app",
        });
        let mut seen = HashSet::new();
        let mut result = ModuleResult::new();
        extract_entities(
            &item,
            "victim_login",
            "scan",
            "stealer",
            "see-know.eu:test",
            &mut seen,
            &mut result,
        );
        assert!(
            !result.entities.iter().any(|e| e.kind == EntityKind::Url),
            "a non-web (scheme-less/native-app) stealer URL must not mint a Url entity"
        );
        assert!(
            result.entities.iter().any(|e| e.kind == EntityKind::Credential
                && e.value == "victim_login@android://com.example.app"),
            "the login↔surface Credential is still captured for a native-app surface"
        );
    }

    #[test]
    fn extract_entities_enriches_a_breach_hash_with_offline_intelligence() {
        use serde_json::json;
        // A breach row carrying a leaked HASH (not a plaintext). The credential path
        // must apply the same offline hash intelligence dehashed/oathnet do: classify
        // the algorithm + crackability and reverse-look-up a common-password digest
        // to recover its plaintext. md5("password") is the canonical weak hash.
        let item = json!({
            "dbname": "TestBreach",
            "email": "victim@example.com",
            "hash": "5f4dcc3b5aa765d61d8327deb882cf99",
        });
        let mut seen = HashSet::new();
        let mut result = ModuleResult::new();
        extract_entities(
            &item,
            "victim@example.com",
            "scan",
            "search",
            "see-know.eu:test",
            &mut seen,
            &mut result,
        );
        let pw_hash = result
            .entities
            .iter()
            .find(|e| {
                e.kind == EntityKind::Password
                    && e.value == "5f4dcc3b5aa765d61d8327deb882cf99"
            })
            .expect("the hash must surface as a Password entity");
        assert!(pw_hash.has_tag("password-hash"), "must classify as a hash");
        assert!(pw_hash.has_tag("hash:md5"), "must identify the algorithm");
        assert!(
            pw_hash.has_tag("crackable:fast"),
            "an unsalted md5 is fast-crackable"
        );
        assert!(
            pw_hash.has_tag("cracked"),
            "a common-password digest must be flagged cracked"
        );
        // The recovered plaintext becomes a first-class node.
        let plain = result
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Password && e.value == "password")
            .expect("the cracked plaintext must surface as a Password entity");
        assert!(plain.has_tag("cracked") && plain.has_tag("from-hash"));

        // A PLAINTEXT password must NOT be mis-enriched (no hash tags, no recovery).
        let mut seen2 = HashSet::new();
        let mut result2 = ModuleResult::new();
        extract_entities(
            &json!({"dbname": "T", "email": "x@y.com", "password": "hunter2"}),
            "x@y.com",
            "scan",
            "search",
            "see-know.eu:test",
            &mut seen2,
            &mut result2,
        );
        let plain_pw = result2
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Password && e.value == "hunter2")
            .expect("plaintext password still surfaces");
        assert!(
            !plain_pw.has_tag("password-hash") && !plain_pw.has_tag("cracked"),
            "a plaintext password must not gain hash tags"
        );
    }

    #[test]
    fn a_dedicated_salt_column_marks_a_fast_hash_salted() {
        use serde_json::json;
        // A fast MD5 shipped with a SEPARATE `salt` column (Snusbase-style schema)
        // must be tagged `salted` — without the column check it was mis-classified
        // as unsalted/rainbow-crackable, overstating exposure. Mirrors OathNet.
        let hash = "a1b2c3d4e5f60718293a4b5c6d7e8f90"; // 32-hex, not a common pw
        let item = json!({ "username": "u", "password_hash": hash, "salt": "deadbeef" });
        let (mut seen, mut result) = (HashSet::new(), ModuleResult::new());
        extract_entities(&item, "u", "scan", "search", "k", &mut seen, &mut result);
        let h = result
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Password && e.value == hash)
            .expect("the hash surfaces as a Password entity");
        assert!(h.has_tag("hash:md5"), "still identified as md5");
        assert!(
            h.has_tag("salted"),
            "a non-empty dedicated salt column must mark the hash salted"
        );

        // Control: the SAME hash with NO salt column stays unsalted.
        let bare = json!({ "username": "u", "password_hash": hash });
        let (mut s2, mut r2) = (HashSet::new(), ModuleResult::new());
        extract_entities(&bare, "u", "scan", "search", "k", &mut s2, &mut r2);
        let h2 = r2
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Password && e.value == hash)
            .expect("hash entity");
        assert!(
            !h2.has_tag("salted"),
            "no appended salt and no salt column ⇒ not salted"
        );
    }

    #[test]
    fn iban_field_is_validated_before_minting_a_financial_node() {
        use serde_json::json;
        let is_iban = |e: &crate::core::entity::Entity| {
            matches!(&e.kind, EntityKind::Other(k) if k == "iban")
        };
        // A valid IBAN (canonical GB test value, in grouped form) mints a financial
        // pivot; the grouped spacing must be normalised before the mod-97 check.
        let valid = json!({ "username": "u", "iban": "GB82 WEST 1234 5698 7654 32" });
        let (mut seen, mut result) = (HashSet::new(), ModuleResult::new());
        extract_entities(&valid, "u", "scan", "search", "k", &mut seen, &mut result);
        let iban = result
            .entities
            .iter()
            .find(|e| is_iban(e))
            .expect("a valid IBAN must mint an Other(\"iban\") node");
        assert!(iban.has_tag("financial"), "a validated IBAN is tagged financial");

        // A bad check digit must mint NOTHING — no bogus financial artifact.
        let bad = json!({ "username": "u", "iban": "GB82 WEST 1234 5698 7654 99" });
        let (mut s2, mut r2) = (HashSet::new(), ModuleResult::new());
        extract_entities(&bad, "u", "scan", "search", "k", &mut s2, &mut r2);
        assert!(
            !r2.entities.iter().any(is_iban),
            "an invalid IBAN must not mint a financial artifact"
        );
    }

    #[test]
    fn domain_intel_subdomains_mint_only_the_targets_own_tree() {
        use serde_json::json;
        let item = json!({
            "domain": "acme.com",
            "subdomains": ["mail.acme.com", "vpn.acme.com", "evil.example.net"],
        });
        let has_dom = |r: &ModuleResult, v: &str| {
            r.entities
                .iter()
                .any(|e| e.kind == EntityKind::Domain && e.value == v)
        };

        let (mut seen, mut result) = (HashSet::new(), ModuleResult::new());
        extract_entities(
            &item,
            "acme.com",
            "scan",
            "domain_intel",
            "k",
            &mut seen,
            &mut result,
        );
        assert!(has_dom(&result, "mail.acme.com"), "target subdomain minted");
        assert!(has_dom(&result, "vpn.acme.com"), "target subdomain minted");
        assert!(
            !has_dom(&result, "evil.example.net"),
            "a third-party host in the array must NOT be minted"
        );
        let sd = result
            .entities
            .iter()
            .find(|e| e.value == "mail.acme.com")
            .unwrap();
        assert!(sd.has_tag("subdomain") && !sd.has_tag("breach"));

        // Endpoint gate: the SAME record via a non-domain_intel endpoint mints
        // no subdomains (only /domain/intel returns a subdomains array).
        let (mut s2, mut r2) = (HashSet::new(), ModuleResult::new());
        extract_entities(&item, "acme.com", "scan", "search", "k", &mut s2, &mut r2);
        assert!(
            !has_dom(&r2, "mail.acme.com"),
            "subdomains are only minted for the domain_intel endpoint"
        );
    }

    #[test]
    fn discord_connected_accounts_mint_cross_platform_pivots() {
        use serde_json::json;
        let item = json!({
            "discord_id": "80351110224678912",
            "connected_accounts": [
                { "type": "steam", "id": "76561197960287930", "name": "gaben" },
                { "type": "twitch", "id": "44322889", "name": "ninja" },
                { "type": "reddit", "name": "spez" },
                // Junk shapes that must be ignored.
                { "type": "", "name": "x" },
                { "id": "no-type" },
            ],
        });
        let has_u = |r: &ModuleResult, v: &str| {
            r.entities
                .iter()
                .any(|e| e.kind == EntityKind::Username && e.value == v)
        };
        let (mut seen, mut result) = (HashSet::new(), ModuleResult::new());
        extract_entities(
            &item,
            "80351110224678912",
            "scan",
            "discord_user",
            "k",
            &mut seen,
            &mut result,
        );
        // Steam link → the pivot-feeding `steam:<id>` shape (fed to the steam pivot).
        assert!(
            has_u(&result, "steam:76561197960287930"),
            "a steam connected_account must mint the steam:<id> pivot"
        );
        // Other platforms → `{type}:{handle}` (name preferred, id fallback).
        assert!(has_u(&result, "twitch:ninja"), "twitch handle pivot");
        assert!(has_u(&result, "reddit:spez"), "reddit handle pivot");
        // Malformed entries must be ignored (no empty-type / no-handle nodes).
        assert!(
            !result
                .entities
                .iter()
                .any(|e| e.kind == EntityKind::Username && e.value.starts_with(':')),
            "an entry with an empty type must not mint a node"
        );
        let tw = result
            .entities
            .iter()
            .find(|e| e.value == "twitch:ninja")
            .unwrap();
        assert!(tw.has_tag("discord-linked") && tw.has_tag("twitch"));
    }

    #[test]
    fn record_evidence_stamps_canonical_dbname_for_au105() {
        use serde_json::json;
        // AU-105 (credential reuse across breaches) groups records by the `dbname`
        // evidence attribute. SeekNow labels the breach under `source` (renamed to
        // `source_db` when folding the raw field), so a record that carries the
        // breach name in `source` with NO `dbname` field previously produced NO
        // `dbname` attribute at all — AU-105 then fell back to the module name and
        // collapsed every SeekNow record into one pseudo-breach. The breach name
        // must be stamped under the canonical `dbname` attr.
        let item = json!({
            "source": "TestBreach",
            "email": "victim@example.com",
            "password": "reused-secret-1",
        });
        let mut seen = HashSet::new();
        let mut result = ModuleResult::new();
        extract_entities(
            &item,
            "victim@example.com",
            "scan",
            "search",
            "see-know.eu:test",
            &mut seen,
            &mut result,
        );
        let email = result
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Email && e.value == "victim@example.com")
            .expect("the subject email entity");
        assert_eq!(
            email.evidence[0].attributes.get("dbname").map(String::as_str),
            Some("TestBreach"),
            "the breach name must be on the canonical `dbname` attr AU-105 reads"
        );
    }

    #[test]
    fn record_evidence_stamps_canonical_postcode_for_au091() {
        use serde_json::json;
        // AU-091/AU-093 (AU residential locality) read a subject's postcode from
        // the canonical `postcode` key. SeekNow labels it `postal`, which the rule
        // never inspects (widening its shared POSTCODE_KEYS is unsafe — the IP-geo
        // modules also stamp `postal`, a network-derived class). The breach
        // record's self-reported postcode must be aliased to `postcode` at the
        // producer, leaving the raw `postal` intact.
        let item = json!({
            "dbname": "TestBreach",
            "email": "victim@example.com",
            "postal": "4000",
        });
        let mut seen = HashSet::new();
        let mut result = ModuleResult::new();
        extract_entities(
            &item,
            "victim@example.com",
            "scan",
            "search",
            "see-know.eu:test",
            &mut seen,
            &mut result,
        );
        let ev = &result
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Email && e.value == "victim@example.com")
            .expect("the subject email entity")
            .evidence[0];
        assert_eq!(
            ev.attributes.get("postcode").map(String::as_str),
            Some("4000"),
            "the self-reported postcode must be on the canonical `postcode` attr AU-091 reads"
        );
        assert_eq!(
            ev.attributes.get("postal").map(String::as_str),
            Some("4000"),
            "the raw `postal` attribute is retained for existing consumers"
        );

        // A record that already carries a canonical `postcode` must keep it — the
        // `postal`-derived alias never overrides a real value.
        let item2 = json!({
            "dbname": "TestBreach",
            "email": "victim@example.com",
            "postcode": "2000",
            "postal": "4000",
        });
        let mut seen2 = HashSet::new();
        let mut result2 = ModuleResult::new();
        extract_entities(
            &item2,
            "victim@example.com",
            "scan",
            "search",
            "see-know.eu:test",
            &mut seen2,
            &mut result2,
        );
        let ev2 = &result2
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Email && e.value == "victim@example.com")
            .expect("the subject email entity")
            .evidence[0];
        assert_eq!(
            ev2.attributes.get("postcode").map(String::as_str),
            Some("2000"),
            "a real `postcode` must not be overridden by the `postal` alias"
        );
    }

    #[test]
    fn extract_rich_detail_surfaces_the_whole_record() {
        use serde_json::json;
        // A fat record with the long tail SeekNow returns: composed name, org,
        // device fingerprints, extra social handles, a multi-part address, and
        // an unrecognised field. Every one must become a pivotable node.
        let item = json!({
            "first_name": "Jordan",
            "last_name": "Avery",
            "company": "Acme Pty Ltd",
            "mac_address": "DC:44:27:AA:BB:CC",
            "hwid": "WIN-ABC123XYZ",
            "telegram": "javery",
            "city": "Brisbane",
            "state": "QLD",
            "postal": "4000",
            "country": "AU",
            "gender": "M",
            "ip_country_code": "AU"
        });
        let mut seen = HashSet::new();
        let mut result = ModuleResult::new();
        extract_entities(
            &item,
            "x",
            "scan",
            "search",
            "see-know.eu:test",
            &mut seen,
            &mut result,
        );

        let has = |k: EntityKind, pred: &dyn Fn(&Entity) -> bool| {
            result.entities.iter().any(|e| e.kind == k && pred(e))
        };
        // Composed Person from first+last.
        assert!(has(EntityKind::Person, &|e| e.value == "Jordan Avery"));
        // Organisation.
        assert!(has(EntityKind::Organisation, &|e| e.value == "Acme Pty Ltd"));
        // Device fingerprints.
        assert!(has(EntityKind::MacAddress, &|e| e
            .value
            .to_lowercase()
            .contains("dc:44:27")));
        assert!(has(EntityKind::DeviceId, &|e| e.value == "WIN-ABC123XYZ"
            && e.has_tag("stealer")));
        // Extra social handle as a platform-prefixed Username.
        assert!(has(EntityKind::Username, &|e| e.value == "telegram:javery"));
        // Composed multi-part address (parts + country).
        assert!(has(EntityKind::Address, &|e| e.value.contains("Brisbane")
            && e.value.contains("AU")
            && e.has_tag("composed-address")));
        // Catch-all: unrecognised value-bearing fields become Other(field) nodes
        // tagged raw-field — NOTHING is dropped.
        assert!(has(EntityKind::Other("gender".into()), &|e| e.value == "M"
            && e.has_tag("raw-field")));
        assert!(has(EntityKind::Other("ip_country_code".into()), &|e| e
            .value
            == "AU"));
        // Structural/metadata keys never become standalone nodes.
        assert!(
            !result
                .entities
                .iter()
                .any(|e| matches!(&e.kind, EntityKind::Other(k) if k == "first_name"))
        );
    }

    #[test]
    fn extract_geo_entities_characterization() {
        use serde_json::json;

        // Coordinates from f64 fields, tagged with the endpoint.
        {
            let (mut seen, mut r) = (HashSet::new(), ModuleResult::new());
            extract_geo_entities(
                &json!({"lat": 40.7128, "lon": -74.0060}),
                "ip_info",
                "s",
                &mut seen,
                &mut r,
            );
            assert!(
                r.entities
                    .iter()
                    .any(|e| e.kind == EntityKind::Coordinates && e.has_tag("via:ip_info")),
                "f64 coords"
            );
        }
        // Coordinates from STRING fields (the dual f64/str parse path).
        {
            let (mut seen, mut r) = (HashSet::new(), ModuleResult::new());
            extract_geo_entities(
                &json!({"latitude": "51.5", "longitude": "-0.12"}),
                "phone_info",
                "s",
                &mut seen,
                &mut r,
            );
            assert!(
                r.entities.iter().any(|e| e.kind == EntityKind::Coordinates),
                "string coords"
            );
        }
        // Out-of-range coordinates are rejected.
        {
            let (mut seen, mut r) = (HashSet::new(), ModuleResult::new());
            extract_geo_entities(
                &json!({"lat": 999.0, "lon": 0.0}),
                "ip_info",
                "s",
                &mut seen,
                &mut r,
            );
            assert!(
                !r.entities.iter().any(|e| e.kind == EntityKind::Coordinates),
                "out-of-range rejected"
            );
        }
        // Null Island (0,0) is rejected — common null-location value in breach
        // aggregator records; the shared validator drops it.
        {
            let (mut seen, mut r) = (HashSet::new(), ModuleResult::new());
            extract_geo_entities(
                &json!({"lat": 0.0, "lon": 0.0}),
                "ip_info",
                "s",
                &mut seen,
                &mut r,
            );
            assert!(
                !r.entities.iter().any(|e| e.kind == EntityKind::Coordinates),
                "Null Island rejected"
            );
        }
        // Location hint, timezone, ASN + org (ip_info only).
        {
            let (mut seen, mut r) = (HashSet::new(), ModuleResult::new());
            extract_geo_entities(
                &json!({"location": "Sydney, NSW", "timezone": "Australia/Sydney", "asn": "AS15169", "org": "Google"}),
                "ip_info",
                "s",
                &mut seen,
                &mut r,
            );
            assert!(
                r.entities
                    .iter()
                    .any(|e| e.value == "Sydney, NSW" && e.has_tag("geo-hint"))
            );
            assert!(
                r.entities
                    .iter()
                    .any(|e| e.value == "tz:Australia/Sydney" && e.has_tag("timezone"))
            );
            assert!(
                r.entities
                    .iter()
                    .any(|e| e.kind == EntityKind::Asn && e.value == "AS15169")
            );
            assert!(
                r.entities
                    .iter()
                    .any(|e| e.kind == EntityKind::Organisation)
            );
        }
        // ASN/org gated to the ip_info endpoint.
        {
            let (mut seen, mut r) = (HashSet::new(), ModuleResult::new());
            extract_geo_entities(&json!({"asn": "AS1"}), "phone_info", "s", &mut seen, &mut r);
            assert!(!r.entities.iter().any(|e| e.kind == EntityKind::Asn));
        }
        // WHOIS registrant address (>= 2 parts) on the whois endpoint.
        {
            let (mut seen, mut r) = (HashSet::new(), ModuleResult::new());
            extract_geo_entities(
                &json!({"registrant_city": "Reno", "registrant_state": "NV", "registrant_country": "US"}),
                "whois",
                "s",
                &mut seen,
                &mut r,
            );
            assert!(
                r.entities
                    .iter()
                    .any(|e| e.value == "Reno, NV, US" && e.has_tag("whois-registrant"))
            );
        }
    }

    #[test]
    fn accepts_six_target_kinds() {
        let m = SeekNow;
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
        assert!(matches!(SeekNow.cost(), ModuleCost::Paid));
    }

    #[test]
    fn is_the_highest_priority_module_at_all_times() {
        // Operator directive: SeekNow is THE highest-priority API, always queried
        // first. Pin it to the maximum AND against the WHOLE registry, so neither
        // a new module nor a priority retune can ever silently out-rank it.
        let p = SeekNow.priority();
        assert_eq!(p, u8::MAX, "SeekNow must be pinned to the maximum priority");
        for m in crate::modules::registry() {
            assert!(
                p >= m.priority(),
                "SeekNow ({p}) must be >= every module's priority; {} is {}",
                m.name(),
                m.priority()
            );
        }
    }

    #[test]
    fn category_is_breach() {
        assert_eq!(SeekNow.category(), ModuleCategory::Breach);
    }

    #[test]
    fn attack_techniques_credit_the_full_recon_surface() {
        use crate::core::attack;
        let t = SeekNow.attack_techniques();
        // Superset of the Breach category default — SeekNow genuinely returns
        // leaked credentials and emails, so the precise mapping must still claim
        // them (regression guard against silently narrowing the override).
        for default in attack::techniques_for_category(ModuleCategory::Breach) {
            assert!(
                t.contains(default),
                "see_know mapping must keep the Breach default {default}, got {t:?}"
            );
        }
        // …plus the additional surfaces its extractors actually gather, so the
        // per-scan ATT&CK coverage report credits them: employee names, physical
        // location, org relationships, host fingerprints, and social handles.
        for id in [
            "T1589.003", // Employee Names
            "T1590.005", // IP Addresses
            "T1591.001", // Physical Locations
            "T1591.002", // Business Relationships
            "T1592",     // Host Information (device fingerprints)
            "T1593.001", // Social Media
            "T1597.002", // Purchase Technical Data (paid closed corpus)
        ] {
            assert!(t.contains(&id), "see_know must claim {id}");
            assert!(attack::technique(id).is_some(), "{id} must be catalogued");
        }
    }

    #[test]
    fn produces_includes_geo_and_identity_kinds() {
        let kinds = SeekNow.produces();
        assert!(kinds.contains(&EntityKind::Coordinates));
        assert!(kinds.contains(&EntityKind::Address));
        assert!(kinds.contains(&EntityKind::Email));
        assert!(kinds.contains(&EntityKind::Username));
        assert!(kinds.contains(&EntityKind::Phone));
        assert!(kinds.contains(&EntityKind::ApiKey));
        // The shared key_harvest path also emits CryptoAddress — declared so the
        // producer graph matches what process() actually emits.
        assert!(kinds.contains(&EntityKind::CryptoAddress));
    }

    #[tokio::test]
    async fn resolve_identity_pivots_is_noop_and_terminates_without_ids() {
        // A graph with no discord:/steam: IDs converges on the first hop with
        // no HTTP and no new entities — the termination guarantee on the empty
        // case (the multi-hop network behaviour is covered at the util layer).
        crate::util::see_know::reset_budget();
        let mut seen = HashSet::new();
        let mut result = ModuleResult::new();
        result.push(Entity::new(EntityKind::Email, "a@b.com", 0.8, "t"));
        let before = result.entities.len();
        resolve_identity_pivots(
            "key",
            "see-know.eu:test",
            "seed",
            "t",
            &mut seen,
            &mut result,
        )
        .await;
        assert_eq!(
            result.entities.len(),
            before,
            "no pivot IDs ⇒ no dispatch, no growth, clean halt"
        );
    }

    #[test]
    fn extract_pivot_entities_also_harvests_a_leaked_key_from_a_pivot_response() {
        // The identity-pivot responses (discord/user, discord/to-roblox,
        // gaming/steam) were the one SeekNow data-ingestion point that skipped
        // the key-harvest pass every other endpoint already runs every item
        // through. A linked account's own response can carry a `token`/
        // `password`/`note` field exactly like a breach/search row does —
        // this proves `extract_pivot_entities` now reaches it too, not just
        // identity/geo/message extraction.
        let items = vec![(
            "discord_user",
            vec![serde_json::json!({
                "id": "123456789012345678",
                // AWS access-key shape — the same synthetic fixture
                // `util::key_harvest`'s own orchestrator tests use.
                "token": "AKIAJK28SLQQV61MNG9X",
            })],
        )];
        let mut seen = HashSet::new();
        let mut result = ModuleResult::new();
        extract_pivot_entities(&items, "seed", "t", "see-know.eu:test", &mut seen, &mut result);
        assert!(
            result
                .entities
                .iter()
                .any(|e| e.kind == EntityKind::ApiKey && e.has_tag("service:aws")),
            "expected an AWS ApiKey entity harvested from the pivot response's \
             `token` field, got: {:?}",
            result.entities.iter().map(|e| &e.kind).collect::<Vec<_>>()
        );
    }

    // ── /search/deep fallback (T-current: the largest documented,
    //    previously-unwired SeekNow coverage gap) ────────────────────────

    #[test]
    fn deep_search_fires_only_on_a_typed_query_that_drew_a_genuine_blank() {
        // The core policy this fallback exists to express: never spend the
        // extra ~40s latency when fast /search already found something, and
        // never on the auto/name path (excluded — see `max_timeout_ms`'s doc
        // comment for the timeout-budget arithmetic this protects).
        assert!(
            should_try_deep_search(0, "email", false),
            "a genuine typed miss must trigger the fallback"
        );
        assert!(
            !should_try_deep_search(1, "email", false),
            "a typed HIT must never trigger the fallback — wasted latency+quota"
        );
        assert!(
            !should_try_deep_search(0, "", false),
            "the auto/name path (empty query_type) must never chain deep search"
        );
        assert!(
            !should_try_deep_search(0, "email", true),
            "a cancelled scan must never trigger a fresh ~40s call"
        );
    }

    #[test]
    fn deep_search_max_timeout_covers_the_typed_fast_plus_deep_worst_case() {
        // 110s must comfortably exceed both the pre-existing single-call
        // worst case (~60s, name/auto path, unaffected by this change) and
        // the new chained worst case (typed fast ~15s + deep ~45s ≈ 60s) with
        // real headroom — never regress to a budget that risks a spurious
        // module-level timeout truncating a real deep-search response.
        assert!(SeekNow.max_timeout_ms() >= 100_000);
    }

    #[test]
    fn absorb_search_hits_builds_the_breach_parent_and_extracts_records_for_the_deep_endpoint() {
        // Proves the refactored helper generalises correctly to the NEW
        // /search/deep call site (not just the pre-existing fast /search
        // behaviour the old inline code covered) — same construction, only
        // the endpoint labels differ.
        let target = Target::new(TargetKind::Email, "subject@example.com");
        let items = vec![serde_json::json!({
            "email": "subject@example.com",
            "dbname": "examplebreach.com",
        })];
        let mut seen: HashSet<String> = HashSet::new();
        let mut result = ModuleResult::new();
        absorb_search_hits(
            &items,
            &target,
            "subject@example.com",
            "/api/v1/search/deep",
            "search/deep",
            "see-know.eu:test",
            "scan-1",
            &mut seen,
            &mut result,
        );

        let parent = result
            .entities
            .iter()
            .find(|e| e.value == "subject@example.com" && e.has_tag(crate::core::tags::BREACH))
            .expect("a BREACH parent entity for the matched subject");
        assert!(parent.has_tag("see-know"));
        let ev = &parent.evidence[0];
        assert_eq!(
            ev.attributes.get("endpoint").map(String::as_str),
            Some("/api/v1/search/deep"),
            "the deep endpoint's own path must be recorded, not fast /search's"
        );
        assert!(
            ev.summary.contains("/api/v1/search/deep"),
            "the evidence summary must name the endpoint that actually produced the hit: {}",
            ev.summary
        );
    }

    #[test]
    fn absorb_search_hits_skips_the_breach_parent_when_no_row_matches_the_subject() {
        // A broad seed can return term-sharing strangers; the parent stamp
        // must stay gated on `search_subject_present`, exactly as the
        // pre-refactor inline fast-path logic did.
        let target = Target::new(TargetKind::Email, "subject@example.com");
        let items = vec![serde_json::json!({
            "email": "someone-else@example.com",
            "dbname": "examplebreach.com",
        })];
        let mut seen: HashSet<String> = HashSet::new();
        let mut result = ModuleResult::new();
        absorb_search_hits(
            &items,
            &target,
            "subject@example.com",
            "/api/v1/search",
            "search",
            "see-know.eu:test",
            "scan-1",
            &mut seen,
            &mut result,
        );
        assert!(
            !result
                .entities
                .iter()
                .any(|e| e.value == "subject@example.com" && e.has_tag(crate::core::tags::BREACH)),
            "no row identified the subject — no BREACH parent should be minted"
        );
    }

    #[test]
    fn absorb_search_hits_extracts_geo_from_search_records() {
        // Regression: `/search` and `/search/deep` are SeekNow's broadest,
        // highest-yield calls, yet this absorption path used to skip
        // `extract_geo_entities` (the per-endpoint dispatch path and the pivot
        // path both already called it), silently dropping every coordinate /
        // timezone / location lead from the module's single most productive
        // endpoint. A `/search` record carrying a lat/lon pair must now mint a
        // Coordinates lead so the downstream geocode/overpass/wigle correlators
        // get it.
        let target = Target::new(TargetKind::Email, "subject@example.com");
        let items = vec![serde_json::json!({
            "email": "subject@example.com",
            "dbname": "examplebreach.com",
            "latitude": 40.7128,
            "longitude": -74.0060,
        })];
        let mut seen: HashSet<String> = HashSet::new();
        let mut result = ModuleResult::new();
        absorb_search_hits(
            &items,
            &target,
            "subject@example.com",
            "/api/v1/search",
            "search",
            "see-know.eu:test",
            "scan-1",
            &mut seen,
            &mut result,
        );
        assert!(
            result
                .entities
                .iter()
                .any(|e| e.kind == EntityKind::Coordinates && e.has_tag("via:search")),
            "a Coordinates lead from the /search record must now be extracted — \
             it was dropped before the geo wiring was added to absorb_search_hits"
        );
    }
