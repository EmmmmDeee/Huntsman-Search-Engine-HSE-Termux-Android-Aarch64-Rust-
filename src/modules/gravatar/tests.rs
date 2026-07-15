use super::*;
// `Account` is only constructed by the legacy-string test below; the module
// body doesn't name it, so import it here (test-only) rather than in `mod.rs`
// where it would be an unused import in non-test builds.
use crate::util::gravatar::Account;

    #[test]
    fn gravatar_hash_is_md5_of_lowercased_trimmed_email() {
        // Documented Gravatar example: MD5("MyEmailAddress@example.com " trimmed
        // + lowercased) — the canonical hash for that address.
        assert_eq!(
            gravatar_hash("  MyEmailAddress@example.com "),
            "0bc83cb571cd1c50ba6f3e8a78ef1346"
        );
        // Case/space insensitivity.
        assert_eq!(
            gravatar_hash("matt@example.com"),
            gravatar_hash("  MATT@Example.COM  ")
        );
    }

    #[test]
    fn extract_entry_emits_the_full_identity_graph() {
        let json = serde_json::json!({
            "hash": "abc",
            "profileUrl": "https://gravatar.com/matt",
            "preferredUsername": "matt",
            "thumbnailUrl": "https://gravatar.com/avatar/abc",
            "displayName": "Matt D",
            "name": { "formatted": "Jordan Avery", "givenName": "Jordan", "familyName": "Avery" },
            "currentLocation": "Brisbane, QLD",
            "accounts": [
                { "shortname": "github", "username": "javery", "url": "https://github.com/javery", "verified": "true" },
                { "shortname": "twitter", "username": "mattd", "url": "https://twitter.com/mattd", "verified": "false" }
            ],
            "urls": [ { "value": "https://javery.dev", "title": "Blog" } ]
        });
        let entry: Entry = serde_json::from_value(json).unwrap();
        let mut r = ModuleResult::new();
        extract_entry(&entry, "abc", "scan", &mut r);

        let has = |k: EntityKind, v: &str| r.entities.iter().any(|e| e.kind == k && e.value == v);
        assert!(has(EntityKind::Person, "Jordan Avery"));
        assert!(has(EntityKind::Username, "matt"));
        assert!(has(EntityKind::Address, "Brisbane, QLD"));
        assert!(has(EntityKind::Url, "https://gravatar.com/matt"));
        assert!(has(EntityKind::Url, "https://javery.dev"));
        // The owner's self-asserted link label (UrlEntry.title) is now carried
        // as `link_title` evidence on the personal-URL entity.
        let blog = r
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Url && e.value == "https://javery.dev")
            .expect("personal url entity");
        assert_eq!(
            blog.evidence[0].attributes.get("link_title").map(String::as_str),
            Some("Blog")
        );
        // Bare platform usernames (platform tag, not prefixed value) + their URLs.
        assert!(has(EntityKind::Username, "javery"), "github username bare");
        assert!(has(EntityKind::Username, "mattd"), "twitter username bare");
        assert!(has(EntityKind::Url, "https://github.com/javery"));
        // Platform tag + gravatar-pivot tag carried on account usernames.
        assert!(
            r.entities
                .iter()
                .any(|e| e.value == "javery" && e.has_tag("github") && e.has_tag("verified"))
        );
        assert!(
            r.entities
                .iter()
                .any(|e| e.value == "mattd" && e.has_tag("twitter") && !e.has_tag("verified"))
        );
        // Every entity carries the gravatar source tag + the profile evidence.
        assert!(r.entities.iter().all(|e| e.has_tag("gravatar")));
    }

    #[test]
    fn extract_entry_is_quiet_on_an_empty_profile() {
        let entry = Entry::default();
        let mut r = ModuleResult::new();
        extract_entry(&entry, "h", "scan", &mut r);
        assert!(r.entities.is_empty(), "no fields ⇒ no entities");
    }

    #[test]
    fn module_metadata() {
        let m = Gravatar;
        assert_eq!(m.name(), "gravatar");
        assert!(!m.description().is_empty());
        assert!(m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "y.com")));
        assert!(!m.attack_techniques().is_empty());
    }

    #[test]
    fn gravatar_profile_url_uses_hash() {
        let hash = gravatar_hash("matt@example.com");
        // The lookup URL is "https://gravatar.com/{hash}.json"
        let expected_url = format!("https://gravatar.com/{hash}.json");
        assert!(expected_url.contains(&hash));
        assert!(expected_url.ends_with(".json"));
    }

    #[test]
    fn real_profile_response_with_boolean_verified_parses_and_yields_entities() {
        // Real body fetched live 2026-07-14 from
        // gravatar.com/205e460b479e2e5b48aec07710c08d50.json (Gravatar's own
        // documented example profile). `accounts[0].verified` is a genuine JSON
        // `true`, not the string `"true"` `Account::verified` used to require —
        // before the fix this failed `serde_json::from_str` outright (the error
        // was `invalid type: boolean true, expected a string`), and because
        // `Entry` nests inside `GravatarResp`, that one field's type mismatch
        // failed the WHOLE profile parse. `process()` folds any parse error into
        // the same "no Gravatar profile" empty result as a real 404, so every
        // profile with a linked account — the common, valuable case — was
        // silently dropped as a false miss.
        let body = r##"{"entry":[{"hash":"22bd03ace6f176bfe0c593650bcf45d8","requestHash":"205e460b479e2e5b48aec07710c08d50","profileUrl":"https://gravatar.com/beau","preferredUsername":"beau","thumbnailUrl":"https://0.gravatar.com/avatar/22bd03ace6f176bfe0c593650bcf45d8","photos":[{"value":"https://0.gravatar.com/avatar/22bd03ace6f176bfe0c593650bcf45d8","type":"thumbnail"}],"displayName":"Beau Lebens","pronouns":"he/him","aboutMe":"Lead of WooCommerce, at Automattic.","currentLocation":"Golden, CO","job_title":"Lead, WooCommerce","company":"Automattic","contactInfo":[{"type":"contactform","value":"https://beau.blog/about"}],"emails":[{"primary":"true","value":"beau@automattic.com"}],"accounts":[{"domain":"x.com","display":"@beaulebens","url":"https://x.com/beaulebens","iconUrl":"https://gravatar.com/icons/x.svg","is_hidden":false,"username":"beaulebens","verified":true,"name":"X","shortname":"twitter"}],"profileBackground":{"url":"https://2.gravatar.com/bg/1428/5eb8482783a9b095bc8c43399f845ad2","color":"#7a866a","opacity":1,"primaryColor":"#566039"}}]}"##;
        let parsed: GravatarResp =
            serde_json::from_str(body).expect("the real, live API response shape must parse");
        let entry = parsed.entry.into_iter().next().expect("one entry");

        let mut r = ModuleResult::new();
        extract_entry(&entry, "22bd03ace6f176bfe0c593650bcf45d8", "scan", &mut r);

        // The bare-username pivot from the (correctly parsed) verified account,
        // tagged both with the platform and "verified".
        assert!(
            r.entities
                .iter()
                .any(|e| e.kind == EntityKind::Username
                    && e.value == "beaulebens"
                    && e.has_tag("twitter")
                    && e.has_tag("verified")),
            "verified account should yield a tagged Username pivot: {:?}",
            r.entities
        );
        // The rest of the profile survives too — it was previously lost
        // wholesale by the same parse failure.
        assert!(r.entities.iter().any(|e| e.kind == EntityKind::Person));
        assert!(
            r.entities
                .iter()
                .any(|e| e.kind == EntityKind::Address && e.value == "Golden, CO")
        );
    }

    #[test]
    fn resolve_profile_propagates_a_genuine_fetch_error_instead_of_masking_it_as_no_profile() {
        // T2.112: before this fix, `process()` folded EVERY `Err` from the
        // fetch — a 429, a 5xx, or a transport failure even the curl
        // fallback couldn't rescue — into the same clean `Ok(empty)` a real
        // "no Gravatar profile" 404 produces, making a genuine outage
        // indistinguishable from a negative result.
        let err = crate::core::error::Error::module("gravatar", "simulated 503 from gravatar.com");
        let result = resolve_profile(Err(err), "deadbeef", "scan-1");
        assert!(
            result.is_err(),
            "a genuine fetch error must propagate, not collapse into Ok(empty)"
        );
    }

    #[test]
    fn resolve_profile_treats_a_confirmed_404_as_a_clean_miss() {
        // Gravatar's real, live-confirmed "no such profile" signal (a 404 —
        // reconfirmed live 2026-07-15 against a random unregistered email);
        // `fetch_json_or_404` maps it to `Ok(None)` before any body is read.
        let result = resolve_profile(Ok(None), "deadbeef", "scan-1").unwrap();
        assert!(result.entities.is_empty());
    }

    #[test]
    fn resolve_profile_builds_entities_from_a_real_profile() {
        let resp: GravatarResp =
            serde_json::from_str(r#"{"entry":[{"preferredUsername":"matt"}]}"#).unwrap();
        let result = resolve_profile(Ok(Some(resp)), "deadbeef", "scan-1").unwrap();
        assert!(
            result
                .entities
                .iter()
                .any(|e| e.kind == EntityKind::Username && e.value == "matt")
        );
    }

    #[test]
    fn resolve_profile_is_a_clean_miss_when_the_profile_has_no_entry() {
        // A `200` whose `entry` array is empty (no linked identity data) is
        // not an error either — just nothing to extract.
        let resp: GravatarResp = serde_json::from_str(r#"{"entry":[]}"#).unwrap();
        let result = resolve_profile(Ok(Some(resp)), "deadbeef", "scan-1").unwrap();
        assert!(result.entities.is_empty());
    }

    #[test]
    fn account_verified_accepts_legacy_string_shape_too() {
        // The field was originally typed for the string "true"/"false" shape;
        // the fix must stay backward-compatible with it, not just add the bool
        // shape.
        let json = serde_json::json!({"shortname": "github", "verified": "true"});
        let acct: Account = serde_json::from_value(json).unwrap();
        assert_eq!(acct.verified, Some(true));

        let json = serde_json::json!({"shortname": "github", "verified": "false"});
        let acct: Account = serde_json::from_value(json).unwrap();
        assert_eq!(acct.verified, Some(false));

        let json = serde_json::json!({"shortname": "github"});
        let acct: Account = serde_json::from_value(json).unwrap();
        assert_eq!(acct.verified, None);
    }
