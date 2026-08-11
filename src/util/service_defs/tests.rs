use super::*;

    #[test]
    fn poolable_only_for_recognised_providers() {
        // Recognised keyed providers (in SERVICE_DEFS) are poolable...
        assert!(is_poolable_service("shodan"));
        assert!(is_poolable_service("SHODAN")); // case-insensitive
        // ...while catch-all / non-service "key" tags are NOT — these were the
        // unbounded pool-bloat source (8668 `generic_hex` blobs → 4 MB pool).
        assert!(!is_poolable_service("generic_hex"));
        assert!(!is_poolable_service("jwt_token"));
        assert!(!is_poolable_service("crypto_sol"));
        assert!(!is_poolable_service("unknown"));
    }

    #[test]
    fn find_service_is_case_insensitive() {
        assert!(find_service("shodan").is_some());
        assert!(find_service("SHODAN").is_some());
        assert!(find_service("Shodan").is_some());
        assert!(find_service("nonexistent_service_xyz").is_none());
    }

    #[test]
    fn rate_limit_reset_uses_service_value() {
        // shodan has 300s reset; virustotal has 15s reset.
        assert_eq!(rate_limit_reset("shodan"), 300);
        assert_eq!(rate_limit_reset("virustotal"), 15);
    }

    #[test]
    fn rate_limit_reset_defaults_to_3600_for_unknown() {
        assert_eq!(rate_limit_reset("nonexistent_xyz"), 3600);
    }

    #[test]
    fn service_defs_is_non_empty_and_has_unique_names() {
        let defs = service_defs();
        assert!(!defs.is_empty());
        let mut names: Vec<&str> = defs.iter().map(|d| d.name).collect();
        let orig_len = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), orig_len, "service names must be unique");
    }

    #[test]
    fn see_know_validation_probe_uses_x_api_key_not_bearer() {
        // The see-know.eu server REJECTS `Authorization: Bearer` with "Missing API
        // key. Use X-API-Key" (see see_know/client.rs, AuthScheme::XApiKey). The
        // key-validation probe reads this ServiceDef, so it must send the same
        // header the real client does — otherwise a VALID see_know key is probed
        // with the wrong header, 401s, and is mis-reported as invalid.
        let def = find_service("see_know").expect("see_know service def present");
        match &def.key_header {
            KeyPlacement::Header(h) => assert_eq!(*h, "X-API-Key"),
            other => panic!("see_know must authenticate with X-API-Key, got {other:?}"),
        }
    }

    #[test]
    fn netlas_validation_probe_uses_x_api_key_not_bearer() {
        // The netlas module (modules/netlas/mod.rs) and api_key_probe both send an
        // `X-API-Key` header, so the ServiceDef the validator reads must match — a
        // `BearerAuth` probe would 401 a VALID netlas key and mis-report it invalid.
        let def = find_service("netlas").expect("netlas service def present");
        match &def.key_header {
            KeyPlacement::Header(h) => assert_eq!(*h, "X-API-Key"),
            other => panic!("netlas must authenticate with X-API-Key, got {other:?}"),
        }
    }

    // ── Nine services that had zero key-pool integration (2026-07-14 fix):
    // never poolable, invisible on the health dashboard, and the documented
    // `KEY=a,b,c` multi-key convention silently broken for them. One test per
    // service confirms it is now findable/poolable AND authenticates with the
    // exact scheme its own module code uses — the `see_know`/`netlas` tests
    // above are the precedent for why the latter matters: a mismatched
    // `key_header` makes the validator 401 a genuinely valid key.

    #[test]
    fn github_is_poolable_and_uses_bearer_auth() {
        // github_user/github_code_search/github_commits all call
        // `req.bearer_auth(token)` / `Authorization: Bearer <token>`.
        assert!(is_poolable_service("github"));
        let def = find_service("github").expect("github service def present");
        assert_eq!(def.env_var, "HUNTSMAN_GITHUB_TOKEN");
        assert!(matches!(def.key_header, KeyPlacement::BearerAuth));
    }

    #[test]
    fn urlhaus_is_poolable_and_uses_auth_key_header() {
        // modules/urlhaus/mod.rs sends `Auth-Key: <key>`, not Bearer/X-API-Key.
        assert!(is_poolable_service("urlhaus"));
        let def = find_service("urlhaus").expect("urlhaus service def present");
        assert_eq!(def.env_var, "HUNTSMAN_ABUSECH_KEY");
        match &def.key_header {
            KeyPlacement::Header(h) => assert_eq!(*h, "Auth-Key"),
            other => panic!("urlhaus must authenticate with Auth-Key, got {other:?}"),
        }
    }

    #[test]
    fn hlrlookups_and_opencnam_are_poolable_and_use_query_param_auth() {
        // modules/hlr_cnam/mod.rs sends both as URL query params, not headers.
        assert!(is_poolable_service("hlrlookups"));
        let hlr = find_service("hlrlookups").expect("hlrlookups service def present");
        assert_eq!(hlr.env_var, "HUNTSMAN_HLR_KEY");
        match &hlr.key_header {
            KeyPlacement::QueryParam(p) => assert_eq!(*p, "api_key"),
            other => panic!("hlrlookups must authenticate via api_key query param, got {other:?}"),
        }

        assert!(is_poolable_service("opencnam"));
        let cnam = find_service("opencnam").expect("opencnam service def present");
        assert_eq!(cnam.env_var, "HUNTSMAN_OPENCNAM_KEY");
        match &cnam.key_header {
            KeyPlacement::QueryParam(p) => assert_eq!(*p, "auth_token"),
            other => panic!("opencnam must authenticate via auth_token query param, got {other:?}"),
        }
        // OpenCNAM's real endpoint always pairs auth_token with a hardcoded
        // account_sid=huntsman (modules/hlr_cnam/mod.rs) — the probe URL must
        // already carry it, since KeyPlacement can only splice in the key itself.
        assert!(
            cnam.test_url.contains("account_sid=huntsman"),
            "opencnam test_url must carry the required account_sid pairing"
        );
    }

    #[test]
    fn trove_au_is_poolable_and_uses_x_api_key_header() {
        // modules/trove_au/mod.rs sends `X-API-KEY: <key>` (already calls
        // `keyed_ok_or_404`/`report_key_exhausted` correctly — this test just
        // confirms registration turns that pre-existing report into real pool
        // state instead of a no-op).
        assert!(is_poolable_service("trove_au"));
        let def = find_service("trove_au").expect("trove_au service def present");
        assert_eq!(def.env_var, "HUNTSMAN_TROVE_KEY");
        match &def.key_header {
            KeyPlacement::Header(h) => assert_eq!(*h, "X-API-KEY"),
            other => panic!("trove_au must authenticate with X-API-KEY, got {other:?}"),
        }
    }

    #[test]
    fn fullcontact_is_poolable_and_uses_bearer_auth() {
        // modules/fullcontact/mod.rs calls `.bearer_auth(key)`.
        assert!(is_poolable_service("fullcontact"));
        let def = find_service("fullcontact").expect("fullcontact service def present");
        assert_eq!(def.env_var, "HUNTSMAN_FULLCONTACT_KEY");
        assert!(matches!(def.key_header, KeyPlacement::BearerAuth));
    }

    #[test]
    fn domainsdb_is_poolable_and_probe_url_omits_the_unverified_search_param() {
        // modules/domainsdb/mod.rs sends `Authorization: Bearer <key>`. The
        // live-confirmed (2026-07-14) landmine: domainsdb.info's search
        // endpoint returns 200 for ANY non-empty bearer token — a `domain=`
        // -bearing probe URL would make the validator mis-report a garbage
        // key as valid. The probe URL must omit `domain` so it 400s before
        // that unreliable check would ever matter.
        assert!(is_poolable_service("domainsdb"));
        let def = find_service("domainsdb").expect("domainsdb service def present");
        assert_eq!(def.env_var, "HUNTSMAN_DOMAINSDB_KEY");
        assert!(matches!(def.key_header, KeyPlacement::BearerAuth));
        assert!(
            !def.test_url.contains("domain="),
            "domainsdb probe URL must omit `domain` — including it lets ANY \
             non-empty bearer token read as a false-valid 200 (confirmed live)"
        );
    }

    #[test]
    fn niamonx_is_poolable_and_uses_x_api_key_header() {
        // modules/niamonx/mod.rs sends `X-API-Key: <key>` (already calls
        // `keyed_ok_or_404` correctly — registration is what makes it matter).
        assert!(is_poolable_service("niamonx"));
        let def = find_service("niamonx").expect("niamonx service def present");
        assert_eq!(def.env_var, "HUNTSMAN_NIAMONX_KEY");
        match &def.key_header {
            KeyPlacement::Header(h) => assert_eq!(*h, "X-API-Key"),
            other => panic!("niamonx must authenticate with X-API-Key, got {other:?}"),
        }
    }

    #[test]
    fn osintcat_is_poolable_and_uses_lowercase_x_api_key_header() {
        // modules/osintcat/mod.rs sends `x-api-key: <key>` (lowercase; HTTP
        // header names are case-insensitive on the wire, but matched here for
        // documentation clarity against the module's own literal).
        assert!(is_poolable_service("osintcat"));
        let def = find_service("osintcat").expect("osintcat service def present");
        assert_eq!(def.env_var, "HUNTSMAN_OSINTCAT_KEY");
        match &def.key_header {
            KeyPlacement::Header(h) => assert_eq!(*h, "x-api-key"),
            other => panic!("osintcat must authenticate with x-api-key, got {other:?}"),
        }
    }

    #[test]
    fn nine_newly_registered_services_all_expand_the_pool() {
        // service_defs_is_non_empty_and_has_unique_names above already proves
        // no dupes; this just anchors the expected count so a future accidental
        // deletion of one of the nine fails loudly here rather than silently.
        for name in [
            "github",
            "urlhaus",
            "hlrlookups",
            "opencnam",
            "trove_au",
            "fullcontact",
            "domainsdb",
            "niamonx",
            "osintcat",
        ] {
            assert!(is_poolable_service(name), "{name} must be poolable");
        }
    }

    #[test]
    fn service_for_env_resolves_the_canonical_pool_name() {
        assert_eq!(
            service_for_env("HUNTSMAN_HUNTER_KEY").map(|d| d.name),
            Some("hunter")
        );
        assert_eq!(service_for_env("HUNTSMAN_EXA_KEY").map(|d| d.name), Some("exa"));
        assert_eq!(
            service_for_env("HUNTSMAN_HLR_KEY").map(|d| d.name),
            Some("hlrlookups")
        );
        assert!(service_for_env("HUNTSMAN_NOT_A_KEY").is_none());
    }

    /// Every keyed module whose SRC differs from its pool `ServiceDef.name` must
    /// resolve to a registered pool service via its own KEY_ENV, or every key
    /// burn is a silent no-op. The table below is the authoritative assertion
    /// set. Also asserts every service is resolvable by its own name.
    #[test]
    fn keyed_module_pool_services_are_registered() {
        for (env, svc) in [
            ("HUNTSMAN_HUNTER_KEY", "hunter"),
            ("HUNTSMAN_EXA_KEY", "exa"),
            ("HUNTSMAN_HLR_KEY", "hlrlookups"),
            ("HUNTSMAN_WHOISXML_KEY", "whoisxml"),
        ] {
            assert_eq!(service_for_env(env).map(|d| d.name), Some(svc), "{env}");
        }
        for d in service_defs() {
            assert!(
                find_service(d.name).is_some(),
                "{} must be resolvable by name",
                d.name
            );
        }
    }
