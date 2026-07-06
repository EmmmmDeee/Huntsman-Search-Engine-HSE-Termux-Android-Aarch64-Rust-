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
