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

    /// HIBP's validity probe must hit the genuinely auth-gated
    /// `subscription/status` endpoint. Live control tests proved the two prior
    /// choices could NOT reject an invalid key: `/api/v3/breaches` is public
    /// (200 with no key), and the `breachedaccount/…hibp-integration-tests.com`
    /// test account returns a fixed 200 for ANY well-formed key header (a
    /// garbage key passes). Only `subscription/status` returns 401 for an
    /// invalid key, so pin it here — a revert to either dead-end endpoint would
    /// silently re-break `hse keys validate hibp`.
    #[test]
    fn hibp_validity_probe_uses_the_auth_gated_subscription_endpoint() {
        let hibp = find_service("hibp").expect("hibp is a registered service");
        assert_eq!(
            hibp.test_url,
            "https://haveibeenpwned.com/api/v3/subscription/status"
        );
        assert!(
            !hibp.test_url.contains("breachedaccount"),
            "the test-account endpoint 200s for any key — not a validity probe"
        );
        assert!(
            !hibp.test_url.ends_with("/breaches"),
            "the public catalogue endpoint needs no key at all"
        );
    }
