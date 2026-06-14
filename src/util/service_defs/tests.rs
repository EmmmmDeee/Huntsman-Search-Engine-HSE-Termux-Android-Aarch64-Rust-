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
