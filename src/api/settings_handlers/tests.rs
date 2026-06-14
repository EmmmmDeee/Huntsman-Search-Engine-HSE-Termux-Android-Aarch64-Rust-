
#[test]
    fn summarize_pool_counts_by_status_and_never_leaks_values() {
        use super::summarize_pool;
        use crate::util::key_pool::{KeyEntry, KeyStatus, PoolData};
        let mut data = PoolData::default();
        let mut active = KeyEntry::new("SECRET-ACTIVE");
        active.status = KeyStatus::Active;
        active.use_count = 5;
        let mut limited = KeyEntry::new("SECRET-RL");
        limited.status = KeyStatus::RateLimited;
        limited.error_count = 2;
        data.services.insert("shodan".into(), vec![active, limited]);
        let mut invalid = KeyEntry::new("SECRET-INVALID");
        invalid.status = KeyStatus::Invalid;
        data.services.insert("censys".into(), vec![invalid]);

        let summary = summarize_pool(&data);
        // Sorted by service name.
        assert_eq!(summary[0].service, "censys");
        assert_eq!(summary[1].service, "shodan");
        let shodan = &summary[1];
        assert_eq!(shodan.total, 2);
        assert_eq!(shodan.active, 1);
        assert_eq!(shodan.rate_limited, 1);
        assert_eq!(shodan.uses, 5);
        assert_eq!(shodan.errors, 2);
        assert_eq!(summary[0].invalid, 1);

        // CRITICAL: no key value may appear in the serialised summary.
        let json = serde_json::to_string(&summary).unwrap();
        assert!(
            !json.contains("SECRET"),
            "key values must never be exposed: {json}"
        );
    }
