
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

    #[test]
    fn avg_health_ignores_untested_keys_and_is_none_when_all_untested() {
        use super::summarize_pool;
        use crate::util::key_pool::{KeyEntry, KeyStatus, PoolData};
        let mut data = PoolData::default();

        // A pool with ONLY untested keys must report health as `None`
        // ("untested"), never a fabricated ~0.97 — the bug this guards.
        let untested_a = KeyEntry::new("UT-A");
        let untested_b = KeyEntry::new("UT-B");
        assert_eq!(untested_a.status, KeyStatus::Untested);
        data.services
            .insert("airtable".into(), vec![untested_a, untested_b]);

        // A mixed pool: two untested keys plus one exercised, invalid key. The
        // average must be taken over the ONE tested key only (so it reflects the
        // invalid key's 0.0), not diluted upward by the untested pair.
        let mut invalid = KeyEntry::new("INV");
        invalid.status = KeyStatus::Invalid;
        invalid.use_count = 3;
        invalid.error_count = 3;
        let untested_c = KeyEntry::new("UT-C");
        let untested_d = KeyEntry::new("UT-D");
        data.services
            .insert("shodan".into(), vec![invalid, untested_c, untested_d]);

        let summary = summarize_pool(&data);
        let airtable = summary.iter().find(|q| q.service == "airtable").unwrap();
        assert_eq!(airtable.untested, 2);
        assert_eq!(airtable.tested, 0);
        assert_eq!(
            airtable.avg_health, None,
            "an all-untested pool has no proven health to report"
        );

        let shodan = summary.iter().find(|q| q.service == "shodan").unwrap();
        assert_eq!(shodan.untested, 2);
        assert_eq!(shodan.invalid, 1);
        assert_eq!(shodan.tested, 1, "only the invalid key has a verdict");
        assert_eq!(
            shodan.avg_health,
            Some(0.0),
            "health averages the one tested (invalid → 0.0) key, not the untested pair"
        );
    }
