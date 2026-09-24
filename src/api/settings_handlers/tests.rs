
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
        let json = serde_json::to_string(&summary).expect("should succeed");
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
        let airtable = summary.iter().find(|q| q.service == "airtable").expect("should succeed");
        assert_eq!(airtable.untested, 2);
        assert_eq!(airtable.tested, 0);
        assert_eq!(
            airtable.avg_health, None,
            "an all-untested pool has no proven health to report"
        );

        let shodan = summary.iter().find(|q| q.service == "shodan").expect("should succeed");
        assert_eq!(shodan.untested, 2);
        assert_eq!(shodan.invalid, 1);
        assert_eq!(shodan.tested, 1, "only the invalid key has a verdict");
        assert_eq!(
            shodan.avg_health,
            Some(0.0),
            "health averages the one tested (invalid → 0.0) key, not the untested pair"
        );
    }

    /// REQ-SETTINGS-001: a toggle write refused because the settings file cannot
    /// be used is a 409 that names the file and the fix, a read failure the same;
    /// a write that failed stays a 400.
    #[tokio::test]
    async fn a_toggle_refused_over_an_unusable_settings_file_is_a_conflict() {
        use super::toggle_not_written;
        use crate::util::settings::SettingsError;
        use axum::http::StatusCode;
        let path = std::path::PathBuf::from("/home/op/.huntsman/settings.json");
        let parse = serde_json::from_str::<std::collections::BTreeMap<String, bool>>("{,}")
            .expect_err("not a settings file");

        let refused = toggle_not_written(&SettingsError::Parse {
            path: path.clone(),
            source: parse,
        });
        assert_eq!(refused.status(), StatusCode::CONFLICT);
        let body = axum::body::to_bytes(refused.into_body(), usize::MAX)
            .await
            .expect("body");
        let said: serde_json::Value = serde_json::from_slice(&body).expect("json");
        let said = said["error"].as_str().expect("an error text");
        assert!(
            said.contains("/home/op/.huntsman/settings.json") && said.contains("move it aside"),
            "{said}"
        );

        let unreadable = SettingsError::Read {
            path: path.clone(),
            source: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        };
        assert_eq!(toggle_not_written(&unreadable).status(), StatusCode::CONFLICT);
        let failed = SettingsError::Write {
            path,
            source: std::io::Error::other("no space left on device"),
        };
        assert_eq!(toggle_not_written(&failed).status(), StatusCode::BAD_REQUEST);
    }
