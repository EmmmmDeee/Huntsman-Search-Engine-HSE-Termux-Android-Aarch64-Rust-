use super::*;

    #[test]
    fn fingerprint_table_is_sorted_and_non_empty() {
        assert!(!TAKEOVER_FINGERPRINTS.is_empty());
        for &(pattern, service, _) in TAKEOVER_FINGERPRINTS {
            assert!(!pattern.is_empty());
            assert!(!service.is_empty());
        }
    }

    #[test]
    fn known_services_present() {
        let services: Vec<&str> = TAKEOVER_FINGERPRINTS.iter().map(|t| t.1).collect();
        assert!(services.contains(&"AWS S3"));
        assert!(services.contains(&"Heroku"));
        assert!(services.contains(&"GitHub Pages"));
        assert!(services.contains(&"Netlify"));
    }

    #[tokio::test]
    async fn module_metadata() {
        let m = SubdomainTakeover;
        assert!(m.accepts(&Target::new(TargetKind::Domain, "sub.example.com")));
        assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.2.3.4")));
    }
