use super::*;

    #[test]
    fn accepts_domain_url_and_ip() {
        let m = UrlScan;
        assert!(m.accepts(&Target::new(TargetKind::Domain, "example.com")));
        assert!(m.accepts(&Target::new(TargetKind::Url, "https://example.com/path")));
        assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Username, "alice")));
    }

    #[test]
    fn module_metadata() {
        let m = UrlScan;
        assert_eq!(m.name(), "urlscan");
        assert_eq!(m.priority(), 15);
        assert_eq!(m.cost(), crate::core::module::ModuleCost::Free);
        assert_eq!(m.max_timeout_ms(), 8_000);
        assert!(!m.description().is_empty());
    }

    #[test]
    fn deserialize_empty_results() {
        let raw = r#"{"results":[]}"#;
        let resp: SearchResp = serde_json::from_str(raw).unwrap();
        assert!(resp.results.is_empty());
    }

    #[test]
    fn deserialize_results_with_page_and_verdicts() {
        let raw = r#"{
            "results": [
                {
                    "page": {
                        "url": "https://example.com/login",
                        "domain": "example.com",
                        "ip": "93.184.216.34",
                        "country": "US",
                        "server": "nginx"
                    },
                    "verdicts": {
                        "malicious": false
                    }
                },
                {
                    "page": {
                        "url": "https://example.com/phish",
                        "domain": "example.com",
                        "ip": "104.21.5.100",
                        "country": "DE",
                        "server": "cloudflare"
                    },
                    "verdicts": {
                        "malicious": true
                    }
                }
            ]
        }"#;
        let resp: SearchResp = serde_json::from_str(raw).unwrap();
        assert_eq!(resp.results.len(), 2);

        let first = &resp.results[0];
        let page = first.page.as_ref().unwrap();
        assert_eq!(page.domain.as_deref(), Some("example.com"));
        assert_eq!(page.ip.as_deref(), Some("93.184.216.34"));
        assert_eq!(page.country.as_deref(), Some("US"));
        assert_eq!(page.server.as_deref(), Some("nginx"));
        assert_eq!(first.verdicts.as_ref().unwrap().malicious, Some(false));

        let second = &resp.results[1];
        assert_eq!(second.verdicts.as_ref().unwrap().malicious, Some(true));
    }

    #[test]
    fn deserialize_sparse_response() {
        // URLScan.io can return results with missing optional fields.
        let raw = r#"{
            "results": [
                {
                    "page": {
                        "url": "https://example.com/"
                    }
                },
                {}
            ]
        }"#;
        let resp: SearchResp = serde_json::from_str(raw).unwrap();
        assert_eq!(resp.results.len(), 2);

        let first = &resp.results[0];
        let page = first.page.as_ref().unwrap();
        assert_eq!(page.url.as_deref(), Some("https://example.com/"));
        assert!(page.ip.is_none());
        assert!(page.country.is_none());
        assert!(first.verdicts.is_none());

        // Completely empty result object still deserialises.
        let second = &resp.results[1];
        assert!(second.page.is_none());
        assert!(second.verdicts.is_none());
    }
