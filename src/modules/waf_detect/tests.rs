use super::*;
    use reqwest::header::{HeaderMap, HeaderValue};

    #[test]
    fn detect_cloudflare() {
        let mut h = HeaderMap::new();
        h.insert("cf-ray", HeaderValue::from_static("abc123"));
        assert!(has_cloudflare(&h));
    }

    #[test]
    fn detect_cloudfront() {
        let mut h = HeaderMap::new();
        h.insert("x-amz-cf-id", HeaderValue::from_static("xyz"));
        assert!(has_cloudfront(&h));
    }

    #[test]
    fn no_waf_detected() {
        let h = HeaderMap::new();
        assert!(!has_cloudflare(&h));
        assert!(!has_akamai(&h));
        assert!(!has_cloudfront(&h));
    }

    #[test]
    fn fingerprint_table_non_empty() {
        assert!(FINGERPRINTS.len() >= 8);
    }

    #[tokio::test]
    async fn module_metadata() {
        let m = WafDetect;
        assert!(m.accepts(&Target::new(TargetKind::Domain, "example.com")));
        assert!(m.accepts(&Target::new(TargetKind::Url, "https://example.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    }

    #[test]
    fn detect_fastly_via_header() {
        let mut h = HeaderMap::new();
        h.insert("x-fastly-request-id", HeaderValue::from_static("req-xyz"));
        assert!(has_fastly(&h));
    }

    #[test]
    fn detect_akamai_via_server_header() {
        let mut h = HeaderMap::new();
        h.insert("server", HeaderValue::from_static("AkamaiGHost"));
        assert!(has_akamai(&h));
    }

    #[test]
    fn detect_stackpath_via_waf_header() {
        let mut h = HeaderMap::new();
        h.insert("x-sp-waf", HeaderValue::from_static("1"));
        assert!(has_stackpath(&h));
    }

    #[test]
    fn module_metadata_shape() {
        let m = WafDetect;
        assert_eq!(m.name(), "waf_detect");
        assert!(!m.description().is_empty());
        assert_eq!(m.max_timeout_ms(), 6_000);
        assert!(!m.attack_techniques().is_empty());
        assert!(m.produces().contains(&EntityKind::Domain));
    }

    #[test]
    fn detect_sucuri_via_id_header_and_server() {
        let mut by_id = HeaderMap::new();
        by_id.insert("x-sucuri-id", HeaderValue::from_static("12345"));
        assert!(has_sucuri(&by_id));

        let mut by_server = HeaderMap::new();
        by_server.insert("server", HeaderValue::from_static("Sucuri/Cloudproxy"));
        assert!(has_sucuri(&by_server));
    }

    #[test]
    fn sucuri_not_detected_on_unrelated_headers() {
        assert!(!has_sucuri(&HeaderMap::new()));
        let mut h = HeaderMap::new();
        h.insert("server", HeaderValue::from_static("nginx"));
        assert!(!has_sucuri(&h));
    }

    #[test]
    fn detect_incapsula_via_iinfo_header_and_cdn() {
        let mut by_iinfo = HeaderMap::new();
        by_iinfo.insert("x-iinfo", HeaderValue::from_static("1-2-3"));
        assert!(has_incapsula(&by_iinfo));

        let mut by_cdn = HeaderMap::new();
        by_cdn.insert("x-cdn", HeaderValue::from_static("Incapsula"));
        assert!(has_incapsula(&by_cdn));
    }

    #[test]
    fn incapsula_not_detected_on_unrelated_headers() {
        assert!(!has_incapsula(&HeaderMap::new()));
        let mut h = HeaderMap::new();
        h.insert("x-cdn", HeaderValue::from_static("cloudfront"));
        assert!(!has_incapsula(&h));
    }

    #[test]
    fn detect_ddos_guard_via_server_header() {
        let mut h = HeaderMap::new();
        h.insert("server", HeaderValue::from_static("ddos-guard"));
        assert!(has_ddos_guard(&h));
    }

    #[test]
    fn ddos_guard_not_detected_on_unrelated_headers() {
        assert!(!has_ddos_guard(&HeaderMap::new()));
        let mut h = HeaderMap::new();
        h.insert("server", HeaderValue::from_static("cloudflare"));
        assert!(!has_ddos_guard(&h));
    }
