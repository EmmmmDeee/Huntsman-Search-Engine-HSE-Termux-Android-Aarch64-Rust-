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
