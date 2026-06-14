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
