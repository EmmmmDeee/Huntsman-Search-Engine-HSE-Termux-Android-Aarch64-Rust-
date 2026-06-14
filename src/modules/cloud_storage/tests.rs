use super::*;

    #[test]
    fn extract_base_from_domain() {
        assert_eq!(extract_base_name("www.example.com"), "example");
        assert_eq!(extract_base_name("acme-corp.com.au"), "acme-corp");
        assert_eq!(extract_base_name("EXAMPLE.COM"), "example");
    }

    #[test]
    fn generate_buckets_bounded() {
        let names = generate_bucket_names("test");
        assert!(names.len() <= MAX_PROBES);
        assert!(names.iter().any(|(u, _, _)| u.contains("s3.amazonaws")));
        assert!(names.iter().any(|(u, _, _)| u.contains("blob.core")));
        assert!(
            names
                .iter()
                .any(|(u, _, _)| u.contains("storage.googleapis"))
        );
    }

    #[test]
    fn s3_403_is_exposed() {
        assert!(is_exposed(403, "AWS S3"));
        assert!(is_exposed(200, "AWS S3"));
        assert!(!is_exposed(404, "AWS S3"));
    }

    #[test]
    fn azure_needs_200() {
        assert!(is_exposed(200, "Azure Blob"));
        assert!(!is_exposed(403, "Azure Blob"));
    }

    #[test]
    fn short_name_skipped() {
        assert!(extract_base_name("a.b").len() < 3);
    }

    #[tokio::test]
    async fn module_metadata() {
        let m = CloudStorage;
        assert!(m.accepts(&Target::new(TargetKind::Domain, "example.com")));
        assert!(m.accepts(&Target::new(TargetKind::Organisation, "Acme Corp")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    }
