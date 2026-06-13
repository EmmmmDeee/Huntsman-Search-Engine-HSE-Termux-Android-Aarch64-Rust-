use super::*;

    #[test]
    fn histogram_us_eastern() {
        // Activity at UTC hours 13-23 = 08:00-18:00 at UTC-5 (US Eastern)
        let hours: Vec<u32> = vec![13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23];
        let tz = infer_timezone(&hours).unwrap();
        assert_eq!(tz.utc_offset, -5);
        assert!(tz.region.contains("Eastern"));
    }

    #[test]
    fn too_few_timestamps_returns_none() {
        let hours = vec![10, 11, 12];
        assert!(infer_timezone(&hours).is_none());
    }

    #[test]
    fn uniform_distribution_returns_none() {
        // Activity evenly spread = no timezone signal
        let hours: Vec<u32> = (0..24).collect();
        assert!(infer_timezone(&hours).is_none());
    }

    #[test]
    fn offset_to_region_coverage() {
        assert!(offset_to_region(10).contains("Australia"));
        assert!(offset_to_region(0).contains("UK"));
        assert!(offset_to_region(-5).contains("Eastern"));
    }

    #[tokio::test]
    async fn module_metadata() {
        let m = BreachTimezone;
        assert!(m.is_passive());
        assert!(m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "y.com")));
    }
