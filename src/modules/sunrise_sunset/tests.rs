use super::*;

    #[test]
    fn accepts_coordinates_only() {
        let m = SunriseSunset;
        assert!(m.accepts(&Target::new(TargetKind::Coordinates, "-33.8,151.2")));
        assert!(!m.accepts(&Target::new(TargetKind::Address, "Sydney")));
    }

    #[test]
    fn module_metadata() {
        assert_eq!(SunriseSunset.name(), "sunrise_sunset");
        assert_eq!(SunriseSunset.priority(), 10);
        assert_eq!(SunriseSunset.max_timeout_ms(), 12_000);
    }

    #[test]
    fn parse_response() {
        let raw = r#"{
            "status": "OK",
            "results": {
                "sunrise": "2024-06-15T20:00:00+00:00",
                "sunset": "2024-06-16T07:00:00+00:00",
                "solar_noon": "2024-06-16T01:30:00+00:00",
                "day_length": 39600,
                "civil_twilight_begin": "2024-06-15T19:30:00+00:00",
                "civil_twilight_end": "2024-06-16T07:30:00+00:00"
            }
        }"#;
        let r: SsResp = serde_json::from_str(raw).unwrap();
        assert_eq!(r.status.as_deref(), Some("OK"));
        let res = r.results.unwrap();
        assert!(res.sunrise.is_some());
        assert!(res.sunset.is_some());
    }

    #[test]
    fn civil_from_days_matches_known_dates() {
        // Unix epoch and a handful of known day-counts (days since 1970-01-01).
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
        assert_eq!(civil_from_days(31), (1970, 2, 1));
        // 2000-02-29 (leap day) is day 11016.
        assert_eq!(civil_from_days(11016), (2000, 2, 29));
        // 2024-06-16 is day 19890.
        assert_eq!(civil_from_days(19890), (2024, 6, 16));
    }

    fn results(json: &str) -> SsResults {
        serde_json::from_str(json).unwrap()
    }

    fn attr<'a>(e: &'a Entity, k: &str) -> Option<&'a str> {
        e.evidence[0].attributes.get(k).map(String::as_str)
    }

    #[test]
    fn solar_entity_records_phases_and_numeric_day_length() {
        let res = results(
            r#"{
                "sunrise":"2024-06-15T20:00:00+00:00",
                "sunset":"2024-06-16T07:00:00+00:00",
                "solar_noon":"2024-06-16T01:30:00+00:00",
                "day_length":39600,
                "civil_twilight_begin":"2024-06-15T19:30:00+00:00"
            }"#,
        );
        let e = build_solar_entity("-33.8,151.2", -33.8, 151.2, "2024-06-16", &res, "s");
        assert_eq!(e.kind, EntityKind::Coordinates);
        assert!(e.has_tag("sunrise-sunset") && e.has_tag("chronolocation") && e.has_tag("geoint"));
        assert!((e.confidence - 0.55).abs() < 1e-9);
        assert_eq!(attr(&e, "date"), Some("2024-06-16"));
        assert_eq!(attr(&e, "latitude"), Some("-33.800000"));
        assert_eq!(attr(&e, "longitude"), Some("151.200000"));
        assert_eq!(attr(&e, "sunrise_utc"), Some("2024-06-15T20:00:00+00:00"));
        assert_eq!(
            attr(&e, "solar_noon_utc"),
            Some("2024-06-16T01:30:00+00:00")
        );
        assert_eq!(
            attr(&e, "civil_twilight_begin"),
            Some("2024-06-15T19:30:00+00:00")
        );
        // Numeric day_length normalised to a string.
        assert_eq!(attr(&e, "day_length_s"), Some("39600"));
    }

    #[test]
    fn solar_entity_accepts_string_day_length_and_omits_absent_phases() {
        // The default (formatted) endpoint returns day_length as "11:00:00".
        let res = results(r#"{"sunrise":"6:00:00 AM","day_length":"11:00:00"}"#);
        let e = build_solar_entity("0,0", 0.0, 0.0, "2024-01-01", &res, "s");
        assert_eq!(attr(&e, "day_length_s"), Some("11:00:00"));
        assert_eq!(attr(&e, "sunrise_utc"), Some("6:00:00 AM"));
        // Phases the response omitted must not appear.
        assert_eq!(attr(&e, "sunset_utc"), None);
        assert_eq!(attr(&e, "nautical_twilight_begin"), None);
    }
