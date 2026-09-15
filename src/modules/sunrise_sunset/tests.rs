use crate::core::confidence;
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
        let r: SsResp = serde_json::from_str(raw).expect("should succeed");
        assert_eq!(r.status.as_deref(), Some("OK"));
        let res: SsResults =
            serde_json::from_value(r.results.expect("should succeed")).expect("phase object");
        assert!(res.sunrise.is_some());
        assert!(res.sunset.is_some());
        // The provider's documented error shape carries `"results": ""` — a
        // string — and must still decode so the status can be reported.
        let e: SsResp = serde_json::from_str(r#"{"results":"","status":"UNKNOWN_ERROR"}"#)
            .expect("error answers decode");
        assert_eq!(e.status.as_deref(), Some("UNKNOWN_ERROR"));
        assert!(!e.results.expect("present").is_object());
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
        serde_json::from_str(json).expect("should succeed")
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
        assert!((e.confidence - confidence::MEDIUM_HIGH).abs() < 1e-9);
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

    #[tokio::test]
    async fn a_provider_error_status_or_a_404_is_a_failed_lookup_never_an_empty_result() {
        // Backlog #43. The provider computes solar phases for ANY coordinates,
        // so there is no "no data here": its documented `UNKNOWN_ERROR` (a
        // server-side failure), an `INVALID_REQUEST`, a 404 on the fixed
        // endpoint, or an `OK` without `results` are all failed lookups. Before
        // this every one of them was `Ok(empty)` — a clean negative.
        use crate::util::http::test_server::{Canned, serve};
        let base = serve(vec![
            Canned::json(200, r#"{"results":"","status":"UNKNOWN_ERROR"}"#),
            Canned::json(200, r#"{"results":"","status":"INVALID_REQUEST"}"#),
            Canned::text(404, "Not Found"),
            Canned::json(200, r#"{"status":"OK"}"#),
            Canned::json(
                200,
                r#"{"results":{"sunrise":"2026-09-15T20:07:21+00:00","sunset":"2026-09-16T08:03:12+00:00","solar_noon":"2026-09-16T02:05:16+00:00","day_length":43000},"status":"OK"}"#,
            ),
        ])
        .await;
        let client = reqwest::Client::new();
        let endpoint = format!("{base}/json");
        let (lat, lon) = (-33.8688, 151.2093);

        let err = fetch_solar(&client, &endpoint, lat, lon, "2026-09-15")
            .await
            .expect_err("UNKNOWN_ERROR is the provider failing, not an empty answer");
        assert!(err.to_string().contains("UNKNOWN_ERROR"), "{err}");
        let err = fetch_solar(&client, &endpoint, lat, lon, "2026-09-15")
            .await
            .expect_err("INVALID_REQUEST is a failed lookup");
        assert!(err.to_string().contains("INVALID_REQUEST"), "{err}");
        let err = fetch_solar(&client, &endpoint, lat, lon, "2026-09-15")
            .await
            .expect_err("404 on the fixed endpoint is the endpoint gone");
        assert!(err.to_string().contains("404"), "{err}");
        let err = fetch_solar(&client, &endpoint, lat, lon, "2026-09-15")
            .await
            .expect_err("OK without results is a shape change, not an empty answer");
        assert!(err.to_string().contains("results"), "{err}");
        let ok = fetch_solar(&client, &endpoint, lat, lon, "2026-09-15")
            .await
            .expect("a genuine OK answer parses");
        assert_eq!(ok.sunrise.as_deref(), Some("2026-09-15T20:07:21+00:00"));
    }
