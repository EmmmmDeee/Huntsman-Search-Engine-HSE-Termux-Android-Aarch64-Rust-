use super::*;

#[test]
fn parses_a_well_formed_crates_io_response() {
    let raw = r#"{"version":{"created_at":"2024-05-01T12:34:56.000000+00:00"}}"#;
    let parsed = parse_publish_date(raw).expect("valid crates.io response parses");
    assert_eq!(
        parsed,
        OffsetDateTime::parse("2024-05-01T12:34:56Z", &Rfc3339).unwrap()
    );
}

#[test]
fn crates_io_response_shape_survives_extra_unknown_fields() {
    // crates.io's real response carries many more fields (`num`, `dl_path`, `yanked`, ...);
    // `VersionResponse`/`VersionField` must only require the ones this tool actually reads.
    let raw = r#"{
        "version": {
            "num": "1.2.3",
            "created_at": "2026-01-15T09:00:00.123456+00:00",
            "yanked": false,
            "dl_path": "/api/v1/crates/example/1.2.3/download"
        }
    }"#;
    let parsed = parse_publish_date(raw).expect("extra fields must not break parsing");
    assert_eq!(
        parsed,
        OffsetDateTime::parse("2026-01-15T09:00:00.123456Z", &Rfc3339).unwrap()
    );
}

#[test]
fn malformed_json_is_a_parse_error() {
    assert!(parse_publish_date("not json").is_err());
}

#[test]
fn missing_created_at_field_is_a_parse_error() {
    let raw = r#"{"version":{"num":"1.0.0"}}"#;
    assert!(parse_publish_date(raw).is_err());
}

#[test]
fn unparseable_timestamp_is_a_parse_error() {
    let raw = r#"{"version":{"created_at":"not a real timestamp"}}"#;
    assert!(parse_publish_date(raw).is_err());
}
