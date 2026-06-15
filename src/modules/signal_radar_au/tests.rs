use super::parse_coords;

#[test]
fn parses_valid_coords() {
    let (lat, lon) = parse_coords("-33.8688,151.2093").unwrap();
    assert!((lat - -33.8688_f64).abs() < 1e-4);
    assert!((lon - 151.2093_f64).abs() < 1e-4);
}

#[test]
fn rejects_invalid_coords() {
    assert!(parse_coords("not-a-coord").is_none());
    assert!(parse_coords("").is_none());
    assert!(parse_coords("-33.8688").is_none());
}
