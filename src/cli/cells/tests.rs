//! Unit tests for `hse cells` CSV parsing and country-code helpers.

use super::{STALE_THRESHOLD_SECS, mcc_for_country, parse_csv_line, staleness_warning};

// ── parse_csv_line ──────────────────────────────────────────────────────────

#[test]
fn parse_csv_line_parses_valid_row() {
    // radio,mcc,net,area,cell,unit,lon,lat,range,samples,changeable,created,updated,averageSignal
    let line = "LTE,505,1,54321,12345,0,153.021000,-27.471000,500,10,1,1609459200,1609459200,-80";
    let row = parse_csv_line(line).expect("should parse");
    assert_eq!(row.radio, "LTE");
    assert_eq!(row.mcc, 505);
    assert_eq!(row.mnc, 1);
    assert_eq!(row.lac, 54321);
    assert_eq!(row.cid, 12345);
    assert!((row.lon - 153.021).abs() < 0.0001);
    assert!((row.lat - (-27.471)).abs() < 0.0001);
    assert_eq!(row.range_m, 500);
    assert_eq!(row.samples, 10);
    assert_eq!(row.avg_signal, -80);
}

#[test]
fn parse_csv_line_skips_header() {
    let header = "radio,mcc,net,area,cell,unit,lon,lat,range,samples,changeable,created,updated,averageSignal";
    assert!(
        parse_csv_line(header).is_none(),
        "header line must be skipped"
    );
}

#[test]
fn parse_csv_line_returns_none_on_short_row() {
    let short = "LTE,505,1,100,200";
    assert!(
        parse_csv_line(short).is_none(),
        "row with fewer than 14 columns must return None"
    );
}

#[test]
fn parse_csv_line_returns_none_on_non_numeric_mcc() {
    let bad = "LTE,BADMCC,1,100,200,0,153.0,-27.47,500,10,1,0,0,-80";
    assert!(parse_csv_line(bad).is_none());
}

#[test]
fn parse_csv_line_handles_zero_signal() {
    let line = "GSM,505,2,111,222,0,151.0,-33.87,1000,5,1,0,0,0";
    let row = parse_csv_line(line).expect("valid row");
    assert_eq!(row.avg_signal, 0);
}

#[test]
fn parse_csv_line_rejects_out_of_range_lat() {
    // lat > 90 is invalid
    let line = "LTE,505,1,1,1,0,153.0,95.0,500,10,1,0,0,-80";
    assert!(parse_csv_line(line).is_none());
}

// ── mcc_for_country ─────────────────────────────────────────────────────────

#[test]
fn mcc_for_country_maps_au_to_505() {
    assert_eq!(mcc_for_country("AU"), Some(505));
    assert_eq!(mcc_for_country("au"), Some(505));
}

#[test]
fn mcc_for_country_maps_world_to_none() {
    assert_eq!(mcc_for_country("world"), None);
    assert_eq!(mcc_for_country("WORLD"), None);
}

#[test]
fn mcc_for_country_parses_raw_mcc() {
    assert_eq!(mcc_for_country("505"), Some(505));
    assert_eq!(mcc_for_country("310"), Some(310));
}

#[test]
fn mcc_for_country_maps_gb_and_uk_to_234() {
    assert_eq!(mcc_for_country("GB"), Some(234));
    assert_eq!(mcc_for_country("UK"), Some(234));
}

#[test]
fn mcc_for_country_maps_nz_to_530() {
    assert_eq!(mcc_for_country("NZ"), Some(530));
}

// ── staleness_warning ───────────────────────────────────────────────────────

/// Regression guard for the C5 "cell_local auto-sync" gap (`SOLUTION_TREE`
/// §4a): `hse cells status` previously reported an import's age with no
/// judgement at all, so an operator relying on a long-forgotten snapshot got
/// no signal their cell-tower coverage may be missing recently added/moved
/// towers.
#[test]
fn staleness_warning_none_for_a_fresh_import() {
    assert_eq!(staleness_warning(0), None);
    assert_eq!(staleness_warning(3600), None, "an hour old is fresh");
    assert_eq!(staleness_warning(30 * 86400), None, "30 days old is fresh");
}

#[test]
fn staleness_warning_none_exactly_at_the_threshold() {
    assert_eq!(
        staleness_warning(STALE_THRESHOLD_SECS),
        None,
        "exactly at the threshold is not yet stale"
    );
}

#[test]
fn staleness_warning_fires_just_past_the_threshold() {
    let warning =
        staleness_warning(STALE_THRESHOLD_SECS + 1).expect("must warn just past the threshold");
    assert!(warning.contains("WARNING"));
    assert!(warning.contains("hse cells import"), "must name the fix");
}

#[test]
fn staleness_warning_fires_for_a_long_forgotten_import() {
    let warning = staleness_warning(365 * 86400).expect("a year-old import must warn");
    assert!(warning.contains("365d"));
}
