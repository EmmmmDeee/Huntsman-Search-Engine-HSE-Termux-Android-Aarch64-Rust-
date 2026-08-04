//! Unit tests for `hse cells` CSV parsing and country-code helpers.

use super::{
    import_from_file, import_from_file_off_runtime, mcc_for_country, mcc_header_line,
    opencellid_download_url, opencellid_filename, parse_csv_line,
};

// ── spawn_blocking boundary ─────────────────────────────────────────────────

/// The off-runtime wrapper must be behaviourally transparent: the same input
/// that fails synchronously must fail identically through `spawn_blocking`.
/// Guards the boundary added so a web-triggered OpenCelliD import (up to
/// `MAX_DECOMPRESSED_BYTES`, 16 GiB) can no longer stall a tokio worker — the
/// runtime is only 2 workers wide on Termux, and `POST /api/v1/cells/import`
/// reaches this path.
#[tokio::test]
async fn off_runtime_import_propagates_the_same_error_as_the_blocking_call() {
    let missing = "/nonexistent/hse-cells-does-not-exist.csv";

    let sync_err = import_from_file(missing, None).expect_err("missing file must error");
    let async_err = import_from_file_off_runtime(missing.to_string(), None)
        .await
        .expect_err("missing file must error through spawn_blocking too");

    assert_eq!(
        sync_err.to_string(),
        async_err.to_string(),
        "the spawn_blocking wrapper must not alter the error it forwards"
    );
    assert!(
        async_err.to_string().contains("File not found"),
        "expected the not-found message, got: {async_err}"
    );
}

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

// ── mcc_header_line ─────────────────────────────────────────────────────────

#[test]
fn mcc_header_line_states_the_true_total_when_truncated() {
    // The bug: "By MCC (top 10)" read as if there were only 10, when a global
    // OpenCelliD import easily spans 100+ countries.
    assert_eq!(mcc_header_line(37), "By MCC (top 10 of 37):");
}

#[test]
fn mcc_header_line_is_plain_when_the_full_list_already_fits() {
    assert_eq!(mcc_header_line(10), "By MCC:");
    assert_eq!(mcc_header_line(1), "By MCC:");
}

// ── opencellid_filename / opencellid_download_url ──────────────────────────
// Shared by the CLI's `--country` import and `POST /api/v1/cells/import` —
// pinning these as pure functions is what lets the API build the identical
// request the CLI already does, without duplicating the string logic.

#[test]
fn opencellid_filename_maps_world_to_the_full_dataset_name() {
    assert_eq!(opencellid_filename("world", None), "cell_towers.csv.gz");
    assert_eq!(opencellid_filename("WORLD", None), "cell_towers.csv.gz");
}

#[test]
fn opencellid_filename_uses_the_resolved_mcc_for_a_country_code() {
    assert_eq!(
        opencellid_filename("AU", Some(505)),
        "OCID_cells_mcc505.csv.gz"
    );
}

#[test]
fn opencellid_filename_falls_back_to_the_raw_input_when_mcc_is_unresolved() {
    // An unrecognised country string with no MCC mapping still produces a
    // deterministic filename rather than panicking or silently dropping it.
    assert_eq!(opencellid_filename("ZZ", None), "OCID_cells_mccZZ.csv.gz");
}

#[test]
fn opencellid_download_url_embeds_the_token_and_filename() {
    let url = opencellid_download_url("OCID_cells_mcc505.csv.gz", "MYTOKEN");
    assert!(url.starts_with("https://opencellid.org/downloads/?"));
    assert!(url.contains("token=MYTOKEN"));
    assert!(url.contains("file=OCID_cells_mcc505.csv.gz"));
    assert!(url.contains("sourceFilter=ocid"));
    assert!(url.contains("type=full"));
}
