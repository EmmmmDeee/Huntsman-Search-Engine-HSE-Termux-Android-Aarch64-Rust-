//! Unit tests for `hse cells` CSV parsing and country-code helpers.

use super::{
    mcc_for_country, mcc_header_line, opencellid_download_url, opencellid_filename, parse_csv_line,
};

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

// ── clear: the file must actually shrink ────────────────────────────────────
//
// Driven against a dedicated database rather than `cell_db_path()`: under
// `cfg(test)` that path is ONE per-process temp location shared by every test,
// so using it here would race any sibling touching the cell DB — and this
// property needs a file it exclusively owns and has grown to a known size.

/// Build a cell DB at `path` carrying `n` tower rows, and return its size.
fn seeded_cell_db(path: &std::path::Path, n: i64) -> (rusqlite::Connection, u64) {
    let conn = rusqlite::Connection::open(path).expect("open temp cell db");
    crate::util::cell_db::init_schema(&conn).expect("schema");
    let batch: Vec<crate::util::cell_db::CellRow> = (0..n)
        .map(|i| crate::util::cell_db::CellRow {
            radio: "LTE".to_string(),
            mcc: 505,
            mnc: 1,
            lac: 54321,
            cid: i,
            lon: 153.021,
            lat: -27.471,
            range_m: 500,
            samples: 10,
            avg_signal: -80,
        })
        .collect();
    crate::util::cell_db::insert_batch(&conn, &batch).expect("insert");
    // Checkpoint so the pages are in the main file, not only the WAL, before
    // the size is read — otherwise `bytes_before` understates the real DB.
    let _ = conn.execute("PRAGMA wal_checkpoint(TRUNCATE)", []);
    let size = std::fs::metadata(path).map_or(0, |m| m.len());
    (conn, size)
}

#[test]
fn clear_returns_the_freed_pages_to_the_filesystem() {
    // Regression: `clear_in` used to be DELETE-only. SQLite moves deleted pages
    // to an internal freelist and keeps the file at its old size, so clearing a
    // multi-GB OpenCellID import reclaimed NOTHING — the opposite of the reason
    // an operator runs it on a storage-constrained phone.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("cell_towers.db");
    let (conn, before) = seeded_cell_db(&path, 4_000);
    assert!(before > 0, "seeded DB must exist on disk");

    let report = super::clear_in(&conn, &path).expect("clear must succeed");

    assert_eq!(report.rows_deleted, 4_000, "every tower row is removed");
    assert_eq!(
        report.vacuum_error, None,
        "the vacuum must succeed on a normal filesystem"
    );
    assert!(
        report.bytes_after < report.bytes_before,
        "the file must physically shrink: {} -> {}",
        report.bytes_before,
        report.bytes_after
    );
    assert!(
        report.bytes_reclaimed() > 0,
        "reclaimed byte count must be non-zero"
    );
    // The reported figures must match the filesystem, not just each other.
    let on_disk = std::fs::metadata(&path).map_or(0, |m| m.len());
    assert_eq!(
        report.bytes_after, on_disk,
        "bytes_after must be what the filesystem actually shows"
    );
}

#[test]
fn clear_of_an_already_empty_db_is_a_no_op_that_still_succeeds() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("cell_towers.db");
    let (conn, _) = seeded_cell_db(&path, 0);

    let report = super::clear_in(&conn, &path).expect("clearing an empty DB must succeed");

    assert_eq!(report.rows_deleted, 0);
    assert_eq!(report.vacuum_error, None);
    assert_eq!(
        report.bytes_reclaimed(),
        report.bytes_before.saturating_sub(report.bytes_after),
        "reclaimed is a saturating difference and never underflows"
    );
}

#[test]
fn bytes_reclaimed_saturates_when_the_file_grew() {
    // A concurrent writer growing the file between the two stats must not
    // underflow the subtraction into a near-u64::MAX "reclaimed" figure.
    let report = super::ClearReport {
        rows_deleted: 0,
        bytes_before: 1_000,
        bytes_after: 4_096,
        vacuum_error: None,
    };
    assert_eq!(report.bytes_reclaimed(), 0);
}
