//! Offline, version-pinned Network Survey LTE CSV interoperability.
//! Importing a file is not a live radio scan or proof of its author, clock or location.
//! Device serial numbers and mission identifiers are deliberately not retained.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde::Serialize;
use serde_json::json;

use super::{CellObservation, parse_cells};
use crate::error::Error;
use crate::textnorm::escape_controls;
use crate::timefmt::parse_timestamp;

pub const MAX_SURVEY_CSV_BYTES: u64 = 262_144;
pub const CSV_VERSION: &str = "0.5.0";

#[derive(Debug, Clone, Serialize)]
pub struct LteCsvRecord {
    pub observation: CellObservation,
    /// Source-claimed sequence and scan-group numbers, not unique evidence IDs.
    pub record_number: Option<u64>,
    pub group_number: Option<u64>,
    /// Source-reported GNSS data, deliberately separate from RF sighting position.
    pub reported_latitude: Option<f64>,
    pub reported_longitude: Option<f64>,
    pub reported_accuracy_m: Option<f64>,
    pub location_age_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LteCsvReport {
    pub source: &'static str,
    pub acquisition: &'static str,
    pub csv_version: &'static str,
    pub status: &'static str,
    pub observed: usize,
    pub rejected: usize,
    pub observations: Vec<LteCsvRecord>,
}

fn invalid(message: &str) -> Error {
    Error::Invalid(format!("Network Survey LTE CSV: {message}"))
}

/// RFC4180-style records, including quoted commas, escaped quotes and newlines.
/// Input, field, row and column counts are all bounded.
fn csv_rows(input: &str) -> Result<Vec<Vec<String>>, Error> {
    let mut chars = input.chars().peekable();
    let mut rows = Vec::new();
    let mut row = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut closed = false;
    while let Some(ch) = chars.next() {
        if quoted {
            if ch == '"' {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    field.push('"');
                } else {
                    quoted = false;
                    closed = true;
                }
            } else {
                field.push(ch);
            }
        } else {
            match ch {
                '"' if field.is_empty() && !closed => quoted = true,
                '"' => return Err(invalid("unexpected quote")),
                ',' => {
                    row.push(std::mem::take(&mut field));
                    closed = false;
                }
                '\n' => {
                    row.push(std::mem::take(&mut field));
                    rows.push(std::mem::take(&mut row));
                    closed = false;
                }
                '\r' if chars.peek() == Some(&'\n') => {
                    chars.next();
                    row.push(std::mem::take(&mut field));
                    rows.push(std::mem::take(&mut row));
                    closed = false;
                }
                '\r' => return Err(invalid("bare carriage return")),
                _ if closed => return Err(invalid("text after quoted field")),
                _ => field.push(ch),
            }
        }
        if field.len() > 4096 || row.len() > 32 || rows.len() > 4097 {
            return Err(invalid("CSV field or record limit exceeded"));
        }
    }
    if quoted {
        return Err(invalid("unterminated quoted field"));
    }
    if !field.is_empty() || !row.is_empty() || closed {
        row.push(field);
        rows.push(row);
    }
    Ok(rows)
}

fn cell_number(
    row: &[String],
    columns: &BTreeMap<&str, usize>,
    name: &str,
    max: u64,
) -> Option<u64> {
    let value = columns.get(name).and_then(|index| row.get(*index))?;
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    value.parse::<u64>().ok().filter(|n| *n <= max)
}

fn column<'a>(row: &'a [String], columns: &BTreeMap<&str, usize>, name: &str) -> &'a str {
    columns
        .get(name)
        .and_then(|index| row.get(*index))
        .map_or("", String::as_str)
}

fn optional_u64(row: &[String], columns: &BTreeMap<&str, usize>, name: &str) -> Option<u64> {
    cell_number(row, columns, name, u64::MAX)
}

fn parse_record(row: &[String], columns: &BTreeMap<&str, usize>) -> Option<LteCsvRecord> {
    let (mcc, mnc) = column(row, columns, "plmn").split_once('-')?;
    if mcc.len() != 3
        || !(2..=3).contains(&mnc.len())
        || mcc == "000"
        || !mcc.bytes().all(|b| b.is_ascii_digit())
        || !mnc.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let tac = cell_number(row, columns, "tac", 65_535)?;
    let eci = cell_number(row, columns, "eci", 268_435_455)?;
    let timestamp = column(row, columns, "deviceTime");
    // The specification requires a timezone. Do not invent UTC for naive dates.
    if !timestamp.contains('T')
        || !timestamp
            .get(19..)
            .is_some_and(|tail| tail.contains('+') || tail.contains('-') || tail.ends_with('Z'))
    {
        return None;
    }
    let epoch = parse_timestamp(timestamp)?;
    let serving = match column(row, columns, "servingCell") {
        "true" => Some(true),
        "false" => Some(false),
        "" => None,
        _ => return None,
    };
    let pci = match column(row, columns, "pci") {
        "" => None,
        _ => Some(u32::try_from(cell_number(row, columns, "pci", 503)?).ok()?),
    };
    let ta = match column(row, columns, "ta") {
        "" => None,
        _ => Some(u32::try_from(cell_number(row, columns, "ta", 1282)?).ok()?),
    };
    let raw = serde_json::to_vec(&json!([{
        "type": "lte", "mcc": mcc, "mnc": mnc,
        "tac": tac, "ci": eci, "registered": serving,
        "pci": pci, "timing_advance": ta
    }]))
    .ok()?;
    let mut scan = parse_cells(&raw).ok()?;
    let mut observation = scan.observations.pop()?;
    observation.freshness = "offline_unverified";
    observation.sighting.observed_at = Some(timestamp.to_owned());
    observation.sighting.observed_epoch = Some(epoch);
    observation.sighting.signal_dbm = column(row, columns, "rsrp")
        .parse::<f64>()
        .ok()
        .filter(|dbm| dbm.is_finite() && (-160.0..=-1.0).contains(dbm));

    let lat = column(row, columns, "latitude").parse::<f64>().ok();
    let lon = column(row, columns, "longitude").parse::<f64>().ok();
    let accuracy = column(row, columns, "accuracy").parse::<f64>().ok();
    let location = match (lat, lon, accuracy) {
        (Some(lat), Some(lon), Some(accuracy))
            if lat.is_finite()
                && lon.is_finite()
                && (-90.0..=90.0).contains(&lat)
                && (-180.0..=180.0).contains(&lon)
                && accuracy.is_finite()
                && accuracy > 0.0
                && accuracy <= 100_000.0 =>
        {
            (Some(lat), Some(lon), Some(accuracy))
        }
        _ => (None, None, None),
    };
    Some(LteCsvRecord {
        observation,
        record_number: optional_u64(row, columns, "recordNumber"),
        group_number: optional_u64(row, columns, "groupNumber"),
        reported_latitude: location.0,
        reported_longitude: location.1,
        reported_accuracy_m: location.2,
        location_age_ms: cell_number(row, columns, "locationAge", 86_400_000),
    })
}

/// Parse only the documented LTE CSV version 0.5.0, rejecting schema drift.
/// No cross-row anomaly audit is run: records can span different times and places.
/// Device serials, SIM slots, mission names and provider labels are not retained.
///
/// # Errors
/// Malformed UTF-8/CSV, unsupported versions or missing/duplicate columns fail closed.
pub fn parse_lte(bytes: &[u8]) -> Result<LteCsvReport, Error> {
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_SURVEY_CSV_BYTES {
        return Err(invalid("input exceeds 256 KiB"));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| invalid("not UTF-8"))?;
    let mut offset = 0;
    let mut version = None;
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if !trimmed.starts_with('#') {
            break;
        }
        if let Some(value) = trimmed.strip_prefix("# CSV Version=") {
            if version.replace(value.trim()).is_some() {
                return Err(invalid("duplicate CSV version"));
            }
        }
        offset += line.len();
    }
    if version != Some(CSV_VERSION) {
        return Err(invalid("missing or unsupported CSV version"));
    }
    let mut rows = csv_rows(&text[offset..])?.into_iter();
    let header = rows.next().ok_or_else(|| invalid("missing header"))?;
    if header.len() > 32 {
        return Err(invalid("too many columns"));
    }
    let mut columns = BTreeMap::new();
    for (index, name) in header.iter().enumerate() {
        if columns.insert(name.as_str(), index).is_some() {
            return Err(invalid("duplicate header column"));
        }
    }
    for required in [
        "deviceTime",
        "plmn",
        "tac",
        "eci",
        "pci",
        "rsrp",
        "ta",
        "servingCell",
        "recordNumber",
        "groupNumber",
        "latitude",
        "longitude",
        "accuracy",
        "locationAge",
    ] {
        if !columns.contains_key(required) {
            return Err(invalid("missing required LTE column"));
        }
    }
    let mut observations = Vec::new();
    let mut rejected = 0;
    for row in rows {
        if row.len() != header.len() {
            rejected += 1;
            continue;
        }
        if let Some(record) = parse_record(&row, &columns) {
            observations.push(record);
        } else {
            rejected += 1;
        }
    }
    Ok(LteCsvReport {
        source: "unverified_network_survey_csv_file",
        acquisition: "offline_replay_no_capture_authentication",
        csv_version: CSV_VERSION,
        status: if observations.is_empty() {
            "inconclusive"
        } else {
            "historical_unverified"
        },
        observed: observations.len(),
        rejected,
        observations,
    })
}

#[must_use]
pub fn render(report: &LteCsvReport) -> String {
    let mut out = format!(
        "source={}\tversion={}\tstatus={}\tobserved={}\trejected={}\n",
        report.source, report.csv_version, report.status, report.observed, report.rejected
    );
    for record in &report.observations {
        let cell = &record.observation;
        let _ = writeln!(
            out,
            "lte\tid={}\ttime={}\tregistered={}\tgroup={}\tlocation_age_ms={}",
            escape_controls(&cell.sighting.network_id),
            escape_controls(cell.sighting.observed_at.as_deref().unwrap_or("unknown")),
            cell.registered
                .map_or("unknown", |v| if v { "yes" } else { "no" }),
            record
                .group_number
                .map_or_else(|| "unknown".to_owned(), |n| n.to_string()),
            record
                .location_age_ms
                .map_or_else(|| "unknown".to_owned(), |n| n.to_string())
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER: &str = "# Created by Network Survey version=2.0\n# CSV Version=0.5.0\ndeviceTime,latitude,longitude,accuracy,recordNumber,groupNumber,plmn,tac,eci,pci,rsrp,ta,servingCell,locationAge,deviceSerialNumber\n";

    #[test]
    fn preserves_plmn_time_and_location_uncertainty_without_device_serial() {
        let data = format!(
            "{HEADER}2025-10-10T13:58:27.603261-04:00,37.7749,-122.4194,22,1,2,310-01,12345,12345678,36,-112.0,39,true,4916,SECRET\n"
        );
        let report = parse_lte(data.as_bytes()).unwrap();
        assert_eq!((report.observed, report.rejected), (1, 0));
        let row = &report.observations[0];
        assert_eq!(
            row.observation.sighting.network_id,
            "lte:310-01-12345-12345678"
        );
        assert_eq!(row.observation.sighting.signal_dbm, Some(-112.0));
        assert_eq!(row.observation.registered, Some(true));
        assert_eq!(row.location_age_ms, Some(4916));
        assert_eq!(row.reported_accuracy_m, Some(22.0));
        assert_eq!(row.observation.sighting.latitude, None);
        assert!(serde_json::to_string(&report).unwrap().contains("310-01"));
        assert!(!serde_json::to_string(&report).unwrap().contains("SECRET"));
    }

    #[test]
    fn malformed_and_unsupported_records_fail_closed() {
        let valid =
            format!("{HEADER}2025-10-10T13:58:27Z,1,2,5,1,1,310-01,1,2,3,-110,0,false,100,x\n");
        assert_eq!(parse_lte(valid.as_bytes()).unwrap().observed, 1);
        assert!(parse_lte(valid.replace("0.5.0", "0.6.0").as_bytes()).is_err());
        assert!(
            parse_lte(valid.replace("310-01", "310-1").as_bytes())
                .unwrap()
                .observations
                .is_empty()
        );
        assert!(
            parse_lte(valid.replace(",3,-110", ",504,-110").as_bytes())
                .unwrap()
                .observations
                .is_empty()
        );
        assert!(
            parse_lte(valid.replace("false", "maybe").as_bytes())
                .unwrap()
                .observations
                .is_empty()
        );
        assert!(parse_lte(b"# CSV Version=0.5.0\na,b\n\"unterminated").is_err());
    }

    #[test]
    fn quoted_csv_fields_and_oversize_inputs_are_bounded() {
        let data = format!(
            "{HEADER}2025-10-10T13:58:27Z,1,2,5,1,1,310-01,1,2,3,-110,0,false,100,\"a,\"\"b\"\"\nline\"\n"
        );
        assert_eq!(parse_lte(data.as_bytes()).unwrap().observed, 1);
        let too_big = vec![b'x'; usize::try_from(MAX_SURVEY_CSV_BYTES).unwrap() + 1];
        assert!(parse_lte(&too_big).is_err());
    }
}
