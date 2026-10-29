//! Bounded, offline Network Survey 5G NR CSV v0.4.0 importer.
//! Source-claimed timestamps and GNSS fixes are unverified; no radio capture occurs.
//! Device serials, mission IDs, SIM slots and provider labels are never emitted.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde::Serialize;
use serde_json::json;

use super::{MAX_SURVEY_CSV_BYTES, cell_number, column, csv_rows};
use crate::cell_radar::{CellObservation, parse_cells};
use crate::error::Error;
use crate::textnorm::escape_controls;
use crate::timefmt::parse_timestamp;

pub const NR_CSV_VERSION: &str = "0.4.0";
const HEADER: [&str; 28] = [
    "deviceTime",
    "latitude",
    "longitude",
    "altitude",
    "speed",
    "accuracy",
    "missionId",
    "recordNumber",
    "groupNumber",
    "mcc",
    "mnc",
    "plmn",
    "tac",
    "nci",
    "narfcn",
    "pci",
    "ssRsrp",
    "ssRsrq",
    "ssSinr",
    "csiRsrp",
    "csiRsrq",
    "csiSinr",
    "ta",
    "servingCell",
    "provider",
    "slot",
    "deviceSerialNumber",
    "locationAge",
];

#[derive(Debug, Clone, Serialize)]
pub struct NrCsvRecord {
    pub observation: CellObservation,
    pub record_number: Option<u64>,
    pub group_number: Option<u64>,
    pub reported_latitude: Option<f64>,
    pub reported_longitude: Option<f64>,
    pub reported_accuracy_m: Option<f64>,
    pub location_age_ms: Option<u64>,
    pub narfcn: Option<u32>,
    pub timing_advance: Option<u32>,
    pub ss_rsrq_db: Option<f64>,
    pub ss_sinr_db: Option<f64>,
    pub csi_rsrp_dbm: Option<f64>,
    pub csi_rsrq_db: Option<f64>,
    pub csi_sinr_db: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NrCsvReport {
    pub source: &'static str,
    pub acquisition: &'static str,
    pub csv_version: &'static str,
    pub status: &'static str,
    pub observed: usize,
    pub rejected: usize,
    pub observations: Vec<NrCsvRecord>,
}

fn invalid(reason: &str) -> Error {
    Error::Invalid(format!("Network Survey NR CSV: {reason}"))
}

fn optional_number(
    row: &[String],
    columns: &BTreeMap<&str, usize>,
    name: &str,
    max: u64,
) -> Result<Option<u64>, &'static str> {
    if column(row, columns, name).is_empty() {
        Ok(None)
    } else {
        cell_number(row, columns, name, max)
            .map(Some)
            .ok_or("invalid optional number")
    }
}

fn optional_measurement(
    row: &[String],
    columns: &BTreeMap<&str, usize>,
    name: &str,
    low: f64,
    high: f64,
) -> Result<Option<f64>, &'static str> {
    let raw = column(row, columns, name);
    if raw.is_empty() {
        return Ok(None);
    }
    let value = raw
        .parse::<f64>()
        .map_err(|_| "invalid optional measurement")?;
    if value.is_finite() && (low..=high).contains(&value) {
        Ok(Some(value))
    } else {
        Err("out-of-range optional measurement")
    }
}

fn parse_record(row: &[String], columns: &BTreeMap<&str, usize>) -> Option<NrCsvRecord> {
    let (mcc, mnc) = column(row, columns, "plmn").split_once('-')?;
    if mcc.len() != 3
        || mcc == "000"
        || !(2..=3).contains(&mnc.len())
        || !mcc.bytes().all(|b| b.is_ascii_digit())
        || !mnc.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    // Deprecated integer fields must not contradict the leading-zero-preserving PLMN.
    for (name, value) in [("mcc", mcc), ("mnc", mnc)] {
        let legacy = column(row, columns, name);
        if !legacy.is_empty() && legacy.parse::<u16>().ok()? != value.parse::<u16>().ok()? {
            return None;
        }
    }
    let tac = cell_number(row, columns, "tac", 16_777_215)?;
    let nci = cell_number(row, columns, "nci", 68_719_476_735)?;
    let narfcn = optional_u32(row, columns, "narfcn", 3_279_165).ok()?;
    let pci = optional_u32(row, columns, "pci", 1007).ok()?;
    let timing_advance = optional_u32(row, columns, "ta", 3846).ok()?;
    let record_number = optional_number(row, columns, "recordNumber", u64::MAX).ok()?;
    let group_number = optional_number(row, columns, "groupNumber", u64::MAX).ok()?;
    let location_age_ms = optional_number(row, columns, "locationAge", 86_400_000).ok()?;
    let sync_signal_power = optional_measurement(row, columns, "ssRsrp", -156.0, -31.0).ok()?;
    let sync_signal_quality = optional_measurement(row, columns, "ssRsrq", -43.0, 20.0).ok()?;
    let sync_signal_sinr = optional_measurement(row, columns, "ssSinr", -23.0, 40.0).ok()?;
    let channel_state_power = optional_measurement(row, columns, "csiRsrp", -140.0, -44.0).ok()?;
    let channel_state_quality =
        optional_measurement(row, columns, "csiRsrq", -200.0, 200.0).ok()?;
    let channel_state_sinr = optional_measurement(row, columns, "csiSinr", -23.0, 40.0).ok()?;
    let serving = match column(row, columns, "servingCell") {
        "true" => Some(true),
        "false" => Some(false),
        "" => None,
        _ => return None,
    };
    let timestamp = column(row, columns, "deviceTime");
    if !timestamp.contains('T')
        || !timestamp
            .get(19..)
            .is_some_and(|tail| tail.contains('+') || tail.contains('-') || tail.ends_with('Z'))
    {
        return None;
    }
    let epoch = parse_timestamp(timestamp)?;
    let raw = serde_json::to_vec(&json!([{
        "type": "nr", "mcc": mcc, "mnc": mnc,
        "tac": tac, "nci": nci, "registered": serving, "pci": pci
    }]))
    .ok()?;
    let mut scan = parse_cells(&raw).ok()?;
    let mut observation = scan.observations.pop()?;
    observation.freshness = "offline_unverified";
    observation.sighting.observed_at = Some(timestamp.to_owned());
    observation.sighting.observed_epoch = Some(epoch);
    observation.sighting.signal_dbm = sync_signal_power;

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
    Some(NrCsvRecord {
        observation,
        record_number,
        group_number,
        reported_latitude: location.0,
        reported_longitude: location.1,
        reported_accuracy_m: location.2,
        location_age_ms,
        narfcn,
        timing_advance,
        ss_rsrq_db: sync_signal_quality,
        ss_sinr_db: sync_signal_sinr,
        csi_rsrp_dbm: channel_state_power,
        csi_rsrq_db: channel_state_quality,
        csi_sinr_db: channel_state_sinr,
    })
}

fn optional_u32(
    row: &[String],
    columns: &BTreeMap<&str, usize>,
    name: &str,
    max: u64,
) -> Result<Option<u32>, &'static str> {
    optional_number(row, columns, name, max)?
        .map(|value| u32::try_from(value).map_err(|_| "out-of-range optional number"))
        .transpose()
}

/// Parse an explicitly supplied NR CSV, refusing unknown schema versions and column layouts.
/// The result is historical unverified evidence, not a contemporaneous RF observation.
///
/// # Errors
/// Refuses oversized, invalid UTF-8, malformed CSV, unsupported versions and schema drift.
pub fn parse_nr(bytes: &[u8]) -> Result<NrCsvReport, Error> {
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
    if version != Some(NR_CSV_VERSION) {
        return Err(invalid("missing or unsupported CSV version"));
    }
    let mut rows = csv_rows(&text[offset..])?.into_iter();
    let header = rows.next().ok_or_else(|| invalid("missing header"))?;
    if header.len() != HEADER.len()
        || !header
            .iter()
            .zip(HEADER)
            .all(|(actual, expected)| actual.as_str() == expected)
    {
        return Err(invalid(
            "NR 0.4.0 requires the exact documented 28-column header",
        ));
    }
    let columns: BTreeMap<&str, usize> = header
        .iter()
        .enumerate()
        .map(|(index, name)| (name.as_str(), index))
        .collect();
    let mut observations = Vec::new();
    let mut rejected = 0;
    for row in rows {
        if row.len() != HEADER.len() {
            rejected += 1;
        } else if let Some(record) = parse_record(&row, &columns) {
            observations.push(record);
        } else {
            rejected += 1;
        }
    }
    Ok(NrCsvReport {
        source: "unverified_network_survey_nr_csv_file",
        acquisition: "offline_replay_no_capture_authentication",
        csv_version: NR_CSV_VERSION,
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
pub fn render(report: &NrCsvReport) -> String {
    let mut out = format!(
        "source={}\tversion={}\tstatus={}\tobserved={}\trejected={}\n",
        report.source, report.csv_version, report.status, report.observed, report.rejected
    );
    for record in &report.observations {
        let cell = &record.observation;
        let _ = writeln!(
            out,
            "nr\tid={}\ttime={}\tregistered={}\tgroup={}\tlocation_age_ms={}",
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

    const PREFIX: &str = "# Created by Network Survey version=2.0\n# CSV Version=0.4.0\ndeviceTime,latitude,longitude,altitude,speed,accuracy,missionId,recordNumber,groupNumber,mcc,mnc,plmn,tac,nci,narfcn,pci,ssRsrp,ssRsrq,ssSinr,csiRsrp,csiRsrq,csiSinr,ta,servingCell,provider,slot,deviceSerialNumber,locationAge\n";

    fn row() -> String {
        [
            "2025-10-10T13:58:27.603261-04:00",
            "37.7749",
            "-122.4194",
            "15",
            "0",
            "22",
            "PRIVATE-MISSION",
            "1",
            "2",
            "310",
            "1",
            "310-01",
            "16777215",
            "68719476735",
            "3279165",
            "1007",
            "-101.5",
            "-12",
            "20",
            "-110",
            "-15",
            "10",
            "3846",
            "true",
            "Example",
            "0",
            "PRIVATE-SERIAL",
            "4916",
        ]
        .join(",")
    }

    #[test]
    fn preserves_36bit_identity_plmn_and_uncertainty_without_device_identity() {
        let report = parse_nr(format!("{PREFIX}{}\n", row()).as_bytes()).unwrap();
        assert_eq!((report.observed, report.rejected), (1, 0));
        let record = &report.observations[0];
        assert_eq!(
            record.observation.sighting.network_id,
            "nr:310-01-16777215-68719476735"
        );
        assert_eq!(record.observation.sighting.signal_dbm, Some(-101.5));
        assert_eq!(record.observation.registered, Some(true));
        assert_eq!(record.observation.site, None);
        assert_eq!(record.reported_accuracy_m, Some(22.0));
        assert_eq!(record.location_age_ms, Some(4916));
        assert_eq!(record.narfcn, Some(3_279_165));
        assert_eq!(record.timing_advance, Some(3846));
        assert_eq!(record.observation.sighting.latitude, None);
        let serialized = serde_json::to_string(&report).unwrap();
        assert!(!serialized.contains("PRIVATE-MISSION"));
        assert!(!serialized.contains("PRIVATE-SERIAL"));
        assert!(!serialized.contains("Example"));
    }

    #[test]
    fn invalid_ids_plmn_conflicts_and_unknown_serving_are_rejected() {
        let valid = format!("{PREFIX}{}\n", row());
        for bad in [
            valid.replace("68719476735", "68719476736"),
            valid.replace("16777215", "16777216"),
            valid.replace("3279165", "3279166"),
            valid.replace(",1007,", ",1008,"),
            valid.replace(",310,1,310-01,", ",310,2,310-01,"),
            valid.replace(",true,Example,", ",maybe,Example,"),
            valid.replace("-101.5", "NaN"),
        ] {
            let report = parse_nr(bad.as_bytes()).unwrap();
            assert_eq!((report.observed, report.rejected), (0, 1));
        }
    }

    #[test]
    fn strict_schema_and_input_limits_fail_closed() {
        let valid = format!("{PREFIX}{}\n", row());
        assert!(parse_nr(valid.replace("0.4.0", "0.5.0").as_bytes()).is_err());
        assert!(parse_nr(valid.replace("narfcn,pci", "pci,narfcn").as_bytes()).is_err());
        assert!(parse_nr(b"# CSV Version=0.4.0\na,b\n\"unterminated").is_err());
        assert!(parse_nr(&vec![b'x'; 262_145]).is_err());
    }

    #[test]
    fn absent_optional_measurements_remain_unknown() {
        let mut parts: Vec<String> = row().split(',').map(str::to_owned).collect();
        for index in [14, 15, 16, 17, 18, 19, 20, 21, 22] {
            parts[index].clear();
        }
        parts[23].clear();
        let report = parse_nr(format!("{PREFIX}{}\n", parts.join(",")).as_bytes()).unwrap();
        assert_eq!(report.observed, 1);
        let record = &report.observations[0];
        assert_eq!(record.observation.registered, None);
        assert_eq!(record.observation.sighting.signal_dbm, None);
        assert_eq!(record.narfcn, None);
    }
}
