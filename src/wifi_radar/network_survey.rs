//! Version-pinned, bounded offline Network Survey Wi-Fi CSV interoperability.
//! Imported rows are unverified historical claims, not live Android scan results.
//! Deliberately never creates a WifiScan, MITM assessment, or tracking sweep.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde::Serialize;

use crate::cell_radar::network_survey::{MAX_SURVEY_CSV_BYTES, csv_rows};
use crate::error::Error;
use crate::rf::{band, canonical_network_id, valid_wifi_bssid};
use crate::textnorm::escape_controls;
use crate::timefmt::parse_timestamp;

pub const CSV_VERSION: &str = "0.4.0";
const HEADER: [&str; 30] = [
    "deviceTime", "latitude", "longitude", "altitude", "speed", "accuracy",
    "missionId", "recordNumber", "sourceAddress", "destinationAddress", "bssid",
    "beaconInterval", "serviceSetType", "ssid", "supportedRates",
    "extendedSupportedRates", "cipherSuites", "akmSuites", "encryptionType",
    "wps", "channel", "frequencyMhz", "signalStrength", "snr", "nodeType",
    "standard", "passpoint", "bandwidth", "deviceSerialNumber", "locationAge",
];

#[derive(Debug, Clone, Serialize)]
pub struct WifiCsvRecord {
    /// Canonical individual BSSID, not evidence of ownership or present proximity.
    pub bssid: String,
    pub ssid: Option<String>,
    /// Unauthenticated timestamp supplied by the file, never a host capture clock.
    pub observed_at: String,
    pub observed_epoch: i64,
    pub signal_dbm: f64,
    pub frequency_mhz: Option<i64>,
    pub band: Option<&'static str>,
    pub channel: Option<u16>,
    pub snr_db: Option<f64>,
    pub encryption_type: Option<String>,
    pub node_type: Option<String>,
    pub bandwidth: Option<String>,
    pub wps: Option<bool>,
    pub passpoint: Option<bool>,
    pub record_number: Option<u64>,
    /// GNSS position is a separate, source-reported device fix, not an AP location.
    pub reported_latitude: Option<f64>,
    pub reported_longitude: Option<f64>,
    pub reported_accuracy_m: Option<f64>,
    pub location_age_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WifiCsvReport {
    pub source: &'static str,
    pub acquisition: &'static str,
    pub csv_version: &'static str,
    pub status: &'static str,
    pub observed: usize,
    pub rejected: usize,
    pub observations: Vec<WifiCsvRecord>,
}

fn invalid(reason: &str) -> Error {
    Error::Invalid(format!("Network Survey Wi-Fi CSV: {reason}"))
}

fn column<'a>(row: &'a [String], columns: &BTreeMap<&str, usize>, name: &str) -> &'a str {
    columns
        .get(name)
        .and_then(|index| row.get(*index))
        .map_or("", String::as_str)
}

fn optional_u64(row: &[String], columns: &BTreeMap<&str, usize>, name: &str, max: u64) -> Option<Option<u64>> {
    let raw = column(row, columns, name);
    if raw.is_empty() {
        return Some(None);
    }
    if !raw.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    raw.parse::<u64>().ok().filter(|value| *value <= max).map(Some)
}

fn optional_f64(row: &[String], columns: &BTreeMap<&str, usize>, name: &str, low: f64, high: f64) -> Option<Option<f64>> {
    let raw = column(row, columns, name);
    if raw.is_empty() {
        return Some(None);
    }
    let value = raw.parse::<f64>().ok()?;
    (value.is_finite() && (low..=high).contains(&value)).then_some(Some(value))
}

fn optional_bool(row: &[String], columns: &BTreeMap<&str, usize>, name: &str) -> Option<Option<bool>> {
    match column(row, columns, name) {
        "" => Some(None),
        "true" => Some(Some(true)),
        "false" => Some(Some(false)),
        _ => None,
    }
}

fn optional_text(row: &[String], columns: &BTreeMap<&str, usize>, name: &str, max_bytes: usize) -> Option<Option<String>> {
    let raw = column(row, columns, name);
    if raw.len() > max_bytes {
        return None;
    }
    (!raw.is_empty()).then(|| raw.to_owned()).map_or(Some(None), |value| Some(Some(value)))
}

fn parse_record(row: &[String], columns: &BTreeMap<&str, usize>) -> Option<WifiCsvRecord> {
    let raw_bssid = column(row, columns, "bssid");
    if !valid_wifi_bssid(raw_bssid) {
        return None;
    }
    let timestamp = column(row, columns, "deviceTime");
    // Explicit RFC3339 timezone required. A naive local clock is not UTC.
    if !timestamp.contains('T')
        || !timestamp
            .get(19..)
            .is_some_and(|tail| tail.contains('+') || tail.contains('-') || tail.ends_with('Z'))
    {
        return None;
    }
    let epoch = parse_timestamp(timestamp)?;
    let rssi = column(row, columns, "signalStrength").parse::<f64>().ok()?;
    if !rssi.is_finite() || !(-150.0..=0.0).contains(&rssi) {
        return None;
    }
    let frequency = optional_u64(row, columns, "frequencyMhz", 7125)?
        .map(i64::try_from)
        .transpose()
        .ok()?
        .filter(|freq| (2300..=7125).contains(freq));
    // A supplied but implausible frequency is invalid, not silently unknown.
    if !column(row, columns, "frequencyMhz").is_empty() && frequency.is_none() {
        return None;
    }
    let channel = optional_u64(row, columns, "channel", 255)?
        .map(u16::try_from)
        .transpose()
        .ok()?;
    let snr = optional_f64(row, columns, "snr", -100.0, 100.0)?;
    let wps = optional_bool(row, columns, "wps")?;
    let passpoint = optional_bool(row, columns, "passpoint")?;
    let ssid = optional_text(row, columns, "ssid", 32)?;
    let encryption_type = optional_text(row, columns, "encryptionType", 64)?;
    let node_type = optional_text(row, columns, "nodeType", 32)?;
    let bandwidth = optional_text(row, columns, "bandwidth", 32)?;
    let record_number = optional_u64(row, columns, "recordNumber", u64::MAX)?;
    let location_age_ms = optional_u64(row, columns, "locationAge", 86_400_000)?;
    let lat = column(row, columns, "latitude").parse::<f64>().ok();
    let lon = column(row, columns, "longitude").parse::<f64>().ok();
    let accuracy = column(row, columns, "accuracy").parse::<f64>().ok();
    let location = match (lat, lon, accuracy) {
        (Some(lat), Some(lon), Some(accuracy))
            if lat.is_finite()
                && lon.is_finite()
                && (-90.0..=90.0).contains(&lat)
                && (-180.0..=180.0).contains(&lon)
                && !(lat == 0.0 && lon == 0.0)
                && accuracy.is_finite()
                && accuracy > 0.0
                && accuracy <= 100_000.0 =>
        {
            (Some(lat), Some(lon), Some(accuracy))
        }
        _ => (None, None, None),
    };
    Some(WifiCsvRecord {
        bssid: canonical_network_id(raw_bssid),
        ssid,
        observed_at: timestamp.to_owned(),
        observed_epoch: epoch,
        signal_dbm: rssi,
        frequency_mhz: frequency,
        band: band(frequency),
        channel,
        snr_db: snr,
        encryption_type,
        node_type,
        bandwidth,
        wps,
        passpoint,
        record_number,
        reported_latitude: location.0,
        reported_longitude: location.1,
        reported_accuracy_m: location.2,
        location_age_ms,
    })
}

/// Parse only Network Survey Wi-Fi CSV v0.4.0 with the exact 30-column schema.
/// This intentionally excludes source/destination MACs, mission and device serial
/// from output, and never promotes historical claims to a current sensor scan.
///
/// # Errors
/// Oversized input, invalid UTF-8, malformed CSV and schema drift fail closed.
pub fn parse_wifi(bytes: &[u8]) -> Result<WifiCsvReport, Error> {
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
    if header.len() != HEADER.len()
        || !header.iter().zip(HEADER).all(|(actual, expected)| actual == expected)
    {
        return Err(invalid("Wi-Fi 0.4.0 requires the exact documented 30-column header"));
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
    Ok(WifiCsvReport {
        source: "unverified_network_survey_wifi_csv_file",
        acquisition: "offline_replay_no_capture_authentication",
        csv_version: CSV_VERSION,
        status: if observations.is_empty() { "inconclusive" } else { "historical_unverified" },
        observed: observations.len(),
        rejected,
        observations,
    })
}

#[must_use]
pub fn render(report: &WifiCsvReport) -> String {
    let mut out = format!(
        "source={}\tversion={}\tstatus={}\tobserved={}\trejected={}\n",
        report.source, report.csv_version, report.status, report.observed, report.rejected
    );
    for row in &report.observations {
        let _ = writeln!(
            out,
            "wifi-historical\tbssid={}\tssid={}\ttime={}\trssi_dbm={}\tband={}\tlocation_age_ms={}",
            escape_controls(&row.bssid),
            escape_controls(row.ssid.as_deref().unwrap_or("")),
            escape_controls(&row.observed_at),
            row.signal_dbm,
            row.band.unwrap_or("unknown"),
            row.location_age_ms.map_or_else(|| "unknown".to_owned(), |value| value.to_string())
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const PREFIX: &str = "# Created by Network Survey version=2.0\n# CSV Version=0.4.0\ndeviceTime,latitude,longitude,altitude,speed,accuracy,missionId,recordNumber,sourceAddress,destinationAddress,bssid,beaconInterval,serviceSetType,ssid,supportedRates,extendedSupportedRates,cipherSuites,akmSuites,encryptionType,wps,channel,frequencyMhz,signalStrength,snr,nodeType,standard,passpoint,bandwidth,deviceSerialNumber,locationAge\n";

    fn row() -> String {
        [
            "2025-10-10T13:58:27Z", "37.7", "-122.4", "10", "0", "22",
            "PRIVATE-MISSION", "1", "PRIVATE-SOURCE", "PRIVATE-DEST",
            "3C:5A:B4:11:22:33", "100", "ESS", "SurveyAP", "6;12", "24",
            "CCMP", "PSK", "WPA2", "true", "1", "2412", "-57", "20",
            "AP", "IEEE80211AX", "false", "MHZ_20", "PRIVATE-SERIAL", "4916",
        ].join(",")
    }

    #[test]
    fn historical_wifi_preserves_identity_uncertainty_and_privacy() {
        let report = parse_wifi(format!("{PREFIX}{}\n", row()).as_bytes()).unwrap();
        assert_eq!((report.observed, report.rejected), (1, 0));
        assert_eq!(report.status, "historical_unverified");
        let record = &report.observations[0];
        assert_eq!(record.bssid, "3c:5a:b4:11:22:33");
        assert_eq!(record.signal_dbm, -57.0);
        assert_eq!(record.band, Some("2.4GHz"));
        assert_eq!(record.reported_accuracy_m, Some(22.0));
        assert_eq!(record.location_age_ms, Some(4916));
        let json = serde_json::to_string(&report).unwrap();
        for secret in ["PRIVATE-MISSION", "PRIVATE-SOURCE", "PRIVATE-DEST", "PRIVATE-SERIAL"] {
            assert!(!json.contains(secret));
        }
        assert!(!json.contains("mitm_assessment"));
        assert!(!json.contains("os_cached"));
    }

    #[test]
    fn invalid_identifiers_clock_and_signal_are_rejected() {
        let valid = format!("{PREFIX}{}\n", row());
        for bad in [
            valid.replace("3C:5A:B4:11:22:33", "02:00:00:00:00:00"),
            valid.replace("13:58:27Z", "13:58:27"),
            valid.replace(",-57,20,", ",NaN,20,"),
            valid.replace(",-57,20,", ",1,20,"),
            valid.replace(",true,1,2412,", ",maybe,1,2412,"),
            valid.replace(",1,2412,-57,", ",1,9000,-57,"),
        ] {
            let report = parse_wifi(bad.as_bytes()).unwrap();
            assert_eq!((report.observed, report.rejected), (0, 1));
        }
    }

    #[test]
    fn version_schema_and_input_bounds_fail_closed() {
        let valid = format!("{PREFIX}{}\n", row());
        assert!(parse_wifi(valid.replace("0.4.0", "0.5.0").as_bytes()).is_err());
        assert!(parse_wifi(valid.replace("channel,frequencyMhz", "frequencyMhz,channel").as_bytes()).is_err());
        assert!(parse_wifi(b"# CSV Version=0.4.0\na,b\n\"unterminated").is_err());
        assert!(parse_wifi(&vec![b'x'; 262_145]).is_err());
    }

    #[test]
    fn quoted_ssid_and_missing_optional_fields_are_supported() {
        let mut fields: Vec<String> = row().split(',').map(str::to_owned).collect();
        fields[13] = "\"Lab, \"\"guest\"\"\"".to_owned();
        for index in [20, 21, 23, 26, 27, 29] {
            fields[index].clear();
        }
        let report = parse_wifi(format!("{PREFIX}{}\n", fields.join(",")).as_bytes()).unwrap();
        assert_eq!(report.observed, 1);
        let record = &report.observations[0];
        assert_eq!(record.ssid.as_deref(), Some("Lab, \"guest\""));
        assert_eq!(record.frequency_mhz, None);
        assert_eq!(record.location_age_ms, None);
    }
}
