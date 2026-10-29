//! Bounded, version-pinned offline Network Survey Bluetooth CSV interoperability.
//! These are unauthenticated historical claims, never live Android Bluetooth scans.
//! No device-owner attribution, cross-session identity assertion, or tracking sweep.

use std::fmt::Write as _;

use serde::Serialize;

use crate::rf::survey_csv::{MAX_SURVEY_CSV_BYTES, csv_rows};
use crate::error::Error;
use crate::rf::{canonical_network_id, is_mac};
use crate::textnorm::escape_controls;
use crate::timefmt::parse_timestamp;

pub const CSV_VERSION: &str = "0.3.0";

const HEADER: [&str; 23] = [
    "deviceTime",
    "latitude",
    "longitude",
    "altitude",
    "speed",
    "accuracy",
    "missionId",
    "recordNumber",
    "sourceAddress",
    "destinationAddress",
    "signalStrength",
    "txPower",
    "technology",
    "supportedTechnologies",
    "otaDeviceName",
    "channel",
    "deviceSerialNumber",
    "locationAge",
    "addressType",
    "deviceClass",
    "serviceUuids",
    "companyId",
    "mfgData",
];

#[derive(Debug, Clone, Serialize)]
pub struct BluetoothCsvRecord {
    /// One source-claimed radio address; not an authenticated persistent identity.
    pub address: String,
    pub address_type: &'static str,
    pub identity_stability: &'static str,
    pub technology: &'static str,
    pub supported_technologies: Option<&'static str>,
    pub observed_at: String,
    pub observed_epoch: i64,
    pub signal_dbm: f64,
    pub tx_power_dbm: Option<f64>,
    pub channel: Option<u8>,
    pub advertised_name: Option<String>,
    pub service_uuids: Option<String>,
    pub company_id: Option<String>,
    pub device_class: Option<String>,
    pub record_number: Option<u64>,
    /// These are unverified fixes for the collecting handset, not the emitter.
    pub reported_latitude: Option<f64>,
    pub reported_longitude: Option<f64>,
    pub reported_accuracy_m: Option<f64>,
    pub location_age_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BluetoothCsvReport {
    pub source: &'static str,
    pub acquisition: &'static str,
    pub csv_version: &'static str,
    pub status: &'static str,
    pub observed: usize,
    pub rejected: usize,
    pub observations: Vec<BluetoothCsvRecord>,
}

fn invalid(reason: &str) -> Error {
    Error::Invalid(format!("Network Survey Bluetooth CSV: {reason}"))
}

#[derive(Debug, Clone, Copy)]
struct InvalidField;

fn number(raw: &str, max: u64) -> Result<Option<u64>, InvalidField> {
    if raw.is_empty() {
        return Ok(None);
    }
    if !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(InvalidField);
    }
    raw.parse::<u64>()
        .ok()
        .filter(|value| *value <= max)
        .map(Some)
        .ok_or(InvalidField)
}

fn finite(raw: &str, low: f64, high: f64) -> Result<Option<f64>, InvalidField> {
    if raw.is_empty() {
        return Ok(None);
    }
    let value = raw.parse::<f64>().map_err(|_| InvalidField)?;
    (value.is_finite() && (low..=high).contains(&value))
        .then_some(Some(value))
        .ok_or(InvalidField)
}

fn enum_value(raw: &str, allowed: &[&'static str]) -> Result<Option<&'static str>, InvalidField> {
    if raw.is_empty() {
        return Ok(None);
    }
    allowed
        .iter()
        .copied()
        .find(|value| *value == raw)
        .map(Some)
        .ok_or(InvalidField)
}

fn text_field(raw: &str, max_bytes: usize) -> Result<Option<String>, InvalidField> {
    if raw.len() > max_bytes {
        return Err(InvalidField);
    }
    Ok((!raw.is_empty()).then(|| raw.to_owned()))
}

fn hex_field(raw: &str, max_digits: usize) -> Result<Option<String>, InvalidField> {
    if raw.is_empty() {
        return Ok(None);
    }
    let digits = raw.strip_prefix("0x").unwrap_or(raw);
    if digits.is_empty()
        || digits.len() > max_digits
        || !digits.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(InvalidField);
    }
    Ok(Some(digits.to_ascii_uppercase()))
}

fn valid_manufacturer_data(raw: &str) -> bool {
    raw.is_empty()
        || (raw.len() <= 1024
            && raw.len().is_multiple_of(2)
            && raw.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn parse_record(row: &[String]) -> Option<BluetoothCsvRecord> {
    let address = row[8].as_str();
    // Bluetooth LE random addresses do not follow Wi-Fi's I/G-bit rules.
    // Reject only malformed addresses and known Android redaction sentinels.
    if !is_mac(address)
        || address.eq_ignore_ascii_case("00:00:00:00:00:00")
        || address.eq_ignore_ascii_case("02:00:00:00:00:00")
    {
        return None;
    }
    let address_type = enum_value(&row[18], &["UNKNOWN", "PUBLIC", "RANDOM", "ANONYMOUS"])
        .ok()?
        .unwrap_or("UNKNOWN");
    // Anonymous advertising cannot establish an address-based observation.
    if address_type == "ANONYMOUS" {
        return None;
    }
    let timestamp = row[0].as_str();
    if !timestamp.contains('T')
        || !timestamp
            .get(19..)
            .is_some_and(|tail| tail.contains('+') || tail.contains('-') || tail.ends_with('Z'))
    {
        return None;
    }
    let observed_epoch = parse_timestamp(timestamp)?;
    let signal_dbm = finite(&row[10], -200.0, 200.0).ok()??;
    let tx_power_dbm = finite(&row[11], -200.0, 200.0).ok()?;
    let technology = enum_value(&row[12], &["UNKNOWN", "BR_EDR", "LE"])
        .ok()?
        .unwrap_or("UNKNOWN");
    let supported_technologies = enum_value(&row[13], &["UNKNOWN", "BR_EDR", "LE", "DUAL"]).ok()?;
    let advertised_name = text_field(&row[14], 128).ok()?;
    let channel = number(&row[15], 78)
        .ok()?
        .map(u8::try_from)
        .transpose()
        .ok()?;
    let record_number = number(&row[7], u64::MAX).ok()?;
    if record_number == Some(0) {
        return None;
    }
    let location_age_ms = number(&row[17], 86_400_000).ok()?;
    let device_class = hex_field(&row[19], 8).ok()?;
    let service_uuids = text_field(&row[20], 1024).ok()?;
    let company_id = hex_field(&row[21], 8).ok()?;
    // Validate but never emit raw manufacturer payloads: these can carry
    // rotating identifiers, telemetry or application-specific private data.
    if !valid_manufacturer_data(&row[22]) {
        return None;
    }

    let location = match (
        row[1].parse::<f64>().ok(),
        row[2].parse::<f64>().ok(),
        row[5].parse::<f64>().ok(),
    ) {
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

    Some(BluetoothCsvRecord {
        address: canonical_network_id(address),
        address_type,
        identity_stability: if address_type == "RANDOM" {
            "randomized_or_ephemeral"
        } else {
            "unverified"
        },
        technology,
        supported_technologies,
        observed_at: timestamp.to_owned(),
        observed_epoch,
        signal_dbm,
        tx_power_dbm,
        channel,
        advertised_name,
        service_uuids,
        company_id,
        device_class,
        record_number,
        reported_latitude: location.0,
        reported_longitude: location.1,
        reported_accuracy_m: location.2,
        location_age_ms,
    })
}

/// Parse exactly Network Survey Bluetooth CSV v0.3.0 with its 23-column header.
/// No capture, transport, live radar, tracking, or owner-attribution side effects.
///
/// # Errors
/// Oversized input, invalid UTF-8, malformed CSV or schema drift fail closed.
pub fn parse_bluetooth(bytes: &[u8]) -> Result<BluetoothCsvReport, Error> {
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
    let mut rows = csv_rows(&text[offset..])
        .map_err(|_| invalid("malformed CSV"))?
        .into_iter();
    let header = rows.next().ok_or_else(|| invalid("missing header"))?;
    if header.len() != HEADER.len()
        || !header
            .iter()
            .zip(HEADER)
            .all(|(actual, expected)| actual.as_str() == expected)
    {
        return Err(invalid(
            "Bluetooth 0.3.0 requires the exact documented 23-column header",
        ));
    }
    let mut observations = Vec::new();
    let mut rejected = 0;
    for row in rows {
        if row.len() != HEADER.len() {
            rejected += 1;
        } else if let Some(record) = parse_record(&row) {
            observations.push(record);
        } else {
            rejected += 1;
        }
    }
    Ok(BluetoothCsvReport {
        source: "unverified_network_survey_bluetooth_csv_file",
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
pub fn render(report: &BluetoothCsvReport) -> String {
    let mut out = format!(
        "source={}\tversion={}\tstatus={}\tobserved={}\trejected={}\n",
        report.source, report.csv_version, report.status, report.observed, report.rejected
    );
    for row in &report.observations {
        let _ = writeln!(
            out,
            "bluetooth-historical\taddress={}\ttype={}\tstability={}\ttechnology={}\tname={}\ttime={}\trssi_dbm={}",
            escape_controls(&row.address),
            row.address_type,
            row.identity_stability,
            row.technology,
            escape_controls(row.advertised_name.as_deref().unwrap_or("")),
            escape_controls(&row.observed_at),
            row.signal_dbm
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const PREFIX: &str = "# Created by Network Survey version=2.0\n# CSV Version=0.3.0\ndeviceTime,latitude,longitude,altitude,speed,accuracy,missionId,recordNumber,sourceAddress,destinationAddress,signalStrength,txPower,technology,supportedTechnologies,otaDeviceName,channel,deviceSerialNumber,locationAge,addressType,deviceClass,serviceUuids,companyId,mfgData\n";

    fn row() -> String {
        [
            "2025-10-10T13:58:27Z",
            "37.7",
            "-122.4",
            "10",
            "0",
            "22",
            "PRIVATE-MISSION",
            "1",
            "C3:12:34:56:78:9A",
            "PRIVATE-DEST",
            "-57",
            "-10",
            "LE",
            "DUAL",
            "Survey Beacon",
            "37",
            "PRIVATE-SERIAL",
            "4916",
            "RANDOM",
            "5A0C",
            "180D;180F",
            "004C",
            "4C00AABB",
        ]
        .join(",")
    }

    #[test]
    fn preserves_ble_metadata_but_not_private_capture_identifiers() {
        let report = parse_bluetooth(format!("{PREFIX}{}\n", row()).as_bytes()).unwrap();
        assert_eq!((report.observed, report.rejected), (1, 0));
        assert_eq!(report.status, "historical_unverified");
        let record = &report.observations[0];
        assert_eq!(record.address, "c3:12:34:56:78:9a");
        assert_eq!(record.identity_stability, "randomized_or_ephemeral");
        assert_eq!(record.technology, "LE");
        assert_eq!(record.service_uuids.as_deref(), Some("180D;180F"));
        assert_eq!(record.company_id.as_deref(), Some("004C"));
        assert_eq!(record.reported_accuracy_m, Some(22.0));
        assert_eq!(record.location_age_ms, Some(4916));
        let json = serde_json::to_string(&report).unwrap();
        for secret in [
            "PRIVATE-MISSION",
            "PRIVATE-DEST",
            "PRIVATE-SERIAL",
            "4C00AABB",
        ] {
            assert!(!json.contains(secret));
        }
        assert!(!json.contains("BluetoothRadar"));
        assert!(!json.contains("follower"));
    }

    #[test]
    fn rejects_invalid_identity_clock_signal_and_enumerations() {
        let valid = format!("{PREFIX}{}\n", row());
        for bad in [
            valid.replace("C3:12:34:56:78:9A", "00:00:00:00:00:00"),
            valid.replace("13:58:27Z", "13:58:27"),
            valid.replace(",-57,-10,", ",NaN,-10,"),
            valid.replace(",LE,DUAL,", ",WIFI,DUAL,"),
            valid.replace(",RANDOM,5A0C,", ",MYSTERY,5A0C,"),
            valid.replace(",37,PRIVATE-SERIAL,", ",79,PRIVATE-SERIAL,"),
            valid.replace(",004C,4C00AABB", ",004C,NOT_HEX"),
        ] {
            let report = parse_bluetooth(bad.as_bytes()).unwrap();
            assert_eq!((report.observed, report.rejected), (0, 1));
        }
    }

    #[test]
    fn schema_version_csv_and_input_limits_fail_closed() {
        let valid = format!("{PREFIX}{}\n", row());
        assert!(parse_bluetooth(valid.replace("0.3.0", "0.4.0").as_bytes()).is_err());
        assert!(
            parse_bluetooth(
                valid
                    .replace("signalStrength,txPower", "txPower,signalStrength")
                    .as_bytes()
            )
            .is_err()
        );
        assert!(parse_bluetooth(b"# CSV Version=0.3.0\na,b\n\"unterminated").is_err());
        assert!(parse_bluetooth(&vec![b'x'; 262_145]).is_err());
    }

    #[test]
    fn quoted_name_and_missing_location_do_not_invent_coordinates() {
        let mut fields: Vec<String> = row().split(',').map(str::to_owned).collect();
        fields[14] = "\"Lab, \"\"beacon\"\"\"".to_owned();
        for index in [1, 2, 5, 11, 17, 19, 20, 21, 22] {
            fields[index].clear();
        }
        let report = parse_bluetooth(format!("{PREFIX}{}\n", fields.join(",")).as_bytes()).unwrap();
        assert_eq!(report.observed, 1);
        let record = &report.observations[0];
        assert_eq!(record.advertised_name.as_deref(), Some("Lab, \"beacon\""));
        assert_eq!(record.reported_latitude, None);
        assert_eq!(record.reported_accuracy_m, None);
        assert_eq!(record.tx_power_dbm, None);
    }
}
