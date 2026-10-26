//! Rootless Android cell-tower observations from Termux:API's telephony cache.
//! Cell identities describe what Android reported, not GPS coordinates or
//! independent evidence that a tower was within range at a specific UTC time.

use std::fmt::Write as _;

use serde::Serialize;
use serde_json::Value;

use crate::error::Error;
use crate::rf::{RadioKind, RfSighting, RfSource};
use crate::textnorm::escape_controls;

/// The same memory bound as the Wi-Fi JSON acquisition path.
pub const MAX_CELL_SCAN_BYTES: u64 = 1_048_576;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CellObservation {
    pub sighting: RfSighting,
    pub technology: &'static str,
    /// Mobile country and network codes; unavailable for CDMA identities.
    pub mcc: Option<String>,
    pub mnc: Option<String>,
    pub area_code: u64,
    pub cell_id: u64,
    pub registered: Option<bool>,
    /// No reliable capture-age field is exposed by this Termux:API JSON.
    pub freshness: &'static str,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CellScan {
    pub source: &'static str,
    pub acquisition: &'static str,
    pub status: &'static str,
    pub observed: usize,
    pub rejected: usize,
    pub observations: Vec<CellObservation>,
}

impl CellScan {
    /// Return a coarse registered-cell bucket only when the Android snapshot
    /// identifies exactly one distinct registered cell. Multiple registered
    /// identities may reflect dual SIMs or concurrent radio technologies;
    /// choosing whichever appeared first would fabricate a single location.
    /// Duplicate rows for the same identity are acceptable. `None` keeps the
    /// tracking sweep unplaced, without treating the cellular scan as empty.
    ///
    /// Retain the original bucket string format for historical compatibility.
    #[must_use]
    pub fn serving_cell(&self) -> Option<String> {
        let mut registered = self
            .observations
            .iter()
            .filter(|cell| cell.registered == Some(true));
        let first = registered.next()?;
        if registered
            .any(|other| other.sighting.network_id.as_str() != first.sighting.network_id.as_str())
        {
            return None;
        }
        // CDMA's system identifier is part of its canonical identity.
        // Preserve existing non-CDMA bucket formats and stored history.
        if first.technology == "cdma" {
            return Some(first.sighting.network_id.clone());
        }
        Some(format!(
            "{}:{}-{}-{}-{}",
            first.technology,
            first.mcc.as_deref().unwrap_or("?"),
            first.mnc.as_deref().unwrap_or("?"),
            first.area_code,
            first.cell_id
        ))
    }
}

fn digit_string(value: Option<&Value>, min_len: usize, max_len: usize) -> Option<String> {
    let value = match value? {
        Value::String(s) => s.trim().to_owned(),
        Value::Number(n) => n.as_u64()?.to_string(),
        _ => return None,
    };
    if value.is_empty() || value.len() > max_len || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let number: u64 = value.parse().ok()?;
    if number > 999 {
        return None;
    }
    Some(format!("{value:0>min_len$}"))
}

fn bounded_id(row: &Value, name: &str, max: u64) -> Option<u64> {
    let id = row.get(name)?.as_u64()?;
    (id <= max).then_some(id)
}

fn signal_dbm(row: &Value) -> Option<f64> {
    row.get("dbm")
        .and_then(Value::as_i64)
        .filter(|v| (-160..=-1).contains(v))
        .and_then(|v| i32::try_from(v).ok())
        .map(f64::from)
}

/// CDMA cell identity belongs to the cellular network, not the handset.
/// Android base-station coordinates are deliberately left unconsumed.
fn parse_cdma_row(row: &Value) -> Option<CellObservation> {
    let system = bounded_id(row, "system", 65_535)?;
    let network = bounded_id(row, "network", 65_535)?;
    let base = bounded_id(row, "basestation", 65_535)?;
    let id = format!("cdma:{system}-{network}-{base}");
    let mut sighting = RfSighting::new(&id, RadioKind::Cellular, RfSource::CellRadar);
    sighting.raw_type = Some("cdma".to_owned());
    sighting.signal_dbm = signal_dbm(row);
    Some(CellObservation {
        sighting,
        technology: "cdma",
        mcc: None,
        mnc: None,
        area_code: network,
        cell_id: base,
        registered: row.get("registered").and_then(Value::as_bool),
        freshness: "unknown",
    })
}

/// Parse Termux:API's GSM/WCDMA/LTE/NR/CDMA schema into typed RF evidence.
///
/// CDMA uses system, network, and base-station identifiers, not mobile
/// country/network codes. Any CDMA tower coordinates supplied by Android
/// remain unused and are never treated as the handset's position.
///
/// Android may redact the cell identity and return an empty array on modern
/// handsets. An empty or rejected-only result is inconclusive, not proof of
/// cellular absence. Raw tower coordinates or UTC timestamps are not inferred.
pub fn parse_cells(bytes: &[u8]) -> Result<CellScan, Error> {
    if usize::try_from(MAX_CELL_SCAN_BYTES).is_ok_and(|limit| bytes.len() > limit) {
        return Err(Error::Invalid("cell-info output exceeds 1 MiB".into()));
    }
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|e| Error::Invalid(format!("invalid Termux cell-info JSON: {e}")))?;
    if let Some(message) = value.get("API_ERROR").and_then(Value::as_str) {
        return Err(Error::Invalid(format!(
            "Termux:API cell-info error: {}",
            escape_controls(message)
        )));
    }
    let rows = value
        .as_array()
        .ok_or_else(|| Error::Invalid("expected a Termux cell-info JSON array".into()))?;
    let mut observations = Vec::new();
    let mut rejected = 0;
    for row in rows {
        let Some(technology) = row.get("type").and_then(Value::as_str) else {
            rejected += 1;
            continue;
        };
        if technology == "cdma" {
            if let Some(cell) = parse_cdma_row(row) {
                observations.push(cell);
            } else {
                rejected += 1;
            }
            continue;
        }
        let (type_name, area_field, cell_field, area_max, cell_max) = match technology {
            "gsm" => ("gsm", "lac", "cid", 65_535, 65_535),
            "wcdma" => ("wcdma", "lac", "cid", 65_535, 268_435_455),
            "lte" => ("lte", "tac", "ci", 65_535, 268_435_455),
            "nr" => ("nr", "tac", "nci", 16_777_215, 68_719_476_735_u64),
            _ => {
                rejected += 1;
                continue;
            }
        };
        let Some(mcc) = digit_string(row.get("mcc"), 3, 3).filter(|s| s != "000") else {
            rejected += 1;
            continue;
        };
        let Some(mnc) = digit_string(row.get("mnc"), 2, 3) else {
            rejected += 1;
            continue;
        };
        let Some(area_code) = bounded_id(row, area_field, area_max) else {
            rejected += 1;
            continue;
        };
        let Some(cell_id) = bounded_id(row, cell_field, cell_max) else {
            rejected += 1;
            continue;
        };
        // Include RAT to prevent aliases across technologies. These identifiers
        // are service cells, never positions or physical-device identities.
        let id = format!("{type_name}:{mcc}-{mnc}-{area_code}-{cell_id}");
        let mut sighting = RfSighting::new(&id, RadioKind::Cellular, RfSource::CellRadar);
        sighting.raw_type = Some(type_name.to_owned());
        sighting.signal_dbm = signal_dbm(row);
        observations.push(CellObservation {
            sighting,
            technology: type_name,
            mcc: Some(mcc),
            mnc: Some(mnc),
            area_code,
            cell_id,
            registered: row.get("registered").and_then(Value::as_bool),
            freshness: "unknown",
        });
    }
    Ok(CellScan {
        source: "termux-telephony-cellinfo",
        acquisition: "android_os_cell_cache_not_active_scan",
        status: if observations.is_empty() {
            "inconclusive"
        } else {
            "freshness_unknown"
        },
        observed: observations.len(),
        rejected,
        observations,
    })
}

/// JSON captured elsewhere cannot establish its collection device, time,
/// current radio visibility, or Android permission state.
pub fn parse_replay(bytes: &[u8]) -> Result<CellScan, Error> {
    let mut scan = parse_cells(bytes)?;
    scan.source = "unverified_json_file";
    scan.acquisition = "offline_replay_no_capture_provenance";
    Ok(scan)
}

#[must_use]
pub fn render(scan: &CellScan) -> String {
    let mut text = format!(
        "source={}\tacquisition={}\tstatus={}\tobserved={}\trejected={}\n",
        scan.source, scan.acquisition, scan.status, scan.observed, scan.rejected
    );
    for row in &scan.observations {
        let signal = row
            .sighting
            .signal_dbm
            .map_or_else(|| "unknown".to_owned(), |n| format!("{n:.0}"));
        let _ = writeln!(
            text,
            "cell\ttype={}\tid={}\tregistered={}\tdbm={}\tfreshness={}",
            row.technology,
            escape_controls(&row.sighting.network_id),
            row.registered
                .map_or("unknown", |v| if v { "yes" } else { "no" }),
            signal,
            row.freshness,
        );
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supports_actual_tech_specific_termux_fields_without_inventing_position() {
        let raw = br#"[{"type":"gsm","mcc":505,"mnc":1,"lac":17,"cid":91,"registered":true,"dbm":-83},{"type":"wcdma","mcc":505,"mnc":1,"lac":18,"cid":112,"dbm":-91},{"type":"lte","mcc":505,"mnc":1,"tac":19,"ci":12345,"registered":false,"dbm":-101},{"type":"nr","mcc":"505","mnc":"01","tac":20,"nci":68719476735,"dbm":2147483647}]"#;
        let scan = parse_cells(raw).unwrap();
        assert_eq!((scan.observed, scan.rejected), (4, 0));
        assert_eq!(scan.status, "freshness_unknown");
        assert_eq!(scan.observations[0].sighting.network_id, "gsm:505-01-17-91");
        assert_eq!(
            scan.observations[2].sighting.network_id,
            "lte:505-01-19-12345"
        );
        assert_eq!(
            scan.observations[3].sighting.network_id,
            "nr:505-01-20-68719476735"
        );
        assert_eq!(scan.observations[0].registered, Some(true));
        assert_eq!(scan.observations[2].registered, Some(false));
        assert_eq!(scan.observations[3].sighting.signal_dbm, None);
        for row in &scan.observations {
            assert_eq!(row.sighting.observed_epoch, None);
            assert!(!row.sighting.has_usable_position());
            assert_eq!(row.freshness, "unknown");
        }
    }

    #[test]
    fn multiple_registered_cells_do_not_create_an_arbitrary_location() {
        let raw = br#"[{"type":"lte","mcc":505,"mnc":1,"tac":42,"ci":1234,"registered":true},{"type":"nr","mcc":505,"mnc":1,"tac":43,"nci":5678,"registered":true}]"#;
        let scan = parse_cells(raw).unwrap();
        assert_eq!(scan.observed, 2);
        assert_eq!(scan.status, "freshness_unknown");
        assert_eq!(scan.serving_cell(), None);
        let reversed = br#"[{"type":"nr","mcc":505,"mnc":1,"tac":43,"nci":5678,"registered":true},{"type":"lte","mcc":505,"mnc":1,"tac":42,"ci":1234,"registered":true}]"#;
        assert_eq!(parse_cells(reversed).unwrap().serving_cell(), None);
        assert_eq!(parse_replay(raw).unwrap().serving_cell(), None);
    }

    #[test]
    fn duplicate_registered_identity_preserves_original_bucket_format() {
        let raw = br#"[{"type":"lte","mcc":505,"mnc":1,"tac":42,"ci":1234,"registered":true},{"type":"lte","mcc":"505","mnc":"01","tac":42,"ci":1234,"registered":true},{"type":"nr","mcc":505,"mnc":1,"tac":43,"nci":5678,"registered":false}]"#;
        let scan = parse_cells(raw).unwrap();
        assert_eq!(scan.serving_cell().as_deref(), Some("lte:505-01-42-1234"));
        let no_registered =
            br#"[{"type":"lte","mcc":505,"mnc":1,"tac":42,"ci":1234,"registered":false}]"#;
        assert_eq!(parse_cells(no_registered).unwrap().serving_cell(), None);
    }

    #[test]
    fn missing_or_redacted_cell_identifiers_are_rejected() {
        let raw = br#"[{"type":"lte","mcc":505,"mnc":1,"tac":2147483647,"ci":123},{"type":"nr","mcc":null,"mnc":"01","tac":12,"nci":34},{"type":"lte","mcc":505,"mnc":1,"tac":42,"ci":2147483647},{"type":"cdma","system":1,"network":2},{"type":"gsm","mcc":505,"mnc":1,"lac":1,"cid":3}]"#;
        let scan = parse_cells(raw).unwrap();
        assert_eq!((scan.observed, scan.rejected), (1, 4));
        assert_eq!(scan.observations[0].sighting.network_id, "gsm:505-01-1-3");
    }

    #[test]
    fn cdma_base_station_ids_are_kept_without_claiming_handset_coordinates() {
        // Android returns CDMA latitude/longitude as base-station metadata.
        // Those are not the device's observed coordinates.
        let raw = br#"[{"type":"cdma","registered":true,"system":11,"network":22,"basestation":33,"latitude":1234567,"longitude":2345678,"dbm":-85}]"#;
        let scan = parse_cells(raw).unwrap();
        assert_eq!((scan.observed, scan.rejected), (1, 0));
        let cell = &scan.observations[0];
        assert_eq!(cell.technology, "cdma");
        assert_eq!(cell.sighting.network_id, "cdma:11-22-33");
        assert_eq!(cell.mcc, None);
        assert_eq!(cell.mnc, None);
        assert_eq!(cell.area_code, 22);
        assert_eq!(cell.cell_id, 33);
        assert_eq!(cell.registered, Some(true));
        assert_eq!(cell.sighting.signal_dbm, Some(-85.0));
        assert_eq!(cell.sighting.observed_epoch, None);
        assert!(!cell.sighting.has_usable_position());
        assert_eq!(cell.freshness, "unknown");
        let replay = parse_replay(raw).unwrap();
        assert_eq!(replay.source, "unverified_json_file");
        assert_eq!(replay.observations[0].sighting.latitude, None);
    }

    #[test]
    fn cdma_serving_bucket_preserves_system_identity() {
        let first =
            br#"[{"type":"cdma","registered":true,"system":11,"network":22,"basestation":33}]"#;
        let second =
            br#"[{"type":"cdma","registered":true,"system":12,"network":22,"basestation":33}]"#;
        assert_eq!(
            parse_cells(first).unwrap().serving_cell().as_deref(),
            Some("cdma:11-22-33")
        );
        assert_eq!(
            parse_cells(second).unwrap().serving_cell().as_deref(),
            Some("cdma:12-22-33")
        );
        let ambiguous = br#"[{"type":"cdma","registered":true,"system":11,"network":22,"basestation":33},{"type":"cdma","registered":true,"system":12,"network":22,"basestation":33}]"#;
        assert_eq!(parse_cells(ambiguous).unwrap().serving_cell(), None);
    }

    #[test]
    fn incomplete_or_out_of_range_cdma_does_not_become_a_tower_sighting() {
        let raw = br#"[{"type":"cdma","system":11,"network":22},{"type":"cdma","system":65536,"network":22,"basestation":33},{"type":"cdma","system":11,"network":22,"basestation":65536}]"#;
        let scan = parse_cells(raw).unwrap();
        assert_eq!((scan.observed, scan.rejected), (0, 3));
        assert_eq!(scan.status, "inconclusive");
    }

    #[test]
    fn empty_or_unknown_cell_data_is_not_a_negative_radio_finding() {
        assert_eq!(parse_cells(b"[]").unwrap().status, "inconclusive");
        assert!(parse_cells(br#"{"API_ERROR":"permission denied"}"#).is_err());
        assert!(parse_cells(br#"{"anything":1}"#).is_err());
        assert!(parse_cells(b"null").is_err());
        let scan = parse_replay(br#"[{"type":"gsm","mcc":505,"mnc":1,"lac":1,"cid":3}]"#).unwrap();
        assert_eq!(scan.source, "unverified_json_file");
        assert_eq!(scan.acquisition, "offline_replay_no_capture_provenance");
        assert_eq!(scan.observations[0].freshness, "unknown");
    }

    #[test]
    fn text_output_never_claims_freshness_or_position() {
        let raw =
            br#"[{"type":"lte","mcc":505,"mnc":1,"tac":42,"ci":1234,"registered":true,"dbm":-80}]"#;
        let scan = parse_cells(raw).unwrap();
        let rendered = render(&scan);
        assert!(rendered.contains("registered=yes"));
        assert!(rendered.contains("freshness=unknown"));
        assert!(!rendered.contains("latitude"));
        assert_eq!(rendered.lines().count(), 2);
    }
}
