//! Android OS-provided cellular information from Termux:API, with no root.
//! This is a cached operating-system snapshot, not an active tower sweep.
//! No UTC observation timestamp, handset location or tower coordinates can be inferred.

use std::fmt::Write as _;

use serde::Serialize;

use crate::error::Error;
use crate::rf::{RadioKind, RfSighting, RfSource};

pub const MAX_CELL_SCAN_BYTES: u64 = 1_048_576;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CellObservation {
    pub sighting: RfSighting,
    pub technology: &'static str,
    pub registered: Option<bool>,
    pub mcc: Option<String>,
    pub mnc: Option<String>,
    pub area_code: u64,
    pub cell_id: u64,
    /// The Android API does not supply a trustworthy sample timestamp.
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

fn bounded_id(row: &serde_json::Value, key: &str, maximum: u64) -> Option<u64> {
    row.get(key)
        .and_then(serde_json::Value::as_u64)
        .filter(|n| *n > 0 && *n <= maximum)
}

fn network_code(row: &serde_json::Value, key: &str, min: usize, max: usize) -> Option<String> {
    let field = row.get(key)?;
    let raw = match field {
        serde_json::Value::Number(n) => n.as_u64()?.to_string(),
        serde_json::Value::String(s) => s.clone(),
        _ => return None,
    };
    (raw.len() >= min && raw.len() <= max && raw.bytes().all(|c| c.is_ascii_digit()))
        .then_some(raw)
}

fn cell_signal(row: &serde_json::Value) -> Option<f64> {
    row.get("dbm")
        .and_then(serde_json::Value::as_i64)
        .filter(|value| (-160..=-1).contains(value))
        .and_then(|dbm| i32::try_from(dbm).ok())
        .map(f64::from)
}

fn parse_row(row: &serde_json::Value) -> Option<CellObservation> {
    let technology = match row.get("type")?.as_str()? {
        "gsm" => "gsm",
        "wcdma" => "wcdma",
        "lte" => "lte",
        "nr" => "nr",
        "cdma" => "cdma",
        _ => return None,
    };
    let (mcc, mnc, area_code, cell_id, identity) = if technology == "cdma" {
        let system = bounded_id(row, "system", u64::from(u16::MAX))?;
        let network = bounded_id(row, "network", u64::from(u16::MAX))?;
        let base = bounded_id(row, "basestation", u64::from(u16::MAX))?;
        (None, None, network, base, format!("cdma:{system}:{network}:{base}"))
    } else {
        let mcc = network_code(row, "mcc", 3, 3)?;
        let mnc = network_code(row, "mnc", 1, 3)?;
        let (area_key, cell_key, limit) = match technology {
            "gsm" => ("lac", "cid", u64::from(u16::MAX)),
            "wcdma" => ("lac", "cid", (1_u64 << 28) - 1),
            "lte" => ("tac", "ci", (1_u64 << 28) - 1),
            "nr" => ("tac", "nci", (1_u64 << 36) - 1),
            _ => return None,
        };
        let area_limit = if technology == "nr" { (1_u64 << 24) - 1 } else { u64::from(u16::MAX) };
        let area = bounded_id(row, area_key, area_limit)?;
        let cell = bounded_id(row, cell_key, limit)?;
        let identity = format!("{technology}:{mcc}:{mnc}:{area}:{cell}");
        (Some(mcc), Some(mnc), area, cell, identity)
    };
    let mut sighting = RfSighting::new(&identity, RadioKind::Cellular, RfSource::CellRadar);
    sighting.signal_dbm = cell_signal(row);
    // The CDMA API emits base-station latitude/longitude as encoded integers.
    // Never confuse tower metadata with a position observed on this handset.
    Some(CellObservation {
        sighting,
        technology,
        registered: row.get("registered").and_then(serde_json::Value::as_bool),
        mcc,
        mnc,
        area_code,
        cell_id,
        freshness: "unknown",
    })
}

/// Parse Termux:API's actual TelephonyCellInfo array schema. The Android
/// operating system may return a cached list or an empty list when permission
/// is unavailable. Empty is inconclusive, not proof that no towers exist.
pub fn parse_scan(bytes: &[u8]) -> Result<CellScan, Error> {
    if usize::try_from(MAX_CELL_SCAN_BYTES).is_ok_and(|n| bytes.len() > n) {
        return Err(Error::Invalid("cellular API output exceeds 1 MiB".into()));
    }
    let raw: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|e| Error::Invalid(format!("invalid Termux cellular JSON: {e}")))?;
    if let Some(message) = raw.get("API_ERROR") {
        return Err(Error::Invalid(format!("Termux cellular API error: {message}")));
    }
    let rows = raw
        .as_array()
        .ok_or_else(|| Error::Invalid("expected Termux cellular JSON array".into()))?;
    let mut observations = Vec::new();
    let mut rejected = 0;
    for row in rows {
        if let Some(observation) = parse_row(row) {
            observations.push(observation);
        } else {
            rejected += 1;
        }
    }
    let status = if observations.is_empty() {
        "inconclusive"
    } else {
        "os_cached_freshness_unknown"
    };
    Ok(CellScan {
        source: "termux-telephony-cellinfo",
        acquisition: "android_get_all_cell_info_not_active_sweep",
        status,
        observed: observations.len(),
        rejected,
        observations,
    })
}

/// Imported JSON cannot authenticate its provenance or acquisition time.
pub fn parse_replay(bytes: &[u8]) -> Result<CellScan, Error> {
    let mut scan = parse_scan(bytes)?;
    scan.source = "unverified_json_file";
    scan.acquisition = "offline_cellular_replay_no_time_or_device_provenance";
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
            .map_or_else(|| "unknown".to_owned(), |dbm| format!("{dbm:.0}"));
        let registered = row.registered.map_or("unknown", |v| if v { "yes" } else { "no" });
        let _ = writeln!(
            text,
            "cell\tid={}\ttechnology={}\tregistered={}\tdbm={}\tfreshness=unknown",
            row.sighting.network_id, row.technology, registered, signal
        );
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_lte_gsm_and_5g_with_real_termux_field_names() {
        let input = br#"[{"type":"lte","registered":true,"mcc":505,"mnc":1,"tac":345,"ci":123456,"dbm":-92},{"type":"nr","registered":false,"mcc":"505","mnc":"01","tac":987,"nci":68719476734,"dbm":-107},{"type":"gsm","mcc":505,"mnc":2,"lac":99,"cid":123,"dbm":-75}]"#;
        let scan = parse_scan(input).unwrap();
        assert_eq!((scan.observed, scan.rejected), (3, 0));
        assert_eq!(scan.status, "os_cached_freshness_unknown");
        assert_eq!(scan.observations[0].sighting.network_id, "lte:505:1:345:123456");
        assert_eq!(scan.observations[1].sighting.network_id, "nr:505:01:987:68719476734");
        assert_eq!(scan.observations[1].mnc.as_deref(), Some("01"));
        assert_eq!(scan.observations[0].sighting.signal_dbm, Some(-92.0));
        assert_eq!(scan.observations[2].sighting.signal_dbm, Some(-75.0));
        for cell in &scan.observations {
            assert_eq!(cell.freshness, "unknown");
            assert_eq!(cell.sighting.observed_epoch, None);
            assert!(!cell.sighting.has_usable_position());
            assert_eq!(cell.sighting.radio, RadioKind::Cellular);
            assert_eq!(cell.sighting.source, RfSource::CellRadar);
        }
    }

    #[test]
    fn no_unverified_tower_position_from_cdma_metadata() {
        let raw = br#"[{"type":"cdma","system":11,"network":22,"basestation":33,"latitude":1000000,"longitude":500000,"dbm":-85},{"type":"wcdma","mcc":"505","mnc":"03","lac":123,"cid":3456}]"#;
        let parsed = parse_scan(raw).unwrap();
        assert_eq!(parsed.observed, 2);
        assert_eq!(parsed.observations[0].sighting.network_id, "cdma:11:22:33");
        assert_eq!(parsed.observations[1].sighting.network_id, "wcdma:505:03:123:3456");
        assert!(!parsed.observations[0].sighting.has_usable_position());
    }

    #[test]
    fn omitted_unknown_cell_ids_and_out_of_range_values_are_rejected() {
        let raw = br#"[{"type":"lte","mcc":505,"mnc":1,"tac":345,"ci":2147483647},{"type":"nr","mcc":"505","mnc":"01","tac":1,"nci":9223372036854775807},{"type":"lte","mcc":505,"mnc":1,"tac":1},{"type":"wifi","mcc":505,"mnc":1,"tac":1,"ci":2},{"type":"lte","mcc":505,"mnc":1,"tac":345,"ci":90,"dbm":2147483647}]"#;
        let parsed = parse_scan(raw).unwrap();
        assert_eq!((parsed.observed, parsed.rejected), (1, 4));
        assert_eq!(parsed.observations[0].sighting.signal_dbm, None);
    }

    #[test]
    fn empty_api_cache_and_replays_do_not_assert_radio_absence() {
        let scan = parse_scan(b"[]").unwrap();
        assert_eq!(scan.status, "inconclusive");
        let replay = parse_replay(br#"[{"type":"lte","mcc":505,"mnc":1,"tac":1,"ci":2}]"#).unwrap();
        assert_eq!(replay.source, "unverified_json_file");
        assert_eq!(replay.observations[0].freshness, "unknown");
        assert_eq!(replay.observations[0].sighting.observed_epoch, None);
    }

    #[test]
    fn errors_and_non_array_shapes_never_look_like_empty_scans() {
        for raw in [
            r#"{"API_ERROR":"Location disabled"}"#,
            r#"{"random":"object"}"#,
            "null",
            "not json",
        ] {
            assert!(parse_scan(raw.as_bytes()).is_err(), "{raw}");
        }
    }

    #[test]
    fn invalid_signal_and_untrusted_identity_do_not_inject_output_rows() {
        let scan = parse_scan(br#"[{"type":"lte","mcc":505,"mnc":1,"tac":1,"ci":2,"dbm":0},{"type":"lte\nfake","mcc":505,"mnc":1,"tac":1,"ci":2}]"#).unwrap();
        assert_eq!((scan.observed, scan.rejected), (1, 1));
        assert_eq!(render(&scan).lines().count(), 2);
        assert!(scan.observations[0].sighting.signal_dbm.is_none());
    }
}
