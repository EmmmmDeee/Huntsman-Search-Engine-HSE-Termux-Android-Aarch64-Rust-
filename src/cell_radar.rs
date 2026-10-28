//! Rootless Android cell-tower observations from Termux:API's telephony cache.
//! Cell identities describe what Android reported, not GPS coordinates or
//! independent evidence that a tower was within range at a specific UTC time.
//!
//! Beyond the identity, each cell keeps what Android's public telephony API exposes and a
//! rootless survey app (`ICdetection`, Network Survey, `AIMSICD`) reads: the physical cell or
//! scrambling code, the LTE timing advance as a distance band, the bands, and the site an LTE
//! or WCDMA cell identity names (eNodeB and sector, RNC and cell). Neighbour cells Android
//! reports by physical cell only are kept as neighbours. [`audit`] then flags, conservatively,
//! the patterns those apps treat as worth review: a 2G serving cell while the same operator's
//! 4G or 5G is heard, no neighbours at all, and sectors of one eNodeB in different tracking
//! areas. An app cannot read the modem's RRC or NAS signalling, so none of these detects an
//! IMSI catcher; each is an anomaly to corroborate.

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
    /// LTE or NR physical cell identity, or the WCDMA primary scrambling code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pci: Option<u32>,
    /// The bands Android reports the cell on (Android 11 and later).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub bands: Vec<u32>,
    /// The site the cell identity names: an LTE eNodeB or a WCDMA RNC.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub site: Option<CellSite>,
    /// How far the LTE timing advance places the handset from the cell's antenna.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timing_advance: Option<TimingAdvance>,
}

/// The site part of a cell identity. An LTE E-UTRAN cell identity is a 20-bit eNodeB ID and an
/// 8-bit cell (sector) ID, and a WCDMA UTRAN cell identity a 12-bit RNC ID and a 16-bit cell ID
/// (3GPP TS 36.300 and 25.401), so every sector of one site shares `id`. An NR cell identity
/// splits at a gNB-ID length the network chooses (22 to 32 bits), which Android does not
/// report, so an NR cell names no site.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CellSite {
    /// `lte-enb:MCC-MNC-ENB` or `wcdma-rnc:MCC-MNC-RNC`.
    pub id: String,
    /// The sector (LTE) or cell (WCDMA) within the site.
    pub sector: u64,
}

/// An LTE timing advance and the distance band it stands for. One step of the LTE timing
/// advance is 16 Ts of round trip, 78.125 m of distance (3GPP TS 36.213 and 36.211), so a
/// reading of N puts the antenna between N and N+1 steps away along the radio path. Android
/// reports it for the serving cell only; multipath and repeaters lengthen the path.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TimingAdvance {
    pub value: u32,
    pub min_distance_m: f64,
    pub max_distance_m: f64,
}

/// One step of the LTE timing advance in metres: c × 16 Ts / 2.
pub const LTE_TA_STEP_M: f64 = 78.125;
/// The largest LTE timing advance a random-access response can set (3GPP TS 36.321).
pub const LTE_TA_MAX: u32 = 1282;

/// A neighbour Android reports by its physical cell (or scrambling code) only, without the
/// cell identity: what a modem measures of cells it is not camped on.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct NeighbourCell {
    pub technology: &'static str,
    pub pci: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal_dbm: Option<f64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub bands: Vec<u32>,
}

/// One pattern [`audit`] flags: an anomaly to corroborate, never a detection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CellFinding {
    /// `weak` or `moderate`; nothing an app can see is stronger.
    pub severity: &'static str,
    pub code: &'static str,
    /// The cell identities the finding is about.
    pub cells: Vec<String>,
    pub evidence: String,
    pub resolution: &'static str,
}

/// What no finding here can establish.
pub const AUDIT_LIMIT: &str = "Android apps cannot read the modem's RRC or NAS signalling, so these indicators cannot detect an IMSI catcher or a fake base station; each is an anomaly to corroborate over time and place, and legitimate networks produce all of them.";

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CellScan {
    pub source: &'static str,
    pub acquisition: &'static str,
    pub status: &'static str,
    pub observed: usize,
    pub rejected: usize,
    pub observations: Vec<CellObservation>,
    /// Cells reported by physical cell only.
    pub neighbours: Vec<NeighbourCell>,
    /// What [`audit`] flags in this snapshot.
    pub findings: Vec<CellFinding>,
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

fn bounded_u32(row: &Value, name: &str, max: u32) -> Option<u32> {
    row.get(name)?
        .as_u64()
        .and_then(|v| u32::try_from(v).ok())
        .filter(|v| *v <= max)
}

/// The bands Android lists, each a plausible 3GPP band number; at most 16 are kept.
fn bands(row: &Value) -> Vec<u32> {
    row.get("bands")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_u64)
                .filter_map(|band| u32::try_from(band).ok())
                .filter(|band| (1..=512).contains(band))
                .take(16)
                .collect()
        })
        .unwrap_or_default()
}

/// The physical cell field of a technology and its largest value: LTE PCI 0..503, NR PCI 0..1007
/// and the WCDMA primary scrambling code 0..511.
fn physical_cell(technology: &str, row: &Value) -> Option<u32> {
    match technology {
        "lte" => bounded_u32(row, "pci", 503),
        "nr" => bounded_u32(row, "pci", 1007),
        "wcdma" => bounded_u32(row, "psc", 511),
        _ => None,
    }
}

fn cell_site(technology: &str, mcc: &str, mnc: &str, cell_id: u64) -> Option<CellSite> {
    let (kind, site, sector) = match technology {
        "lte" => ("lte-enb", cell_id >> 8, cell_id & 0xFF),
        "wcdma" => ("wcdma-rnc", cell_id >> 16, cell_id & 0xFFFF),
        _ => return None,
    };
    Some(CellSite {
        id: format!("{kind}:{mcc}-{mnc}-{site}"),
        sector,
    })
}

fn timing_advance(technology: &str, row: &Value) -> Option<TimingAdvance> {
    if technology != "lte" {
        return None;
    }
    let value = bounded_u32(row, "timing_advance", LTE_TA_MAX)?;
    Some(TimingAdvance {
        value,
        min_distance_m: f64::from(value) * LTE_TA_STEP_M,
        max_distance_m: f64::from(value + 1) * LTE_TA_STEP_M,
    })
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
        pci: None,
        bands: Vec::new(),
        site: None,
        timing_advance: None,
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
    let mut neighbours = Vec::new();
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
        let identity = (
            digit_string(row.get("mcc"), 3, 3).filter(|s| s != "000"),
            digit_string(row.get("mnc"), 2, 3),
            bounded_id(row, area_field, area_max),
            bounded_id(row, cell_field, cell_max),
        );
        let (Some(mcc), Some(mnc), Some(area_code), Some(cell_id)) = identity else {
            // A neighbour is measured by its physical cell, without the identity it broadcasts.
            match physical_cell(type_name, row) {
                Some(pci) if row.get("registered").and_then(Value::as_bool) != Some(true) => {
                    neighbours.push(NeighbourCell {
                        technology: type_name,
                        pci,
                        signal_dbm: signal_dbm(row),
                        bands: bands(row),
                    });
                }
                _ => rejected += 1,
            }
            continue;
        };
        // Include RAT to prevent aliases across technologies. These identifiers
        // are service cells, never positions or physical-device identities.
        let id = format!("{type_name}:{mcc}-{mnc}-{area_code}-{cell_id}");
        let mut sighting = RfSighting::new(&id, RadioKind::Cellular, RfSource::CellRadar);
        sighting.raw_type = Some(type_name.to_owned());
        sighting.signal_dbm = signal_dbm(row);
        let site = cell_site(type_name, &mcc, &mnc, cell_id);
        observations.push(CellObservation {
            sighting,
            technology: type_name,
            mcc: Some(mcc),
            mnc: Some(mnc),
            area_code,
            cell_id,
            registered: row.get("registered").and_then(Value::as_bool),
            freshness: "unknown",
            pci: physical_cell(type_name, row),
            bands: bands(row),
            site,
            timing_advance: timing_advance(type_name, row),
        });
    }
    let findings = audit(&observations, &neighbours);
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
        neighbours,
        findings,
    })
}

/// The anomalies a rootless survey app flags in one snapshot of Android's cells, each to
/// corroborate (see [`AUDIT_LIMIT`]):
/// - `serving_2g_while_4g_5g_heard` (moderate): the handset is registered on a GSM cell while
///   the same operator's LTE or NR cells are reported. 2G has no mutual authentication, which
///   fake base stations exploit by forcing a downgrade; networks also fall back to 2G for
///   coverage or voice.
/// - `enodeb_sectors_in_different_tracking_areas` (moderate): two LTE sectors of one eNodeB
///   report different tracking area codes. A site's sectors normally share one; a cell copying
///   a real cell's identity into another area produces exactly this.
/// - `serving_cell_without_neighbours` (weak): a registered cell and no other cell at all. Fake
///   base stations often advertise no neighbours, but many modems report none either.
#[must_use]
pub fn audit(observations: &[CellObservation], neighbours: &[NeighbourCell]) -> Vec<CellFinding> {
    let mut findings = Vec::new();
    let operator = |cell: &CellObservation| (cell.mcc.clone(), cell.mnc.clone());
    let registered: Vec<&CellObservation> = observations
        .iter()
        .filter(|cell| cell.registered == Some(true))
        .collect();
    for serving in registered.iter().filter(|cell| cell.technology == "gsm") {
        let newer: Vec<String> = observations
            .iter()
            .filter(|cell| {
                matches!(cell.technology, "lte" | "nr") && operator(cell) == operator(serving)
            })
            .map(|cell| cell.sighting.network_id.clone())
            .collect();
        if !newer.is_empty() {
            findings.push(CellFinding {
                severity: "moderate",
                code: "serving_2g_while_4g_5g_heard",
                cells: std::iter::once(serving.sighting.network_id.clone())
                    .chain(newer.iter().cloned())
                    .collect(),
                evidence: format!(
                    "registered on GSM cell {} while {} LTE/NR cell(s) of the same operator are reported",
                    serving.sighting.network_id,
                    newer.len()
                ),
                resolution: "Note where and when it happens; a downgrade that recurs only in one place, or with the operator's 4G/5G strong, is worth corroborating with another handset.",
            });
        }
    }
    let mut sites: std::collections::BTreeMap<&str, Vec<&CellObservation>> =
        std::collections::BTreeMap::new();
    for cell in observations.iter().filter(|cell| cell.technology == "lte") {
        if let Some(site) = &cell.site {
            sites.entry(site.id.as_str()).or_default().push(cell);
        }
    }
    for (site, cells) in sites {
        let areas: std::collections::BTreeSet<u64> =
            cells.iter().map(|cell| cell.area_code).collect();
        if areas.len() > 1 {
            findings.push(CellFinding {
                severity: "moderate",
                code: "enodeb_sectors_in_different_tracking_areas",
                cells: cells
                    .iter()
                    .map(|cell| cell.sighting.network_id.clone())
                    .collect(),
                evidence: format!(
                    "sectors of {site} report tracking areas {}",
                    areas
                        .iter()
                        .map(u64::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                resolution: "Check the sectors against OpenCelliD or another survey of the area; a cell whose identity belongs to a site elsewhere is the pattern of a copied identity.",
            });
        }
    }
    if !registered.is_empty()
        && neighbours.is_empty()
        && observations
            .iter()
            .all(|cell| cell.registered == Some(true))
    {
        findings.push(CellFinding {
            severity: "weak",
            code: "serving_cell_without_neighbours",
            cells: registered
                .iter()
                .map(|cell| cell.sighting.network_id.clone())
                .collect(),
            evidence: "Android reported the registered cell and no neighbouring cell".to_owned(),
            resolution: "Compare with later reads and other places: many modems report no neighbours, so only a change at one place is informative.",
        });
    }
    findings
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
        let _ = write!(
            text,
            "cell\ttype={}\tid={}\tregistered={}\tdbm={}\tfreshness={}",
            row.technology,
            escape_controls(&row.sighting.network_id),
            row.registered
                .map_or("unknown", |v| if v { "yes" } else { "no" }),
            signal,
            row.freshness,
        );
        if let Some(pci) = row.pci {
            let _ = write!(text, "\tpci={pci}");
        }
        if let Some(site) = &row.site {
            let _ = write!(text, "\tsite={}\tsector={}", site.id, site.sector);
        }
        if let Some(ta) = &row.timing_advance {
            let _ = write!(
                text,
                "\tta={}\tdistance_m={:.0}-{:.0}",
                ta.value, ta.min_distance_m, ta.max_distance_m
            );
        }
        if !row.bands.is_empty() {
            let _ = write!(text, "\tbands={}", join_bands(&row.bands));
        }
        text.push('\n');
    }
    for neighbour in &scan.neighbours {
        let _ = write!(
            text,
            "neighbour\ttype={}\tpci={}\tdbm={}",
            neighbour.technology,
            neighbour.pci,
            neighbour
                .signal_dbm
                .map_or_else(|| "unknown".to_owned(), |n| format!("{n:.0}"))
        );
        if !neighbour.bands.is_empty() {
            let _ = write!(text, "\tbands={}", join_bands(&neighbour.bands));
        }
        text.push('\n');
    }
    for finding in &scan.findings {
        let _ = writeln!(
            text,
            "finding\tseverity={}\tcode={}\tcells={}\tevidence={}",
            finding.severity,
            finding.code,
            escape_controls(&finding.cells.join(",")),
            escape_controls(&finding.evidence)
        );
    }
    if !scan.findings.is_empty() {
        let _ = writeln!(text, "limit\t{AUDIT_LIMIT}");
    }
    text
}

fn join_bands(bands: &[u32]) -> String {
    bands
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",")
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
        assert_eq!(
            rendered.lines().filter(|l| l.starts_with("cell\t")).count(),
            1
        );
    }

    /// Termux:API's LTE row as Android 11+ writes it: identity, PCI, timing advance and bands on
    /// the serving cell, and a neighbour measured by PCI only (no `ci` or `tac`).
    #[test]
    fn an_lte_cell_names_its_enodeb_sector_and_timing_advance_band_and_keeps_pci_only_neighbours() {
        let raw = br#"[{"type":"lte","registered":true,"dbm":-95,"timing_advance":13,"ci":3221778,"pci":187,"tac":12305,"mcc":505,"mnc":1,"bands":[3,28]},{"type":"lte","registered":false,"dbm":-108,"pci":44,"bands":[3]},{"type":"wcdma","registered":false,"cid":262243,"lac":31,"mcc":505,"mnc":1,"psc":402},{"type":"nr","registered":false,"nci":123456789,"pci":901,"tac":12305,"mcc":"505","mnc":"01"}]"#;
        let scan = parse_cells(raw).unwrap();
        assert_eq!((scan.observed, scan.rejected), (3, 0));
        let lte = &scan.observations[0];
        assert_eq!(lte.pci, Some(187));
        assert_eq!(lte.bands, [3, 28]);
        // 3221778 = eNodeB 12585 (3221778 >> 8), sector 18 (3221778 & 0xFF).
        assert_eq!(
            lte.site,
            Some(CellSite {
                id: "lte-enb:505-01-12585".into(),
                sector: 18
            })
        );
        let ta = lte.timing_advance.as_ref().unwrap();
        assert_eq!(ta.value, 13);
        assert!((ta.min_distance_m - 1015.625).abs() < 1e-9);
        assert!((ta.max_distance_m - 1093.75).abs() < 1e-9);
        // 262243 = RNC 4 (262243 >> 16), cell 99 (262243 & 0xFFFF); its PSC is kept as pci.
        let wcdma = &scan.observations[1];
        assert_eq!(
            wcdma.site,
            Some(CellSite {
                id: "wcdma-rnc:505-01-4".into(),
                sector: 99
            })
        );
        assert_eq!(wcdma.pci, Some(402));
        // An NR cell identity splits at a gNB length Android does not report: no site.
        let nr = &scan.observations[2];
        assert_eq!((nr.pci, nr.site.as_ref()), (Some(901), None));
        assert_eq!(nr.timing_advance, None);
        assert_eq!(
            scan.neighbours,
            [NeighbourCell {
                technology: "lte",
                pci: 44,
                signal_dbm: Some(-108.0),
                bands: vec![3]
            }]
        );
        let text = render(&scan);
        assert!(text.contains("\tpci=187\tsite=lte-enb:505-01-12585\tsector=18\tta=13\tdistance_m=1016-1094\tbands=3,28"), "{text}");
        assert!(
            text.contains("neighbour\ttype=lte\tpci=44\tdbm=-108\tbands=3"),
            "{text}"
        );
        assert!(scan.findings.is_empty(), "{:?}", scan.findings);
    }

    #[test]
    fn out_of_range_physical_cells_and_timing_advance_are_not_kept() {
        let raw = br#"[{"type":"lte","registered":true,"ci":1234,"tac":7,"mcc":505,"mnc":1,"pci":504,"timing_advance":1283,"bands":[0,99999]},{"type":"lte","registered":false,"pci":600},{"type":"lte","registered":true,"pci":12}]"#;
        let scan = parse_cells(raw).unwrap();
        assert_eq!((scan.observed, scan.rejected), (1, 2), "{scan:?}");
        let cell = &scan.observations[0];
        assert_eq!(
            (cell.pci, cell.timing_advance.as_ref(), cell.bands.len()),
            (None, None, 0)
        );
        assert!(
            scan.neighbours.is_empty(),
            "a registered row is no neighbour"
        );
    }

    #[test]
    fn a_2g_serving_cell_beside_the_operators_4g_is_flagged_and_another_operators_is_not() {
        let downgrade = br#"[{"type":"gsm","registered":true,"cid":91,"lac":17,"mcc":1,"mnc":1},{"type":"lte","registered":false,"ci":5000,"tac":3,"mcc":1,"mnc":1}]"#;
        let findings = parse_cells(downgrade).unwrap().findings;
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].code, "serving_2g_while_4g_5g_heard");
        assert_eq!(findings[0].severity, "moderate");
        assert_eq!(findings[0].cells, ["gsm:001-01-17-91", "lte:001-01-3-5000"]);
        let other_operator = br#"[{"type":"gsm","registered":true,"cid":91,"lac":17,"mcc":1,"mnc":1},{"type":"lte","registered":false,"ci":5000,"tac":3,"mcc":1,"mnc":2}]"#;
        assert!(parse_cells(other_operator).unwrap().findings.is_empty());
        let on_4g = br#"[{"type":"lte","registered":true,"ci":5000,"tac":3,"mcc":1,"mnc":1},{"type":"gsm","registered":false,"cid":91,"lac":17,"mcc":1,"mnc":1}]"#;
        assert!(parse_cells(on_4g).unwrap().findings.is_empty());
    }

    #[test]
    fn sectors_of_one_enodeb_in_different_tracking_areas_are_flagged() {
        // ci 2560 and 2561 are sectors 0 and 1 of eNodeB 10.
        let split = br#"[{"type":"lte","registered":true,"ci":2560,"tac":100,"mcc":1,"mnc":1},{"type":"lte","registered":false,"ci":2561,"tac":200,"mcc":1,"mnc":1}]"#;
        let findings = parse_cells(split).unwrap().findings;
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(
            findings[0].code,
            "enodeb_sectors_in_different_tracking_areas"
        );
        assert!(
            findings[0].evidence.contains("lte-enb:001-01-10"),
            "{findings:?}"
        );
        assert!(findings[0].evidence.contains("100, 200"), "{findings:?}");
        let same = br#"[{"type":"lte","registered":true,"ci":2560,"tac":100,"mcc":1,"mnc":1},{"type":"lte","registered":false,"ci":2561,"tac":100,"mcc":1,"mnc":1}]"#;
        assert!(parse_cells(same).unwrap().findings.is_empty());
    }

    #[test]
    fn a_registered_cell_alone_is_a_weak_finding_and_a_neighbour_clears_it() {
        let alone = br#"[{"type":"lte","registered":true,"ci":2560,"tac":100,"mcc":1,"mnc":1}]"#;
        let scan = parse_cells(alone).unwrap();
        assert_eq!(scan.findings.len(), 1);
        assert_eq!(
            (scan.findings[0].code, scan.findings[0].severity),
            ("serving_cell_without_neighbours", "weak")
        );
        assert!(render(&scan).contains(&format!("limit\t{AUDIT_LIMIT}")));
        let with_neighbour = br#"[{"type":"lte","registered":true,"ci":2560,"tac":100,"mcc":1,"mnc":1},{"type":"lte","registered":false,"pci":7}]"#;
        assert!(parse_cells(with_neighbour).unwrap().findings.is_empty());
        assert!(parse_cells(b"[]").unwrap().findings.is_empty());
    }
}
