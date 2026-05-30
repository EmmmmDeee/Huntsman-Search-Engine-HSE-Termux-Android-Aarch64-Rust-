//! Cell tower survey and geolocation — single call to `termux-telephony-cellinfo`.
//!
//! Merges the former `cell_survey` and `cell_locate` modules so the Termux
//! command is invoked **once** instead of twice.  For every visible cell tower
//! the module produces:
//!
//!   1. A `DeviceId` entity (tower ID, signal info, radio type)
//!   2. A `Coordinates` entity via OpenCelliD or MCC centroid fallback
//!
//! API priority for geolocation:
//!   1. OpenCelliD / UnwiredLabs (free tier: 100 req/day, env key)
//!   2. Built-in MCC -> country centroid fallback (offline, coarse)
//!
//! Off-device -> no-op via the termux_cmd helper.

use std::borrow::Cow;
use std::collections::HashSet;

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleContext, ModuleResult},
    scan::Target,
};
use crate::util::geo::is_valid_coords;
use crate::util::termux::termux_cmd;

const OPENCELLID_KEY_ENV: &str = "HUNTSMAN_OPENCELLID_KEY";

const SRC: &str = "cell_intel";

pub struct CellIntel;

#[derive(Deserialize)]
struct Cell {
    #[serde(rename = "type")]
    cell_type: Option<String>,
    registered: Option<bool>,
    asu: Option<i64>,
    dbm: Option<i64>,
    level: Option<i64>,
    cid: Option<i64>,
    lac: Option<i64>,
    tac: Option<i64>,
    mcc: Option<serde_json::Value>, // can be string or int across Android versions
    mnc: Option<serde_json::Value>,
    pci: Option<i64>,
}

#[derive(Deserialize)]
struct OpenCellidResp {
    #[serde(default)]
    lat: Option<f64>,
    #[serde(default)]
    lon: Option<f64>,
    #[serde(default)]
    range: Option<u64>,
    #[serde(default)]
    status: Option<String>,
}

#[async_trait]
impl Module for CellIntel {
    fn name(&self) -> &'static str {
        "cell_intel"
    }

    fn description(&self) -> &'static str {
        "Cell tower survey and geolocation via Termux + OpenCelliD"
    }

    fn priority(&self) -> u8 {
        64
    }

    fn is_passive(&self) -> bool {
        true
    }

    fn accepts(&self, _t: &Target) -> bool {
        true
    }

    fn max_timeout_ms(&self) -> u64 {
        15_000
    }

    async fn process(&self, _target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        // Single invocation — the key performance win over two separate modules.
        let Some(stdout) = termux_cmd("termux-telephony-cellinfo", &[], 5000).await else {
            return Ok(ModuleResult::new());
        };

        let cells: Vec<Cell> = match serde_json::from_slice(&stdout) {
            Ok(v) => v,
            Err(_) => return Ok(ModuleResult::new()),
        };

        let api_key = ctx.key_opt(OPENCELLID_KEY_ENV);
        let mut result = ModuleResult::new();
        let mut seen = HashSet::new();

        for cell in &cells {
            let mcc = json_to_str(&cell.mcc);
            let mnc = json_to_str(&cell.mnc);
            let lac = cell.lac.or(cell.tac).unwrap_or(0);
            let cid = cell.cid.unwrap_or(0);
            if mcc.is_empty() || cid == 0 {
                continue;
            }

            let ctype = cell.cell_type.as_deref().unwrap_or("unknown");
            let tower_id = format!("{mcc}-{mnc}-{lac}-{cid}");

            // ---- 1. DeviceId entity (from former cell_survey) ----
            let mut dev = Entity::new(EntityKind::DeviceId, &tower_id, 0.80, &ctx.scan_id);
            dev.tag("cell-tower");
            dev.tag(format!("radio:{ctype}"));
            dev.add_evidence(
                Evidence::new(SRC, format!("Cell tower {ctype} {tower_id}"))
                    .with_attr("type", ctype)
                    .with_attr("mcc", mcc.as_ref())
                    .with_attr("mnc", mnc.as_ref())
                    .with_attr("lac_tac", lac.to_string())
                    .with_attr("cid", cid.to_string())
                    .with_attr("pci", cell.pci.unwrap_or(0).to_string())
                    .with_attr("dbm", cell.dbm.unwrap_or(0).to_string())
                    .with_attr("asu", cell.asu.unwrap_or(0).to_string())
                    .with_attr("level", cell.level.unwrap_or(0).to_string())
                    .with_attr("registered", cell.registered.unwrap_or(false).to_string()),
            );
            result.push(dev);

            // ---- 2. Coordinates entity (from former cell_locate) ----
            // Skip duplicate geolocation for the same tower.
            if mnc.is_empty() || lac == 0 || !seen.insert(tower_id.clone()) {
                continue;
            }

            let radio = match ctype.to_lowercase().as_str() {
                "lte" => "LTE",
                "gsm" => "GSM",
                "umts" | "wcdma" => "UMTS",
                "nr" | "5g" => "NR",
                "cdma" => "CDMA",
                _ => "GSM",
            };

            if let Some(key) = api_key
                && let Some((lat, lon, range)) =
                    query_opencellid(&ctx.http, key, &mcc, &mnc, lac, cid, radio).await
            {
                let coords = format!("{lat:.6},{lon:.6}");
                let confidence = accuracy_to_confidence(range);
                let mut e = Entity::new(EntityKind::Coordinates, &coords, confidence, &ctx.scan_id);
                e.tag("geoint");
                e.tag("cell-tower");
                e.tag(format!("radio:{}", ctype.to_lowercase()));
                e.add_evidence(
                    Evidence::new(SRC, format!("Cell tower {radio} {tower_id} -> {coords}"))
                        .with_attr("tower_id", &tower_id)
                        .with_attr("radio", radio)
                        .with_attr("mcc", mcc.as_ref())
                        .with_attr("mnc", mnc.as_ref())
                        .with_attr("range_m", range.to_string())
                        .with_attr("source", "OpenCelliD")
                        .with_attr("dbm", cell.dbm.unwrap_or(0).to_string())
                        .with_attr("registered", cell.registered.unwrap_or(false).to_string()),
                );
                result.push(e);
                continue;
            }

            // Fallback: MCC -> country centroid (coarse but free, offline)
            if let Some((lat, lon, country)) = mcc_to_centroid(&mcc) {
                let coords = format!("{lat:.4},{lon:.4}");
                let mut e = Entity::new(EntityKind::Coordinates, &coords, 0.25, &ctx.scan_id);
                e.tag("geoint");
                e.tag("cell-tower");
                e.tag("coarse");
                e.tag(format!("country:{country}"));
                e.add_evidence(
                    Evidence::new(
                        SRC,
                        format!("Cell tower MCC {mcc} -> {country} (country centroid)"),
                    )
                    .with_attr("tower_id", &tower_id)
                    .with_attr("mcc", mcc.as_ref())
                    .with_attr("country", country)
                    .with_attr("source", "mcc-centroid")
                    .with_attr("accuracy", "country-level"),
                );
                result.push(e);
            }
        }

        Ok(result)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn query_opencellid(
    http: &reqwest::Client,
    key: &str,
    mcc: &str,
    mnc: &str,
    lac: i64,
    cid: i64,
    radio: &str,
) -> Option<(f64, f64, u64)> {
    let url = format!(
        "https://opencellid.org/cell/get?key={key}&mcc={mcc}&mnc={mnc}&lac={lac}&cellid={cid}&radio={radio}&format=json"
    );

    let resp = http
        .get(&url)
        .header("Accept", "application/json")
        .send()
        .await
        .ok()?;

    if !resp.status().is_success() {
        return None;
    }

    let data: OpenCellidResp = crate::util::http::json_scanned(resp, SRC).await.ok()?;

    if data.status.as_deref() == Some("error") {
        return None;
    }

    let lat = data.lat?;
    let lon = data.lon?;
    // Shared validator: rejects Null Island AND out-of-range / non-finite
    // values a malformed OpenCelliD payload could carry (see util::geo).
    if !is_valid_coords(lat, lon) {
        return None;
    }

    Some((lat, lon, data.range.unwrap_or(5000)))
}

fn accuracy_to_confidence(range_m: u64) -> f64 {
    match range_m {
        0..=100 => 0.85,
        101..=500 => 0.75,
        501..=2000 => 0.65,
        2001..=10000 => 0.50,
        _ => 0.35,
    }
}

/// `mcc`/`mnc` come as `"505"` on some Android versions and `505` on others.
/// Normalise to string; missing -> empty.
fn json_to_str(v: &Option<serde_json::Value>) -> Cow<'_, str> {
    match v {
        Some(serde_json::Value::String(s)) => Cow::Borrowed(s.as_str()),
        Some(serde_json::Value::Number(n)) => Cow::Owned(n.to_string()),
        _ => Cow::Borrowed(""),
    }
}

fn mcc_to_centroid(mcc: &str) -> Option<(f64, f64, &'static str)> {
    match mcc {
        // Oceania / Australia
        "505" => Some((-25.2744, 133.7751, "AU")),
        "530" => Some((-41.2865, 174.7762, "NZ")),
        // North America
        "310" | "311" | "312" | "313" | "314" | "315" | "316" => Some((39.8283, -98.5795, "US")),
        "302" => Some((56.1304, -106.3468, "CA")),
        "334" => Some((23.6345, -102.5528, "MX")),
        // Europe
        "234" | "235" => Some((55.3781, -3.4360, "GB")),
        "262" => Some((51.1657, 10.4515, "DE")),
        "208" => Some((46.6034, 1.8883, "FR")),
        "222" => Some((41.8719, 12.5674, "IT")),
        "214" => Some((40.4637, -3.7492, "ES")),
        "204" => Some((52.1326, 5.2913, "NL")),
        "206" => Some((50.5039, 4.4699, "BE")),
        "228" => Some((46.8182, 8.2275, "CH")),
        "232" => Some((47.5162, 14.5501, "AT")),
        "240" => Some((60.1282, 18.6435, "SE")),
        "242" => Some((60.4720, 8.4689, "NO")),
        "244" => Some((61.9241, 25.7482, "FI")),
        "238" => Some((56.2639, 9.5018, "DK")),
        "260" => Some((51.9194, 19.1451, "PL")),
        "226" => Some((45.9432, 24.9668, "RO")),
        "230" => Some((49.8175, 15.4730, "CZ")),
        "216" => Some((41.0082, 28.9784, "HU")),
        "219" => Some((44.0165, 21.0059, "HR")),
        "202" => Some((39.0742, 21.8243, "GR")),
        "268" => Some((39.3999, -8.2245, "PT")),
        "272" => Some((53.4129, -8.2439, "IE")),
        "255" => Some((48.3794, 31.1656, "UA")),
        // Asia
        "440" | "441" => Some((36.2048, 138.2529, "JP")),
        "450" => Some((35.9078, 127.7669, "KR")),
        "460" | "461" => Some((35.8617, 104.1954, "CN")),
        "404" | "405" => Some((20.5937, 78.9629, "IN")),
        "510" => Some((-0.7893, 113.9213, "ID")),
        "502" => Some((4.2105, 101.9758, "MY")),
        "520" => Some((15.8700, 100.9925, "TH")),
        "515" => Some((12.8797, 121.7740, "PH")),
        "452" => Some((14.0583, 108.2772, "VN")),
        "525" => Some((1.3521, 103.8198, "SG")),
        // Middle East
        "420" => Some((23.8859, 45.0792, "SA")),
        "424" => Some((23.4241, 53.8478, "AE")),
        "425" => Some((31.0461, 34.8516, "IL")),
        "432" => Some((32.4279, 53.6880, "IR")),
        // South America
        "724" => Some((-14.2350, -51.9253, "BR")),
        "722" => Some((-38.4161, -63.6167, "AR")),
        "730" => Some((-35.6751, -71.5430, "CL")),
        "716" => Some((-9.1900, -75.0152, "PE")),
        "732" => Some((4.5709, -74.2973, "CO")),
        // Africa
        "655" => Some((-30.5595, 22.9375, "ZA")),
        "621" => Some((9.0820, 8.6753, "NG")),
        "620" => Some((-6.3690, 34.8888, "TZ")),
        "639" => Some((-0.0236, 37.9062, "KE")),
        "602" => Some((26.8206, 30.8025, "EG")),
        "604" => Some((31.7917, -7.0926, "MA")),
        // Russia
        "250" => Some((61.5240, 105.3188, "RU")),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Standalone parse helper (used in tests to exercise survey logic without
// needing a ModuleContext / async runtime).
// ---------------------------------------------------------------------------

#[cfg(test)]
fn parse_cells_survey(stdout: &[u8], scan_id: &str) -> ModuleResult {
    let cells: Vec<Cell> = match serde_json::from_slice(stdout) {
        Ok(v) => v,
        Err(_) => return ModuleResult::new(),
    };

    let mut result = ModuleResult {
        entities: Vec::with_capacity(cells.len()),
    };
    for cell in &cells {
        let mcc = json_to_str(&cell.mcc);
        let mnc = json_to_str(&cell.mnc);
        let lac = cell.lac.or(cell.tac).unwrap_or(0);
        let cid = cell.cid.unwrap_or(0);
        if mcc.is_empty() || cid == 0 {
            continue;
        }

        let ctype = cell.cell_type.as_deref().unwrap_or("unknown");
        let tower_id = format!("{mcc}-{mnc}-{lac}-{cid}");

        let mut e = Entity::new(EntityKind::DeviceId, &tower_id, 0.80, scan_id);
        e.tag("cell-tower");
        e.tag(format!("radio:{ctype}"));
        e.add_evidence(
            Evidence::new(SRC, format!("Cell tower {ctype} {tower_id}"))
                .with_attr("type", ctype)
                .with_attr("mcc", mcc.as_ref())
                .with_attr("mnc", mnc.as_ref())
                .with_attr("lac_tac", lac.to_string())
                .with_attr("cid", cid.to_string())
                .with_attr("pci", cell.pci.unwrap_or(0).to_string())
                .with_attr("dbm", cell.dbm.unwrap_or(0).to_string())
                .with_attr("asu", cell.asu.unwrap_or(0).to_string())
                .with_attr("level", cell.level.unwrap_or(0).to_string())
                .with_attr("registered", cell.registered.unwrap_or(false).to_string()),
        );
        result.push(e);
    }
    result
}

// ---------------------------------------------------------------------------
// Tests (merged from cell_survey and cell_locate)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::scan::TargetKind;

    // ---- Module trait tests ----

    #[test]
    fn is_passive() {
        assert!(CellIntel.is_passive());
    }

    #[test]
    fn accepts_any_target() {
        assert!(CellIntel.accepts(&Target::new(TargetKind::Email, "x@y")));
    }

    #[test]
    fn module_name_and_priority() {
        assert_eq!(CellIntel.name(), "cell_intel");
        assert_eq!(CellIntel.priority(), 64);
    }

    #[test]
    fn module_description() {
        assert_eq!(
            CellIntel.description(),
            "Cell tower survey and geolocation via Termux + OpenCelliD"
        );
    }

    #[test]
    fn module_max_timeout() {
        assert_eq!(CellIntel.max_timeout_ms(), 15_000);
    }

    // ---- Survey (DeviceId) tests (from cell_survey) ----

    #[test]
    fn parses_mcc_as_string_or_number() {
        let json = br#"[
            {"type":"lte","registered":true,"cid":12345,"tac":54321,
             "mcc":"505","mnc":"01","dbm":-75,"asu":30,"level":4,"pci":100},
            {"type":"gsm","registered":true,"cid":99,"lac":42,
             "mcc":505,"mnc":1,"dbm":-90,"asu":10,"level":2}
        ]"#;
        let r = parse_cells_survey(json, "test");
        assert_eq!(r.entities.len(), 2);
        assert_eq!(r.entities[0].value, "505-01-54321-12345");
        assert_eq!(r.entities[1].value, "505-1-42-99");
    }

    #[test]
    fn skips_cells_without_mcc_or_cid() {
        let json = br#"[{"type":"lte","registered":true}]"#;
        let r = parse_cells_survey(json, "test");
        assert_eq!(r.entities.len(), 0);
    }

    #[test]
    fn malformed_json_no_ops() {
        let r = parse_cells_survey(b"{", "test");
        assert_eq!(r.entities.len(), 0);
    }

    #[test]
    fn entity_tags_include_cell_tower_and_radio_type() {
        let json = br#"[
            {"type":"lte","registered":true,"cid":5678,"tac":1234,
             "mcc":"310","mnc":"260","dbm":-85,"asu":25,"level":3,"pci":42}
        ]"#;
        let r = parse_cells_survey(json, "scan-x");
        assert_eq!(r.entities.len(), 1);
        let e = &r.entities[0];
        assert_eq!(e.kind, EntityKind::DeviceId);
        assert_eq!(e.value, "310-260-1234-5678");
        assert!((e.confidence - 0.80).abs() < 1e-6);
        assert!(e.has_tag("cell-tower"));
        assert!(e.has_tag("radio:lte"));
        assert_eq!(e.scan_id, "scan-x");
    }

    #[test]
    fn evidence_attributes_populated() {
        let json = br#"[
            {"type":"gsm","registered":false,"cid":100,"lac":200,
             "mcc":"505","mnc":"01","dbm":-95,"asu":8,"level":1,"pci":0}
        ]"#;
        let r = parse_cells_survey(json, "test");
        let ev = &r.entities[0].evidence[0];
        assert_eq!(ev.source, "cell_intel");
        assert_eq!(ev.attributes.get("type").unwrap(), "gsm");
        assert_eq!(ev.attributes.get("mcc").unwrap(), "505");
        assert_eq!(ev.attributes.get("mnc").unwrap(), "01");
        assert_eq!(ev.attributes.get("lac_tac").unwrap(), "200");
        assert_eq!(ev.attributes.get("cid").unwrap(), "100");
        assert_eq!(ev.attributes.get("dbm").unwrap(), "-95");
        assert_eq!(ev.attributes.get("asu").unwrap(), "8");
        assert_eq!(ev.attributes.get("level").unwrap(), "1");
        assert_eq!(ev.attributes.get("registered").unwrap(), "false");
    }

    #[test]
    fn lac_falls_back_to_tac_for_lte() {
        let json = br#"[{"type":"lte","cid":999,"tac":555,"mcc":"310","mnc":"410"}]"#;
        let r = parse_cells_survey(json, "test");
        assert_eq!(r.entities[0].value, "310-410-555-999");
    }

    #[test]
    fn lac_preferred_over_tac_when_both_present() {
        let json = br#"[{"type":"gsm","cid":1,"lac":10,"tac":20,"mcc":"505","mnc":"01"}]"#;
        let r = parse_cells_survey(json, "test");
        assert_eq!(r.entities[0].value, "505-01-10-1");
    }

    #[test]
    fn skips_cell_with_zero_cid() {
        let json = br#"[{"type":"lte","cid":0,"tac":123,"mcc":"310","mnc":"260"}]"#;
        let r = parse_cells_survey(json, "test");
        assert_eq!(r.entities.len(), 0);
    }

    #[test]
    fn empty_json_array() {
        let r = parse_cells_survey(b"[]", "test");
        assert_eq!(r.entities.len(), 0);
    }

    #[test]
    fn missing_type_defaults_to_unknown() {
        let json = br#"[{"cid":42,"lac":7,"mcc":"001","mnc":"01"}]"#;
        let r = parse_cells_survey(json, "test");
        assert_eq!(r.entities.len(), 1);
        assert!(r.entities[0].has_tag("radio:unknown"));
        assert!(r.entities[0].evidence[0].summary.contains("unknown"));
    }

    // ---- json_to_str tests (from both modules) ----

    #[test]
    fn json_to_str_handles_all_variants() {
        use std::borrow::Cow;

        // String value
        let s = Some(serde_json::Value::String("505".into()));
        assert_eq!(json_to_str(&s), Cow::Borrowed("505"));

        // Number value
        let n = Some(serde_json::json!(310));
        assert_eq!(json_to_str(&n).as_ref(), "310");

        // Null value
        let null = Some(serde_json::Value::Null);
        assert_eq!(json_to_str(&null), Cow::Borrowed(""));

        // None
        assert_eq!(json_to_str(&None), Cow::Borrowed(""));
    }

    // ---- Geolocation helper tests (from cell_locate) ----

    #[test]
    fn accuracy_to_confidence_tiers() {
        assert!((accuracy_to_confidence(50) - 0.85).abs() < 1e-6);
        assert!((accuracy_to_confidence(300) - 0.75).abs() < 1e-6);
        assert!((accuracy_to_confidence(1000) - 0.65).abs() < 1e-6);
        assert!((accuracy_to_confidence(5000) - 0.50).abs() < 1e-6);
        assert!((accuracy_to_confidence(50000) - 0.35).abs() < 1e-6);
    }

    #[test]
    fn mcc_us_maps_to_us_centroid() {
        let (lat, lon, cc) = mcc_to_centroid("310").unwrap();
        assert!((lat - 39.8283).abs() < 0.01);
        assert!((lon - (-98.5795)).abs() < 0.01);
        assert_eq!(cc, "US");
    }

    #[test]
    fn mcc_au_maps_to_au_centroid() {
        let (lat, lon, cc) = mcc_to_centroid("505").unwrap();
        assert!((lat - (-25.2744)).abs() < 0.01);
        assert_eq!(cc, "AU");
        assert!(lon > 100.0);
    }

    #[test]
    fn unknown_mcc_returns_none() {
        assert!(mcc_to_centroid("999").is_none());
    }
}
