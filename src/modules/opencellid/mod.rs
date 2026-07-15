//! OpenCelliD — crowdsourced cell-tower database, bidirectional.
//!
//! **Coordinates → towers (getInArea):** given a `Coordinates` target, queries
//! OpenCelliD's `getInArea` endpoint and enumerates all known cell towers within
//! a ~1 km bounding box. For each tower emits:
//!   * A `DeviceId` entity (tower ID: `<mcc>-<mnc>-<lac>-<cid>`) with radio type,
//!     range, and signal statistics.
//!   * A `Coordinates` entity for the tower's reported position.
//!
//! **DeviceId → location (cell/get):** given a `DeviceId` target in
//! `mcc-mnc-lac-cid` format, looks up that specific tower and emits:
//!   * A `Coordinates` entity (the tower's canonical position).
//!   * A `DeviceId` entity enriched with range, samples, and signal data.
//!
//! Key-gated (`HUNTSMAN_OPENCELLID_KEY`). Free tier: 1,000 requests/day.
//! Results cached for 24 h — tower placements are stable over intra-day timescales.

#[cfg(test)]
mod tests;

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::geo::{is_valid_coords, parse_coords};
use crate::util::http::urlencode;

const SRC: &str = "opencellid";
const KEY_ENV: &str = "HUNTSMAN_OPENCELLID_KEY";
/// Bounding-box half-width in degrees (~556 m at mid-latitudes).
const BBOX_DELTA: f64 = 0.005;

// ── API response types ──────────────────────────────────────────────────────

#[derive(Deserialize)]
pub(super) struct AreaResp {
    #[serde(default)]
    pub(super) cells: Vec<CellEntry>,
    /// Present (with no `cells` key at all) on a key-level failure — see
    /// [`CellEntry::error`].
    #[serde(default)]
    pub(super) error: Option<String>,
}

/// Shared field layout for both `cell/getInArea` (array element) and `cell/get`
/// (top-level object).  OpenCelliD uses the same field aliases in both responses.
#[derive(Deserialize)]
pub(super) struct CellEntry {
    /// OpenCelliD signals a bad/unknown API key as a plain HTTP `200` whose
    /// ENTIRE body is `{"error":"API Key not known: <key>","code":2}` — no
    /// HTTP-level 401/403/429 at all. Live-confirmed 2026-07-15. Every other
    /// field below is naturally absent (`#[serde(default)]`) on this shape, so
    /// checking `error.is_some()` after a successful deserialize is the only
    /// way to detect it — a bad key was previously indistinguishable from a
    /// genuine "no towers here" empty result.
    #[serde(default)]
    pub(super) error: Option<String>,
    #[serde(default)]
    pub(super) radio: Option<String>,
    #[serde(default)]
    pub(super) mcc: Option<i64>,
    /// MNC — OpenCelliD names this field `net`.
    #[serde(rename = "net", default)]
    pub(super) mnc: Option<i64>,
    /// LAC/TAC — OpenCelliD names this field `area`.
    #[serde(rename = "area", default)]
    pub(super) lac: Option<i64>,
    /// Cell ID — OpenCelliD names this field `cell`.
    #[serde(rename = "cell", default)]
    pub(super) cid: Option<i64>,
    #[serde(default)]
    pub(super) lat: Option<f64>,
    #[serde(default)]
    pub(super) lon: Option<f64>,
    #[serde(default)]
    pub(super) range: Option<u64>,
    #[serde(rename = "averageSignal", default)]
    pub(super) average_signal: Option<i64>,
    #[serde(default)]
    pub(super) samples: Option<u64>,
}

// ── Module ──────────────────────────────────────────────────────────────────

pub struct OpenCellId;

#[async_trait]
impl Module for OpenCellId {
    fn name(&self) -> &'static str {
        "opencellid"
    }

    fn description(&self) -> &'static str {
        "OpenCelliD: enumerate towers near a coordinate (getInArea) or geolocate a tower by ID (cell/get)"
    }

    fn priority(&self) -> u8 {
        70
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::KeyGated
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Coordinates | TargetKind::DeviceId)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Geo
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::DeviceId, EntityKind::Coordinates];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        10_000
    }

    fn cache_ttl_secs(&self) -> u64 {
        86_400
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Querying the OpenCelliD crowdsourced cell-tower database to place towers
        // (and thus the subject) is Search Open Technical Databases (T1596) →
        // Determine Physical Locations (T1591.001). It is NOT DNS/Passive DNS
        // (T1596.001, dropped): OpenCelliD is a radio/geolocation database, and
        // this module makes no DNS query. There is no cell-database sub-technique,
        // so the honest mapping stops at the T1596 parent.
        &["T1591.001", "T1596"]
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let api_key = match ctx.key_opt(KEY_ENV) {
            Some(k) => k,
            None => return Ok(ModuleResult::new()),
        };
        match target.kind {
            TargetKind::Coordinates => process_area(target, ctx, api_key).await,
            TargetKind::DeviceId => process_tower(target, ctx, api_key).await,
            _ => Ok(ModuleResult::new()),
        }
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Parse a cell tower ID string `mcc-mnc-lac-cid` into its four numeric components.
/// Returns `None` if the format doesn't match.
fn parse_tower_id(value: &str) -> Option<(i64, i64, i64, i64)> {
    let mut parts = value.splitn(5, '-');
    let mcc: i64 = parts.next()?.parse().ok()?;
    let mnc: i64 = parts.next()?.parse().ok()?;
    let lac: i64 = parts.next()?.parse().ok()?;
    let cid: i64 = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((mcc, mnc, lac, cid))
}

/// Coordinates → towers (getInArea).
async fn process_area(target: &Target, ctx: &ModuleContext, api_key: &str) -> Result<ModuleResult> {
    let (lat, lon) = parse_coords(&target.value)?;

    let bbox = format!(
        "{},{},{},{}",
        lat - BBOX_DELTA,
        lon - BBOX_DELTA,
        lat + BBOX_DELTA,
        lon + BBOX_DELTA,
    );
    let url = format!(
        "https://opencellid.org/cell/getInArea?key={}&BBOX={}&format=json",
        urlencode(api_key),
        urlencode(&bbox),
    );

    let resp = ctx
        .http
        .get(&url)
        .header("Accept", "application/json")
        .send()
        .await;

    let Ok(resp) = resp else {
        return Ok(ModuleResult::new());
    };
    let status = resp.status();
    if !status.is_success() {
        // A present key that gets rejected/throttled must be reported to the
        // pool, or a dead/throttled key silently degrades every future scan
        // with no operator-visible signal and no chance to rotate.
        crate::util::http::note_keyed_error(status.as_u16(), SRC, api_key, ctx);
        return Ok(ModuleResult::new());
    }

    let data: AreaResp = match crate::util::http::json_scanned(resp, SRC).await {
        Ok(d) => d,
        Err(_) => return Ok(ModuleResult::new()),
    };
    if data.error.is_some() {
        // See `CellEntry::error`'s doc comment — a body-level key failure
        // OpenCelliD signals as a plain 200, so this can't be caught by the
        // status check above.
        crate::util::http::note_keyed_error(401, SRC, api_key, ctx);
        return Ok(ModuleResult::new());
    }

    let mut result = ModuleResult::new();
    for cell in &data.cells {
        emit_cell_entities(&mut result, cell, &ctx.scan_id);
    }
    Ok(result)
}

/// DeviceId → exact tower location (cell/get).
async fn process_tower(
    target: &Target,
    ctx: &ModuleContext,
    api_key: &str,
) -> Result<ModuleResult> {
    let (mcc, mnc, lac, cid) = match parse_tower_id(&target.value) {
        Some(t) => t,
        None => return Ok(ModuleResult::new()),
    };

    let url = format!(
        "https://opencellid.org/cell/get?key={}&mcc={}&mnc={}&lac={}&cellid={}&format=json",
        urlencode(api_key),
        mcc,
        mnc,
        lac,
        cid,
    );

    let resp = ctx
        .http
        .get(&url)
        .header("Accept", "application/json")
        .send()
        .await;

    let Ok(resp) = resp else {
        return Ok(ModuleResult::new());
    };
    let status = resp.status();
    if !status.is_success() {
        // Same reporting rationale as `process_area` above.
        crate::util::http::note_keyed_error(status.as_u16(), SRC, api_key, ctx);
        return Ok(ModuleResult::new());
    }

    let cell: CellEntry = match crate::util::http::json_scanned(resp, SRC).await {
        Ok(d) => d,
        Err(_) => return Ok(ModuleResult::new()),
    };
    if cell.error.is_some() {
        // See `CellEntry::error`'s doc comment.
        crate::util::http::note_keyed_error(401, SRC, api_key, ctx);
        return Ok(ModuleResult::new());
    }

    let mut result = ModuleResult::new();
    emit_cell_entities(&mut result, &cell, &ctx.scan_id);
    Ok(result)
}

/// Emit `DeviceId` + `Coordinates` entities for one `CellEntry`.
/// Shared by both the getInArea and cell/get paths.
fn emit_cell_entities(result: &mut ModuleResult, cell: &CellEntry, scan_id: &str) {
    let Some(mcc) = cell.mcc else { return };
    let Some(mnc) = cell.mnc else { return };
    let Some(lac) = cell.lac else { return };
    let Some(cid) = cell.cid else { return };

    let radio = cell.radio.as_deref().unwrap_or("unknown");
    let tower_id = format!("{mcc}-{mnc}-{lac}-{cid}");

    // DeviceId entity
    let mut device = Entity::new(EntityKind::DeviceId, &tower_id, 0.78, scan_id);
    device.tag(crate::core::tags::CELL_TOWER);
    device.tag(format!("radio:{}", radio.to_lowercase()));
    let mut ev = Evidence::new(SRC, format!("OpenCelliD tower {tower_id} ({radio})"))
        .with_attr("tower_id", &tower_id)
        .with_attr("radio", radio)
        .with_attr("mcc", mcc.to_string())
        .with_attr("mnc", mnc.to_string())
        .with_attr("lac", lac.to_string())
        .with_attr("cid", cid.to_string());
    if let Some(r) = cell.range {
        ev = ev.with_attr("range_m", r.to_string());
    }
    if let Some(s) = cell.samples {
        ev = ev.with_attr("samples", s.to_string());
    }
    if let Some(sig) = cell.average_signal {
        ev = ev.with_attr("avg_signal_dbm", sig.to_string());
    }
    device.add_evidence(ev);
    result.push(device);

    // Coordinates entity
    let Some(t_lat) = cell.lat else { return };
    let Some(t_lon) = cell.lon else { return };
    if !is_valid_coords(t_lat, t_lon) {
        return;
    }
    let coords = format!("{t_lat:.6},{t_lon:.6}");
    let confidence = accuracy_to_confidence(cell.range.unwrap_or(5000));
    let mut geo = Entity::new(EntityKind::Coordinates, &coords, confidence, scan_id);
    geo.tag("geoint");
    geo.tag(crate::core::tags::CELL_TOWER);
    geo.tag(format!("radio:{}", radio.to_lowercase()));
    crate::util::geo::tag_au_state(&mut geo, t_lat, t_lon);
    geo.add_evidence(
        Evidence::new(SRC, format!("OpenCelliD tower {tower_id} at {coords}"))
            .with_attr("tower_id", &tower_id)
            .with_attr("radio", radio)
            .with_attr("range_m", cell.range.unwrap_or(5000).to_string())
            .with_attr("source", "OpenCelliD"),
    );
    result.push(geo);
}

/// Map the reported accuracy radius (metres) to an entity confidence level.
/// Tighter coverage → higher confidence. Identical scale to `cell_intel`.
pub(super) fn accuracy_to_confidence(range_m: u64) -> f64 {
    match range_m {
        0..=100 => 0.85,
        101..=500 => 0.75,
        501..=2000 => 0.65,
        2001..=10000 => 0.50,
        _ => 0.35,
    }
}
