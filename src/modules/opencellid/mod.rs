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
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::geo::{is_valid_coords, parse_coords};
use crate::util::http::{RequestBuilderExt, urlencode};

const SRC: &str = "opencellid";

/// The error returned when OpenCelliD rejects the API key in a `200` body.
///
/// Deliberately a `const` rather than a `format!`. OpenCelliD's bad-key body
/// echoes the key back verbatim — `{"error":"API Key not known: <key>",...}` —
/// so interpolating the provider's own message here would write the key into
/// every error surface: the verbose log, the SSE stream and the dossier. Making
/// this a constant means no provider-controlled bytes can reach those surfaces
/// through this path at all, rather than relying on a reviewer to notice.
///
/// The key is still reported to the pool by the `note_keyed_error` call at each
/// site, so rotation is unaffected — only the message text is generic.
const KEY_REJECTED_MSG: &str =
    "OpenCelliD rejected the API key: the 200 body carried an error object instead of results";
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
        "OpenCelliD recon — enumerates towers near a coordinate (getInArea) or geolocates a tower by ID (cell/get)"
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
        let api_key = match crate::util::keys::resolve_key(ctx.key_opt(KEY_ENV)) {
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

    // `send_tagged` rather than a bare `send()`: the request URL carries the API
    // key as its first query parameter, and `reqwest::Error`'s Display embeds
    // that URL. `send_tagged` is the chokepoint that strips it — see
    // `http::tests::send_tagged_strips_url_so_secrets_and_pii_dont_leak`.
    let resp = ctx
        .http
        .get(&url)
        .header("Accept", "application/json")
        .send_tagged(SRC)
        .await?;

    // Every one of these paths used to `return Ok(ModuleResult::new())`, which
    // the engine records as "OpenCelliD found no towers in this bounding box" —
    // an affirmative GEOINT negative that suppresses downstream geo-convergence.
    // A throttled key, a WAF interstitial and a schema change all produced that
    // same answer. The key was at least reported to the pool, so it could still
    // rotate; the SCAN, however, was told a falsehood.
    // `keyed_ok_or_404` is the house chokepoint ~10 sibling keyed modules
    // already route through, and it draws exactly the distinction this needs:
    // 404 is a genuine "nothing here" and stays an empty success, while
    // 401/403/429 (and an auth-shaped 400) report the key to the pool AND
    // return Err. Same pool attribution as the hand-rolled call it replaces —
    // `SRC` — so key rotation behaviour is unchanged.
    let Some(resp) = crate::util::http::keyed_ok_or_404(SRC, api_key, ctx, resp).await? else {
        return Ok(ModuleResult::new());
    };

    // A 2xx was already confirmed, so a decode failure here is OpenCelliD
    // changing its wire format or a captive-portal/WAF page served with 200 —
    // provider drift, not an empty area.
    let data: AreaResp = crate::util::http::json_scanned(resp, SRC)
        .await
        .map_err(|e| Error::module(SRC, e))?;
    if data.error.is_some() {
        // See `CellEntry::error`'s doc comment — OpenCelliD signals a body-level
        // key failure as a plain 200, so the status check above cannot catch it.
        // The key is reported to the pool as before; what changes is that the
        // scan is no longer additionally told the area holds no towers.
        crate::util::http::note_keyed_error(401, SRC, api_key, ctx);
        return Err(Error::module(SRC, KEY_REJECTED_MSG));
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

    // `send_tagged` rather than a bare `send()`: the request URL carries the API
    // key as its first query parameter, and `reqwest::Error`'s Display embeds
    // that URL. `send_tagged` is the chokepoint that strips it — see
    // `http::tests::send_tagged_strips_url_so_secrets_and_pii_dont_leak`.
    let resp = ctx
        .http
        .get(&url)
        .header("Accept", "application/json")
        .send_tagged(SRC)
        .await?;

    // Same rationale as `process_area` above: a failure here is not "this cell
    // is not in OpenCelliD", and a 404 — which is exactly that — still is.
    let Some(resp) = crate::util::http::keyed_ok_or_404(SRC, api_key, ctx, resp).await? else {
        return Ok(ModuleResult::new());
    };

    let cell: CellEntry = crate::util::http::json_scanned(resp, SRC)
        .await
        .map_err(|e| Error::module(SRC, e))?;
    if cell.error.is_some() {
        // See `CellEntry::error`'s doc comment.
        crate::util::http::note_keyed_error(401, SRC, api_key, ctx);
        return Err(Error::module(SRC, KEY_REJECTED_MSG));
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
    let mut device = Entity::new(EntityKind::DeviceId, &tower_id, confidence::STRONG, scan_id);
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

use crate::util::cell_db::accuracy_to_confidence;
