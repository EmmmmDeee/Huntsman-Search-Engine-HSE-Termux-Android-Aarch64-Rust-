//! `OpenCelliD`: keyed cell tower position.
//!
//! One lookup is one `GET https://opencellid.org/cell/get?key={key}&mcc={mcc}&mnc={mnc}&lac={lac}&cellid={cellid}&format=json`.
//! Requires `HUNTSMAN_OPENCELLID_KEY`. 1000 credits/day. Returns lat, lon, range, samples.
//! A missing cell is HTTP 200 with an error body: that is a valid zero.

use crate::api_leg::{self, Answer, Api, KeyPlace, KeyUse, LegError};
use crate::http::Transport;
use crate::indicator_sources::{Finding, Indicator, IndicatorKind, Source};
use crate::keys::Keys;

pub const SOURCE: &str = "opencellid";
pub const KEY_SLOT: &str = crate::environment::OPENCELLID_KEY_ENV;
pub const API: Api = Api {
    source: SOURCE,
    provider: "opencellid.org",
    origin: "https://opencellid.org:443",
    key: Some(KeyUse {
        slot: KEY_SLOT,
        place: KeyPlace::Query("key"),
        required: true,
    }),
};
pub const INTEL: Source = Source {
    api: &API,
    kinds: &[IndicatorKind::Cell],
    lookup,
};

/// Cell identifier: `MCC`, `MNC`, `LAC`, `CellID`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CellId {
    pub mcc: u16,
    pub mnc: u16,
    pub lac: u32,
    /// Up to 36 bits: a 5G NR cell's identity does not fit 32.
    pub cellid: u64,
}

impl CellId {
    /// Parse "mcc:mnc:lac:cellid". **Pure.**
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let mut parts = text.split(':');
        Some(Self {
            mcc: parts.next()?.parse().ok()?,
            mnc: parts.next()?.parse().ok()?,
            lac: parts.next()?.parse().ok()?,
            cellid: parts.next()?.parse().ok()?,
        })
    }
}

/// The request URL for a cell. **Pure.**
#[must_use]
pub fn url(cell: &CellId) -> String {
    format!(
        "https://opencellid.org/cell/get?mcc={}&mnc={}&lac={}&cellid={}&format=json",
        cell.mcc, cell.mnc, cell.lac, cell.cellid
    )
}

/// Look the cell up.
///
/// # Errors
/// The [`LegError`] that stopped the lookup.
pub fn lookup(
    transport: &dyn Transport,
    keys: &Keys,
    indicator: Indicator<'_>,
    now_unix: u64,
) -> Result<Option<Finding>, LegError> {
    let Indicator::Cell(text) = indicator else {
        return Ok(None);
    };
    let Some(cell) = CellId::parse(text) else {
        return Ok(None);
    };
    let url = url(&cell);
    match api_leg::get(transport, &API, keys, &url, now_unix)? {
        Answer::Body(body) => decode(&body),
        Answer::NotFound(_) => Ok(None),
    }
}

/// One answer body. **Pure.**
///
/// # Errors
/// [`LegError::Decode`] for a body that is not UTF-8 or not the expected shape.
pub fn decode(body: &[u8]) -> Result<Option<Finding>, LegError> {
    let text =
        std::str::from_utf8(body).map_err(|_| LegError::Decode("answer is not UTF-8".into()))?;
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|_| LegError::Decode("answer is not JSON".into()))?;
    if value.get("error").is_some() {
        return Ok(None);
    }
    let lat = value.get("lat").and_then(serde_json::Value::as_f64);
    let lon = value.get("lon").and_then(serde_json::Value::as_f64);
    let Some((lat, lon)) = lat.zip(lon) else {
        return Ok(None);
    };
    let mut finding = Finding::new(format!("OpenCelliD: {lat:.4},{lon:.4}"))
        .attr("position", format!("{lat:.6},{lon:.6}"))
        .attr("raw_answer", text);
    if let Some(range) = value.get("range").and_then(serde_json::Value::as_u64) {
        finding = finding.attr("range", range.to_string());
    }
    if let Some(samples) = value.get("samples").and_then(serde_json::Value::as_u64) {
        finding = finding.attr("samples", samples.to_string());
    }
    Ok(Some(finding))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_position_is_kept() {
        let body = br#"{"lat":51.0,"lon":-0.1,"range":1000,"samples":5}"#;
        let f = decode(body).unwrap().unwrap();
        assert!(
            f.attrs
                .iter()
                .any(|(k, v)| *k == "position" && v.starts_with("51"))
        );
    }

    #[test]
    fn an_error_body_is_none() {
        assert!(decode(br#"{"error":"Cell not found"}"#).unwrap().is_none());
    }
}

/// Area search URL. **Pure.**
#[must_use]
pub fn area_url(lat: f64, lon: f64, radius_m: u32) -> String {
    format!(
        "https://opencellid.org/cell/getInArea?lat={lat}&lon={lon}&radius={radius_m}&format=json"
    )
}

/// One cell in an area answer.
#[derive(Debug, Clone, PartialEq)]
pub struct AreaCell {
    pub mcc: u16,
    pub mnc: u16,
    pub lac: u32,
    pub cellid: u32,
    pub lat: f64,
    pub lon: f64,
}

/// Decode an area answer. **Pure.**
pub fn decode_area(body: &[u8]) -> Result<Vec<AreaCell>, LegError> {
    let text =
        std::str::from_utf8(body).map_err(|_| LegError::Decode("answer is not UTF-8".into()))?;
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|_| LegError::Decode("answer is not JSON".into()))?;
    let cells = value
        .get("cells")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let mut out = Vec::new();
    for cell in cells {
        let Some(mcc) = cell.get("mcc").and_then(serde_json::Value::as_u64) else {
            continue;
        };
        let Some(mnc) = cell.get("mnc").and_then(serde_json::Value::as_u64) else {
            continue;
        };
        let Some(lac) = cell.get("lac").and_then(serde_json::Value::as_u64) else {
            continue;
        };
        let Some(cellid) = cell.get("cellid").and_then(serde_json::Value::as_u64) else {
            continue;
        };
        let Some(lat) = cell.get("lat").and_then(serde_json::Value::as_f64) else {
            continue;
        };
        let Some(lon) = cell.get("lon").and_then(serde_json::Value::as_f64) else {
            continue;
        };
        out.push(AreaCell {
            mcc: u16::try_from(mcc).unwrap_or(0),
            mnc: u16::try_from(mnc).unwrap_or(0),
            lac: u32::try_from(lac).unwrap_or(0),
            cellid: u32::try_from(cellid).unwrap_or(0),
            lat,
            lon,
        });
    }
    Ok(out)
}
