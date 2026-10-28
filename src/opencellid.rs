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
        let cell = Self {
            mcc: parts.next()?.parse().ok()?,
            mnc: parts.next()?.parse().ok()?,
            lac: parts.next()?.parse().ok()?,
            cellid: parts.next()?.parse().ok()?,
        };
        parts.next().is_none().then_some(cell)
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
        // OpenCelliD documents missing cells as HTTP 200 / code 1.
        // HTTP 404 means an endpoint is unavailable or misconfigured, not zero results.
        Answer::NotFound(_) => Err(LegError::Unexpected(404)),
    }
}

/// A position is evidence only when both coordinates lie inside their geographic bounds.
/// No clamping: an out-of-range provider value must not become a real location. **Pure.**
fn valid_position(lat: f64, lon: f64) -> bool {
    (-90.0..=90.0).contains(&lat) && (-180.0..=180.0).contains(&lon)
}

/// Classify provider-declared errors without copying the error message into diagnostics:
/// OpenCelliD's invalid-key response may echo the caller's credential. **Pure.**
///
/// Only an explicit "Cell not found" is a genuine zero. Provider error code 1
/// alone is not sufficient: it may also describe temporary endpoint unavailability.
/// The legacy un-coded "Cell not found" body remains compatible.
fn provider_error(value: &serde_json::Value) -> Option<Result<(), LegError>> {
    let message = value.get("error")?;
    let missing = message
        .as_str()
        .is_some_and(|text| text.trim().eq_ignore_ascii_case("Cell not found"));
    let code = value.get("code").and_then(serde_json::Value::as_u64);
    Some(match code {
        Some(1) if missing => Ok(()),
        None if value.get("code").is_none() && missing => Ok(()),
        Some(2) => Err(LegError::Unauthorized),
        Some(3) => Err(LegError::BadRequest(400)),
        Some(4) => Err(LegError::Forbidden),
        Some(5) => Err(LegError::Server(500)),
        Some(6) => Err(LegError::Server(503)),
        Some(7) => Err(LegError::RateLimited { retry_after: None }),
        _ => Err(LegError::Decode(
            "OpenCelliD returned an unrecognised error response".into(),
        )),
    })
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
    if let Some(result) = provider_error(&value) {
        result?;
        return Ok(None);
    }
    let lat = value.get("lat").and_then(serde_json::Value::as_f64);
    let lon = value.get("lon").and_then(serde_json::Value::as_f64);
    let Some((lat, lon)) = lat.zip(lon) else {
        return Err(LegError::Decode("OpenCelliD response has no position".into()));
    };
    if !valid_position(lat, lon) {
        return Err(LegError::Decode("OpenCelliD position out of range".into()));
    }
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

/// The most cells one area answer carries: `getInArea`'s default and maximum `limit`.
pub const AREA_LIMIT: u32 = 50;

/// Half the side of the square searched around a point, in metres. `getInArea` refuses a box over
/// 4,000,000 m²; this one is 1.8 km a side, 3.24 km².
pub const AREA_HALF_SIDE_M: f64 = 900.0;

/// A `getInArea` bounding box, in degrees.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BBox {
    pub lat_min: f64,
    pub lon_min: f64,
    pub lat_max: f64,
    pub lon_max: f64,
}

impl BBox {
    /// The square [`AREA_HALF_SIDE_M`] either side of a point, clamped to valid coordinates.
    /// **Pure.**
    #[must_use]
    pub fn around(lat: f64, lon: f64) -> Self {
        const METRES_PER_DEGREE: f64 = 111_320.0;
        let dlat = AREA_HALF_SIDE_M / METRES_PER_DEGREE;
        // Narrower meridians toward the poles; a floor keeps the box finite there.
        let dlon = AREA_HALF_SIDE_M / (METRES_PER_DEGREE * lat.to_radians().cos().max(0.01));
        Self {
            lat_min: (lat - dlat).max(-90.0),
            lon_min: (lon - dlon).max(-180.0),
            lat_max: (lat + dlat).min(90.0),
            lon_max: (lon + dlon).min(180.0),
        }
    }
}

/// The area search URL, `BBOX` as `latmin,lonmin,latmax,lonmax`. The key is added as the request
/// is sent. **Pure.**
#[must_use]
pub fn area_url(bbox: &BBox) -> String {
    format!(
        "https://opencellid.org/cell/getInArea?BBOX={:.6},{:.6},{:.6},{:.6}&limit={AREA_LIMIT}&format=json",
        bbox.lat_min, bbox.lon_min, bbox.lat_max, bbox.lon_max
    )
}

/// One cell in an area answer.
#[derive(Debug, Clone, PartialEq)]
pub struct AreaCell {
    pub cell: CellId,
    pub lat: f64,
    pub lon: f64,
    /// `GSM`, `UMTS`, `LTE`, `NR`, `NBIOT` or `CDMA`.
    pub radio: Option<String>,
    /// Estimated coverage radius in metres.
    pub range: Option<u64>,
    pub samples: Option<u64>,
}

/// An area answer: the cells in it, at most [`AREA_LIMIT`], and how many the area holds when
/// `OpenCelliD` says.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Area {
    pub cells: Vec<AreaCell>,
    pub count: Option<u64>,
}

/// Search the square around a point.
///
/// # Errors
/// The [`LegError`] that stopped the search.
pub fn area<T: Transport + ?Sized>(
    transport: &T,
    keys: &Keys,
    lat: f64,
    lon: f64,
    now_unix: u64,
) -> Result<Area, LegError> {
    if !valid_position(lat, lon) {
        return Err(LegError::Decode(
            "OpenCelliD area coordinates out of range".into(),
        ));
    }
    match api_leg::get(
        transport,
        &API,
        keys,
        &area_url(&BBox::around(lat, lon)),
        now_unix,
    )? {
        Answer::Body(body) => decode_area(&body),
        // A zero area is HTTP 200 with an empty cells array (or code 1).
        Answer::NotFound(_) => Err(LegError::Unexpected(404)),
    }
}

/// Decode an area answer. An empty area is `{"count":0,"cells":[]}`, and "Cell not found"
/// (code 1) is the same zero; any other error body, or a body without `cells`, is a decode
/// failure rather than an empty area. A cell whose codes do not fit their fields is left out,
/// never narrowed. **Pure.**
///
/// # Errors
/// [`LegError::Decode`] for a body that is not UTF-8, not JSON, an error, or not the expected
/// shape.
pub fn decode_area(body: &[u8]) -> Result<Area, LegError> {
    use serde_json::Value;
    let text =
        std::str::from_utf8(body).map_err(|_| LegError::Decode("answer is not UTF-8".into()))?;
    let value: Value =
        serde_json::from_str(text).map_err(|_| LegError::Decode("answer is not JSON".into()))?;
    if let Some(result) = provider_error(&value) {
        result?;
        return Ok(Area::default());
    }
    let cells = value
        .get("cells")
        .and_then(Value::as_array)
        .ok_or_else(|| LegError::Decode("answer has no cells list".into()))?;
    let number = |cell: &Value, key: &str| cell.get(key).and_then(Value::as_u64);
    let cells = cells
        .iter()
        .filter_map(|cell| {
            let lat = cell.get("lat").and_then(Value::as_f64)?;
            let lon = cell.get("lon").and_then(Value::as_f64)?;
            if !valid_position(lat, lon) {
                return None;
            }
            Some(AreaCell {
                cell: CellId {
                    mcc: u16::try_from(number(cell, "mcc")?).ok()?,
                    mnc: u16::try_from(number(cell, "mnc")?).ok()?,
                    lac: u32::try_from(number(cell, "lac")?).ok()?,
                    cellid: number(cell, "cellid")?,
                },
                lat,
                lon,
                radio: api_leg::clean(cell.get("radio").and_then(Value::as_str)),
                range: number(cell, "range"),
                samples: number(cell, "samples"),
            })
        })
        .collect();
    Ok(Area {
        cells,
        count: value.get("count").and_then(Value::as_u64),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cell_ids_require_exactly_four_components() {
        assert_eq!(
            CellId::parse("505:1:123:456"),
            Some(CellId {
                mcc: 505,
                mnc: 1,
                lac: 123,
                cellid: 456,
            })
        );
        for invalid in [
            "505:1:123",
            "505:1:123:456:",
            "505:1:123:456:789",
            "505:1:123:456:untrusted",
            "505:1:123:456::",
        ] {
            assert!(CellId::parse(invalid).is_none(), "{invalid}");
        }
    }

    #[test]
    fn out_of_range_positions_are_not_emitted_as_evidence() {
        for (lat, lon) in [(91.0, 151.0), (-90.1, 151.0), (0.0, 180.1), (0.0, -180.1)] {
            let body = format!(r#"{{"lat":{lat},"lon":{lon},"range":500}}"#);
            assert!(matches!(decode(body.as_bytes()), Err(LegError::Decode(_))));
        }
        assert!(valid_position(-90.0, -180.0));
        assert!(valid_position(90.0, 180.0));
        assert!(!valid_position(f64::NAN, 0.0));
        assert!(!valid_position(0.0, f64::INFINITY));
    }

    #[test]
    fn area_excludes_invalid_positions_without_erasing_valid_cells() {
        let response = br#"{"count":3,"cells":[
            {"lat":-27.0,"lon":153.0,"mcc":505,"mnc":1,"lac":12,"cellid":100},
            {"lat":91.0,"lon":153.0,"mcc":505,"mnc":1,"lac":12,"cellid":101},
            {"lat":-27.0,"lon":181.0,"mcc":505,"mnc":1,"lac":12,"cellid":102}
        ]}"#;
        let area = decode_area(response).expect("valid response structure");
        assert_eq!(area.cells.len(), 1);
        assert_eq!(area.cells[0].cell.cellid, 100);
        // Provider count is provenance about upstream rows, not the number accepted.
        assert_eq!(area.count, Some(3));
    }

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
    fn only_a_genuine_missing_cell_is_an_empty_result() {
        for body in [
            &br#"{"error":"Cell not found"}"#[..],
            br#"{"error":"Cell not found","code":1}"#,
            br#"{"error":"cell not found","code":1,"notice":"coverage varies"}"#,
        ] {
            assert!(decode(body).unwrap().is_none());
        }
        for body in [
            &br#"{"error":"temporarily unavailable","code":1}"#[..],
            br#"{"error":"Invalid API key"}"#,
            br#"{"error":"Cell not found","code":"1"}"#,
            br#"{"lat":12}"#,
            br#"{}"#,
        ] {
            assert!(matches!(decode(body), Err(LegError::Decode(_))));
        }
    }

    #[test]
    fn provider_failures_preserve_classification_without_leaking_keys() {
        let cases: &[(&[u8], LegError)] = &[
            (
                br#"{"error":"API Key not known: test-secret-should-not-appear","code":2}"#,
                LegError::Unauthorized,
            ),
            (
                br#"{"error":"Invalid input data","code":3}"#,
                LegError::BadRequest(400),
            ),
            (
                br#"{"error":"Forbidden","code":4}"#,
                LegError::Forbidden,
            ),
            (
                br#"{"error":"Internal server error","code":5}"#,
                LegError::Server(500),
            ),
            (
                br#"{"error":"Too many requests","code":6}"#,
                LegError::Server(503),
            ),
            (
                br#"{"error":"Daily limit exceeded","code":7}"#,
                LegError::RateLimited { retry_after: None },
            ),
        ];
        for (body, expected) in cases {
            let failure = decode(body).expect_err("provider failure must not be a zero");
            assert_eq!(&failure, expected);
            assert!(!failure.to_string().contains("test-secret-should-not-appear"));
            assert_eq!(decode_area(body), Err(expected.clone()));
        }
    }

    #[test]
    fn an_area_is_a_box_under_the_documented_limit_in_bbox_order() {
        let bbox = BBox::around(-33.8688, 151.2093);
        let url = area_url(&bbox);
        assert!(
            url.starts_with("https://opencellid.org/cell/getInArea?BBOX=-33.876885,151.199"),
            "{url}"
        );
        assert!(url.ends_with("&limit=50&format=json"), "{url}");
        let height = (bbox.lat_max - bbox.lat_min) * 111_320.0;
        let width = (bbox.lon_max - bbox.lon_min) * 111_320.0 * (-33.8688_f64).to_radians().cos();
        assert!(height * width < 4_000_000.0, "{}", height * width);
        let polar = BBox::around(89.999, 179.9999);
        assert!(polar.lat_max <= 90.0 && polar.lon_max <= 180.0, "{polar:?}");
    }

    #[test]
    fn an_area_keeps_every_cell_with_a_wide_nr_identity_whole() {
        let body = br#"{"count":2,"cells":[
            {"lat":-33.87,"lon":151.21,"mcc":505,"mnc":1,"lac":12345,"cellid":68719476735,"radio":"NR","range":500,"samples":3},
            {"lat":-33.86,"lon":151.2,"mcc":505,"mnc":2,"lac":7,"cellid":17811,"radio":"LTE"},
            {"lat":-33.86,"lon":151.2,"mcc":70000,"mnc":2,"lac":7,"cellid":1}
        ]}"#;
        let area = decode_area(body).unwrap();
        assert_eq!(area.count, Some(2));
        assert_eq!(area.cells.len(), 2);
        assert_eq!(area.cells[0].cell.cellid, 68_719_476_735);
        assert_eq!(area.cells[0].radio.as_deref(), Some("NR"));
        assert_eq!(area.cells[0].range, Some(500));
    }

    #[test]
    fn an_empty_area_is_zero_and_an_error_or_other_body_is_not() {
        assert_eq!(
            decode_area(br#"{"count":0,"cells":[]}"#).unwrap(),
            Area {
                cells: Vec::new(),
                count: Some(0)
            }
        );
        assert_eq!(
            decode_area(br#"{"error":"Cell not found","code":1}"#).unwrap(),
            Area::default()
        );
        assert_eq!(
            decode_area(br#"{"error":"Cell not found"}"#).unwrap(),
            Area::default()
        );
        for body in [
            &br#"{"error":"Invalid input data","code":3}"#[..],
            br#"{"count":3}"#,
            b"<kml stat=\"fail\"/>",
        ] {
            assert!(
                matches!(decode_area(body), Err(LegError::Decode(_))),
                "{}",
                String::from_utf8_lossy(body)
            );
        }
    }
}
