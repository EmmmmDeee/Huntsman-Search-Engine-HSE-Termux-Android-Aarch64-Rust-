//! Mozilla Location Service: keyed geolocation by `WiFi BSSID` or cell.
//!
//! One lookup is one `POST https://location.services.mozilla.com/v1/geolocate?key={key}`
//! with a JSON body of `wifiAccessPoints` or `cellTowers`. Requires `HUNTSMAN_MOZILLA_LOCATION_KEY`.
//! Returns lat, lng, accuracy. A missing result is HTTP 404.

use crate::api_leg::{self, Answer, Api, KeyPlace, KeyUse, LegError};
use crate::http::Transport;
use crate::indicator_sources::{Finding, Indicator, IndicatorKind, Source};
use crate::keys::Keys;

pub const SOURCE: &str = "mozilla_location";
pub const KEY_SLOT: &str = crate::environment::MOZILLA_LOCATION_KEY_ENV;
pub const API: Api = Api {
    source: SOURCE,
    provider: "location.services.mozilla.com",
    origin: "https://location.services.mozilla.com:443",
    key: Some(KeyUse {
        slot: KEY_SLOT,
        place: KeyPlace::Query("key"),
        required: true,
    }),
};
pub const INTEL: Source = Source {
    api: &API,
    kinds: &[IndicatorKind::MacAddress],
    lookup,
};

/// The request URL. **Pure.**
#[must_use]
pub fn url() -> String {
    "https://location.services.mozilla.com/v1/geolocate".into()
}

/// Look the BSSID up.
///
/// # Errors
/// The [`LegError`] that stopped the lookup.
pub fn lookup(
    transport: &dyn Transport,
    keys: &Keys,
    indicator: Indicator<'_>,
    now_unix: u64,
) -> Result<Option<Finding>, LegError> {
    let Indicator::MacAddress(bssid) = indicator else {
        return Ok(None);
    };
    let body = serde_json::json!({
        "wifiAccessPoints": [{ "macAddress": bssid }]
    });
    let url = url();
    match api_leg::post_json(transport, &API, keys, &url, &body, now_unix)? {
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
    let location = value.get("location");
    let lat = location
        .and_then(|l| l.get("lat"))
        .and_then(serde_json::Value::as_f64);
    let lng = location
        .and_then(|l| l.get("lng"))
        .and_then(serde_json::Value::as_f64);
    let Some((lat, lng)) = lat.zip(lng) else {
        return Ok(None);
    };
    let mut finding = Finding::new(format!("Mozilla Location: {lat:.4},{lng:.4}"))
        .attr("position", format!("{lat:.6},{lng:.6}"))
        .attr("raw_answer", text);
    if let Some(accuracy) = value.get("accuracy").and_then(serde_json::Value::as_f64) {
        finding = finding.attr("accuracy", format!("{accuracy:.1}"));
    }
    Ok(Some(finding))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_position_is_kept() {
        let body = br#"{"location":{"lat":51.0,"lng":-0.1},"accuracy":1200.0}"#;
        let f = decode(body).unwrap().unwrap();
        assert!(
            f.attrs
                .iter()
                .any(|(k, v)| *k == "position" && v.starts_with("51"))
        );
    }

    #[test]
    fn a_missing_location_is_none() {
        assert!(decode(br"{}").unwrap().is_none());
    }
}
