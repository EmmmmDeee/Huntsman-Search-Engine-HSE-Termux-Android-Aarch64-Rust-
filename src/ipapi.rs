//! ip-api: keyless IP geolocation.
//!
//! One lookup is one `GET http://ip-api.com/json/{ip}`.
//! No key. HTTP only. Non-commercial. 45 req/min.
//! Returns country, city, lat, lon, ISP, ASN.

use crate::api_leg::{self, Answer, Api, LegError};
use crate::http::{Transport, percent_encode_component};
use crate::indicator_sources::{Finding, Indicator, IndicatorKind, Source};
use crate::keys::Keys;

pub const SOURCE: &str = "ipapi";
pub const API: Api = Api {
    source: SOURCE,
    provider: "ip-api.com",
    origin: "http://ip-api.com:80",
    key: None,
};
pub const INTEL: Source = Source {
    api: &API,
    kinds: &[IndicatorKind::Ip],
    lookup,
};

/// The request URL for an IP. **Pure.**
#[must_use]
pub fn url(ip: &str) -> String {
    format!(
        "http://ip-api.com/json/{}?fields=status,country,city,lat,lon,isp,as",
        percent_encode_component(ip)
    )
}

/// Look the IP up.
///
/// # Errors
/// The [`LegError`] that stopped the lookup.
pub fn lookup(
    transport: &dyn Transport,
    keys: &Keys,
    indicator: Indicator<'_>,
    now_unix: u64,
) -> Result<Option<Finding>, LegError> {
    let Indicator::Ip(ip) = indicator else {
        return Ok(None);
    };
    let url = url(ip);
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
    let text = std::str::from_utf8(body)
        .map_err(|_| LegError::Decode("answer is not UTF-8".into()))?;
    let value: serde_json::Value = serde_json::from_str(text)
        .map_err(|_| LegError::Decode("answer is not JSON".into()))?;
    if value.get("status").and_then(|v| v.as_str()) != Some("success") {
        return Ok(None);
    }
    let lat = value.get("lat").and_then(|v| v.as_f64());
    let lon = value.get("lon").and_then(|v| v.as_f64());
    let country = value.get("country").and_then(|v| v.as_str()).unwrap_or("");
    let city = value.get("city").and_then(|v| v.as_str()).unwrap_or("");
    let mut finding = Finding::new(format!("ip-api: {city}, {country}"))
        .attr("country", country)
        .attr("city", city)
        .attr("raw_answer", text);
    if let Some((lat, lon)) = lat.zip(lon) {
        finding = finding.attr("position", format!("{lat:.6},{lon:.6}"));
    }
    if let Some(isp) = value.get("isp").and_then(|v| v.as_str()) {
        finding = finding.attr("isp", isp);
    }
    if let Some(asn) = value.get("as").and_then(|v| v.as_str()) {
        finding = finding.attr("asn", asn);
    }
    Ok(Some(finding))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_position_is_kept() {
        let body = br#"{"status":"success","country":"US","city":"Mountain View","lat":37.4,"lon":-122.1,"isp":"Google"}"#;
        let f = decode(body).unwrap().unwrap();
        assert!(f.attrs.iter().any(|(k, v)| *k == "position" && v.starts_with("37")));
    }

    #[test]
    fn a_failure_is_none() {
        assert!(decode(br#"{"status":"fail"}"#).unwrap().is_none());
    }
}
