//! `IPinfo` Lite country and ASN enrichment. Requires the existing `IPinfo` key slot.
//! Kept separate from the legacy `IPinfo` endpoint to preserve its keyless behavior.
use crate::api_leg::{self, Api, KeyPlace, KeyUse, LegError};
use crate::http::Transport;
use crate::indicator_sources::{Finding, Indicator, IndicatorKind, PivotKind, Source};
use crate::keys::Keys;
use serde::Deserialize;

pub const SOURCE: &str = "ipinfo_lite";
pub const API: Api = Api {
    source: SOURCE,
    provider: "ipinfo.io",
    origin: "https://api.ipinfo.io:443",
    key: Some(KeyUse {
        slot: crate::environment::IPINFO_KEY_ENV,
        place: KeyPlace::Query("token"),
        required: true,
    }),
};
pub const INTEL: Source = Source {
    api: &API,
    kinds: &[IndicatorKind::Ip],
    lookup,
};

#[derive(Deserialize)]
struct Body {
    ip: String,
    #[serde(default)]
    bogon: bool,
    #[serde(default)]
    anycast: bool,
    #[serde(default)]
    asn: Option<String>,
    #[serde(default)]
    as_name: Option<String>,
    #[serde(default)]
    as_domain: Option<String>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    country_code: Option<String>,
    #[serde(default)]
    continent: Option<String>,
    #[serde(default)]
    continent_code: Option<String>,
}

#[must_use]
pub fn url(ip: &str) -> String {
    format!("https://api.ipinfo.io/lite/{ip}")
}

/// # Errors
/// Returns the guarded HTTP or decoding error.
pub fn lookup(
    transport: &dyn Transport,
    keys: &Keys,
    indicator: Indicator<'_>,
    now_unix: u64,
) -> Result<Option<Finding>, LegError> {
    let Indicator::Ip(ip) = indicator else {
        return Ok(None);
    };
    // Never interpolate a selector into a URL without validating it.
    let parsed = ip
        .parse::<std::net::IpAddr>()
        .map_err(|_| LegError::Decode("invalid IP selector".into()))?;
    let body = api_leg::get(transport, &API, keys, &url(&parsed.to_string()), now_unix)?
        .body_or_unexpected()?;
    decode(&body, &parsed.to_string())
}

/// Decode a Lite response without treating a missing field as a fabricated fact.
///
/// # Errors
/// Rejects malformed JSON and responses naming a different address.
pub fn decode(body: &[u8], ip: &str) -> Result<Option<Finding>, LegError> {
    let body: Body = api_leg::decode(body)?;
    let expected = ip
        .parse::<std::net::IpAddr>()
        .map_err(|_| LegError::Decode("invalid IP selector".into()))?;
    let actual = body
        .ip
        .parse::<std::net::IpAddr>()
        .map_err(|_| LegError::Decode("invalid response IP".into()))?;
    if actual != expected {
        return Err(LegError::Decode("answer names another address".into()));
    }
    if body.bogon {
        return Ok(None);
    }
    let mut finding = Finding::new(format!(
        "IPinfo Lite: {}",
        body.as_name
            .as_deref()
            .or(body.asn.as_deref())
            .unwrap_or("network not given")
    ))
    .opt_attr("asn", body.asn.as_deref())
    .opt_attr("as_name", body.as_name.as_deref())
    .opt_attr("as_domain", body.as_domain.as_deref())
    .opt_attr("country", body.country.as_deref())
    .opt_attr("country_code", body.country_code.as_deref())
    .opt_attr("continent", body.continent.as_deref())
    .opt_attr("continent_code", body.continent_code.as_deref())
    .tag_if(body.anycast, "anycast");
    if let Some(asn) = body.asn.as_deref() {
        finding = finding.pivot(PivotKind::Asn, asn, "Origin ASN reported by IPinfo Lite");
    }
    if let Some(name) = body.as_name.as_deref() {
        finding = finding.pivot(
            PivotKind::Organisation,
            name,
            "AS name reported by IPinfo Lite",
        );
    }
    if let Some(domain) = body.as_domain.as_deref() {
        finding = finding.pivot(
            PivotKind::Domain,
            domain,
            "AS domain reported by IPinfo Lite",
        );
    }
    Ok(Some(finding))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_country_asn_and_pivots() {
        let body = br#"{"ip":"8.8.8.8","asn":"AS15169","as_name":"Google LLC","as_domain":"google.com","country_code":"US","country":"United States","continent_code":"NA","continent":"North America"}"#;
        let finding = decode(body, "8.8.8.8").unwrap().unwrap();
        assert!(
            finding
                .attrs
                .iter()
                .any(|(k, v)| *k == "country_code" && v == "US")
        );
        assert!(
            finding
                .pivots
                .iter()
                .any(|p| p.kind == PivotKind::Asn && p.value == "AS15169")
        );
    }

    #[test]
    fn rejects_wrong_address_and_bad_json() {
        assert!(decode(br#"{"ip":"1.1.1.1"}"#, "8.8.8.8").is_err());
        assert!(decode(b"not json", "8.8.8.8").is_err());
    }

    #[test]
    fn requires_configured_key_and_preserves_legacy_fallback() {
        let empty = Keys::parse("").expect("empty key file");
        assert!(!API.wanted(&empty));
        let configured = Keys::parse("HUNTSMAN_IPINFO_KEY=test_token_123").expect("valid key file");
        assert!(API.wanted(&configured));
        assert!(!crate::ipinfo::API.key.expect("legacy key").required);
    }

    #[test]
    fn ipv6_equivalent_spellings_match() {
        let response = br#"{"ip":"2001:4860:4860::8888","asn":"AS15169"}"#;
        assert!(decode(response, "2001:4860:4860:0:0:0:0:8888").is_ok());
    }

    #[test]
    fn bogon_is_valid_zero_and_anycast_is_tagged() {
        let bogon = br#"{"ip":"10.0.0.1","bogon":true}"#;
        assert_eq!(decode(bogon, "10.0.0.1"), Ok(None));
        let anycast = br#"{"ip":"8.8.8.8","anycast":true}"#;
        let finding = decode(anycast, "8.8.8.8").unwrap().unwrap();
        assert!(finding.tags.contains(&"anycast"));
    }

    #[test]
    fn url_never_contains_token() {
        assert_eq!(url("8.8.8.8"), "https://api.ipinfo.io/lite/8.8.8.8");
    }
}
