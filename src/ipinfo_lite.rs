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
        place: KeyPlace::Bearer,
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
    #[serde(default, alias = "is_bogon")]
    bogon: bool,
    #[serde(default, alias = "is_anycast")]
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
    // The indicator is not an HTTP destination. An IP in a URL path still
    // discloses the operator's local addresses to a third party.
    if !crate::egress::is_public_ip(parsed) {
        return Err(LegError::Refused(
            "IPinfo Lite does not enrich non-public addresses".into(),
        ));
    }
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
    if let Some(asn) = body.asn.as_deref().filter(|asn| !asn.trim().is_empty()) {
        if crate::textnorm::parse_asn(asn)
            .and_then(|number| u32::try_from(number).ok())
            .is_none()
        {
            return Err(LegError::Decode("IPinfo Lite returned an invalid ASN".into()));
        }
    }
    // A successful HTTP 200 containing only the queried IP is *not* evidence
    // of a country or network. Keep provider-incomplete distinct from a genuine
    // negative so a missing-data response cannot invent an observed entity.
    let has_metadata = [
        body.asn.as_deref(),
        body.as_name.as_deref(),
        body.as_domain.as_deref(),
        body.country.as_deref(),
        body.country_code.as_deref(),
        body.continent.as_deref(),
        body.continent_code.as_deref(),
    ]
    .into_iter()
    .flatten()
    .any(|value| !value.trim().is_empty());
    if !has_metadata && !body.anycast {
        return Err(LegError::Decode(
            "IPinfo Lite response omitted enrichment data".into(),
        ));
    }
    let mut finding = Finding::new(format!(
        "IPinfo Lite: {}",
        body.as_name
            .as_deref()
            .or(body.asn.as_deref())
            .unwrap_or("network not given")
    ))
    .attr("data_attribution", "IP address data powered by IPinfo (https://ipinfo.io)")
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

    #[test]
    fn lite_uses_bearer_auth_without_a_token_in_the_url() {
        assert_eq!(API.key.expect("Lite requires a key").place, KeyPlace::Bearer);
        assert!(!url("8.8.8.8").contains("token"));
    }

    #[test]
    fn incomplete_responses_cannot_invent_network_evidence() {
        for body in [
            br#"{"ip":"8.8.8.8"}"#.as_slice(),
            br#"{"ip":"8.8.8.8","asn":"   ","country":" "}"#.as_slice(),
        ] {
            assert!(matches!(decode(body, "8.8.8.8"), Err(LegError::Decode(_))));
        }
        assert!(matches!(
            decode(br#"{"ip":"8.8.8.8","asn":"ASAS15169"}"#, "8.8.8.8"),
            Err(LegError::Decode(_))
        ));
        assert!(matches!(
            decode(br#"{"ip":"8.8.8.8","asn":"AS4294967296"}"#, "8.8.8.8"),
            Err(LegError::Decode(_))
        ));
    }

    #[test]
    fn accepts_lite_ip_type_aliases() {
        assert_eq!(
            decode(br#"{"ip":"10.0.0.1","is_bogon":true}"#, "10.0.0.1"),
            Ok(None)
        );
        let finding = decode(
            br#"{"ip":"8.8.8.8","is_anycast":true,"asn":"AS15169"}"#,
            "8.8.8.8",
        )
        .unwrap()
        .unwrap();
        assert!(finding.tags.contains(&"anycast"));
        assert!(finding.attrs.iter().any(|(key, value)| {
            *key == "data_attribution" && value.contains("https://ipinfo.io")
        }));
    }

    #[test]
    fn non_public_addresses_are_refused_before_transport_or_credential_lookup() {
        struct NoNetwork;
        impl Transport for NoNetwork {
            fn send(
                &self,
                _: &crate::http::Request,
            ) -> Result<crate::http::Response, crate::http::TransportFailure> {
                panic!("non-public IP must never be sent");
            }
        }
        let no_keys = Keys::parse("").expect("empty keys");
        for address in [
            "10.0.0.1",
            "127.0.0.1",
            "192.0.2.1",
            "100.64.1.1",
            "2001:db8::1",
            "::1",
        ] {
            assert!(
                matches!(
                    lookup(&NoNetwork, &no_keys, Indicator::Ip(address), 0),
                    Err(LegError::Refused(_))
                ),
                "{address}"
            );
        }
    }
}
