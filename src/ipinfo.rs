//! `IPinfo`: hostname, network and coarse location of one IP address.
//!
//! One lookup is one `GET https://ipinfo.io/{ip}/json`. `IPinfo` answers without a key at a low
//! limit; with `HUNTSMAN_IPINFO_KEY` set the token goes in the `token` query parameter (added as
//! the request is sent) and the account's limit applies. Kept: the reverse hostname, the origin
//! AS and its holder, city, region and country, and whether the address is anycast. The postcode
//! and coordinates are not kept. A bogon address is a valid zero.

use serde::Deserialize;

use crate::api_leg::{self, Answer, Api, KeyPlace, KeyUse, LegError};
use crate::http::Transport;
use crate::indicator_sources::{Finding, Indicator, IndicatorKind, PivotKind, Source};
use crate::keys::Keys;

pub const SOURCE: &str = "ipinfo";
pub const KEY_SLOT: &str = crate::environment::IPINFO_KEY_ENV;
pub const API: Api = Api {
    source: SOURCE,
    provider: "ipinfo.io",
    origin: "https://ipinfo.io:443",
    key: Some(KeyUse {
        slot: KEY_SLOT,
        place: KeyPlace::Query("token"),
        required: false,
    }),
};
pub const INTEL: Source = Source {
    api: &API,
    kinds: &[IndicatorKind::Ip],
    lookup,
};

/// The fields kept; `loc` and `postal` are not decoded.
#[derive(Deserialize)]
struct Body {
    ip: String,
    #[serde(default)]
    bogon: bool,
    #[serde(default)]
    hostname: Option<String>,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    region: Option<String>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    org: Option<String>,
    #[serde(default)]
    anycast: bool,
}

/// The request URL for `ip`. **Pure.**
#[must_use]
pub fn url(ip: &str) -> String {
    format!("https://ipinfo.io/{ip}/json")
}

/// Look `indicator` up; only an address is an `IPinfo` lookup.
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
    match api_leg::get(transport, &API, keys, &url(ip), now_unix)? {
        Answer::Body(body) => decode(&body, ip),
        Answer::NotFound(_) => Err(LegError::Unexpected(404)),
    }
}

/// One answer body for `ip`. **Pure.**
///
/// # Errors
/// [`LegError::Decode`] for a body that is not the documented shape or names another address.
pub fn decode(body: &[u8], ip: &str) -> Result<Option<Finding>, LegError> {
    let body: Body = api_leg::decode(body)?;
    if !body.ip.eq_ignore_ascii_case(ip) {
        return Err(LegError::Decode("answer names another address".into()));
    }
    if body.bogon {
        return Ok(None);
    }
    let place: Vec<&str> = [&body.city, &body.region, &body.country]
        .into_iter()
        .filter_map(|v| v.as_deref().filter(|s| !s.is_empty()))
        .collect();
    let mut finding = Finding::new(format!(
        "IPinfo: {}{}",
        body.org.as_deref().unwrap_or("network not given"),
        if place.is_empty() {
            String::new()
        } else {
            format!(", {}", place.join(", "))
        }
    ))
    .opt_attr("hostname", body.hostname.as_deref())
    .opt_attr("network", body.org.as_deref())
    .opt_attr("city", body.city.as_deref())
    .opt_attr("region", body.region.as_deref())
    .opt_attr("country", body.country.as_deref())
    .tag_if(body.anycast, "anycast");
    if let Some(host) = body.hostname.as_deref() {
        finding = finding.pivot(PivotKind::Domain, host, "Reverse hostname IPinfo gives");
    }
    if let Some((asn, holder)) = body.org.as_deref().and_then(|o| o.split_once(' ')) {
        finding = finding
            .pivot(
                PivotKind::Asn,
                asn,
                "Origin AS IPinfo gives for the address",
            )
            .pivot(
                PivotKind::Organisation,
                holder,
                "AS holder IPinfo gives for the address",
            );
    }
    Ok(Some(finding))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Recorded without a key for `8.8.8.8` on 2026-10-14.
    const RECORDED: &str = r#"{"ip":"8.8.8.8","hostname":"dns.google","city":"Mountain View","region":"California","country":"US","loc":"38.0088,-122.1175","org":"AS15169 Google LLC","postal":"94043","timezone":"America/Los_Angeles","readme":"https://ipinfo.io/missingauth","anycast":true}"#;

    #[test]
    fn a_recorded_answer_keeps_host_network_and_place_but_no_coordinates() {
        let f = decode(RECORDED.as_bytes(), "8.8.8.8")
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("recorded body must decode"));
        assert_eq!(
            f.summary,
            "IPinfo: AS15169 Google LLC, Mountain View, California, US"
        );
        assert_eq!(f.tags, ["anycast"]);
        let text = format!("{f:?}");
        assert!(
            !text.contains("38.0088") && !text.contains("94043"),
            "{text}"
        );
        let pivots: Vec<&str> = f.pivots.iter().map(|p| p.value.as_str()).collect();
        assert_eq!(pivots, ["dns.google", "AS15169", "Google LLC"]);
    }

    #[test]
    fn a_bogon_is_a_zero_and_another_address_is_refused() {
        assert_eq!(
            decode(br#"{"ip":"10.0.0.1","bogon":true}"#, "10.0.0.1"),
            Ok(None)
        );
        assert!(decode(RECORDED.as_bytes(), "1.1.1.1").is_err());
    }
}
