//! `IPinfo`: hostname, network and coarse location of one IP address.
//!
//! One lookup is one `GET https://ipinfo.io/{ip}/json`. `IPinfo` answers without a key at a low
//! limit; with `HUNTSMAN_IPINFO_KEY` set the token goes in the `token` query parameter (added as
//! the request is sent) and the account's limit applies. Kept: everything the answer gives about
//! the address: the reverse hostname, the origin AS and its holder, city, region, country,
//! postcode, time zone, whether the address is anycast, and the position (`loc`), which is also a
//! coordinates pivot. A bogon address is a valid zero.

use serde::Deserialize;

use crate::api_leg::{self, Answer, Api, KeyPlace, KeyUse, LegError};
use crate::canonical::canonical_coordinates;
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

/// The fields kept.
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
    loc: Option<String>,
    #[serde(default)]
    postal: Option<String>,
    #[serde(default)]
    timezone: Option<String>,
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
    .opt_attr("postal_code", body.postal.as_deref())
    .opt_attr("timezone", body.timezone.as_deref())
    .tag_if(body.anycast, "anycast");
    if let Some(position) = body.loc.as_deref().and_then(canonical_coordinates) {
        finding = finding.attr("coordinates", &position).pivot(
            PivotKind::Coordinates,
            position,
            "Position IPinfo gives for the address",
        );
    }
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
    fn a_recorded_answer_keeps_everything_it_gives_including_the_position() {
        let f = decode(RECORDED.as_bytes(), "8.8.8.8")
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("recorded body must decode"));
        assert_eq!(
            f.summary,
            "IPinfo: AS15169 Google LLC, Mountain View, California, US"
        );
        assert_eq!(f.tags, ["anycast"]);
        let attr = |key: &str| {
            f.attrs
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(attr("postal_code"), Some("94043"));
        assert_eq!(attr("timezone"), Some("America/Los_Angeles"));
        assert_eq!(attr("coordinates"), Some("38.008800,-122.117500"));
        let pivots: Vec<(PivotKind, &str)> = f
            .pivots
            .iter()
            .map(|p| (p.kind, p.value.as_str()))
            .collect();
        assert_eq!(
            pivots,
            [
                (PivotKind::Coordinates, "38.008800,-122.117500"),
                (PivotKind::Domain, "dns.google"),
                (PivotKind::Asn, "AS15169"),
                (PivotKind::Organisation, "Google LLC"),
            ]
        );
    }

    #[test]
    fn a_position_that_is_not_a_place_is_not_kept() {
        let body = br#"{"ip":"8.8.8.8","loc":"91.0,200.0","org":"AS15169 Google LLC"}"#;
        let f = decode(body, "8.8.8.8")
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("body must decode"));
        assert!(f.attrs.iter().all(|(k, _)| *k != "coordinates"));
        assert!(f.pivots.iter().all(|p| p.kind != PivotKind::Coordinates));
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
