//! `VirusTotal` v3 reputation for one domain or IP (free key: 4 lookups a minute, 500 a day).
//!
//! One lookup is one `GET https://www.virustotal.com/api/v3/domains/{domain}` or
//! `.../ip_addresses/{ip}` with the key in the `x-apikey` header. It runs only when
//! `HUNTSMAN_VIRUSTOTAL_KEY` is set. What is kept is the last analysis verdict counts, the
//! community reputation, and the object's registry context: registrar and creation date for a
//! domain, AS number, AS owner, network and country for an address. A `404` `NotFoundError` is
//! "`VirusTotal` has no object for it", a valid zero.

use serde::Deserialize;
use std::collections::BTreeMap;

use crate::api_leg::{self, Answer, Api, KeyPlace, KeyUse, LegError};
use crate::http::{Transport, percent_encode_component};
use crate::keys::Keys;

pub const SOURCE: &str = "virustotal";
pub const KEY_SLOT: &str = crate::environment::VIRUSTOTAL_KEY_ENV;
pub const API: Api = Api {
    source: SOURCE,
    provider: "virustotal.com",
    origin: "https://www.virustotal.com:443",
    key: Some(KeyUse {
        slot: KEY_SLOT,
        place: KeyPlace::Header("x-apikey"),
        required: true,
    }),
};
/// Most categories kept.
pub const MAX_CATEGORIES: usize = 8;

/// What a lookup is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Object {
    Domain,
    Ip,
}

/// `VirusTotal`'s report on one object.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Report {
    pub malicious: u32,
    pub suspicious: u32,
    pub harmless: u32,
    pub undetected: u32,
    pub reputation: i64,
    /// Distinct category labels the engines give it, sorted.
    pub categories: Vec<String>,
    pub registrar: Option<String>,
    /// Unix seconds.
    pub creation_date: Option<i64>,
    pub asn: Option<u32>,
    pub as_owner: Option<String>,
    pub network: Option<String>,
    pub country: Option<String>,
}

impl Report {
    /// Engines that flagged it malicious or suspicious.
    #[must_use]
    pub const fn flagged(&self) -> u32 {
        self.malicious.saturating_add(self.suspicious)
    }
}

#[derive(Deserialize)]
struct Envelope {
    data: Data,
}

#[derive(Deserialize)]
struct Data {
    #[serde(rename = "type")]
    kind: String,
    attributes: Attributes,
}

#[derive(Deserialize)]
struct Attributes {
    #[serde(default)]
    last_analysis_stats: Stats,
    #[serde(default)]
    reputation: i64,
    #[serde(default)]
    categories: BTreeMap<String, String>,
    #[serde(default)]
    registrar: Option<String>,
    #[serde(default)]
    creation_date: Option<i64>,
    #[serde(default)]
    asn: Option<u32>,
    #[serde(default)]
    as_owner: Option<String>,
    #[serde(default)]
    network: Option<String>,
    #[serde(default)]
    country: Option<String>,
}

#[derive(Deserialize, Default)]
struct Stats {
    #[serde(default)]
    malicious: u32,
    #[serde(default)]
    suspicious: u32,
    #[serde(default)]
    harmless: u32,
    #[serde(default)]
    undetected: u32,
}

#[derive(Deserialize)]
struct ErrorEnvelope {
    error: ErrorBody,
}

#[derive(Deserialize)]
struct ErrorBody {
    code: String,
}

/// The request URL for `value`. **Pure.**
#[must_use]
pub fn url(object: Object, value: &str) -> String {
    let collection = match object {
        Object::Domain => "domains",
        Object::Ip => "ip_addresses",
    };
    format!(
        "https://www.virustotal.com/api/v3/{collection}/{}",
        percent_encode_component(value)
    )
}

/// Look `value` up. `Ok(None)` is "no such object".
///
/// # Errors
/// [`LegError::MissingKey`] before any request when no key is configured; otherwise the
/// [`LegError`] that stopped the lookup.
pub fn lookup<T: Transport + ?Sized>(
    transport: &T,
    keys: &Keys,
    object: Object,
    value: &str,
    now_unix: u64,
) -> Result<Option<Report>, LegError> {
    decode(
        api_leg::get(transport, &API, keys, &url(object, value), now_unix)?,
        object,
    )
}

/// One answer as a report on an `object`. **Pure.**
///
/// # Errors
/// [`LegError::Decode`] for a body that is not the documented shape or is another object type.
pub fn decode(answer: Answer, object: Object) -> Result<Option<Report>, LegError> {
    let body = match answer {
        Answer::NotFound(body) => {
            let error: ErrorEnvelope = api_leg::decode(&body)?;
            return if error.error.code == "NotFoundError" {
                Ok(None)
            } else {
                Err(LegError::Decode("404 without NotFoundError".into()))
            };
        }
        Answer::Body(body) => body,
    };
    let data = api_leg::decode::<Envelope>(&body)?.data;
    let expected = match object {
        Object::Domain => "domain",
        Object::Ip => "ip_address",
    };
    if data.kind != expected {
        return Err(LegError::Decode("answer is another object type".into()));
    }
    let a = data.attributes;
    let mut categories: Vec<String> = a
        .categories
        .values()
        .filter_map(|c| api_leg::clean(Some(c)))
        .map(|c| c.to_ascii_lowercase())
        .collect();
    categories.sort();
    categories.dedup();
    categories.truncate(MAX_CATEGORIES);
    Ok(Some(Report {
        malicious: a.last_analysis_stats.malicious,
        suspicious: a.last_analysis_stats.suspicious,
        harmless: a.last_analysis_stats.harmless,
        undetected: a.last_analysis_stats.undetected,
        reputation: a.reputation,
        categories,
        registrar: api_leg::clean(a.registrar.as_deref()),
        creation_date: a.creation_date,
        asn: a.asn,
        as_owner: api_leg::clean(a.as_owner.as_deref()),
        network: api_leg::clean(a.network.as_deref()),
        country: api_leg::clean(a.country.as_deref()),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shaped as the v3 `domains/{domain}` object of the `VirusTotal` API reference.
    const DOMAIN: &str = r#"{"data":{"id":"example.com","type":"domain","links":{"self":"https://www.virustotal.com/api/v3/domains/example.com"},"attributes":{"last_analysis_stats":{"harmless":66,"malicious":2,"suspicious":1,"undetected":24,"timeout":0},"reputation":-3,"registrar":"RESERVED-Internet Assigned Numbers Authority","creation_date":808372800,"categories":{"Forcepoint ThreatSeeker":"Reference Materials","BitDefender":"computersandsoftware","Sophos":"reference materials"},"tags":[]}}}"#;
    /// Shaped as the v3 `ip_addresses/{ip}` object.
    const IP: &str = r#"{"data":{"id":"1.1.1.1","type":"ip_address","attributes":{"last_analysis_stats":{"harmless":60,"malicious":0,"suspicious":0,"undetected":30},"reputation":20,"asn":13335,"as_owner":"CLOUDFLARENET","network":"1.1.1.0/24","country":"AU"}}}"#;

    #[test]
    fn a_domain_report_keeps_verdicts_registrar_and_categories() {
        let report = decode(Answer::Body(DOMAIN.into()), Object::Domain)
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("domain body must decode"));
        assert_eq!(report.malicious, 2);
        assert_eq!(report.flagged(), 3);
        assert_eq!(report.reputation, -3);
        assert_eq!(report.creation_date, Some(808_372_800));
        assert_eq!(
            report.categories,
            ["computersandsoftware", "reference materials"]
        );
    }

    #[test]
    fn an_ip_report_keeps_its_network_context() {
        let report = decode(Answer::Body(IP.into()), Object::Ip)
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("ip body must decode"));
        assert_eq!(report.asn, Some(13335));
        assert_eq!(report.network.as_deref(), Some("1.1.1.0/24"));
        assert_eq!(report.flagged(), 0);
    }

    #[test]
    fn a_report_on_another_object_type_is_refused() {
        assert!(decode(Answer::Body(IP.into()), Object::Domain).is_err());
    }

    #[test]
    fn not_found_error_is_a_valid_zero_and_other_404s_are_not() {
        let missing =
            r#"{"error":{"code":"NotFoundError","message":"Domain \"x.invalid\" not found"}}"#;
        assert_eq!(
            decode(Answer::NotFound(missing.into()), Object::Domain),
            Ok(None)
        );
        let other = r#"{"error":{"code":"WrongCredentialsError","message":"x"}}"#;
        assert!(decode(Answer::NotFound(other.into()), Object::Domain).is_err());
    }
}
