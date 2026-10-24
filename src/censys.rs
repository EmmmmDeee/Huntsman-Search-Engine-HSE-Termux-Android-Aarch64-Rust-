//! `Censys` Platform v3 host lookup for a public IP address.
//!
//! Free Platform accounts can retrieve an individual host with a Personal Access
//! Token (PAT). Legacy Censys API ID/secret pairs are not accepted by this API.
//! A configured `HUNTSMAN_CENSYS_TOKEN` enables the lookup; without one no request
//! is sent. Each request is origin-bound and redirects are refused by `api_leg`.
//! A documented HTTP 404 means no host; a malformed 200 never becomes a zero.

use serde_json::Value;

use crate::api_leg::{self, Answer, Api, KeyPlace, KeyUse, LegError};
use crate::http::Transport;
use crate::indicator_sources::{Finding, Indicator, IndicatorKind, PivotKind, Source};
use crate::keys::Keys;

pub const SOURCE: &str = "censys";
pub const KEY_SLOT: &str = crate::environment::CENSYS_TOKEN_ENV;
pub const API: Api = Api {
    source: SOURCE,
    provider: "censys.io",
    origin: "https://api.platform.censys.io:443",
    key: Some(KeyUse {
        slot: KEY_SLOT,
        place: KeyPlace::Bearer,
        required: true,
    }),
};
pub const INTEL: Source = Source {
    api: &API,
    kinds: &[IndicatorKind::Ip],
    lookup,
};

#[must_use]
pub fn url(ip: &str) -> String {
    format!("https://api.platform.censys.io/v3/global/asset/host/{ip}")
}

/// Look up a host through the free-plan-compatible asset endpoint.
///
/// # Errors
/// Returns a typed transport, authentication, quota or schema error; only a
/// documented HTTP 404 becomes `Ok(None)`.
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
        Answer::Body(body) => decode(&body, ip).map(Some),
        Answer::NotFound(_) => Ok(None),
    }
}

fn string_at<'a>(value: &'a Value, path: &str) -> Option<&'a str> {
    value.pointer(path).and_then(Value::as_str)
}

/// Convert one Censys v3 response into the evidence and canonical pivots
/// the IP lookup already stores.
///
/// # Errors
/// Rejects unexpected envelope shapes, a different host and malformed arrays.
pub fn decode(body: &[u8], ip: &str) -> Result<Finding, LegError> {
    let document: Value = api_leg::decode(body)?;
    let host = document
        .pointer("/result/resource")
        .filter(|value| value.is_object())
        .ok_or_else(|| LegError::Decode("Censys host envelope missing".into()))?;
    let requested = ip
        .parse::<std::net::IpAddr>()
        .map_err(|_| LegError::Decode("invalid requested host address".into()))?;
    let returned = string_at(host, "/ip").and_then(|address| address.parse().ok());
    if returned != Some(requested) {
        return Err(LegError::Decode("Censys answer names another host".into()));
    }
    let services = match host.get("services") {
        None | Some(Value::Null) => &[][..],
        Some(Value::Array(services)) => services.as_slice(),
        Some(_) => return Err(LegError::Decode("Censys services are not an array".into())),
    };
    let dns = match host.pointer("/dns/names") {
        None | Some(Value::Null) => &[][..],
        Some(Value::Array(names)) => names.as_slice(),
        Some(_) => return Err(LegError::Decode("Censys DNS names are not an array".into())),
    };
    let asn = host
        .pointer("/autonomous_system/asn")
        .and_then(Value::as_u64)
        .map(|number| format!("AS{number}"));
    let organisation = string_at(host, "/autonomous_system/name");
    let country = string_at(host, "/location/country");
    let city = string_at(host, "/location/city");
    let mut finding = Finding::new(format!("Censys: {} services on {ip}", services.len()))
        .attr("service_count", services.len().to_string())
        .opt_attr("country", country)
        .opt_attr("city", city)
        .opt_attr("as_name", organisation)
        .opt_attr("asn", asn.as_deref());

    let ports: Vec<String> = services
        .iter()
        .filter_map(|service| {
            let port = service.get("port")?.as_u64()?;
            if port > u64::from(u16::MAX) {
                return None;
            }
            let protocol = service
                .get("transport_protocol")
                .and_then(Value::as_str)
                .or_else(|| service.get("protocol").and_then(Value::as_str))
                .unwrap_or("unknown");
            Some(format!("{port}/{protocol}"))
        })
        .collect();
    if !ports.is_empty() {
        finding = finding.list_attr("services", &ports);
    }
    if let Some(asn) = asn {
        finding = finding.pivot(PivotKind::Asn, asn, "Censys observed the network ASN");
    }
    if let Some(name) = organisation {
        finding = finding.pivot(
            PivotKind::Organisation,
            name,
            "Censys observed the network organisation",
        );
    }
    for name in dns.iter().filter_map(Value::as_str) {
        finding = finding.pivot(PivotKind::Domain, name, "Censys observed a DNS name");
    }
    Ok(finding)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{Request, Response, TransportFailure};
    use crate::source_outcome::SourceOutcomeKind;
    use std::sync::Mutex;

    const HOST: &str = r#"{"result":{"resource":{"ip":"1.1.1.1","location":{"country":"Australia","city":"Brisbane"},"autonomous_system":{"asn":13335,"name":"Cloudflare"},"services":[{"port":443,"transport_protocol":"tcp","protocol":"HTTP"},{"port":53,"transport_protocol":"udp","protocol":"DNS"}],"dns":{"names":["one.one.one.one"]}}}}"#;

    #[derive(Default)]
    struct Recording {
        sent: Mutex<Vec<Request>>,
        status: u16,
        body: &'static str,
    }

    impl Transport for Recording {
        fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
            self.sent
                .lock()
                .expect("recorded requests")
                .push(request.clone());
            Ok(Response {
                status: self.status,
                headers: Vec::new(),
                body: self.body.as_bytes().to_vec(),
                truncated: false,
            })
        }
    }

    fn keys() -> Keys {
        Keys::parse("HUNTSMAN_CENSYS_TOKEN=TEST_ONLY_CENSYS_TOKEN").expect("fixture key")
    }

    #[test]
    fn host_enrichment_retains_service_ports_and_verified_pivots() {
        let finding = decode(HOST.as_bytes(), "1.1.1.1").expect("host");
        assert_eq!(finding.summary, "Censys: 2 services on 1.1.1.1");
        assert!(
            finding
                .attrs
                .contains(&("services", "443/tcp,53/udp".into()))
        );
        assert!(finding.attrs.contains(&("country", "Australia".into())));
        assert!(
            finding
                .pivots
                .iter()
                .any(|p| p.kind == PivotKind::Asn && p.value == "AS13335")
        );
        assert!(
            finding
                .pivots
                .iter()
                .any(|p| p.kind == PivotKind::Domain && p.value == "one.one.one.one")
        );
    }

    #[test]
    fn malformed_host_or_wrong_address_is_not_a_negative_result() {
        assert!(decode(br#"{"result":{}}"#, "1.1.1.1").is_err());
        assert!(decode(HOST.as_bytes(), "8.8.8.8").is_err());
        assert!(
            decode(
                br#"{"result":{"resource":{"ip":"1.1.1.1","services":{}}}}"#,
                "1.1.1.1"
            )
            .is_err()
        );
    }

    #[test]
    fn equivalent_ipv6_spellings_are_the_same_host() {
        let body = br#"{"result":{"resource":{"ip":"2606:4700:4700:0:0:0:0:1111"}}}"#;
        assert!(decode(body, "2606:4700:4700::1111").is_ok());
        assert!(decode(body, "2606:4700:4700::1001").is_err());
    }

    #[test]
    fn no_key_makes_no_request_and_valid_key_is_bearer_origin_bound() {
        let recorder = Recording {
            status: 200,
            body: HOST,
            ..Recording::default()
        };
        assert!(!API.wanted(&Keys::default()));
        assert!(matches!(
            lookup(&recorder, &Keys::default(), Indicator::Ip("1.1.1.1"), 1),
            Err(LegError::MissingKey(_))
        ));
        assert!(recorder.sent.lock().expect("sent").is_empty());
        let result = lookup(&recorder, &keys(), Indicator::Ip("1.1.1.1"), 1);
        assert!(matches!(result, Ok(Some(_))), "{result:?}");
        let sent = recorder.sent.lock().expect("sent");
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].url, url("1.1.1.1"));
        assert_eq!(
            sent[0].header_value("authorization"),
            Some("Bearer TEST_ONLY_CENSYS_TOKEN")
        );
    }

    #[test]
    fn documented_404_is_zero_but_auth_and_quota_are_failures() {
        for (status, expected_zero) in [(404, true), (401, false), (403, false), (429, false)] {
            let recorder = Recording {
                status,
                body: "{}",
                ..Recording::default()
            };
            let result = lookup(&recorder, &keys(), Indicator::Ip("1.1.1.1"), 1);
            assert_eq!(
                matches!(result, Ok(None)),
                expected_zero,
                "{status}: {result:?}"
            );
            if status != 404 {
                assert!(result.is_err());
            }
        }
        assert_eq!(API.key.expect("key").slot, KEY_SLOT);
        assert_eq!(SourceOutcomeKind::ValidZero.as_str(), "valid_zero");
    }
}
