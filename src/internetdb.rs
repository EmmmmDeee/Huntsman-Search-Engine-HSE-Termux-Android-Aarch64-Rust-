//! Shodan `InternetDB`: keyless open ports, hostnames, CPEs, tags and known CVEs for one IP.
//!
//! One lookup is one `GET https://internetdb.shodan.io/{ip}`. No key, no account; the data is
//! Shodan's weekly scan summary. A `404` whose body says `No information available` is the
//! documented "nothing known" answer and is a valid zero; any other `404` is not an answer.
//! Every answer names the address it describes (`ip`): a body without it, or about another
//! address, is not an answer either, however few of its lists it has. Every port, hostname, CPE,
//! tag and CVE of an answer is kept, each once.

use std::net::IpAddr;

use serde::Deserialize;

use crate::api_leg::{self, Answer, Api, LegError};
use crate::http::Transport;
use crate::keys::Keys;

pub const SOURCE: &str = "internetdb";
pub const API: Api = Api {
    source: SOURCE,
    provider: "internetdb.shodan.io",
    origin: "https://internetdb.shodan.io:443",
    key: None,
};
/// What `InternetDB` knows about one address.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Host {
    pub ports: Vec<u16>,
    pub hostnames: Vec<String>,
    pub cpes: Vec<String>,
    pub tags: Vec<String>,
    pub vulns: Vec<String>,
}

#[derive(Deserialize)]
struct Body {
    ip: String,
    #[serde(default)]
    ports: Vec<u16>,
    #[serde(default)]
    hostnames: Vec<String>,
    #[serde(default)]
    cpes: Vec<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    vulns: Vec<String>,
}

#[derive(Deserialize)]
struct Missing {
    detail: String,
}

/// The request URL for `ip`. **Pure.**
#[must_use]
pub fn url(ip: &str) -> String {
    format!("https://internetdb.shodan.io/{ip}")
}

/// Look `ip` up. `Ok(None)` is `InternetDB`'s "no information available".
///
/// # Errors
/// The [`LegError`] that stopped the lookup.
pub fn lookup<T: Transport + ?Sized>(
    transport: &T,
    ip: &str,
    now_unix: u64,
) -> Result<Option<Host>, LegError> {
    decode(
        api_leg::get(transport, &API, &Keys::default(), &url(ip), now_unix)?,
        ip,
    )
}

/// One answer about `ip` as a host. **Pure.**
///
/// # Errors
/// [`LegError::Decode`] for a body that is not the documented shape or is about another
/// address.
pub fn decode(answer: Answer, ip: &str) -> Result<Option<Host>, LegError> {
    match answer {
        Answer::NotFound(body) => {
            let missing: Missing = api_leg::decode(&body)?;
            if missing
                .detail
                .eq_ignore_ascii_case("No information available")
            {
                Ok(None)
            } else {
                Err(LegError::Decode("404 without the documented detail".into()))
            }
        }
        Answer::Body(body) => {
            let body: Body = api_leg::decode(&body)?;
            let about = |text: &str| text.trim().parse::<IpAddr>().ok();
            if about(&body.ip).is_none() || about(&body.ip) != about(ip) {
                return Err(LegError::Decode(
                    "answer is not about the address looked up".into(),
                ));
            }
            let list = |items: Vec<String>| -> Vec<String> {
                let mut kept: Vec<String> = items
                    .iter()
                    .filter_map(|item| api_leg::clean(Some(item)))
                    .collect();
                kept.sort();
                kept.dedup();
                kept
            };
            let mut ports = body.ports;
            ports.sort_unstable();
            ports.dedup();
            Ok(Some(Host {
                ports,
                hostnames: list(body.hostnames),
                cpes: list(body.cpes),
                tags: list(body.tags),
                vulns: list(body.vulns),
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Recorded from `https://internetdb.shodan.io/1.1.1.1` on 2026-10-14.
    const RECORDED: &str = r#"{"cpes":["cpe:/a:cloudflare:cloudflare"],"hostnames":["one.one.one.one","webauth.phsa.ca"],"ip":"1.1.1.1","ports":[53,80,443,2052,2053,2082,2083,2086,2087,8080,8443],"tags":[],"vulns":[]}"#;
    /// Recorded from `https://internetdb.shodan.io/192.0.2.1` on 2026-10-14 (HTTP 404).
    const NOTHING: &str = r#"{"detail":"No information available"}"#;

    #[test]
    fn a_recorded_answer_keeps_ports_hostnames_and_cpes() {
        let host = decode(Answer::Body(RECORDED.into()), "1.1.1.1")
            .ok()
            .flatten();
        let host = host.unwrap_or_else(|| panic!("recorded body must decode"));
        assert_eq!(host.ports.len(), 11);
        assert_eq!(host.ports[0], 53);
        assert_eq!(host.hostnames, ["one.one.one.one", "webauth.phsa.ca"]);
        assert_eq!(host.cpes, ["cpe:/a:cloudflare:cloudflare"]);
        assert!(host.vulns.is_empty());
    }

    #[test]
    fn the_documented_404_is_a_valid_zero_and_any_other_is_not() {
        let ip = "192.0.2.1";
        assert_eq!(decode(Answer::NotFound(NOTHING.into()), ip), Ok(None));
        assert!(decode(Answer::NotFound(br#"{"detail":"Not Found"}"#.to_vec()), ip).is_err());
        assert!(decode(Answer::NotFound(b"<html>".to_vec()), ip).is_err());
    }

    #[test]
    fn a_200_that_does_not_describe_the_address_is_not_an_answer() {
        let answer = |body: &str, ip: &str| {
            lookup(&crate::test_support::OneResponse::json(200, body), ip, 1)
        };
        for body in [
            "{}",
            r#"{"detail":"Service is being upgraded"}"#,
            r#"{"ip":"8.8.8.8","ports":[53]}"#,
            r#"{"ip":"","ports":[]}"#,
        ] {
            let looked_up = answer(body, "1.1.1.1");
            assert!(
                matches!(looked_up, Err(LegError::Decode(_))),
                "{body}: {looked_up:?}"
            );
        }
        // The address may be written another way; it is the same address.
        let host = answer(
            r#"{"ip":"2606:4700:4700:0:0:0:0:1111","ports":[443]}"#,
            "2606:4700:4700::1111",
        );
        assert_eq!(host.ok().flatten().map(|host| host.ports), Some(vec![443]));
    }

    #[test]
    fn every_item_of_every_list_is_kept_once() {
        let ports: Vec<String> = (1..=300).map(|p| p.to_string()).collect();
        let vulns: Vec<String> = (0..150).map(|n| format!(r#""CVE-2020-{n:05}""#)).collect();
        let body = format!(
            r#"{{"ip":"192.0.2.7","ports":[{},1],"vulns":[{},"CVE-2020-00000"],"hostnames":[],"cpes":[],"tags":[]}}"#,
            ports.join(","),
            vulns.join(",")
        );
        let host = decode(Answer::Body(body.into_bytes()), "192.0.2.7")
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("a long answer must decode"));
        assert_eq!(host.ports.len(), 300);
        assert_eq!(host.vulns.len(), 150);
    }

    #[test]
    fn the_url_names_only_the_address() {
        assert_eq!(
            url("2001:db8::1"),
            "https://internetdb.shodan.io/2001:db8::1"
        );
    }
}
