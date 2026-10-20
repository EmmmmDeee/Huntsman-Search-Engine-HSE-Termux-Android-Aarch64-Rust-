//! `GreyNoise` Community: is one IP mass-scanning the internet, or a known benign service?
//!
//! One lookup is one `GET https://api.greynoise.io/v3/community/{ip}`. The Community API answers
//! without a key at a low daily limit; with `HUNTSMAN_GREYNOISE_KEY` set (a free Community key)
//! the key goes in the `key` header and the limit is the account's. A `404` whose body has the
//! address and `noise: false` is the documented "not observed" answer, a valid zero.
//! This Community endpoint accepts routable IPv4 only; IPv6 receives HTTP 400.

use serde::Deserialize;

use crate::api_leg::{self, Answer, Api, KeyPlace, KeyUse, LegError};
use crate::http::Transport;
use crate::keys::Keys;

pub const SOURCE: &str = "greynoise";
pub const KEY_SLOT: &str = crate::environment::GREYNOISE_KEY_ENV;
pub const API: Api = Api {
    source: SOURCE,
    provider: "greynoise.io",
    origin: "https://api.greynoise.io:443",
    key: Some(KeyUse {
        slot: KEY_SLOT,
        place: KeyPlace::Header("key"),
        required: false,
    }),
};

/// What `GreyNoise` has seen of one address.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Sighting {
    /// Seen scanning the internet.
    pub noise: bool,
    /// A known benign business service (`RIOT`: Rule It Out).
    pub riot: bool,
    /// `benign`, `malicious` or `unknown`.
    pub classification: Option<String>,
    /// The actor or service name `GreyNoise` gives it.
    pub name: Option<String>,
    pub last_seen: Option<String>,
}

#[derive(Deserialize)]
struct Body {
    ip: String,
    #[serde(default)]
    noise: bool,
    #[serde(default)]
    riot: bool,
    #[serde(default)]
    classification: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    last_seen: Option<String>,
}

/// Whether `GreyNoise` Community can answer this address. IPv6 is unsupported.
/// This capability check sends no network request.
#[must_use]
pub fn answers_for(ip: &str) -> bool {
    ip.parse::<std::net::Ipv4Addr>().is_ok()
}

/// The request URL for `ip`. **Pure.**
#[must_use]
pub fn url(ip: &str) -> String {
    format!("https://api.greynoise.io/v3/community/{ip}")
}

/// Look `ip` up. `Ok(None)` is "not observed".
///
/// # Errors
/// The [`LegError`] that stopped the lookup.
pub fn lookup<T: Transport + ?Sized>(
    transport: &T,
    keys: &Keys,
    ip: &str,
    now_unix: u64,
) -> Result<Option<Sighting>, LegError> {
    decode(api_leg::get(transport, &API, keys, &url(ip), now_unix)?, ip)
}

/// One answer for `ip`. **Pure.**
///
/// # Errors
/// [`LegError::Decode`] for a body that is not the documented shape or names another address.
pub fn decode(answer: Answer, ip: &str) -> Result<Option<Sighting>, LegError> {
    let (body, not_found) = match answer {
        Answer::Body(body) => (body, false),
        Answer::NotFound(body) => (body, true),
    };
    let body: Body = api_leg::decode(&body)?;
    if body.ip.trim() != ip {
        return Err(LegError::Decode("answer names another address".into()));
    }
    if not_found {
        return if body.noise || body.riot {
            Err(LegError::Decode("404 that claims a sighting".into()))
        } else {
            Ok(None)
        };
    }
    Ok(Some(Sighting {
        noise: body.noise,
        riot: body.riot,
        classification: api_leg::clean(body.classification.as_deref()),
        name: api_leg::clean(body.name.as_deref()).filter(|n| n != "unknown"),
        last_seen: api_leg::clean(body.last_seen.as_deref()),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Recorded without a key for `71.6.135.131` on 2026-10-14.
    const SCANNER: &str = r#"{"ip":"71.6.135.131","noise":true,"riot":false,"classification":"benign","name":"Shodan.io","link":"https://viz.greynoise.io/ip/71.6.135.131","last_seen":"2026-10-14","message":"Success"}"#;
    /// Recorded without a key for `8.8.8.8` on 2026-10-14 (HTTP 404).
    const UNSEEN: &str = r#"{"ip":"8.8.8.8","noise":false,"riot":false,"message":"IP not observed scanning the internet."}"#;

    #[test]
    fn a_recorded_scanner_is_noise_with_its_name() {
        let sighting = decode(Answer::Body(SCANNER.into()), "71.6.135.131")
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("recorded body must decode"));
        assert!(sighting.noise);
        assert!(!sighting.riot);
        assert_eq!(sighting.classification.as_deref(), Some("benign"));
        assert_eq!(sighting.name.as_deref(), Some("Shodan.io"));
        assert_eq!(sighting.last_seen.as_deref(), Some("2026-10-14"));
    }

    #[test]
    fn the_documented_404_is_not_observed() {
        assert_eq!(decode(Answer::NotFound(UNSEEN.into()), "8.8.8.8"), Ok(None));
    }

    #[test]
    fn an_answer_about_another_address_is_refused() {
        assert!(decode(Answer::Body(SCANNER.into()), "1.2.3.4").is_err());
        assert!(decode(Answer::NotFound(SCANNER.into()), "71.6.135.131").is_err());
    }
}
