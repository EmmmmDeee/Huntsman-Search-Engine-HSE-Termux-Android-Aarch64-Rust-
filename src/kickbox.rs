//! Kickbox Open: whether the domain of one email address is a disposable-mail provider.
//!
//! One lookup is one keyless `GET https://open.kickbox.com/v1/disposable/{domain}`. Only the
//! address's domain is sent, never the address itself. `{"disposable":true}` tags the address
//! `disposable`; `false` is a valid zero.

use serde::Deserialize;

use crate::api_leg::{self, Answer, Api, LegError};
use crate::http::{Transport, percent_encode_component};
use crate::indicator_sources::{Finding, Indicator, IndicatorKind, Source};
use crate::keys::Keys;

pub const SOURCE: &str = "kickbox";
pub const API: Api = Api {
    source: SOURCE,
    provider: "kickbox.com",
    origin: "https://open.kickbox.com:443",
    key: None,
};
pub const INTEL: Source = Source {
    api: &API,
    kinds: &[IndicatorKind::Email],
    lookup,
};

#[derive(Deserialize)]
struct Body {
    disposable: bool,
}

/// The request URL for `email`'s domain, or `None` for a value with no domain. **Pure.**
#[must_use]
pub fn url(email: &str) -> Option<String> {
    let (_, domain) = email.rsplit_once('@')?;
    (!domain.is_empty()).then(|| {
        format!(
            "https://open.kickbox.com/v1/disposable/{}",
            percent_encode_component(domain)
        )
    })
}

/// Look `indicator` up; only an address is a Kickbox lookup.
///
/// # Errors
/// The [`LegError`] that stopped the lookup.
pub fn lookup(
    transport: &dyn Transport,
    keys: &Keys,
    indicator: Indicator<'_>,
    now_unix: u64,
) -> Result<Option<Finding>, LegError> {
    let Some(url) = (match indicator {
        Indicator::Email(email) => url(email),
        _ => None,
    }) else {
        return Ok(None);
    };
    match api_leg::get(transport, &API, keys, &url, now_unix)? {
        Answer::Body(body) => decode(&body),
        Answer::NotFound(_) => Err(LegError::Unexpected(404)),
    }
}

/// One answer body. **Pure.**
///
/// # Errors
/// [`LegError::Decode`] for a body that is not the documented shape.
pub fn decode(body: &[u8]) -> Result<Option<Finding>, LegError> {
    let body: Body = api_leg::decode(body)?;
    Ok(body.disposable.then(|| {
        Finding::new("Kickbox: the address's domain is a disposable-mail provider")
            .attr("disposable", "true")
            .tag("disposable")
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recorded_answers_tag_only_a_disposable_domain() {
        // Both recorded on 2026-10-14: mailinator.com and gmail.com.
        let f = decode(br#"{"disposable":true}"#)
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("recorded body must decode"));
        assert_eq!(f.tags, ["disposable"]);
        assert_eq!(decode(br#"{"disposable":false}"#), Ok(None));
        assert!(decode(b"{}").is_err());
    }

    #[test]
    fn only_the_domain_is_sent() {
        assert_eq!(
            url("ada@mailinator.com").as_deref(),
            Some("https://open.kickbox.com/v1/disposable/mailinator.com")
        );
        assert_eq!(url("no-at-sign"), None);
    }
}
