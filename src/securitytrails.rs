//! `SecurityTrails`: the subdomains `SecurityTrails` has recorded for one domain.
//!
//! One lookup is one `GET https://api.securitytrails.com/v1/domain/{domain}/subdomains` with the key
//! in the `APIKEY` header, run whenever `HUNTSMAN_SECTRAILS_KEY` is set (free: 50 queries a
//! month). Each subdomain label becomes a pivot to `label.domain`; the total count is kept even
//! when the plan caps the list.

use serde::Deserialize;

use crate::api_leg::{self, Answer, Api, KeyPlace, KeyUse, LegError};
use crate::http::Transport;
use crate::indicator_sources::{Finding, Indicator, PivotKind, Source};
use crate::keys::Keys;

pub const SOURCE: &str = "securitytrails";
pub const KEY_SLOT: &str = crate::environment::SECTRAILS_KEY_ENV;
pub const API: Api = Api {
    source: SOURCE,
    provider: "securitytrails.com",
    origin: "https://api.securitytrails.com:443",
    key: Some(KeyUse {
        slot: KEY_SLOT,
        place: KeyPlace::Header("APIKEY"),
        required: true,
    }),
};
pub const INTEL: Source = Source {
    api: &API,
    ip: false,
    domain: true,
    lookup,
};

#[derive(Deserialize)]
struct Body {
    #[serde(default)]
    subdomains: Vec<String>,
    #[serde(default)]
    subdomain_count: Option<u64>,
    #[serde(default)]
    meta: Option<Meta>,
}

#[derive(Deserialize)]
struct Meta {
    #[serde(default)]
    limit_reached: bool,
}

/// The request URL for `domain`. **Pure.**
#[must_use]
pub fn url(domain: &str) -> String {
    format!("https://api.securitytrails.com/v1/domain/{domain}/subdomains?children_only=false")
}

/// Look `indicator` up; an address is not a `SecurityTrails` subdomain lookup.
///
/// # Errors
/// The [`LegError`] that stopped the lookup.
pub fn lookup(
    transport: &dyn Transport,
    keys: &Keys,
    indicator: Indicator<'_>,
    now_unix: u64,
) -> Result<Option<Finding>, LegError> {
    let Indicator::Domain(domain) = indicator else {
        return Ok(None);
    };
    match api_leg::get(transport, &API, keys, &url(domain), now_unix)? {
        Answer::Body(body) => decode(&body, domain),
        Answer::NotFound(_) => Ok(None),
    }
}

/// One answer body for `domain`. **Pure.**
///
/// # Errors
/// [`LegError::Decode`] for a body that is not the documented shape.
pub fn decode(body: &[u8], domain: &str) -> Result<Option<Finding>, LegError> {
    let body: Body = api_leg::decode(body)?;
    if body.subdomains.is_empty() {
        return Ok(None);
    }
    let total = body.subdomain_count.unwrap_or(body.subdomains.len() as u64);
    let capped = body.meta.is_some_and(|m| m.limit_reached);
    let mut finding = Finding::new(format!("SecurityTrails: {total} subdomain(s)"))
        .attr("subdomain_count", total.to_string())
        .tag_if(capped, "truncated");
    for label in &body.subdomains {
        finding = finding.pivot(
            PivotKind::Domain,
            format!("{label}.{domain}"),
            "Subdomain SecurityTrails recorded for the domain",
        );
    }
    Ok(Some(finding))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The documented `subdomains` answer shape (`SecurityTrails` API reference).
    const DOCUMENTED: &str = r#"{"endpoint":"/v1/domain/example.com/subdomains","meta":{"limit_reached":true},"subdomain_count":3,"subdomains":["www","mail","api.dev"]}"#;

    #[test]
    fn subdomain_labels_become_full_names() {
        let f = decode(DOCUMENTED.as_bytes(), "example.com")
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("documented body must decode"));
        let names: Vec<&str> = f.pivots.iter().map(|p| p.value.as_str()).collect();
        assert_eq!(
            names,
            ["www.example.com", "mail.example.com", "api.dev.example.com"]
        );
        assert_eq!(f.tags, ["truncated"]);
    }

    #[test]
    fn no_subdomains_is_a_zero_and_a_text_refusal_is_not() {
        assert_eq!(
            decode(br#"{"subdomains":[],"subdomain_count":0}"#, "example.com"),
            Ok(None)
        );
        assert!(decode(b"Please check user credentials", "example.com").is_err());
    }
}
