//! Whoxy: the live WHOIS record of one domain (pay-as-you-go, one credit per lookup).
//!
//! One lookup is one `GET https://api.whoxy.com/?whois={domain}`, run whenever `HUNTSMAN_WHOXY_KEY`
//! is set; Whoxy takes the key only as the `key` query parameter, added as the request is sent.
//! Whoxy answers HTTP 200 for its own errors, with `status: 0` and a `status_reason`: an invalid
//! key is reported as a rejected key and an empty balance as a plan refusal, never as a zero.
//! What is kept: registrar, dates, status codes, name servers, and from the registrant the name,
//! organisation, country and address. Street address, phone and fax are not kept.

use serde::Deserialize;

use crate::api_leg::{self, Answer, Api, KeyPlace, KeyUse, LegError};
use crate::http::{Transport, percent_encode_component};
use crate::indicator_sources::{Finding, Indicator, PivotKind, Source};
use crate::keys::Keys;

pub const SOURCE: &str = "whoxy";
pub const KEY_SLOT: &str = crate::environment::WHOXY_KEY_ENV;
pub const API: Api = Api {
    source: SOURCE,
    provider: "whoxy.com",
    origin: "https://api.whoxy.com:443",
    key: Some(KeyUse {
        slot: KEY_SLOT,
        place: KeyPlace::Query("key"),
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
    status: i64,
    #[serde(default)]
    status_reason: Option<String>,
    #[serde(default)]
    domain_name: Option<String>,
    #[serde(default)]
    domain_registered: Option<String>,
    #[serde(default)]
    create_date: Option<String>,
    #[serde(default)]
    update_date: Option<String>,
    #[serde(default)]
    expiry_date: Option<String>,
    #[serde(default)]
    domain_registrar: Option<Registrar>,
    #[serde(default)]
    registrant_contact: Option<Contact>,
    #[serde(default)]
    administrative_contact: Option<Contact>,
    #[serde(default)]
    technical_contact: Option<Contact>,
    #[serde(default)]
    name_servers: Vec<String>,
    #[serde(default)]
    domain_status: Vec<String>,
}

#[derive(Deserialize)]
struct Registrar {
    #[serde(default)]
    registrar_name: Option<String>,
}

/// The contact fields kept; street address, phone and fax are not decoded.
#[derive(Deserialize)]
struct Contact {
    #[serde(default)]
    full_name: Option<String>,
    #[serde(default)]
    company_name: Option<String>,
    #[serde(default)]
    country_code: Option<String>,
    #[serde(default)]
    email_address: Option<String>,
}

/// The request URL for `domain`. **Pure.**
#[must_use]
pub fn url(domain: &str) -> String {
    format!(
        "https://api.whoxy.com/?whois={}",
        percent_encode_component(domain)
    )
}

/// Look `indicator` up; an address has no WHOIS record here.
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
        Answer::NotFound(_) => Err(LegError::Unexpected(404)),
    }
}

/// The error Whoxy's `status: 0` reason means. **Pure.**
fn refusal(reason: Option<&str>) -> LegError {
    let reason = reason.unwrap_or_default().to_ascii_lowercase();
    if reason.contains("api key") {
        LegError::Unauthorized
    } else if reason.contains("balance") || reason.contains("credit") {
        LegError::Forbidden
    } else if reason.contains("limit") {
        LegError::RateLimited { retry_after: None }
    } else {
        LegError::Decode(format!(
            "whoxy refused: {}",
            api_leg::clean(Some(&reason)).unwrap_or_default()
        ))
    }
}

/// One answer body for `domain`. **Pure.**
///
/// # Errors
/// The refusal Whoxy's `status: 0` means, or [`LegError::Decode`] for another shape or domain.
pub fn decode(body: &[u8], domain: &str) -> Result<Option<Finding>, LegError> {
    let body: Body = api_leg::decode(body)?;
    if body.status != 1 {
        return Err(refusal(body.status_reason.as_deref()));
    }
    if body
        .domain_name
        .as_deref()
        .is_some_and(|d| !d.eq_ignore_ascii_case(domain))
    {
        return Err(LegError::Decode("answer names another domain".into()));
    }
    if body.domain_registered.as_deref() == Some("no") {
        return Ok(None);
    }
    let registrar = body
        .domain_registrar
        .and_then(|r| api_leg::clean(r.registrar_name.as_deref()));
    let registrant = body.registrant_contact;
    let mut finding = Finding::new(format!(
        "Whoxy WHOIS: registered{}",
        registrar
            .as_deref()
            .map_or_else(String::new, |r| format!(" with {r}"))
    ))
    .opt_attr("registrar", registrar.as_deref())
    .opt_attr("created", body.create_date.as_deref())
    .opt_attr("updated", body.update_date.as_deref())
    .opt_attr("expires", body.expiry_date.as_deref())
    .list_attr("name_servers", &body.name_servers)
    .list_attr("domain_status", &body.domain_status);
    if let Some(r) = registrant.as_ref() {
        finding = finding
            .opt_attr("registrant_name", r.full_name.as_deref())
            .opt_attr("registrant_org", r.company_name.as_deref())
            .opt_attr("registrant_country", r.country_code.as_deref());
    }
    for ns in &body.name_servers {
        finding = finding.pivot(
            PivotKind::Domain,
            ns,
            "Name server in the domain's WHOIS record",
        );
    }
    for contact in [
        registrant,
        body.administrative_contact,
        body.technical_contact,
    ]
    .into_iter()
    .flatten()
    {
        if let Some(email) = contact.email_address.as_deref() {
            finding = finding.pivot(
                PivotKind::Email,
                email,
                "Contact address in the domain's WHOIS record",
            );
        }
        if let Some(org) = contact.company_name.as_deref() {
            finding = finding.pivot(
                PivotKind::Organisation,
                org,
                "Organisation in the domain's WHOIS record",
            );
        }
    }
    Ok(Some(finding))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Whoxy's published `liveWhois.json` sample, `raw_whois` and repeated contacts trimmed.
    const SAMPLE: &str = r#"{"status":1,"domain_name":"excite.com","query_time":"2016-06-11 19:19:24","whois_server":"whois.markmonitor.com","domain_registered":"yes","create_date":"1995-09-19","update_date":"2016-04-26","expiry_date":"2017-09-18","domain_registrar":{"iana_id":292,"registrar_name":"MarkMonitor, Inc.","whois_server":"whois.markmonitor.com","website_url":"http://www.markmonitor.com","email_address":"abusecomplaints@markmonitor.com","phone_number":"+1.2083895740"},"registrant_contact":{"full_name":"Domain Administrator","company_name":"Mindspark Interactive Network, Inc.","mailing_address":"29 Wells Ave,","city_name":"Yonkers","state_name":"NY","zip_code":"10701","country_name":"United States","country_code":"US","email_address":"dnsmanager@mindspark.com","phone_number":"+1.9145912000","fax_number":"+1.9142064559"},"name_servers":["ns5.iaccap.com","ns6.iaccap.com"],"domain_status":["clientUpdateProhibited","clientTransferProhibited"]}"#;
    /// Recorded with an invalid key on 2026-10-14 (HTTP 200), and Whoxy's published `apiError.json`.
    const INVALID_KEY: &str = r#"{"status": 0, "status_reason": "Invalid API Key"}"#;

    #[test]
    fn the_published_sample_keeps_registrar_dates_and_pivots_but_no_phone_or_street() {
        let f = decode(SAMPLE.as_bytes(), "excite.com")
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("sample must decode"));
        assert_eq!(f.summary, "Whoxy WHOIS: registered with MarkMonitor, Inc.");
        assert!(f.attrs.contains(&("created", "1995-09-19".into())));
        assert!(f.attrs.contains(&("registrant_country", "US".into())));
        let text = format!("{f:?}");
        assert!(
            !text.contains("9145912000") && !text.contains("Wells Ave"),
            "{text}"
        );
        assert!(
            f.pivots
                .iter()
                .any(|p| p.kind == PivotKind::Email && p.value == "dnsmanager@mindspark.com")
        );
        assert!(
            f.pivots
                .iter()
                .any(|p| p.kind == PivotKind::Domain && p.value == "ns5.iaccap.com")
        );
        assert_eq!(
            f.pivots
                .iter()
                .filter(|p| p.kind == PivotKind::Organisation)
                .count(),
            1
        );
    }

    #[test]
    fn status_zero_is_a_refusal_never_a_zero() {
        assert_eq!(
            decode(INVALID_KEY.as_bytes(), "excite.com"),
            Err(LegError::Unauthorized)
        );
        let broke = r#"{"status":0,"status_reason":"Account Balance Exhausted"}"#;
        assert_eq!(
            decode(broke.as_bytes(), "excite.com"),
            Err(LegError::Forbidden)
        );
    }

    #[test]
    fn an_unregistered_domain_is_a_zero_and_another_domain_is_refused() {
        assert_eq!(
            decode(
                br#"{"status":1,"domain_name":"zz.example","domain_registered":"no"}"#,
                "zz.example"
            ),
            Ok(None)
        );
        assert!(decode(SAMPLE.as_bytes(), "example.com").is_err());
    }

    #[test]
    fn the_url_never_holds_the_key() {
        assert_eq!(
            url("example.com"),
            "https://api.whoxy.com/?whois=example.com"
        );
    }
}
