//! Hunter.io domain search: published work addresses at one domain (free key, 25 searches a
//! month, 10 addresses a search).
//!
//! One lookup is one `GET https://api.hunter.io/v2/domain-search?domain={domain}&limit=10` with
//! the key in the `X-API-KEY` header. It runs only when `HUNTSMAN_HUNTER_KEY` is set. Each
//! address keeps Hunter's confidence, type (`personal` or `generic`), the name and position Hunter
//! attributes to it, and how many public pages it was found on. The organisation and the address
//! pattern are kept for the domain. When Hunter reports more addresses than one page holds, the
//! answer is marked partial.

use serde::Deserialize;

use crate::api_leg::{self, Answer, Api, KeyUse, LegError};
use crate::canonical::canonical_email;
use crate::http::{Transport, percent_encode_component};
use crate::keys::Keys;

pub const SOURCE: &str = "hunter";
pub const KEY_SLOT: &str = crate::environment::HUNTER_KEY_ENV;
pub const API: Api = Api {
    source: SOURCE,
    provider: "hunter.io",
    origin: "https://api.hunter.io:443",
    key: Some(KeyUse {
        slot: KEY_SLOT,
        header: "X-API-KEY",
        required: true,
    }),
};
/// Addresses read per search. The free plan's ceiling.
pub const LIMIT: usize = 10;

/// One published address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    pub email: String,
    /// Hunter's confidence, 0 to 100.
    pub confidence: u8,
    pub kind: Option<String>,
    pub name: Option<String>,
    pub position: Option<String>,
    pub sources: usize,
}

/// One domain search page.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Search {
    pub organization: Option<String>,
    pub pattern: Option<String>,
    pub addresses: Vec<Address>,
    /// Addresses Hunter reports in all.
    pub total: Option<u64>,
}

impl Search {
    /// Why this page is not the whole answer, or `None` when it is.
    #[must_use]
    pub fn truncation(&self) -> Option<String> {
        let total = self.total?;
        (total > self.addresses.len() as u64).then(|| {
            format!(
                "partial: read {} of {total} published addresses",
                self.addresses.len()
            )
        })
    }
}

#[derive(Deserialize)]
struct Envelope {
    data: Data,
    #[serde(default)]
    meta: Option<Meta>,
}

#[derive(Deserialize)]
struct Data {
    #[serde(default)]
    organization: Option<String>,
    #[serde(default)]
    pattern: Option<String>,
    #[serde(default)]
    emails: Vec<Email>,
}

#[derive(Deserialize)]
struct Email {
    value: String,
    #[serde(default, rename = "type")]
    kind: Option<String>,
    #[serde(default)]
    confidence: Option<u8>,
    #[serde(default)]
    sources: Vec<serde::de::IgnoredAny>,
    #[serde(default)]
    first_name: Option<String>,
    #[serde(default)]
    last_name: Option<String>,
    #[serde(default)]
    position: Option<String>,
}

#[derive(Deserialize)]
struct Meta {
    #[serde(default)]
    results: Option<u64>,
}

/// The request URL for `domain`. **Pure.**
#[must_use]
pub fn url(domain: &str) -> String {
    format!(
        "https://api.hunter.io/v2/domain-search?domain={}&limit={LIMIT}",
        percent_encode_component(domain)
    )
}

/// Search `domain` with the key in `keys`.
///
/// # Errors
/// [`LegError::MissingKey`] before any request when no key is configured; otherwise the
/// [`LegError`] that stopped the lookup.
pub fn search<T: Transport + ?Sized>(
    transport: &T,
    keys: &Keys,
    domain: &str,
    now_unix: u64,
) -> Result<Search, LegError> {
    match api_leg::get(transport, &API, keys, &url(domain), now_unix)? {
        Answer::Body(body) => decode(&body, domain),
        Answer::NotFound(_) => Err(LegError::Unexpected(404)),
    }
}

/// One answer body for `domain`. An address that is not canonical or not at `domain` (or one of
/// its subdomains) is dropped. **Pure.**
///
/// # Errors
/// [`LegError::Decode`] for a body that is not the documented envelope.
pub fn decode(body: &[u8], domain: &str) -> Result<Search, LegError> {
    let envelope: Envelope = api_leg::decode(body)?;
    let data = envelope.data;
    let mut addresses: Vec<Address> = data
        .emails
        .into_iter()
        .filter_map(|e| {
            let email = canonical_email(&e.value)?;
            let host = email.rsplit_once('@')?.1;
            let at_domain = host == domain || host.ends_with(&format!(".{domain}"));
            if !at_domain {
                return None;
            }
            let name = [e.first_name.as_deref(), e.last_name.as_deref()]
                .into_iter()
                .filter_map(api_leg::clean)
                .collect::<Vec<_>>()
                .join(" ");
            Some(Address {
                email,
                confidence: e.confidence.unwrap_or(0).min(100),
                kind: api_leg::clean(e.kind.as_deref()),
                name: (!name.is_empty()).then_some(name),
                position: api_leg::clean(e.position.as_deref()),
                sources: e.sources.len(),
            })
        })
        .collect();
    addresses.sort_by(|a, b| a.email.cmp(&b.email));
    addresses.dedup_by(|a, b| a.email == b.email);
    addresses.truncate(LIMIT);
    Ok(Search {
        organization: api_leg::clean(data.organization.as_deref()),
        pattern: api_leg::clean(data.pattern.as_deref()),
        addresses,
        total: envelope.meta.and_then(|m| m.results),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `domain-search` example of the Hunter v2 documentation, with a second address, an
    /// address at another domain, and the `meta` block.
    const DOCUMENTED: &str = r#"{"data":{"domain":"intercom.com","disposable":false,"webmail":false,"accept_all":true,"pattern":"{first}","organization":"Intercom","linked_domains":[],"emails":[
        {"value":"ciaran@intercom.com","type":"personal","confidence":92,"sources":[{"domain":"github.com","uri":"http://github.com/ciaranlee","extracted_on":"2015-07-29","last_seen_on":"2017-07-01","still_on_page":true},{"domain":"blog.intercom.com","uri":"http://blog.intercom.com/x","extracted_on":"2015-08-29","last_seen_on":"2017-07-01","still_on_page":true}],"first_name":"Ciaran","last_name":"Lee","position":"Support Engineer","seniority":"senior","department":"it","linkedin":null,"twitter":"ciaran_lee","phone_number":null,"verification":{"date":"2019-12-06","status":"valid"}},
        {"value":"Team@Intercom.com","type":"generic","confidence":250,"sources":[],"first_name":null,"last_name":null,"position":null},
        {"value":"someone@elsewhere.example","type":"personal","confidence":80,"sources":[]}
    ]},"meta":{"results":35,"limit":10,"offset":0,"params":{"domain":"intercom.com"}}}"#;

    #[test]
    fn documented_addresses_keep_name_position_and_confidence() {
        let search =
            decode(DOCUMENTED.as_bytes(), "intercom.com").unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(search.organization.as_deref(), Some("Intercom"));
        assert_eq!(search.pattern.as_deref(), Some("{first}"));
        let emails: Vec<&str> = search.addresses.iter().map(|a| a.email.as_str()).collect();
        assert_eq!(emails, ["ciaran@intercom.com", "team@intercom.com"]);
        let ciaran = &search.addresses[0];
        assert_eq!(ciaran.confidence, 92);
        assert_eq!(ciaran.name.as_deref(), Some("Ciaran Lee"));
        assert_eq!(ciaran.position.as_deref(), Some("Support Engineer"));
        assert_eq!(ciaran.sources, 2);
        assert_eq!(search.addresses[1].confidence, 100, "capped at 100");
        assert_eq!(search.addresses[1].name, None);
    }

    #[test]
    fn more_published_addresses_than_read_is_partial() {
        let search =
            decode(DOCUMENTED.as_bytes(), "intercom.com").unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            search.truncation().as_deref(),
            Some("partial: read 2 of 35 published addresses")
        );
    }

    #[test]
    fn an_error_envelope_is_not_an_empty_domain() {
        let refused = r#"{"errors":[{"id":"authentication_failed","code":401,"details":"No user found for the API key supplied"}]}"#;
        assert!(decode(refused.as_bytes(), "example.com").is_err());
    }
}
