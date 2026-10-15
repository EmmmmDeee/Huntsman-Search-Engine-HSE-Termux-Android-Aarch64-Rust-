//! Hunter.io domain search: published work addresses at one domain (free key, 25 searches a
//! month, 10 addresses a search).
//!
//! One lookup is one `GET https://api.hunter.io/v2/domain-search?domain={domain}&limit=10` with
//! the key in the `X-API-KEY` header. It runs only when `HUNTSMAN_HUNTER_KEY` is set. Each
//! address keeps Hunter's confidence, type (`personal` or `generic`), the name and position Hunter
//! attributes to it, and how many public pages it was found on. The organisation and the address
//! pattern are kept for the domain. When Hunter reports more addresses than one page holds, the
//! answer is marked partial.
//!
//! The same key also verifies one address ([`VERIFY`], an indicator source for `email`): one
//! `GET https://api.hunter.io/v2/email-verifier?email={address}`, keeping everything it answers:
//! Hunter's verdict and result, score, each check (format, gibberish, MX records, SMTP server, SMTP
//! check) and flag (disposable, webmail, accept-all, blocked), every public page that carries the
//! address with when it was seen there, and the whole answer as `raw_answer`.

use serde::Deserialize;

use crate::api_leg::{self, Answer, Api, KeyPlace, KeyUse, LegError};
use crate::canonical::canonical_email;
use crate::http::{Transport, percent_encode_component};
use crate::indicator_sources::{Finding, Indicator, IndicatorKind, Source};
use crate::keys::Keys;

pub const SOURCE: &str = "hunter";
pub const KEY_SLOT: &str = crate::environment::HUNTER_KEY_ENV;
pub const API: Api = Api {
    source: SOURCE,
    provider: "hunter.io",
    origin: "https://api.hunter.io:443",
    key: Some(KeyUse {
        slot: KEY_SLOT,
        place: KeyPlace::Header("X-API-KEY"),
        required: true,
    }),
};
/// Verifies one address with the same key; see [`verify`].
pub const VERIFY: Source = Source {
    api: &API,
    kinds: &[IndicatorKind::Email],
    lookup: verify,
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

#[derive(Deserialize)]
struct VerifyEnvelope {
    data: Verification,
}

#[derive(Deserialize)]
struct Verification {
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    result: Option<String>,
    #[serde(default)]
    score: Option<u8>,
    #[serde(default)]
    regexp: Option<bool>,
    #[serde(default)]
    gibberish: Option<bool>,
    #[serde(default)]
    mx_records: Option<bool>,
    #[serde(default)]
    smtp_server: Option<bool>,
    #[serde(default)]
    smtp_check: Option<bool>,
    #[serde(default)]
    disposable: Option<bool>,
    #[serde(default)]
    webmail: Option<bool>,
    #[serde(default)]
    accept_all: Option<bool>,
    #[serde(default)]
    block: Option<bool>,
    #[serde(default)]
    sources: Vec<serde_json::Value>,
}

/// One public page Hunter found the address on.
#[derive(Deserialize)]
struct SourcePage {
    #[serde(default)]
    uri: Option<String>,
    #[serde(default)]
    domain: Option<String>,
    #[serde(default)]
    extracted_on: Option<String>,
    #[serde(default)]
    last_seen_on: Option<String>,
    #[serde(default)]
    still_on_page: Option<bool>,
}

impl SourcePage {
    /// `uri | first seen D | last seen D | still on the page`, a part the answer leaves out left
    /// out. **Pure.**
    fn row(&self) -> Option<String> {
        let page = api_leg::clean(self.uri.as_deref().or(self.domain.as_deref()))?;
        let mut parts = vec![page];
        if let Some(day) = api_leg::clean(self.extracted_on.as_deref()) {
            parts.push(format!("first seen {day}"));
        }
        if let Some(day) = api_leg::clean(self.last_seen_on.as_deref()) {
            parts.push(format!("last seen {day}"));
        }
        match self.still_on_page {
            Some(true) => parts.push("still on the page".into()),
            Some(false) => parts.push("no longer on the page".into()),
            None => {}
        }
        Some(parts.join(" | "))
    }
}

/// The verifier URL for `email`. **Pure.**
#[must_use]
pub fn verify_url(email: &str) -> String {
    format!(
        "https://api.hunter.io/v2/email-verifier?email={}",
        percent_encode_component(email)
    )
}

/// Verify `indicator` when it is an address.
///
/// # Errors
/// The [`LegError`] that stopped the lookup.
pub fn verify(
    transport: &dyn Transport,
    keys: &Keys,
    indicator: Indicator<'_>,
    now_unix: u64,
) -> Result<Option<Finding>, LegError> {
    let Indicator::Email(email) = indicator else {
        return Ok(None);
    };
    match api_leg::get(transport, &API, keys, &verify_url(email), now_unix)? {
        Answer::Body(body) => decode_verification(&body, email).map(Some),
        Answer::NotFound(_) => Err(LegError::Unexpected(404)),
    }
}

/// One verifier answer for `email`. **Pure.**
///
/// # Errors
/// [`LegError::Decode`] for an error envelope, another shape, or another address.
pub fn decode_verification(body: &[u8], email: &str) -> Result<Finding, LegError> {
    let whole: serde_json::Value = api_leg::decode(body)?;
    let data = api_leg::decode::<VerifyEnvelope>(body)?.data;
    if data
        .email
        .as_deref()
        .is_some_and(|e| !e.eq_ignore_ascii_case(email))
    {
        return Err(LegError::Decode("answer names another address".into()));
    }
    let status = api_leg::clean(data.status.as_deref()).unwrap_or_else(|| "unknown".into());
    let mut finding = Finding::new(format!("Hunter verifier: {status}"))
        .attr("verification", &status)
        .opt_attr("score", data.score.map(|s| s.min(100).to_string()))
        .attr("public_sources", data.sources.len().to_string())
        .opt_attr("result", data.result.as_deref());
    for (check, value) in [
        ("format_valid", data.regexp),
        ("gibberish", data.gibberish),
        ("mx_records", data.mx_records),
        ("smtp_server", data.smtp_server),
        ("smtp_check", data.smtp_check),
        ("disposable", data.disposable),
        ("webmail", data.webmail),
        ("accept_all", data.accept_all),
        ("blocked", data.block),
    ] {
        finding = finding.opt_attr(check, value.map(|v| v.to_string()));
    }
    // A page is read on its own, so one Hunter writes in another shape costs only itself.
    let pages = data.sources.iter().filter_map(|page| {
        serde_json::from_value::<SourcePage>(page.clone())
            .ok()?
            .row()
    });
    for page in pages {
        finding = finding.attr("source_pages", page);
    }
    finding = finding
        .attr("raw_answer", whole.to_string())
        .tag_if(data.disposable == Some(true), "disposable")
        .tag_if(data.webmail == Some(true), "webmail")
        .tag_if(data.accept_all == Some(true), "accept_all")
        .tag_if(data.block == Some(true), "blocked");
    if status == "invalid" {
        finding = finding.tag("undeliverable");
    }
    Ok(finding)
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

    /// The `email-verifier` example of the Hunter v2 documentation.
    const VERIFIED: &str = r#"{"data":{"status":"valid","result":"deliverable","_deprecation_notice":"Using result is deprecated, use status instead","score":100,"email":"patrick@stripe.com","regexp":true,"gibberish":false,"disposable":false,"webmail":false,"mx_records":true,"smtp_server":true,"smtp_check":true,"accept_all":false,"block":false,"sources":[{"domain":"beta.paperbook.app","uri":"http://beta.paperbook.app/x","extracted_on":"2020-12-01","last_seen_on":"2021-01-12","still_on_page":true}]},"meta":{"params":{"email":"patrick@stripe.com"}}}"#;

    #[test]
    fn the_documented_verification_keeps_status_score_and_sources() {
        let f = decode_verification(VERIFIED.as_bytes(), "patrick@stripe.com")
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(f.summary, "Hunter verifier: valid");
        assert!(f.attrs.contains(&("score", "100".into())));
        assert!(f.attrs.contains(&("public_sources", "1".into())));
        for (check, value) in [
            ("result", "deliverable"),
            ("format_valid", "true"),
            ("gibberish", "false"),
            ("mx_records", "true"),
            ("smtp_server", "true"),
            ("smtp_check", "true"),
            ("accept_all", "false"),
            ("blocked", "false"),
        ] {
            assert!(
                f.attrs.contains(&(check, value.into())),
                "{check}: {:?}",
                f.attrs
            );
        }
        assert!(f.attrs.contains(&(
            "source_pages",
            "http://beta.paperbook.app/x | first seen 2020-12-01 | last seen 2021-01-12 | still on the page".into()
        )));
        assert!(
            f.attrs
                .iter()
                .any(|(k, v)| *k == "raw_answer" && v.contains("_deprecation_notice")),
            "{:?}",
            f.attrs
        );
        assert!(f.tags.is_empty());
        assert!(decode_verification(VERIFIED.as_bytes(), "ada@example.com").is_err());
    }

    #[test]
    fn a_verifier_error_envelope_is_not_a_verdict() {
        let refused = r#"{"errors":[{"id":"authentication_failed","code":401,"details":"No user found for the API key supplied"}]}"#;
        assert!(decode_verification(refused.as_bytes(), "ada@example.com").is_err());
        assert_eq!(
            verify_url("a+b@example.com"),
            "https://api.hunter.io/v2/email-verifier?email=a%2Bb%40example.com"
        );
    }
}
