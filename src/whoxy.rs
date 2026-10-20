//! Whoxy: the live WHOIS record of one domain (pay-as-you-go, one credit per lookup).
//!
//! One lookup is one `GET https://api.whoxy.com/?whois={domain}`, run whenever `HUNTSMAN_WHOXY_KEY`
//! is set; Whoxy takes the key only as the `key` query parameter, added as the request is sent.
//! Whoxy answers HTTP 200 for its own errors, with `status: 0` and a `status_reason`: an invalid
//! key is reported as a rejected key and an empty balance as a plan refusal, never as a zero.
//! What is kept: registrar, dates, status codes, name servers, the registrant's country, and from
//! the registrant, administrative and technical contacts the name, organisation and address, under
//! the `registrant_*`, `admin_*` and `tech_*` attributes the registration and shared-operator
//! relations read. A value a privacy service or redaction notice put in place of the owner's is
//! kept under `{role}_proxy` and tags the finding `whois-privacy`, but is never a relation key or a
//! pivot: two domains behind one privacy service share a proxy, not an owner. Street address,
//! phone and fax are not kept.
//!
//! For an address the same key runs a reverse WHOIS (`?reverse=whois&email={address}`, one reverse
//! credit per page): the first page of domains registered with that address, each a domain pivot.

use serde::Deserialize;

use crate::api_leg::{self, Answer, Api, KeyPlace, KeyUse, LegError};
use crate::canonical::canonical_email;
use crate::domains::is_proxy_registrant;
use crate::http::{Transport, percent_encode_component};
use crate::indicator_sources::{Finding, Indicator, IndicatorKind, PivotKind, Source};
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
    kinds: &[IndicatorKind::Domain, IndicatorKind::Email],
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

/// The attributes one contact's fields are kept under.
struct Role {
    name: &'static str,
    org: &'static str,
    email: &'static str,
    /// Any field a privacy service, redaction notice or provider filled in for the owner.
    proxy: &'static str,
}

const REGISTRANT: Role = Role {
    name: "registrant_name",
    org: "registrant_org",
    email: "registrant_email",
    proxy: "registrant_proxy",
};
const ADMIN: Role = Role {
    name: "admin_name",
    org: "admin_org",
    email: "admin_email",
    proxy: "admin_proxy",
};
const TECH: Role = Role {
    name: "tech_name",
    org: "tech_org",
    email: "tech_email",
    proxy: "tech_proxy",
};

/// The tag on a record with at least one field filled in by a privacy service or redaction.
pub const PRIVACY_TAG: &str = "whois-privacy";

/// The request URL for `domain`. **Pure.**
#[must_use]
pub fn url(domain: &str) -> String {
    format!(
        "https://api.whoxy.com/?whois={}",
        percent_encode_component(domain)
    )
}

/// The reverse WHOIS URL for `email`. **Pure.**
#[must_use]
pub fn reverse_url(email: &str) -> String {
    format!(
        "https://api.whoxy.com/?reverse=whois&email={}",
        percent_encode_component(email)
    )
}

/// Look `indicator` up: the WHOIS record of a domain, or the domains registered with an address.
///
/// # Errors
/// The [`LegError`] that stopped the lookup.
pub fn lookup(
    transport: &dyn Transport,
    keys: &Keys,
    indicator: Indicator<'_>,
    now_unix: u64,
) -> Result<Option<Finding>, LegError> {
    let (url, email) = match indicator {
        Indicator::Domain(domain) => (url(domain), None),
        Indicator::Email(email) => (reverse_url(email), Some(email)),
        Indicator::Ip(_) | Indicator::Phone(_) | Indicator::Cell(_) | Indicator::MacAddress(_) => {
            return Ok(None);
        }
    };
    match api_leg::get(transport, &API, keys, &url, now_unix)? {
        Answer::Body(body) => match email {
            Some(_) => decode_reverse(&body),
            None => decode(&body, indicator.value()),
        },
        Answer::NotFound(_) => Err(LegError::Unexpected(404)),
    }
}

#[derive(Deserialize)]
struct Reverse {
    status: i64,
    #[serde(default)]
    status_reason: Option<String>,
    #[serde(default)]
    total_results: Option<u64>,
    #[serde(default)]
    search_result: Vec<ReverseHit>,
}

#[derive(Deserialize)]
struct ReverseHit {
    #[serde(default)]
    domain_name: Option<String>,
}

/// One reverse WHOIS page. No domains is a valid zero. **Pure.**
///
/// # Errors
/// The refusal Whoxy's `status: 0` means, or [`LegError::Decode`] for another shape.
pub fn decode_reverse(body: &[u8]) -> Result<Option<Finding>, LegError> {
    let body: Reverse = api_leg::decode(body)?;
    if body.status != 1 {
        return Err(refusal(body.status_reason.as_deref()));
    }
    let domains: Vec<&str> = body
        .search_result
        .iter()
        .filter_map(|h| h.domain_name.as_deref())
        .collect();
    if domains.is_empty() {
        return Ok(None);
    }
    let total = body.total_results.unwrap_or(domains.len() as u64);
    let mut finding = Finding::new(format!(
        "Whoxy reverse WHOIS: {total} domain(s) registered with the address"
    ))
    .attr("registered_domains", total.to_string())
    .tag_if(total > domains.len() as u64, "truncated");
    for domain in domains {
        finding = finding.pivot(
            PivotKind::Domain,
            domain,
            "Domain whose WHOIS record names the address",
        );
    }
    Ok(Some(finding))
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
    .list_attr("domain_status", &body.domain_status)
    .opt_attr(
        "registrant_country",
        body.registrant_contact
            .as_ref()
            .and_then(|r| r.country_code.as_deref()),
    );
    for ns in &body.name_servers {
        finding = finding.pivot(
            PivotKind::Domain,
            ns,
            "Name server in the domain's WHOIS record",
        );
    }
    for (role, contact) in [
        (&REGISTRANT, body.registrant_contact),
        (&ADMIN, body.administrative_contact),
        (&TECH, body.technical_contact),
    ] {
        if let Some(contact) = contact {
            finding = contact_fields(finding, role, &contact);
        }
    }
    Ok(Some(finding))
}

/// One contact's name, organisation and address on `finding`. The owner's own values are kept
/// under `role`'s attributes and the organisation and address are pivots; a value a privacy
/// service, redaction notice or provider put there instead is kept under `role.proxy` and tags the
/// finding. **Pure.**
fn contact_fields(finding: Finding, role: &Role, contact: &Contact) -> Finding {
    let fields = [
        (
            role.name,
            owner_value(contact.full_name.as_deref(), false),
            None,
        ),
        (
            role.org,
            owner_value(contact.company_name.as_deref(), false),
            Some((
                PivotKind::Organisation,
                "Organisation in the domain's WHOIS record",
            )),
        ),
        (
            role.email,
            owner_value(contact.email_address.as_deref(), true),
            Some((
                PivotKind::Email,
                "Contact address in the domain's WHOIS record",
            )),
        ),
    ];
    fields
        .into_iter()
        .fold(finding, |finding, (key, value, pivot)| match value {
            Some(Ok(value)) => {
                let finding = finding.attr(key, &value);
                match pivot {
                    Some((kind, summary)) => finding.pivot(kind, &value, summary),
                    None => finding,
                }
            }
            Some(Err(value)) => finding.attr(role.proxy, value).tag(PRIVACY_TAG),
            None => finding,
        })
}

/// A contact field as the owner's own value (`Ok`), or as one a privacy service, redaction notice
/// or provider put in its place (`Err`). An address is kept in canonical form; one that does not
/// parse is not the owner's address. `None` when the field is blank. **Pure.**
fn owner_value(value: Option<&str>, is_email: bool) -> Option<Result<String, String>> {
    let value = api_leg::clean(value)?;
    let owner = if is_email {
        canonical_email(&value).filter(|email| !is_proxy_registrant(email, true))
    } else {
        Some(value.clone()).filter(|text| !is_proxy_registrant(text, false))
    };
    Some(owner.ok_or(value))
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
        assert!(
            f.attrs
                .contains(&("registrant_email", "dnsmanager@mindspark.com".into()))
        );
        assert!(f.tags.is_empty(), "{:?}", f.tags);
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

    /// Whoxy's published `reverseWhois.json` shape, trimmed to two results.
    const REVERSE: &str = r#"{"status":1,"total_pages":1,"current_page":1,"total_results":3,"search_result":[{"num":1,"domain_name":"mindspark.com","query_time":"2016-06-11 19:19:24","create_date":"1999-02-08","update_date":"2016-01-09","expiry_date":"2017-02-08","domain_registered":"yes","registrant_contact":{"full_name":"Domain Administrator","email_address":"dnsmanager@mindspark.com","phone_number":"+1.9145912000"}},{"num":2,"domain_name":"excite.com","create_date":"1995-09-19"}]}"#;

    #[test]
    fn a_reverse_page_turns_each_domain_into_a_pivot() {
        let f = decode_reverse(REVERSE.as_bytes())
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("sample must decode"));
        let names: Vec<&str> = f.pivots.iter().map(|p| p.value.as_str()).collect();
        assert_eq!(names, ["mindspark.com", "excite.com"]);
        assert_eq!(f.tags, ["truncated"]);
        assert!(!format!("{f:?}").contains("9145912000"));
        assert_eq!(
            decode_reverse(br#"{"status":1,"total_results":0,"search_result":[]}"#),
            Ok(None)
        );
        assert_eq!(
            decode_reverse(INVALID_KEY.as_bytes()),
            Err(LegError::Unauthorized)
        );
        assert_eq!(
            reverse_url("a+b@example.com"),
            "https://api.whoxy.com/?reverse=whois&email=a%2Bb%40example.com"
        );
    }

    use crate::entity::{Entity, EntityKind, merge_by_uid};
    use crate::http::{Request, Response, TransportFailure};
    use crate::relation::RelationKind;
    use crate::source_outcome::SourceOutcomeKind;

    /// Whoxy answering with one record per domain; every other request fails.
    struct Records(Vec<(String, String)>);

    impl Records {
        fn new(domains: &[&str], contact: impl Fn(&str) -> String) -> Self {
            Self(
                domains
                    .iter()
                    .map(|domain| {
                        let contact = contact(domain);
                        let body = format!(
                            r#"{{"status":1,"domain_name":"{domain}","domain_registered":"yes","domain_registrar":{{"registrar_name":"NameCheap, Inc."}},"registrant_contact":{contact},"administrative_contact":{contact}}}"#
                        );
                        (url(domain), body)
                    })
                    .collect(),
            )
        }
    }

    impl Transport for Records {
        fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
            self.0
                .iter()
                .find(|(url, _)| {
                    request
                        .url
                        .strip_prefix(url.as_str())
                        .is_some_and(|rest| rest.is_empty() || rest.starts_with('&'))
                })
                .map(|(_, body)| crate::test_support::json_ok(body))
                .ok_or_else(|| TransportFailure {
                    kind: SourceOutcomeKind::ConnectFailure,
                    detail: "offline".into(),
                    blocked: false,
                })
        }
    }

    /// One `domain` lookup's indicator legs per domain, with only the Whoxy key set.
    fn lookups(records: &Records, domains: &[&str]) -> Vec<Entity> {
        let keys = Keys::parse(&format!("{KEY_SLOT}=k-0123456789abcdef\n"))
            .unwrap_or_else(|e| panic!("{e}"));
        let mut entities = Vec::new();
        for domain in domains {
            let legs = crate::indicator_legs::run(
                records,
                &keys,
                Indicator::Domain(domain),
                &format!("lookup-{domain}"),
                1,
            );
            let whoxy = legs.outcomes.iter().find(|o| o.module == SOURCE);
            assert!(
                whoxy.is_some_and(|o| o.kind.is_accepted()),
                "{:?}",
                legs.outcomes
            );
            entities.extend(legs.entities);
        }
        merge_by_uid(&mut entities);
        entities
    }

    fn rules_fired(entities: Vec<Entity>) -> Vec<String> {
        crate::analysis::analyze_snapshot(&crate::pipeline::AnalysisSnapshot {
            entities,
            relations: Vec::new(),
            coverage: Vec::new(),
            ancestry: crate::evidence_ancestry::EvidenceAncestryGraph::default(),
            truncated: false,
        })
        .correlations
        .into_iter()
        .map(|correlation| correlation.rule_id)
        .collect()
    }

    fn evidence_attr(entity: &Entity, key: &str) -> Vec<String> {
        entity
            .evidence
            .iter()
            .flat_map(|evidence| evidence.attr_values(key))
            .map(str::to_owned)
            .collect()
    }

    /// Two domains a person registered with one address are registered by that address, and the
    /// shared-registrant rule names them. Before, the address was only a pivot: no relation read
    /// it, so AU-109 fired only when the record also named an organisation.
    #[test]
    fn two_domains_registered_with_one_address_share_a_registrant() {
        let domains = ["alpha-shop.com", "beta-shop.org"];
        let records = Records::new(&domains, |_| {
            r#"{"full_name":"Ada Lovelace","email_address":"Ada@Analytical-Engines.com","country_code":"GB"}"#.into()
        });
        let entities = lookups(&records, &domains);
        let fired = rules_fired(entities.clone());
        assert!(
            fired.iter().any(|id| id == "AU-109"),
            "rules that fired: {fired:?}"
        );

        let address = entities
            .iter()
            .find(|e| e.kind == EntityKind::Email && e.value == "ada@analytical-engines.com")
            .unwrap_or_else(|| panic!("{entities:?}"));
        for domain in domains {
            let entity = entities
                .iter()
                .find(|e| e.kind == EntityKind::Domain && e.value == domain)
                .unwrap_or_else(|| panic!("{domain}"));
            assert_eq!(
                evidence_attr(entity, "registrant_email"),
                ["ada@analytical-engines.com"]
            );
            assert_eq!(
                evidence_attr(entity, "admin_email"),
                ["ada@analytical-engines.com"]
            );
        }
        let registered_by = crate::relation::derive_all(&entities, "two-lookups")
            .into_iter()
            .filter(|r| r.kind == RelationKind::RegisteredBy && r.to_uid == address.uid)
            .count();
        assert_eq!(registered_by, 2);
    }

    /// Domains behind one privacy service share a proxy, not an owner: the proxy's name,
    /// organisation and address stay in the record, but no relation or rule treats them as the
    /// registrant. Before, the proxy became an organisation both domains were registered by, so
    /// AU-109 named any two privacy-protected domains as one operator's.
    #[test]
    fn domains_behind_one_privacy_service_do_not_share_a_registrant() {
        let domains = ["alpha-shop.com", "beta-shop.org"];
        let records = Records::new(&domains, |domain| {
            let mailbox = domain.replace('.', "-");
            format!(
                r#"{{"full_name":"REDACTED FOR PRIVACY","company_name":"Domains By Proxy, LLC","email_address":"{mailbox}@domainsbyproxy.com","country_code":"US"}}"#
            )
        });
        let entities = lookups(&records, &domains);
        let fired = rules_fired(entities.clone());
        assert!(
            !fired.iter().any(|id| id == "AU-109"),
            "rules that fired: {fired:?}"
        );

        for domain in domains {
            let entity = entities
                .iter()
                .find(|e| e.kind == EntityKind::Domain && e.value == domain)
                .unwrap_or_else(|| panic!("{domain}"));
            assert!(entity.tags.iter().any(|t| t == PRIVACY_TAG), "{entity:?}");
            let proxy = evidence_attr(entity, "registrant_proxy").join("; ");
            for kept in [
                "REDACTED FOR PRIVACY",
                "Domains By Proxy, LLC",
                "@domainsbyproxy.com",
            ] {
                assert!(proxy.contains(kept), "{kept} not in {proxy}");
            }
            for key in [
                "registrant_name",
                "registrant_org",
                "registrant_email",
                "admin_org",
            ] {
                assert!(evidence_attr(entity, key).is_empty(), "{key} on {domain}");
            }
        }
        assert!(
            !entities
                .iter()
                .any(|e| matches!(e.kind, EntityKind::Organisation | EntityKind::Email)),
            "{entities:?}"
        );
    }

    /// A record that redacts the name but publishes the organisation keeps the organisation.
    #[test]
    fn a_redacted_name_beside_a_published_organisation_keeps_the_organisation() {
        let body = br#"{"status":1,"domain_name":"acme-shop.com","domain_registered":"yes","registrant_contact":{"full_name":"REDACTED FOR PRIVACY","company_name":"Acme Shops Ltd","email_address":"Please query the RDDS service of the Registrar of Record"}}"#;
        let f = decode(body, "acme-shop.com")
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("record must decode"));
        assert!(
            f.attrs
                .contains(&("registrant_org", "Acme Shops Ltd".into()))
        );
        assert!(
            f.attrs
                .contains(&("registrant_proxy", "REDACTED FOR PRIVACY".into()))
        );
        assert!(f.attrs.contains(&(
            "registrant_proxy",
            "Please query the RDDS service of the Registrar of Record".into()
        )));
        assert_eq!(f.tags, [PRIVACY_TAG]);
        let pivots: Vec<(PivotKind, &str)> = f
            .pivots
            .iter()
            .map(|p| (p.kind, p.value.as_str()))
            .collect();
        assert_eq!(pivots, [(PivotKind::Organisation, "Acme Shops Ltd")]);
    }
}
